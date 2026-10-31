#!/usr/bin/env python3
"""
Build the attack-plan.yaml for the validate-findings harness.

Consumes:  Normalized model (ingest.py) + Scope (scope.py)
Produces:  ordered list of plan steps (recon → replay → chained → novel)
           with adapter classification and rollback hints filled in.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass, field
from itertools import count
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

if __package__:
    from .adapters import get_adapter
    from .chain import Chain, find_chains
    from .ingest import Finding, Normalized, ingest
    from .novel import recon_steps
    from .scope import Action, Scope
    from .scope import build as build_scope
else:  # running as a script: harnessing/5-validate/validate-findings/plan.py
    sys.path.insert(0, str(Path(__file__).parent))
    from adapters import get_adapter
    from chain import Chain, find_chains
    from ingest import Finding, Normalized, ingest
    from novel import recon_steps
    from scope import Action, Scope
    from scope import build as build_scope

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@dataclass
class Step:
    id: str = ""
    technique: str = ""  # recon | replay | adapted | chained | novel
    adapter: str = "k8s"
    verb: str = ""
    target: dict = field(default_factory=dict)
    finding_ref: str | None = None
    chain_ref: str | None = None
    novel_ref: str | None = None
    payload: str | None = None  # manifest / request body
    cmd: str | None = None  # raw command
    classification: str = "safe"
    expected: str = ""
    rollback: str | None = None
    preconditions: list[str] = field(default_factory=list)
    skip: str | None = None  # reason if pre-skipped
    summary: str = ""
    # Triage emitted ``verdict: needs_review`` (evidence not statically
    # locatable; never proven false).  Step is planned like a TP but
    # tagged so downstream can distinguish.
    triage_was_needs_review: bool | None = None

    def to_dict(self):
        d = {k: v for k, v in asdict(self).items() if v not in (None, [], "")}
        return d


# ---------------------------------------------------------------------------
# PoC → step conversion
# ---------------------------------------------------------------------------

K8S_KIND_RE = re.compile(r"^\s*kind:\s*([A-Za-z][A-Za-z0-9]*)\s*$", re.MULTILINE)
K8S_NS_RE = re.compile(r"^\s*namespace:\s*['\"]?([a-z0-9][a-z0-9-]*)['\"]?\s*$", re.MULTILINE)
KUBECTL_RE = re.compile(r"^\s*(kubectl|oc)\s+", re.MULTILINE)
CURL_RE = re.compile(r"^\s*curl\s+", re.MULTILINE)
PODMAN_RE = re.compile(r"^\s*(podman|docker)\s+exec\s+", re.MULTILINE)
WASM_RE = re.compile(r"\b(wasmtime|wasmedge|wasm-tools)\b")


def _step_from_poc(sid: str, f: Finding, poc, scope: Scope) -> Step | None:
    body = poc.body
    lang = poc.lang
    ns = None
    # YAML manifest with a Kind
    kind_m = K8S_KIND_RE.search(body)
    if kind_m or (lang in ("yaml", "yml") and "apiVersion" in body):
        # H7: completeness guard — kubectl needs BOTH apiVersion and
        # kind on every doc or it errors with "no matches for kind X
        # in version ''" / "Object 'Kind' is missing", which dead-ends
        # at inconclusive.  If the audit's evidence snippet captured
        # only the rules:/spec: block, return None so the adapted
        # chain (_rbac_adapted_step etc.) fires instead.
        try:
            docs = [d for d in yaml.safe_load_all(body) if d]
            if not docs or any(
                not isinstance(d, dict) or not d.get("kind") or not d.get("apiVersion")
                for d in docs
            ):
                return None
        except yaml.YAMLError:
            return None
        kind = kind_m.group(1) if kind_m else docs[0].get("kind", "")
        ns_m = K8S_NS_RE.search(body)
        ns = ns_m.group(1) if ns_m else None
        ctx = next(iter(scope.clusters), "__current__")
        return Step(
            id=sid,
            technique="replay",
            adapter="k8s",
            verb="apply-manifest",
            finding_ref=f.id,
            target={"context": ctx, "namespace": ns, "resource": kind.lower()},
            payload=body,
            expected=f.attack_pattern or f"{kind} accepted; {f.title}",
            rollback=(
                f"kubectl --context {ctx} "
                + (f"-n {ns} " if ns else "")
                + f"delete -f -  # re-pipe step {sid} payload"
            ),
            summary=f.title,
        )
    if KUBECTL_RE.search(body):
        ctx = next(iter(scope.clusters), "__current__")
        ns_m = re.search(r"-n\s+([a-z0-9-]+)", body)
        return Step(
            id=sid,
            technique="replay",
            adapter="k8s",
            verb="raw",
            finding_ref=f.id,
            target={"context": ctx, "namespace": ns_m.group(1) if ns_m else None},
            cmd=body,
            expected=f.attack_pattern or f.title,
            summary=f.title,
        )
    if CURL_RE.search(body):
        return Step(
            id=sid,
            technique="replay",
            adapter="k8s",
            verb="port-forward+http",
            finding_ref=f.id,
            target={"context": next(iter(scope.clusters), "__current__")},
            cmd=body,
            expected=f.attack_pattern or f.title,
            summary=f.title,
        )
    if PODMAN_RE.search(body):
        m = re.search(r"(podman|docker)\s+exec\s+(\S+)", body)
        return Step(
            id=sid,
            technique="replay",
            adapter="container",
            verb="exec",
            finding_ref=f.id,
            target={"name": m.group(2) if m else None},
            cmd=body,
            expected=f.attack_pattern or f.title,
            summary=f.title,
        )
    if WASM_RE.search(body) or lang == "wasm":
        art = scope.wasm_artifacts[0] if scope.wasm_artifacts else None
        return Step(
            id=sid,
            technique="replay",
            adapter="wasm",
            verb="invoke-export",
            finding_ref=f.id,
            target={"artifact": art},
            cmd=body,
            expected=f.attack_pattern or f.title,
            summary=f.title,
        )
    return None


# CWE → minimal adapted-probe verb (when no literal PoC exists)
#
# NOTE: these strings are stored as-is in Step.cmd — they are NEVER
# passed through ``str.format()`` (unlike novel.py's cmd_template).
# v0.4.2 doubled the braces in ``%{{http_code}}`` as if .format() were
# called; curl then saw ``%{{http_code}}`` literally and reported
# "unknown --write-out variable: '{http_code'" — 273 inconclusives.
CWE_ADAPTED = {
    # CWE-918 (SSRF) and CWE-306 (Missing AuthN) previously mapped to
    # port-forward+http with target={"context": ctx} only — no service name
    # and unfilled {port}/{path} placeholders → 77 findings hit vf-http-status:000
    # (RESIDUAL-INCONCLUSIVE-ANALYSIS.md §B). These need a finding-specific
    # target service; leave un-adapted so they fall through to replay/no_poc.
    "CWE-269": (
        "k8s",
        "rbac-can-i",
        "kubectl auth can-i --list --as=system:serviceaccount:{ns}:{sa}",
    ),
    # CWE-77/78 (command injection) adapted exec had no target pod →
    # 48 "no pod/name in step.target" inconclusives. Same rationale
    # as 918/306/441/610: needs finding-specific target.
    "CWE-22": ("container", "exec", "cat {path}"),
    # Debug interface / debug info exposed — probe the conventional Go
    # pprof path on the first in-namespace Service.  A 200 confirms.
    "CWE-489": ("k8s", "port-forward+http", "_HTTP_/debug/pprof/"),
    "CWE-215": ("k8s", "port-forward+http", "_HTTP_/debug/pprof/"),
    # CWE-441 (confused deputy) and CWE-610 (externally-controlled reference)
    # were mapped to ("k8s", "apply-manifest", None) — but apply-manifest with
    # no payload is unrunnable: 58 findings hit "no parseable Kubernetes object
    # in payload" (POC-UNPARSEABLE-RESULTS.csv). These CWEs have no generic
    # probe; they need a finding-specific manifest. Leave them un-adapted so
    # they fall through to replay (if evidence has a manifest) or no_poc.
}

# CWEs that CANNOT be generically adapted into a single safe probe.
# Instead of the opaque ``no-poc-no-adapter`` skip, emit a specific
# reason so the validation report explains *why* the finding wasn't
# exercised and what is needed to exercise it.
CWE_SKIP_REASON = {
    # Resource-exhaustion / DoS — validating means generating load that
    # degrades the component.  Requires --destructive AND a finding-
    # specific load profile; never auto-adapt.
    "CWE-400": "dos-needs-destructive-load",
    "CWE-770": "dos-needs-destructive-load",
    "CWE-674": "dos-needs-destructive-load",
    "CWE-1333": "dos-needs-destructive-load",
    # Confused-deputy / externally-controlled reference — needs a
    # finding-specific CR manifest naming the victim resource.
    "CWE-441": "needs-cr-manifest",
    "CWE-610": "needs-cr-manifest",
    "CWE-639": "needs-cr-manifest",
    # Integrity of downloaded code / unsigned artefact — validating
    # requires MITM of the download path, not a cluster probe.
    "CWE-494": "supply-chain-not-cluster-validatable",
    "CWE-345": "supply-chain-not-cluster-validatable",
    "CWE-347": "supply-chain-not-cluster-validatable",
    # Weak crypto / PRNG — needs a statistical or known-answer test
    # against captured output, not a single request.
    "CWE-338": "crypto-needs-statistical-test",
    "CWE-330": "crypto-needs-statistical-test",
    "CWE-327": "crypto-needs-statistical-test",
    # Insecure default — needs the specific resource+field the finding
    # names; no generic shape.
    "CWE-1188": "needs-config-field-ref",
    "CWE-276": "needs-config-field-ref",
    # External control of file/path — needs the specific config field
    # carrying the path (typically a CR spec field or CNI config key).
    "CWE-73": "needs-cr-manifest",
    # Timing / observable-discrepancy side channel — needs many timed
    # samples + statistical comparison, not a single curl.
    "CWE-208": "crypto-needs-statistical-test",
    "CWE-203": "crypto-needs-statistical-test",
    # HTTP request smuggling — needs precise wire-level request shaping
    # that curl can't express; use a dedicated smuggling tool.
    "CWE-444": "needs-protocol-crafting",
    # Unchecked return / improper error handling — behavioural; needs a
    # finding-specific failure injection to observe the swallow.
    "CWE-252": "needs-failure-injection",
    "CWE-390": "needs-failure-injection",
    # Resource exposed to wrong sphere — usually a host-path / socket
    # permission check; needs the concrete path from the finding.
    "CWE-668": "needs-config-field-ref",
    "CWE-732": "needs-config-field-ref",
    # SSRF / improper-access via a CR spec field (not an HTTP endpoint)
    # — only reached when _http_adapted_step found no path; needs the
    # CR kind+field manifest to drive the outbound fetch.
    "CWE-918": "needs-cr-manifest",
    "CWE-284": "needs-cr-manifest",
    "CWE-653": "needs-cr-manifest",
    # Runs-with-unnecessary-privilege — observable via securityContext
    # but a meaningful verdict needs the specific container+capability
    # the finding names.
    "CWE-250": "needs-config-field-ref",
    # Command/argument injection — adapted exec was removed in v0.5.1
    # (48× "no pod/name" inconclusives); needs the specific pod +
    # injection vector from the finding.
    "CWE-77": "needs-exec-target",
    "CWE-78": "needs-exec-target",
    "CWE-88": "needs-exec-target",
    # Non-HTTP protocol auth weakness (DNS AXFR/TSIG, gRPC reflection, …)
    # — only reached when no X-header was extractable for _spoof; needs
    # a protocol-specific client.
    "CWE-290": "needs-protocol-crafting",
    "CWE-306": "needs-protocol-crafting",
}


# ---------------------------------------------------------------------------
# Manual-PoC overlay
#
# Hand-written probe steps for findings the auto-adapters cannot cover.
# Each file is ``<MANUAL_POCS_DIR>/<repo-slug>__<finding-id>.yaml`` and
# contains a single Step mapping (verb, adapter, cmd|payload, expected,
# target, classification).  ``id``/``finding_ref``/``technique`` are
# filled in by the loader.
#
# These live in the CORPUS, not in this repo. A reproducer is written ABOUT a
# specific finding in a specific audited repo — it is campaign output, the same
# category as a fuzz harness, and the skill is the thing that CONSUMES them,
# not the thing they belong to. Default: <analysis-results>/validators/.
#
# Resolution order: MANUAL_POCS_DIR, else
# ``<locations.analysis_results>/validators`` from $TRAUST_CONFIG_HOME, else
# the workspace sibling ``<workspace>/analysis-results/validators``. The loader
# degrades to "no manual PoC steps" when the directory is absent.
# ---------------------------------------------------------------------------

import os as _os  # noqa: E402


def _resolve_manual_pocs_dir(args=None, *, config_home: Path | None = None) -> Path | None:
    explicit = _os.environ.get("MANUAL_POCS_DIR")
    if explicit:
        return Path(explicit)
    try:
        from traust.context import resolve_results_root

        validators = resolve_results_root(args, config_home=config_home) / "validators"
        if validators.is_dir():
            return validators
    except SystemExit:
        pass
    return None


def _manual_poc_step(sid: str, f: Finding, scope: Scope) -> Step | None:
    manual_dir = _resolve_manual_pocs_dir()
    if manual_dir is None or not manual_dir.is_dir():
        return None
    # Derive the repo slug.  source_report_path is the only field that's
    # always the bare directory slug regardless of single/multi-source
    # ingest; source_repo may be ``<pkg>:<repo>`` qualified.
    fid = f.id.split("/")[-1]
    if f.source_report_path:
        repo = Path(f.source_report_path).parent.name
    elif f.source_repo:
        repo = f.source_repo.split(":")[-1].split("/")[-1]
    else:
        repo = f.id.split(":")[0].split("/")[-1]
    for stem in (f"{repo}__{fid}", f.id.replace("/", "__").replace(":", "__")):
        p = manual_dir / f"{stem}.yaml"
        if not p.exists():
            continue
        try:
            d = yaml.safe_load(p.read_text()) or {}
        except Exception:
            return None
        ctx = next(iter(scope.clusters), "__current__")
        tgt = dict(d.get("target") or {})
        tgt.setdefault("context", ctx)
        return Step(
            id=sid,
            technique="replay",
            finding_ref=f.id,
            adapter=d.get("adapter", "k8s"),
            verb=d.get("verb", "raw"),
            target=tgt,
            cmd=d.get("cmd"),
            payload=d.get("payload"),
            classification=d.get("classification", "safe"),
            expected=d.get("expected") or f.attack_pattern or f.title,
            rollback=d.get("rollback"),
            summary=f"manual PoC ({p.name})",
        )
    return None


def _adapted_step(sid: str, f: Finding, scope: Scope) -> Step | None:
    for cwe in f.cwes:
        if cwe in CWE_ADAPTED:
            adapter, verb, cmd = CWE_ADAPTED[cwe]
            ctx = next(iter(scope.clusters), "__current__")
            # Sentinel ``_HTTP_<path>`` → reuse the route/port-forward
            # scaffold from _http_adapted_step with a fixed path.
            if isinstance(cmd, str) and cmd.startswith("_HTTP_"):
                return _http_adapted_step(sid, f, scope, tm=None, force_coords=("GET", cmd[6:]))
            return Step(
                id=sid,
                technique="adapted",
                adapter=adapter,
                verb=verb,
                finding_ref=f.id,
                target={"context": ctx} if adapter == "k8s" else {},
                cmd=cmd,
                expected=f.title,
                summary=f"adapted probe for {cwe}",
            )
    return None


# CWE-312/522/256 — sensitive data stored in plaintext.  Probe: dump every
# Secret + ConfigMap in the in-scope namespaces and scan the *decoded*
# values for credential-shaped strings.  Match → confirmed (data IS
# stored plaintext-readable); no match → refuted.
_SECRET_CWES = frozenset({"CWE-312", "CWE-522", "CWE-256", "CWE-313", "CWE-540", "CWE-260"})
_SECRET_PATTERN = (
    r"(BEGIN [A-Z ]*PRIVATE KEY"
    r"|aws_secret_access_key|AKIA[0-9A-Z]{16}"
    r"|password\s*[:=]\s*[^\s\"]{4,}"
    r"|sha256~[A-Za-z0-9_-]{20,}"
    r"|Bearer [A-Za-z0-9._-]{20,})"
)


def _secret_adapted_step(sid: str, f: Finding, scope: Scope) -> Step | None:
    if not any(c in _SECRET_CWES for c in f.cwes):
        return None
    ctx = next(iter(scope.clusters), "__current__")
    cs = scope.clusters.get(ctx)
    nss = (
        sorted(cs.explicit_namespaces)
        if cs and cs.explicit_namespaces
        else [p for p in (cs.namespaces if cs else []) if "*" not in p]
    )
    if not nss:
        return None
    ns_args = " ".join(f"-n {n}" for n in nss[:1])  # primary ns
    # REDACTION: emit only the key name + length + sha256 prefix of any
    # matched value — NEVER the value itself.  Artifacts are committed to
    # analysis-results; on shared-CI clusters
    # the matched value would be a live cloud credential.
    cmd = (
        f"oc --context {ctx} {ns_args} get secret,cm -o json 2>/dev/null "
        f"| jq -r '.items[] | .metadata.name as $n "
        f'  | (.data // {{}}) | to_entries[] | "\\($n)/\\(.key) \\(.value)"\' '
        f"| while read -r ref v; do "
        f'    d=$(printf %s "$v" | base64 -d 2>/dev/null); '
        f"    if printf %s \"$d\" | grep -qE '{_SECRET_PATTERN}'; then "
        f'      h=$(printf %s "$d" | sha256sum | cut -c1-12); '
        f'      echo "vf-plaintext-cred-found: $ref (${{#d}} bytes, sha256:$h)"; '
        f"    fi; "
        f"  done | head -5; "
        f"echo vf-secret-scan-done"
    )
    return Step(
        id=sid,
        technique="adapted",
        adapter="k8s",
        verb="raw",
        finding_ref=f.id,
        target={"context": ctx, "namespace": nss[0]},
        cmd=cmd,
        expected="vf-plaintext-cred-found — credential-shaped value present "
        "in Secret/ConfigMap data (value redacted; only ref+len+hash "
        "recorded)",
        summary=f"plaintext-credential scan ({','.join(sorted(set(f.cwes) & _SECRET_CWES))})",
    )


# CWE-732/284/269/266/250/276/285 — over-broad RBAC.  Probe: discover
# the operator's primary ServiceAccount in the in-scope namespace, then
# ``oc auth can-i <verb> <resource> -A --as=system:serviceaccount:…``.
# yes → confirmed (effective permission present); no → refuted (rule not
# bound or narrower than claimed).  This closes the 15-finding gap where
# "ClusterRole grants X" had no literal manifest in evidence (only the
# "SA bound to cluster-admin" pattern produced a replay step).
_RBAC_CWES = frozenset(
    {"CWE-732", "CWE-284", "CWE-269", "CWE-266", "CWE-250", "CWE-276", "CWE-285", "CWE-272"}
)
_RBAC_RESOURCE_RE = re.compile(
    r"\b(secret|configmap|clusterrole(?:binding)?s?|rolebinding"
    r"|serviceaccounts?/token|serviceaccount|node|pod|daemonset"
    r"|namespace|crd|customresourcedefinition|persistentvolume"
    r"|validatingwebhookconfiguration|mutatingwebhookconfiguration"
    r"|machineconfig|deployment)s?\b",
    re.I,
)
_RBAC_VERB_RE = re.compile(
    r"\b(get|list|watch|create|update|patch|delete|escalate|bind"
    r"|impersonate|wildcard|crud|read|write|\*/\*|\*\s*verbs)\b",
    re.I,
)


def _rbac_extract_grant(text: str) -> tuple[str, str] | None:
    """Return (verb, resource) from "ClusterRole grants <verb> on <res>".

    Searches *after* the grant keyword so the subject-position
    ``ClusterRole`` isn't picked as the resource (first attempt
    matched ``clusterroles`` for every finding).
    """
    # H8b: CWE-250/276/732 also tag securityContext + POSIX-perm
    # findings ("runs as root", "0666 mode", "readOnlyRootFilesystem
    # absent").  Those have no RBAC surface — bail out so the probe
    # doesn't fire on the first incidental k8s-resource word in the
    # title.  Require an RBAC-object keyword somewhere in the text.
    if not re.search(
        r"\b(ClusterRole|RoleBinding|ClusterRoleBinding"
        r"|RBAC|ServiceAccount\b.{0,40}\bbound"
        r"|bound\s+to\b.{0,30}\b(cluster-admin|ClusterRole)"
        r"|grants?\b)\b",
        text,
        re.I,
    ):
        return None
    grant = re.search(
        r"\b(grant\w*|access to|bound to "
        r"cluster-admin|wildcard.*on)\b",
        text,
        re.I,
    )
    tail = text[grant.end() :] if grant else text
    res_m = _RBAC_RESOURCE_RE.search(tail) or _RBAC_RESOURCE_RE.search(
        # tail had no resource (e.g. grant verb is "allows" appearing
        # *after* the resource) — retry on full text but skip a
        # subject-position ClusterRole/Role at the very start.
        re.sub(r"^.{0,40}?\b(?:Cluster)?Role(?:Binding)?\b", "", text, count=1, flags=re.I)
    )
    if not res_m:
        # Defense-in-depth: cluster-admin binding ⇒ probe secrets
        # cluster-wide as the canonical over-broad capability.
        if "cluster-admin" in text.lower():
            return ("list", "secrets")
        return None
    res = res_m.group(1).lower().rstrip("s")
    res = {
        "secret": "secrets",
        "configmap": "configmaps",
        "clusterrole": "clusterroles",
        "clusterrolebinding": "clusterrolebindings",
        "rolebinding": "rolebindings",
        "node": "nodes",
        "pod": "pods",
        "namespace": "namespaces",
        "deployment": "deployments",
        "daemonset": "daemonsets",
        "serviceaccount": "serviceaccounts",
        "serviceaccounts/token": "serviceaccounts/token",
        "crd": "customresourcedefinitions",
        "customresourcedefinition": "customresourcedefinitions",
        "persistentvolume": "persistentvolumes",
        "validatingwebhookconfiguration": "validatingwebhookconfigurations",
        "mutatingwebhookconfiguration": "mutatingwebhookconfigurations",
        "machineconfig": "machineconfigs.machineconfiguration.openshift.io",
    }.get(res, res + "s")
    verb_m = _RBAC_VERB_RE.search(tail) or _RBAC_VERB_RE.search(text)
    v = verb_m.group(1).lower() if verb_m else "list"
    verb = {
        "wildcard": "'*'",
        "crud": "'*'",
        "read": "get",
        "write": "create",
        "*/*": "'*'",
        "* verbs": "'*'",
    }.get(v, v)
    if verb in ("escalate", "bind") and not res.endswith(("roles", "rolebindings")):
        # escalate/bind only valid on rbac.authorization.k8s.io
        res = "clusterroles"
    return (verb, res)


def _rbac_adapted_step(sid: str, f: Finding, scope: Scope) -> Step | None:
    if not any(c in _RBAC_CWES for c in f.cwes):
        return None
    text = f"{f.title} {f.attack_pattern or ''} {f.description or ''}"
    grant = _rbac_extract_grant(text)
    if not grant:
        return None
    verb, res = grant
    ctx = next(iter(scope.clusters), "__current__")
    cs = scope.clusters.get(ctx)
    nss = (
        sorted(cs.explicit_namespaces)
        if cs and cs.explicit_namespaces
        else [p for p in (cs.namespaces if cs else []) if "*" not in p]
    )
    if not nss:
        return None
    # Prefer the *-operator namespace — operator SAs hold the broad
    # ClusterRoles, operand SAs (e.g. ``dns`` in openshift-dns) usually
    # don't.  First attempt picked nss[0] alphabetically and refuted
    # every probe against the operand SA.
    nss = sorted(nss, key=lambda n: (0 if n.endswith("-operator") else 1, n))
    ns_list = " ".join(nss[:6])
    # H8: a cluster-admin SA in scope (e.g. aro-operator-master in
    # ARO Classic) trivially answers ``yes`` to every can-i, so it
    # contaminates every probe in the package.  When testing a
    # *specific* grant, skip SAs that already hold ``'*' '*' -A`` —
    # their yes tells us nothing about the claimed ClusterRole.  When
    # the claim *is* cluster-admin / wildcard (no "grants <v> <r>" in
    # the text → fallback grant), we are looking for exactly such an
    # SA, so do NOT skip.
    is_wildcard_claim = bool(
        re.search(r"cluster-admin|wildcard|'\*'|\*\s+on\s+\*", text, re.IGNORECASE)
    ) or (verb in {"'*'", "*"} and res in {"'*'", "*"})
    # H9 (deferred): wildcard claims in multi-repo packages (e.g.
    # ARO) can still false-confirm via an unrelated cluster-admin
    # SA in the shared namespace scope.  Title-based hint
    # extraction was tried and reverted (pulled "cluster-admin"/
    # "namespace"/"operand" on ~15/20 core-OCP wildcard claims);
    # repo-token filtering also fails for ARO because every repo
    # slug AND the contaminating SA share the "aro" token.  The
    # right fix is a ClusterRole-name probe (does the *named* CR
    # exist with wildcard rules?) — tracked as H9-followup.  For
    # now those cases are caught by manual review
    # (validations/aro/MANAGEMENT-PLANE-SPLIT.md).
    sa_filter = ""
    subj_hint = ""
    skip_ca = (
        ""
        if is_wildcard_claim
        else (
            f"    if oc --context {ctx} auth can-i '*' '*' "
            f'       --as="$subj" --all-namespaces 2>/dev/null '
            f"       | grep -q '^yes'; then "
            f'       skipped="$skipped $subj"; continue; fi; '
        )
    )
    # Iterate every workload SA across all in-scope namespaces; if ANY
    # (non-cluster-admin) SA can perform the verb on the resource
    # cluster-wide, the over-broad grant is confirmed.  Output:
    # ``yes`` + subject on first hit, else ``no`` + the subjects
    # tried.  rbac-can-i verdict reads the FIRST line.
    cmd = (
        f"hit=; tried=; skipped=; "
        f"for ns in {ns_list}; do "
        f"  for sa in $( ( oc --context {ctx} -n $ns get deploy,statefulset,ds "
        f"    -o jsonpath='{{range .items[*]}}"
        f'{{.spec.template.spec.serviceAccountName}}{{"\\n"}}{{end}}\' '
        f"    2>/dev/null; "
        f"    oc --context {ctx} -n $ns get sa -o name 2>/dev/null "
        f"    | sed 's|.*/||' ) "
        f"    | sort -u | grep -v '^$' "
        f"    | grep -vE '^(default|builder|deployer|pipeline)$'"
        f"{sa_filter} ); do "
        f'    subj="system:serviceaccount:$ns:$sa"; '
        f"{skip_ca}"
        f'    tried="$tried $subj"; '
        f"    if oc --context {ctx} auth can-i {verb} {res} "
        f'       --as="$subj" --all-namespaces 2>/dev/null '
        f"       | grep -q '^yes'; then hit=$subj; break 2; fi; "
        f"  done; "
        f"done; "
        f"if [[ -n $hit ]]; then echo yes; "
        f'  echo "vf-rbac-subject: $hit verb={verb} res={res}"; '
        f"else echo no; "
        f'  echo "vf-rbac-tried:$tried"; '
        + (
            f"  [[ -z $tried ]] && "
            f'echo "vf-rbac-subject-hint-miss: {subj_hint} '
            f'(no matching SA in {len(nss)} ns)"; '
            if subj_hint
            else ""
        )
        + f"  [[ -n $skipped ]] && "
        f'    echo "vf-rbac-skipped-cluster-admin:$skipped"; '
        f'  echo "vf-rbac-probe: verb={verb} res={res}"; fi'
    )
    return Step(
        id=sid,
        technique="adapted",
        adapter="k8s",
        verb="rbac-can-i",
        finding_ref=f.id,
        target={"context": ctx, "namespace": nss[0], "resource": res},
        cmd=cmd,
        expected=f"yes — an in-scope SA can {verb} {res} cluster-wide "
        f"(over-broad RBAC: {f.title[:50]})",
        summary=f"rbac can-i {verb} {res} across {len(nss)} ns",
        classification="safe",
    )


# HTTP-surface CWEs that *may* have an extractable endpoint path in the
# finding text or threat-model entry_points. Unlike CWE_ADAPTED above,
# these only produce a step when (method, path) can be resolved — so
# operator/CRD-field SSRF findings (no HTTP path in their text) still
# fall through to no-poc-no-adapter, preserving the v0.4.x behaviour
# that eliminated 77 vf-http-status:000 inconclusives (RESIDUAL §B).
HTTP_CWES = frozenset(
    {
        "CWE-918",  # SSRF
        "CWE-306",  # Missing authentication
        "CWE-295",  # Improper certificate validation
        "CWE-319",  # Cleartext transmission
        "CWE-200",  # Information exposure
        "CWE-532",  # Information exposure through log
    }
)

_HTTP_VERB_PATH_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/[A-Za-z0-9_./{},\-*]+)")
_HTTP_BARE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(/(?:api|metrics|healthz|debug|auth|version|config|-/)"
    r"[A-Za-z0-9_./{},\-*]*)"
)
# Port-only reference (e.g. ":22623", "TCP 60000", "port 8080") when no
# path is named — fall back to GET /.
_HTTP_PORT_RE = re.compile(
    r"(?::|port\s+|TCP\s+|on\s+)(\d{4,5})\b",
    re.IGNORECASE,
)

# H6: HTTP-surface gate — a finding must reference a network-reachable
# surface for an HTTP probe to be meaningful at all.  Prevents non-HTTP
# behavioural claims (CSR auto-approval, controller reconcile logic)
# from getting a 404 against an unrelated Route.
_HTTP_SURFACE_RE = re.compile(
    r"(?i)\b(endpoint|listener|server|metrics|pprof|route|port|http)\b"
    r"|:\d{4,5}\b"
)


# Component-name hints — when the finding text names a specific service
# (prometheus, alertmanager, …), pick the Route/Service whose name
# contains that token instead of the first one in the namespace.
_SVC_HINT_RE = re.compile(
    r"\b(prometheus|alertmanager|thanos[- ]?(?:querier|ruler)?|grafana|"
    r"telemeter|metrics-server|kube-rbac-proxy|webhook|canary|downloads|"
    r"router|haproxy|coredns|oauth-(?:server|openshift)|registry)\b",
    re.IGNORECASE,
)

# H5: repo-base → svc-hint fallback.  Noise tokens that appear in many
# repo names and so cannot disambiguate a Service.
_REPO_NOISE = frozenset(
    {
        "cluster",
        "csi",
        "driver",
        "cloud",
        "provider",
        "operator",
        "openshift",
        "kubernetes",
        "kube",
        "k8s",
        "controller",
        "plugin",
        "external",
    }
)
# Domain-specific synonyms where the on-cluster Service/pod-image name
# differs from the repo token.
_REPO_HINT_MAP = {
    "openstack": "openstack|cinder",
    "oauth-proxy": "oauth-proxy",
    # r4: monitoring-stack repos whose svc/pod names differ
    "node_exporter": "node-exporter",
    "prometheus-alertmanager": "alertmanager",
    "kube-rbac-proxy": "rbac-proxy",
    "telemeter": "telemeter",
    "thanos": "thanos",
    "prometheus": "prometheus-k8s|prometheus-operated",
    "prometheus-operator": "prometheus-operator",
    "console": "console",
    "console-operator": "console|downloads",
}


def _repo_base(f: Finding) -> str:
    """Bare source-repo directory name with the ``__release-*`` suffix
    stripped (e.g. ``csi-driver-nfs__release-4.22`` → ``csi-driver-nfs``).
    """
    base = ""
    if f.source_repo:
        base = f.source_repo.split(":")[-1].split("/")[-1]
    elif f.source_report_path:
        base = Path(f.source_report_path).parent.name
    return re.sub(r"__release-.*$", "", base)


def _svc_hint(f: Finding, *, repo_only: bool = False) -> str:
    if not repo_only:
        text = " ".join([f.title or "", f.attack_pattern or "", (f.description or "")[:300]])
        m = _SVC_HINT_RE.search(text)
        if m:
            return m.group(1).lower().replace(" ", "-")
    # H5: fall back to a distinctive token from the source-repo name so
    # the route/svc selection refuses to pick an unrelated first-in-ns
    # candidate (3× false-confirm in storage/* — INCONCLUSIVE-FIX-PLAN).
    # r4: ``repo_only=True`` skips the text regex entirely — generic
    # words like "router"/"webhook" in finding text are feature names,
    # not service names; the repo-derived hint is authoritative for
    # the port-forward-only path.
    base = _repo_base(f)
    if not base:
        return ""
    if base in _REPO_HINT_MAP:
        return _REPO_HINT_MAP[base]
    toks = [t for t in base.lower().split("-") if t and t not in _REPO_NOISE]
    hint = "|".join(toks) if toks else base.lower()
    return _REPO_HINT_MAP.get(hint, hint)


def _resolve_http_coords(f: Finding, tm) -> tuple[str, str, int | None] | None:
    """Return (method, path, port|None) if a concrete HTTP endpoint is
    named in the finding text/title or a linked threat-model entry_point.
    None ⇒ caller falls through to the existing skip behaviour."""
    blobs = [f.title or "", f.attack_pattern or "", f.description or ""]
    if tm:
        surfaces = {t.get("surface", "") for t in tm.threats if t.get("id") in set(f.threat_ids)}
        for ep in tm.entry_points:
            if ep.get("name") in surfaces:
                blobs.append(ep.get("description", ""))
    text = " ".join(blobs)
    port = None
    if pm := _HTTP_PORT_RE.search(text):
        p = int(pm.group(1))
        if 1024 <= p <= 65535:
            port = p
    if m := _HTTP_VERB_PATH_RE.search(text):
        return m.group(1).upper(), m.group(2), port
    if m := _HTTP_BARE_PATH_RE.search(text):
        return "GET", m.group(1), port
    # H2: keyword→path mapping when no literal path appeared.  ``GET /``
    # 404s on most Go mux handlers, so derive a useful default from the
    # claim's vocabulary.  Gated on having either a named port or an
    # HTTP-surface keyword so e.g. "Ignition" alone in a build-time
    # finding doesn't trigger.
    if port or _HTTP_SURFACE_RE.search(text):
        if re.search(r"(?i)\bpprof\b", text):
            return "GET", "/debug/pprof/", port
        if re.search(r"/metrics\b|(?i:metrics\s+endpoint)", text):
            return "GET", "/metrics", port
        if re.search(r"Machine Config Server|Ignition", text):
            return "GET", "/config/worker", port
        if re.search(r"[Cc]atalogd", text):
            return "GET", "/api/v1/all", port
    if port:
        # No path, but a specific port is named — probe GET / on it.
        return "GET", "/", port
    return None


def _http_adapted_step(
    sid: str, f: Finding, scope: Scope, tm, *, force_coords: tuple[str, str] | None = None
) -> Step | None:
    """Conditional adapted step for HTTP-surface CWEs.

    Emits a ``port-forward+http`` step ONLY when a concrete (method, path)
    is extractable from the finding/threat-model text. Operator findings
    where SSRF lives in a CR field have no such path and return None —
    identical outcome to pre-patch v0.4.x.
    """
    port: int | None = None
    if force_coords:
        method, path = force_coords
    else:
        # H6: gate on an HTTP-surface keyword so non-HTTP behavioural
        # claims (CSR auto-approval, RBAC, controller logic) don't get a
        # meaningless 404 probe just because they carry CWE-200/306.
        # A literal ``VERB /path`` or bare ``/api|/metrics|…`` reference
        # also satisfies the gate — those are unambiguously HTTP.
        surface_blob = (f.title or "") + " " + (f.description or "")[:300]
        if not (
            _HTTP_SURFACE_RE.search(surface_blob)
            or _HTTP_VERB_PATH_RE.search(surface_blob)
            or _HTTP_BARE_PATH_RE.search(surface_blob)
        ):
            return None
        if not any(c in HTTP_CWES for c in f.cwes):
            return None
        coords = _resolve_http_coords(f, tm)
        if not coords:
            return None
        method, path, port = coords
    # ``/api/x/{a,b,c}`` → pick the first variant so curl resolves.
    path = re.sub(r"\{([^,}]+)(?:,[^}]*)?\}", r"\1", path, count=2)
    ctx = next(iter(scope.clusters), "__current__")
    cs = scope.clusters.get(ctx)
    nss = (
        sorted(cs.explicit_namespaces)
        if cs and cs.explicit_namespaces
        else [p for p in (cs.namespaces if cs else []) if "*" not in p]
    )
    if cs:
        nss = sorted(set(nss) | {grant.namespace for grant in cs.http_discovery.routes})
    nss = [namespace for namespace in nss if not any(char in namespace for char in "*?[]")]
    ns = nss[0] if nss else None
    if __package__:
        from .http_endpoints import HttpProbe
    else:
        from http_endpoints import HttpProbe

    namespaces = tuple(
        namespace for namespace in nss if not any(char in namespace for char in "*?[]")
    )
    node = bool(
        port
        and re.search(
            r"(?i)hostNetwork|node IP|node.s primary interface|bound (?:directly )?on the node",
            f"{f.title or ''} {f.description or ''}"
            if re.search(r"(?i)\bkubelet\b", f.title or "")
            else f.title or "",
        )
    )
    service = bool(
        re.search(r"^/debug/|^/-/|/api/v\d+/admin", path) or "openshift-monitoring" in namespaces
    )
    hint = _svc_hint(f)
    if service or hint in {"webhook", "router", "kube-rbac-proxy"}:
        hint = _svc_hint(f, repo_only=True)
    probe = HttpProbe(
        mode="node" if node else "service" if service else "route",
        method=method,
        path=path,
        port=port,
        namespaces=namespaces,
        hint=hint,
        authenticate=False,
        csrf=False,
        service_account="prometheus-k8s" if path.rstrip("/").endswith("/metrics") else None,
    )
    return Step(
        id=sid,
        technique="adapted",
        adapter="k8s",
        verb="port-forward+http",
        finding_ref=f.id,
        target={
            "context": ctx,
            "namespace": None if node else ns,
            "resource": "nodes" if node else "services" if service else "routes",
            "method": method,
            "path": path,
            **({"port": port} if port else {}),
            "http": probe.model_dump(mode="json"),
        },
        cmd=None,
        classification="destructive"
        if method == "DELETE"
        else "mutating"
        if method in {"POST", "PUT", "PATCH"}
        else "safe",
        expected=f.attack_pattern or f.title,
        summary=f"HTTP probe {method} {path} ({probe.mode})",
    )


# CWE-290 (auth bypass by spoofing) / CWE-348 (use of less-trusted source)
# — typically header-spoof.  Extract the header name from the finding text
# and emit an HTTP probe carrying that header with a canary value.
_SPOOF_CWES = frozenset({"CWE-290", "CWE-348"})
_HEADER_RE = re.compile(r"\b(X-[A-Za-z][A-Za-z0-9-]{2,30})\b")


def _spoof_adapted_step(sid: str, f: Finding, scope: Scope, tm) -> Step | None:
    if not any(c in _SPOOF_CWES for c in f.cwes):
        return None
    text = " ".join([f.title, f.attack_pattern or "", f.description or ""])
    hdrs = _HEADER_RE.findall(text)
    if not hdrs:
        return None
    coords = _resolve_http_coords(f, tm) or ("GET", "/", None)
    s = _http_adapted_step(sid, f, scope, tm, force_coords=(coords[0], coords[1]))
    if not s:
        return None
    s.target["http"]["headers"] = {header: "vf-spoof-canary" for header in dict.fromkeys(hdrs)}
    s.expected = f"upstream reflects/honours spoofed {hdrs[0]} — {f.attack_pattern or f.title}"
    s.summary = f"header-spoof probe {','.join(dict.fromkeys(hdrs))} ({','.join(f.cwes)})"
    return s


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def _credential_gate(f: Finding, blocking_creds: list[dict]) -> str | None:
    """If *f*'s PoC/description references a credential recorded with
    ``blocks_validation: true``, return ``"<kind>/<name>"`` so the
    planner can emit a ``needs-credential`` skip.  Otherwise None.

    Match is heuristic: any of the credential's ``name`` or ``keys[]``
    appearing as a token in the PoC body, attack_pattern, or title.
    """
    if not blocking_creds:
        return None
    blob = " ".join([f.title, f.attack_pattern, f.description, *(p.body for p in f.pocs)])
    for c in blocking_creds:
        tokens = [c.get("name", ""), *list(c.get("keys") or [])]
        for t in tokens:
            if t and re.search(rf"\b{re.escape(t)}\b", blob):
                return f"{c.get('kind', 'external')}/{c.get('name')}"
    return None


def build_plan(
    n: Normalized,
    scope: Scope,
    *,
    replay: bool = True,
    chained: bool = True,
    novel: bool = True,
    permit_destructive: bool = False,
    credentials_needed: list[dict] | None = None,
) -> tuple[list[Step], list[Chain]]:
    """Build the attack plan.

    *credentials_needed* is the list from ``credentials-needed.json``
    written during operand setup.  Findings whose PoCs reference an
    entry with ``blocks_validation: true`` are emitted as
    ``skip: needs-credential:<ref>`` so they can be queued for a
    second pass with real credentials instead of producing a
    meaningless ``inconclusive`` against a dummy.
    """
    steps: list[Step] = []
    ids = count(1)
    blocking_creds = [c for c in (credentials_needed or []) if c.get("blocks_validation")]

    def sid():
        return f"step-{next(ids):03d}"

    # 0. recon (always — safe)
    for rs in recon_steps(scope):
        steps.append(
            Step(
                id=sid(),
                technique="recon",
                adapter=rs.adapter,
                verb=rs.verb,
                target=rs.target,
                cmd=rs.cmd,
                classification="safe",
                expected=rs.expected,
            )
        )

    # 1. replay
    finding_step: dict[str, str] = {}  # finding_id → first step id (for chain glue)
    if replay:
        order = sorted(
            n.findings,
            key=lambda f: (SEV_ORDER.get(f.severity, 9), -(f.confidence or 0)),
        )
        for f in order:
            if f.triage_verdict == "false_positive":
                steps.append(
                    Step(
                        id=sid(),
                        technique="skip",
                        adapter="k8s",
                        verb="noop",
                        finding_ref=f.id,
                        skip="triage-false-positive",
                        summary=f.title,
                    )
                )
                continue
            # ``needs_review`` triage verdict: the triage agent could
            # not locate the cited evidence (e.g. CI-workflow path,
            # missing locations[]) and emitted confidence:0 instead of
            # proving the finding false.  Do NOT skip — attempt
            # validation as if true_positive, but tag the step so the
            # report can flag it.
            needs_review = f.triage_verdict == "needs_review"
            # Surface routing: CI/build-time and host-level findings
            # are not validatable by deploying the operator on a
            # cluster.  Skip them here with an explicit reason so the
            # report can route them to the right track.
            if getattr(f, "surface", "runtime") != "runtime":
                steps.append(
                    Step(
                        id=sid(),
                        technique="skip",
                        adapter="k8s",
                        verb="noop",
                        finding_ref=f.id,
                        skip=f"wrong-surface:{f.surface}",
                        summary=f.title,
                    )
                )
                continue
            # Credential gate: if this finding needs a real credential
            # that the operand setup recorded as blocking, skip it for
            # the second-pass run instead of getting a junk verdict.
            cred_ref = _credential_gate(f, blocking_creds)
            if cred_ref:
                steps.append(
                    Step(
                        id=sid(),
                        technique="skip",
                        adapter="k8s",
                        verb="noop",
                        finding_ref=f.id,
                        skip=f"needs-credential:{cred_ref}",
                        summary=f.title,
                    )
                )
                continue
            made = False
            for poc in f.pocs:
                s = _step_from_poc("__tmp__", f, poc, scope)
                if s:
                    s.id = sid()
                    if needs_review:
                        s.triage_was_needs_review = True
                    steps.append(s)
                    finding_step.setdefault(f.id, s.id)
                    made = True
            if not made:
                s_id = sid()
                # H10: rbac before secret-scan.  RBAC is now strongly
                # gated (H8b: CWE + RBAC-keyword) so it only fires on
                # genuine ClusterRole/RoleBinding claims; secret-scan
                # is a broad fallback that previously swallowed RBAC
                # claims whose title contains "Secrets" and confirmed
                # them via an unrelated cert/secret in the namespace.
                s = (
                    _manual_poc_step(s_id, f, scope)
                    or _http_adapted_step(s_id, f, scope, n.threat_model)
                    or _spoof_adapted_step(s_id, f, scope, n.threat_model)
                    or _rbac_adapted_step(s_id, f, scope)
                    or _secret_adapted_step(s_id, f, scope)
                    or _adapted_step(s_id, f, scope)
                )
                if s:
                    if needs_review:
                        s.triage_was_needs_review = True
                    steps.append(s)
                    finding_step.setdefault(f.id, s.id)
                else:
                    # Categorized skip: if the CWE is one we know cannot
                    # be generically adapted, say WHY instead of the
                    # opaque ``no-poc-no-adapter``.
                    reason = next(
                        (CWE_SKIP_REASON[c] for c in f.cwes if c in CWE_SKIP_REASON),
                        "no-poc-no-adapter",
                    )
                    steps.append(
                        Step(
                            id=sid(),
                            technique="skip",
                            adapter="k8s",
                            verb="noop",
                            finding_ref=f.id,
                            skip=reason,
                            summary=f.title,
                            triage_was_needs_review=(True if needs_review else None),
                        )
                    )

    # 2. chained
    chains: list[Chain] = []
    if chained:
        chains = find_chains(n.findings, n.threat_model)
        for c in chains:
            prev = None
            for fid in c.finding_ids:
                base = finding_step.get(fid)
                glue = Step(
                    id=sid(),
                    technique="chained",
                    adapter="k8s",
                    verb="glue",
                    chain_ref=c.chain_id,
                    finding_ref=fid,
                    target={},
                    classification="safe",
                    expected=f"carry capability from {prev or c.entry_point} into {fid}",
                    preconditions=[base] if base else [],
                    summary=(
                        f"{c.chain_id}: use output of {prev or c.entry_point}"
                        f" to satisfy preconditions of {fid}"
                    ),
                )
                steps.append(glue)
                prev = fid

    # 3. novel — recon-driven probes are added in execute.py second pass;
    #    here we only reserve the section marker so the plan reads cleanly.
    if novel:
        steps.append(
            Step(
                id=sid(),
                technique="novel",
                adapter="k8s",
                verb="placeholder",
                classification="safe",
                expected="materialized after recon (Phase 4 second pass)",
                skip="deferred-until-recon",
                summary="novel probes inserted post-recon",
            )
        )

    # 4. classify + scope pre-check
    _cls_rank = {"safe": 0, "mutating": 1, "destructive": 2}
    for s in steps:
        if s.technique in ("skip",) or s.verb in ("noop", "placeholder", "glue"):
            continue
        ad = get_adapter(s.adapter)
        # Keep an explicit higher-severity classification set by the
        # planner (e.g. H4 hostNetwork → mutating debug-pod) when the
        # verb-table heuristic would downgrade it.
        cls = ad.classify(s.verb, s.payload, s.cmd)
        if _cls_rank.get(cls, 0) >= _cls_rank.get(s.classification, 0):
            s.classification = cls
        if s.classification == "destructive" and not permit_destructive:
            s.skip = "destructive-not-permitted"
        ok, reason = scope.is_in_scope(
            Action(
                adapter=s.adapter,
                verb=s.verb,
                context=s.target.get("context"),
                namespace=s.target.get("namespace"),
                resource=s.target.get("resource"),
                name=s.target.get("name"),
                image=s.target.get("image"),
                artifact=s.target.get("artifact"),
            )
        )
        if not ok:
            s.skip = s.skip or f"blocked_by_scope: {reason}"

    return steps, chains


def write_plan(
    steps: list[Step], chains: list[Chain], out_path: Path, *, target_name: str, scope: Scope
) -> Path:
    doc = {
        "target": target_name,
        "scope_binding_mode": scope.binding_mode,
        "engagement": scope.engagement,
        "chains": [c.to_dict() for c in chains],
        "steps": [s.to_dict() for s in steps],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if yaml:
        out_path.write_text(yaml.safe_dump(doc, sort_keys=False, width=100), encoding="utf-8")
    else:
        out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return out_path


def summarize(steps: list[Step]) -> str:
    from collections import Counter

    by_tc = Counter((s.technique, s.classification) for s in steps)
    lines = [
        "",
        "Attack plan summary",
        "=" * 60,
        f"{'technique':<10} {'class':<12} {'count':>5}",
        "-" * 60,
    ]
    for (t, c), n in sorted(by_tc.items()):
        lines.append(f"{t:<10} {c:<12} {n:>5}")
    lines.append("-" * 60)
    mut = [s for s in steps if s.classification in ("mutating", "destructive") and not s.skip]
    if mut:
        lines.append(f"\n{len(mut)} mutating/destructive step(s) requiring review:")
        for s in mut:
            ref = s.finding_ref or s.chain_ref or s.novel_ref
            lines.append(f"  {s.id}  {s.adapter}/{s.verb:<20} {s.target}  [{ref}]")
    blocked = [s for s in steps if s.skip and s.skip.startswith("blocked_by_scope")]
    if blocked:
        lines.append(f"\n{len(blocked)} step(s) blocked by scope:")
        for s in blocked:
            lines.append(f"  {s.id}  {s.skip}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    import argparse

    from traust.context import add_config_home_arg

    p = argparse.ArgumentParser(description="Build attack-plan.yaml for validate-findings.")
    add_config_home_arg(p)
    p.add_argument("--results-root", type=Path, default=None)
    p.add_argument("source", help="findings dir | report file | product/repo")
    p.add_argument("--targets")
    p.add_argument("--context", action="append", default=[])
    p.add_argument("--ns", action="append", default=[])
    p.add_argument("--image", action="append", default=[])
    p.add_argument("--container", action="append", default=[])
    p.add_argument("--wasm", action="append", default=[])
    p.add_argument("--infer-scope", action="store_true")
    p.add_argument("--replay-only", action="store_true")
    p.add_argument("--novel-only", action="store_true")
    p.add_argument("--destructive", action="store_true")
    p.add_argument("--out")
    a = p.parse_args()

    path_kw = {"config_home": a.config_home, "results_root": a.results_root}
    if "," in a.source:
        from ingest import ingest_many

        n = ingest_many(a.source.split(","), **path_kw)
    else:
        n = ingest(a.source, **path_kw)
    scope = build_scope(
        targets_file=a.targets,
        contexts=a.context,
        namespaces=a.ns,
        images=a.image,
        containers=a.container,
        wasm=a.wasm,
        inferred=n.inferred_scope if a.infer_scope else None,
    )
    steps, chains = build_plan(
        n,
        scope,
        replay=not a.novel_only,
        chained=not a.replay_only and not a.novel_only,
        novel=not a.replay_only,
        permit_destructive=a.destructive,
    )
    out = Path(a.out) if a.out else Path(n.source_dir) / f"{n.target_name}-attack-plan.yaml"
    write_plan(steps, chains, out, target_name=n.target_name, scope=scope)
    print(summarize(steps))
    print(f"plan written: {out}")
