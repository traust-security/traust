#!/usr/bin/env python3
"""
Ingest *-security-audit.{json,md}, *-threat-model.md, *-triage.{json,md}
into a normalized in-memory model for the validate-findings harness.

Outputs (when run as a script): a JSON document with
  { source_reports[], findings[], threat_model{assets,entry_points,threats},
    inferred_scope{clusters,images,containers,wasm} }
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load,
    progress_tracker_dir,
    resolve_results_root,
)

REPORT_KINDS = {
    "security-audit": (r"-security-audit\.(json|md)$", ("json", "md")),
    "threat-model": (r"-threat-model\.md$", ("md",)),
    "triage": (r"-triage\.(json|md)$", ("json", "md")),
}

FENCE_RE = re.compile(
    r"```(?P<lang>[a-zA-Z0-9_+-]*)\n(?P<body>.*?)```",
    re.DOTALL,
)
MD_TABLE_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
# Only match explicit `namespace: <name>` / `namespace=<name>` / `-n <name>`
# forms. Names must be valid RFC-1123 labels with at least one hyphen or a
# well-known component prefix to suppress prose false-positives.
# Additional filtering: reject common English compound words that look like
# namespace names but aren't (e.g. "production-database", "my-application").
NS_HINT_RE = re.compile(
    r"(?:\bnamespace\s*[:=]\s*|(?<=\s)-n\s+)"
    r"((?=[a-z0-9-]{2,63}(?:\s|$|[^a-z0-9-]))"
    r"(?:[a-z0-9]+-[a-z0-9-]*[a-z0-9]|openshift[a-z0-9-]*|kube[a-z0-9-]*))",
)
# Denylist: common prose compound words and generic terms that are not real
# Kubernetes namespace names.  Applied as a post-filter to NS_HINT_RE matches.
_NS_PROSE_DENYLIST = frozenset(
    {
        # generic prose terms
        "production-database",
        "production-environment",
        "production-cluster",
        "production-system",
        "production-service",
        "production-server",
        "target-namespace",
        "source-namespace",
        "destination-namespace",
        "cross-namespace",
        "another-namespace",
        "other-namespace",
        "any-namespace",
        "same-namespace",
        "different-namespace",
        "user-defined",
        "user-specified",
        "user-controlled",
        "my-application",
        "my-service",
        "my-namespace",
        "my-project",
        "some-namespace",
        "some-service",
        "some-name",
        "example-namespace",
        "example-service",
        "example-name",
        "test-namespace",
        "test-service",
        "test-name",
        # single-word with required hyphen that are still prose
        "the-namespace",
        "a-namespace",
        "this-namespace",
        "all-namespaces",
        "no-namespace",
    }
)


def _is_plausible_ns(name: str) -> bool:
    """Return True if *name* looks like an actual k8s namespace, not prose."""
    if name in _NS_PROSE_DENYLIST:
        return False
    # Well-known k8s namespace prefixes are always plausible
    if name.startswith(
        (
            "openshift-",
            "kube-",
            "rook-",
            "ramen-",
            "open-cluster-",
            "multicluster-",
            "rhacs-",
            "stackrox",
            "submariner-",
            "hive-",
            "gitops-",
            "tekton-",
            "pipelines-",
            "cert-manager",
            "metallb-",
            "nmstate-",
            "oadp-",
            "mce-",
            "rhacm-",
            "odf-",
            "skupper-",
            "volsync-",
        )
    ):
        return True
    # Reject names that contain common English words as segments
    _prose_segments = {
        "the",
        "a",
        "an",
        "this",
        "that",
        "my",
        "your",
        "some",
        "any",
        "all",
        "no",
        "production",
        "example",
        "test",
        "another",
        "other",
        "different",
        "same",
        "every",
        "each",
        "user",
        "target",
        "source",
        "destination",
        "cross",
        "internal",
        "external",
    }
    segments = set(name.split("-"))
    return not segments & _prose_segments


IMAGE_HINT_RE = re.compile(
    r"\b((?:quay\.io|registry\.redhat\.io|gcr\.io|ghcr\.io|docker\.io)/[A-Za-z0-9._/-]+)"
)

# ---------------------------------------------------------------------------
# Surface classification
# ---------------------------------------------------------------------------
# A finding whose evidence lives entirely in CI/build infrastructure is
# not validatable by deploying the operator on a cluster — it needs the
# CI workflow itself to be exercised.  These are routed to a separate
# ``validate-ci-findings`` track and skipped by the k8s adapter.

_CI_BUILD_PATH_RE = re.compile(
    r"(?:^|/)("
    r"\.github/|\.gitlab-ci|\.tekton/|\.ci/|\.konflux/|"
    r"Makefile|Dockerfile|Containerfile|"
    r"hack/|scripts/|build/|ci/|release/|"
    r"\.goreleaser|\.pre-commit"
    r")",
    re.IGNORECASE,
)
_CI_BUILD_TITLE_RE = re.compile(
    r"\b(github\s+actions?|workflow_dispatch|gitlab\s+ci|tekton\s+task|"
    r"pipeline\s+task|\$\{\{\s*inputs|\$\{\{\s*github\.|goreleaser|"
    r"build\s+script|release\s+script|\bCI\b\s+pipeline)\b",
    re.IGNORECASE,
)
_HOST_PATH_RE = re.compile(
    r"(?:^|/)(etc/|usr/|var/lib/|systemd/|\.spec$|rpm/|selinux/)",
)
# Repo-name patterns for QE / test-harness / dev-tooling / LLM-assistant
# repos that ship inside a product package but are NOT part of the
# operator's runtime attack surface.  Findings in these repos are
# typically shell/script-level and have no pod on the validation
# cluster to ``oc exec`` into — they belong in a host/CI track.
_TOOLING_REPO_RE = re.compile(
    r"(?:^|[:/])("
    r"[^/]*-qe-[^/]*|[^/]*-e2e-[^/]*|[^/]*-tests?$|[^/]*-test-[^/]*|"
    r"[^/]*-ci-[^/]*|[^/]*-mcp-server|[^/]*-assistant|[^/]*-with-llm|"
    r"[^/]*-starter-kits?[^/]*|[^/]*-prompts?$|"
    r"codesweep|cve-prompts|polarion[^/]*|eval-hub|ilab-on-ocp|"
    r"architecture-context|model-runtimes-agent|org-pulse|"
    r"build-harness[^/]*|test-drive[^/]*|demo-apps|flexbench|"
    r"[^/]*-benchmark[^/]*|[^/]*-scripts$"
    r")$",
    re.IGNORECASE,
)


def classify_surface(finding: Finding) -> str:
    """Return ``ci-build`` / ``host`` / ``runtime`` for *finding*.

    Heuristic: if **all** locations are CI/build paths, or the title
    explicitly names a CI mechanism, → ``ci-build``.  If locations are
    host/RPM paths → ``host``.  Otherwise ``runtime``.
    """
    paths = []
    for loc in finding.locations or []:
        p = loc.get("file") or loc.get("path") or ""
        if p:
            paths.append(p)
    if paths and all(_CI_BUILD_PATH_RE.search(p) for p in paths):
        return "ci-build"
    title_blob = f"{finding.title} {finding.attack_pattern}"
    if _CI_BUILD_TITLE_RE.search(title_blob):
        # Title says CI but at least one location is runtime code →
        # still ci-build if the PoC is a workflow/yaml fence.
        if any(
            p.lang in ("yaml", "yml")
            and (
                "workflow" in p.body.lower() or "uses:" in p.body or "$((" not in p.body
            )  # crude: not a shell-math yaml
            for p in finding.pocs
        ):
            return "ci-build"
        if not paths:
            return "ci-build"
    if paths and all(_HOST_PATH_RE.search(p) for p in paths):
        return "host"
    # Tooling/QE repo — no operator-runtime pod runs this code on the
    # cluster, so k8s ``exec``/``apply`` PoCs have no target.
    repo = (finding.source_repo or "").split(":")[-1]
    if repo and _TOOLING_REPO_RE.search(repo):
        return "tooling"
    return "runtime"


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass
class PoC:
    lang: str
    body: str
    source_field: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cwes: list[str] = field(default_factory=list)
    locations: list[dict] = field(default_factory=list)
    description: str = ""
    attack_pattern: str = ""
    cvss: dict | None = None
    # triage enrichment
    triage_id: str | None = None
    triage_verdict: str | None = None  # true_positive | false_positive | needs_review | ...
    verify_verdict: str | None = None  # exploitable | needs_manual_test
    confidence: float | None = None
    preconditions: list[str] = field(default_factory=list)
    first_links: list[str] = field(default_factory=list)
    owner_hint: str | None = None
    # threat-model linkage
    threat_ids: list[str] = field(default_factory=list)
    # extracted PoCs
    pocs: list[PoC] = field(default_factory=list)
    # source traceability (set when ingesting multi-repo packages)
    source_repo: str | None = None
    # path to the *-security-audit.{json,md} this finding was parsed
    # from — drives ``validated_findings[].source_report`` in report.py
    source_report_path: str | None = None
    source_id: str | None = None
    # attack surface classification — drives which adapter (if any)
    # can validate this finding.  See ``classify_surface()``.
    #   runtime    — operator/operand/cluster behaviour (k8s adapter)
    #   ci-build   — GitHub Actions / Tekton / Makefile / Dockerfile /
    #                build scripts (NOT cluster-validatable; needs the
    #                separate validate-ci-findings track)
    #   tooling    — QE / test-harness / dev-tool / LLM-assistant repo
    #                bundled in the product package; no operator pod
    #                runs this code so k8s exec/apply have no target
    #   host       — RHEL/host-level (container adapter or out of scope)
    surface: str = "runtime"

    def to_dict(self):
        d = asdict(self)
        d["pocs"] = [p.to_dict() for p in self.pocs]
        return d


@dataclass
class ThreatModel:
    assets: list[dict] = field(default_factory=list)  # {name, description, sensitivity}
    # {name, description, trust_boundary, reachable_assets}
    entry_points: list[dict] = field(default_factory=list)
    # {id, threat, actor, surface, asset, impact, likelihood, status, controls, evidence}
    threats: list[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class Normalized:
    target_name: str
    source_dir: str
    source_reports: list[dict] = field(default_factory=list)  # {kind, path, sha256}
    findings: list[Finding] = field(default_factory=list)
    threat_model: ThreatModel = field(default_factory=ThreatModel)
    inferred_scope: dict = field(
        default_factory=lambda: {"clusters": {}, "images": [], "containers": [], "wasm": []}
    )

    def to_dict(self):
        return {
            "target_name": self.target_name,
            "source_dir": self.source_dir,
            "source_reports": self.source_reports,
            "findings": [f.to_dict() for f in self.findings],
            "threat_model": self.threat_model.to_dict(),
            "inferred_scope": self.inferred_scope,
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path.open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_pocs(text: str, source_field: str) -> list[PoC]:
    out = []
    for m in FENCE_RE.finditer(text or ""):
        lang = (m.group("lang") or "text").lower()
        body = m.group("body").strip()
        if not body:
            continue
        out.append(PoC(lang=lang, body=body, source_field=source_field))
    return out


def _md_tables(text: str) -> list[list[list[str]]]:
    """Return a list of tables; each table is a list of rows; each row a list of cells."""
    tables, cur = [], []
    for line in text.splitlines():
        m = MD_TABLE_ROW.match(line)
        if m:
            cells = [c.strip() for c in m.group(1).split("|")]
            # skip separator rows like |---|---|
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                continue
            cur.append(cells)
        else:
            if cur:
                tables.append(cur)
                cur = []
    if cur:
        tables.append(cur)
    return tables


# ---------------------------------------------------------------------------
# path resolution (config-first; never at import time)
# ---------------------------------------------------------------------------


def _analysis_results_root(
    *,
    config_home: Path | None = None,
    results_root: Path | None = None,
) -> Path:
    if results_root is not None:
        return results_root
    return resolve_results_root(config_home=config_home)


def _processed_results_root(
    *,
    config_home: Path | None = None,
    processed_root: Path | None = None,
) -> Path:
    if processed_root is not None:
        return processed_root
    return progress_tracker_dir(load(config_home)) / "processed-results"


# ---------------------------------------------------------------------------
# source resolution
# ---------------------------------------------------------------------------


def resolve_source(
    arg: str,
    *,
    config_home: Path | None = None,
    results_root: Path | None = None,
    processed_root: Path | None = None,
) -> Path:
    """Resolve a findings-source argument to a directory.

    Tries, in order:
      1. Literal path (directory or file → parent)
      2. ``<product>/<repo>`` shorthand → ``analysis-results/findings/``
      3. ``<slug>-findings`` shorthand → ``progress-tracker/processed-results/``
      4. Bare ``<slug>`` shorthand   → same, with ``-findings`` appended
    """
    p = Path(arg)
    if p.is_dir():
        return p.resolve()
    if p.is_file():
        return p.parent.resolve()
    # <product>/<repo> shorthand for analysis-results
    analysis_root = _analysis_results_root(config_home=config_home, results_root=results_root)
    processed_root = _processed_results_root(config_home=config_home, processed_root=processed_root)
    cand = analysis_root / "findings" / arg
    if cand.is_dir():
        return cand.resolve()
    # <slug>-findings or bare <slug> for processed-results packages
    cand2 = processed_root / arg
    if cand2.is_dir():
        return cand2.resolve()
    if not arg.endswith("-findings"):
        cand3 = processed_root / f"{arg}-findings"
        if cand3.is_dir():
            return cand3.resolve()
    raise FileNotFoundError(f"cannot resolve findings source: {arg!r}")


def is_package(source_dir: Path) -> bool:
    """Return True if *source_dir* is a multi-repo product package.

    A package has sub-directories containing audit reports but no audit
    reports at the top level itself.  Executive-Summary HTML and README at
    the top level are expected and do not count.
    """
    top_reports = discover_reports(source_dir)
    if top_reports:
        return False
    # Check for at least one sub-dir that contains audit reports (1–2 levels)
    for child in source_dir.iterdir():
        if not child.is_dir():
            continue
        if discover_reports(child):
            return True
        # two-level nesting: <SubGroup>/<repo>/
        for grandchild in child.iterdir():
            if grandchild.is_dir() and discover_reports(grandchild):
                return True
    return False


def discover_package(source_dir: Path) -> list[Path]:
    """Return all repo directories inside a multi-repo product package.

    Walks 1–2 levels deep, collecting every directory that contains at
    least one ``*-security-audit.{json,md}`` file.  Skips the top-level
    directory itself and any directory whose name starts with ``.``.
    """
    repo_dirs: list[Path] = []
    for child in sorted(source_dir.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if discover_reports(child):
            repo_dirs.append(child)
        else:
            # two-level nesting: <SubGroup>/<repo>/
            for grandchild in sorted(child.iterdir()):
                if (
                    grandchild.is_dir()
                    and not grandchild.name.startswith(".")
                    and discover_reports(grandchild)
                ):
                    repo_dirs.append(grandchild)
    return repo_dirs


def discover_reports(source_dir: Path) -> dict[str, Path]:
    """Find one file per report kind, preferring JSON over MD."""
    found: dict[str, Path] = {}
    for kind, (pattern, prefs) in REPORT_KINDS.items():
        candidates = [p for p in source_dir.iterdir() if re.search(pattern, p.name)]
        for ext in prefs:
            pick = next((c for c in candidates if c.suffix == f".{ext}"), None)
            if pick:
                found[kind] = pick
                break
    return found


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def _parse_security_audit_json(path: Path, n: Normalized):
    data = json.loads(path.read_text(encoding="utf-8"))
    for f in data.get("findings", []):
        finding = Finding(
            id=f["id"],
            title=f.get("title", ""),
            severity=f.get("severity", "informational"),
            cwes=list(f.get("cwes", [])),
            locations=list(f.get("locations", [])),
            description=f.get("description", ""),
            attack_pattern=f.get("attack_pattern", ""),
            cvss=f.get("cvss"),
        )
        for ev in f.get("evidence", []) or []:
            code = ev.get("code", "")
            if code:
                finding.pocs.append(
                    PoC(
                        lang=(ev.get("language") or "text").lower(),
                        body=code,
                        source_field="evidence",
                    )
                )
        finding.pocs.extend(_extract_pocs(finding.description, "description"))
        finding.pocs.extend(_extract_pocs(finding.attack_pattern, "attack_pattern"))
        n.findings.append(finding)
    _harvest_scope_hints(json.dumps(data), n)


def _parse_security_audit_md(path: Path, n: Normalized):
    """Best-effort: extract finding headings + fenced PoCs when JSON is absent."""
    text = path.read_text(encoding="utf-8")
    # match e.g. "### ODR-2026-004 — **CRITICAL** — title" or "### FIND-001: title"
    # Separator is a spaced dash (em/en/ascii) or a colon — a bare ASCII '-'
    # inside the ID does NOT terminate it.
    sep = r"(?:\s+[—–-]{1,3}\s+|:\s+)"
    head_re = re.compile(
        rf"^#{{2,4}}\s+(?P<id>[A-Z][A-Za-z0-9._/-]{{1,49}})"
        rf"{sep}"
        rf"(?:[*_`]*(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)[*_`]*{sep})?"
        rf"(?P<title>.+)$",
        re.MULTILINE,
    )
    spans = list(head_re.finditer(text))
    for i, m in enumerate(spans):
        body_end = spans[i + 1].start() if i + 1 < len(spans) else len(text)
        body = text[m.end() : body_end]
        finding = Finding(
            id=m.group("id"),
            title=m.group("title").strip(),
            severity=(m.group("sev") or "informational").lower(),
        )
        # CWE / CVSS hints in body
        finding.cwes = sorted(set(re.findall(r"CWE-\d{1,5}", body)))
        finding.pocs.extend(_extract_pocs(body, "md-body"))
        n.findings.append(finding)
    _harvest_scope_hints(text, n)


def _parse_triage_json(path: Path, n: Normalized, *, findings: list[Finding] | None = None):
    data = json.loads(path.read_text(encoding="utf-8"))
    by_source: dict[str, dict] = {}
    for tf in data.get("findings", []):
        # triage 'source' usually looks like "<file>#<FIND-ID>"
        src = tf.get("source", "")
        sid = src.split("#", 1)[1] if "#" in src else tf.get("id", "")
        by_source[sid] = tf
        by_source[tf.get("id", "")] = tf  # also index by triage id
    for f in findings if findings is not None else n.findings:
        tf = by_source.get(f.id)
        if not tf:
            continue
        f.triage_id = tf.get("id")
        f.triage_verdict = tf.get("verdict")
        f.verify_verdict = tf.get("verify_verdict")
        _conf = tf.get("confidence")
        if isinstance(_conf, str):
            _conf = {"high": 0.9, "medium": 0.5, "low": 0.1}.get(_conf.strip().lower())
        f.confidence = _conf
        f.preconditions = list(tf.get("preconditions", []))
        f.first_links = list(tf.get("first_links", []))
        f.owner_hint = tf.get("owner_hint")
        f.pocs.extend(_extract_pocs(tf.get("rationale", ""), "triage-rationale"))
    _harvest_scope_hints(json.dumps(data), n)


def _parse_threat_model_md(path: Path, n: Normalized, *, findings: list[Finding] | None = None):
    text = path.read_text(encoding="utf-8")
    tables = _md_tables(text)
    for tbl in tables:
        if not tbl:
            continue
        header = [h.lower() for h in tbl[0]]
        rows = [dict(zip(header, r, strict=False)) for r in tbl[1:] if len(r) == len(header)]
        asset_hdr = {"asset", "sensitivity"}
        asset_desc_hdr = {"asset", "description", "sensitivity"}
        if asset_hdr.issubset(header) or asset_desc_hdr.issubset(header):
            for r in rows:
                n.threat_model.assets.append(
                    {
                        "name": r.get("asset", ""),
                        "description": r.get("description", ""),
                        "sensitivity": r.get("sensitivity", "").lower(),
                    }
                )
        elif "entry_point" in header or "entry point" in header:
            key = "entry_point" if "entry_point" in header else "entry point"
            for r in rows:
                n.threat_model.entry_points.append(
                    {
                        "name": r.get(key, ""),
                        "description": r.get("description", ""),
                        "trust_boundary": r.get("trust_boundary", r.get("trust boundary", "")),
                        "reachable_assets": [
                            a.strip()
                            for a in r.get("reachable_assets", r.get("reachable assets", "")).split(
                                ","
                            )
                            if a.strip()
                        ],
                    }
                )
        elif {"id", "threat"}.issubset(header):
            for r in rows:
                n.threat_model.threats.append(
                    {
                        "id": r.get("id", ""),
                        "threat": r.get("threat", ""),
                        "actor": r.get("actor", ""),
                        "surface": r.get("surface", ""),
                        "asset": r.get("asset", ""),
                        "impact": r.get("impact", "").lower(),
                        "likelihood": r.get("likelihood", "").lower(),
                        "status": r.get("status", "").lower(),
                        "controls": r.get("controls", ""),
                        "evidence": r.get("evidence", ""),
                    }
                )
    # link threats → findings via the 'evidence' column (often holds finding IDs)
    for t in n.threat_model.threats:
        for f in findings if findings is not None else n.findings:
            if f.id and f.id in t.get("evidence", ""):
                f.threat_ids.append(t["id"])
    _harvest_scope_hints(text, n)


def _harvest_scope_hints(text: str, n: Normalized):
    """Populate inferred_scope from free text — namespaces & images only."""
    for ns in set(NS_HINT_RE.findall(text)):
        if not _is_plausible_ns(ns):
            continue
        if ns not in n.inferred_scope["clusters"].setdefault("__current__", []):
            n.inferred_scope["clusters"]["__current__"].append(ns)
    for img in set(IMAGE_HINT_RE.findall(text)):
        if img not in n.inferred_scope["images"]:
            n.inferred_scope["images"].append(img)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def _ingest_repo_dir(repo_dir: Path, n: Normalized, *, repo_label: str | None = None):
    """Parse all reports in a single repo directory into *n*.

    When *repo_label* is set (package mode), finding IDs are prefixed with
    the repo label to prevent collisions across repos, and triage/threat-
    model enrichment is scoped to only the findings from this repo.
    """
    reports = discover_reports(repo_dir)
    if not reports:
        return

    pre_count = len(n.findings)

    # security-audit first so triage/threat-model can enrich
    sa_path: str | None = None
    if (sa := reports.get("security-audit")) is not None:
        sa_path = str(sa)
        n.source_reports.append({"kind": "security-audit", "path": sa_path, "sha256": _sha256(sa)})
        if sa.suffix == ".json":
            _parse_security_audit_json(sa, n)
        else:
            _parse_security_audit_md(sa, n)

    # The slice of findings just added by this repo
    repo_findings = n.findings[pre_count:]
    for f in repo_findings:
        f.source_report_path = sa_path
        f.source_id = f.id

    if (tr := reports.get("triage")) is not None:
        n.source_reports.append({"kind": "triage", "path": str(tr), "sha256": _sha256(tr)})
        if tr.suffix == ".json":
            _parse_triage_json(tr, n, findings=repo_findings)
        # md triage is human-prose; rely on json
    if (tm := reports.get("threat-model")) is not None:
        n.source_reports.append({"kind": "threat-model", "path": str(tm), "sha256": _sha256(tm)})
        _parse_threat_model_md(tm, n, findings=repo_findings)

    # Tag source_repo first (classify_surface reads it for tooling-repo
    # detection), then classify surface.
    if repo_label:
        for f in repo_findings:
            f.source_repo = repo_label
    for f in repo_findings:
        f.surface = classify_surface(f)
    if repo_label:
        for f in repo_findings:
            # Prefix the finding ID to prevent collisions across repos.
            # Use the last path segment of the label (the repo name) as
            # a concise prefix: "FIND-001" → "svc-alpha/FIND-001".
            f.id = f"{repo_label}/{f.id}"


def _ingest_into(src_dir: Path, n: Normalized, *, label_prefix: str = ""):
    """Ingest *src_dir* (single repo or package) into an existing *n*.

    *label_prefix* is prepended to each repo_label so findings from
    different top-level packages remain distinguishable when several
    packages are merged via ``ingest_many()``.
    """
    if is_package(src_dir):
        repo_dirs = discover_package(src_dir)
        if not repo_dirs:
            raise FileNotFoundError(
                f"product package {src_dir} contains no repo directories with audit reports"
            )
        for rd in repo_dirs:
            label = f"{rd.parent.name}/{rd.name}" if rd.parent != src_dir else rd.name
            _ingest_repo_dir(rd, n, repo_label=f"{label_prefix}{label}")
    else:
        reports = discover_reports(src_dir)
        if not reports:
            raise FileNotFoundError(
                f"no *-security-audit / *-threat-model / *-triage reports found in {src_dir}"
            )
        # Single-repo dirs still get a label when merging multiple sources
        repo_lbl = (label_prefix + src_dir.name) if label_prefix else None
        _ingest_repo_dir(src_dir, n, repo_label=repo_lbl)


def ingest(
    source: str,
    *,
    config_home: Path | None = None,
    results_root: Path | None = None,
    processed_root: Path | None = None,
) -> Normalized:
    """Ingest findings from a single repo dir or a multi-repo product package.

    When *source* resolves to a product package (sub-directories with audit
    reports, no reports at the top level), all repos in the package are
    ingested into a single ``Normalized`` model with each finding tagged
    by ``source_repo``.
    """
    src_dir = resolve_source(
        source,
        config_home=config_home,
        results_root=results_root,
        processed_root=processed_root,
    )
    target_name = src_dir.name
    n = Normalized(target_name=target_name, source_dir=str(src_dir))
    _ingest_into(src_dir, n)
    return n


def ingest_many(
    sources: list[str],
    *,
    target_name: str | None = None,
    config_home: Path | None = None,
    results_root: Path | None = None,
    processed_root: Path | None = None,
) -> Normalized:
    """Ingest and merge findings from **multiple** source packages.

    Used when a single logical product maps to several
    ``processed-results/<slug>-findings/`` packages (see the Deduplication
    Map in ``progress-tracker/VALIDATION-PRIORITY-LIST.md``).

    Findings from each package are tagged with a ``<package>:`` label
    prefix so identical repo names across packages do not collide.  After
    merging, findings are de-duplicated by ``(source_repo, id)`` — the
    same physical repo may appear in more than one package.
    """
    if not sources:
        raise ValueError("ingest_many requires at least one source")
    if len(sources) == 1:
        return ingest(
            sources[0],
            config_home=config_home,
            results_root=results_root,
            processed_root=processed_root,
        )

    _resolve = lambda src: resolve_source(  # noqa: E731
        src,
        config_home=config_home,
        results_root=results_root,
        processed_root=processed_root,
    )
    primary_dir = _resolve(sources[0])
    name = target_name or primary_dir.name
    n = Normalized(target_name=name, source_dir=str(primary_dir))

    for src in sources:
        src_dir = _resolve(src)
        pkg_label = src_dir.name.removesuffix("-findings")
        _ingest_into(src_dir, n, label_prefix=f"{pkg_label}:")

    # De-duplicate: same (source_repo, original-id) can appear when two
    # packages bundle the same upstream repo.  The id is already prefixed
    # with the repo label, so keying on the post-prefix tail is what we
    # want — but the package prefix differs.  Strip the package prefix
    # (everything up to the first ':') for the dedup key.
    seen: set[tuple[str | None, str]] = set()
    deduped: list[Finding] = []
    for f in n.findings:
        repo = (f.source_repo or "").split(":", 1)[-1]
        fid = f.id.split(":", 1)[-1]
        key = (repo, fid)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    n.findings = deduped
    return n


def infer_scope(n: Normalized) -> dict:
    """Public hook used by scope.py mode-3."""
    return n.inferred_scope


if __name__ == "__main__":  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument(
        "sources", nargs="+", help="findings-dir | report-file | product/repo | <slug>-findings"
    )
    args = ap.parse_args()
    sources: list[str] = []
    for tok in args.sources:
        sources.extend(s for s in tok.split(",") if s)
    path_kw = {
        "config_home": args.config_home,
        "results_root": args.results_root,
    }
    result = ingest_many(sources, **path_kw) if len(sources) > 1 else ingest(sources[0], **path_kw)
    print(json.dumps(result.to_dict(), indent=2))
