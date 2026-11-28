#!/usr/bin/env python3
"""
Novel-attack hunting for the validate-findings harness.

Two layers:
  1. recon_steps()   — emit safe, read-only reconnaissance steps for the
                        bound target type(s).
  2. probe_steps()   — given recon artifacts + the threat model, emit
                        targeted probes from PROBE_CATALOGUE for surfaces
                        that exist live but are absent from the model.

The skill prompt drives a third layer (AI-assisted hypotheses) using the
recon output; this module supplies the deterministic scaffolding only.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass

# ---------------------------------------------------------------------------
# probe catalogue — keyed by (target_type, surface_class)
# Each entry is a probe template: {verb, payload|cmd, expected, cwes, mitre}
# Probes are intentionally non-destructive unless 'destructive': True.
# ---------------------------------------------------------------------------

PROBE_CATALOGUE: dict[tuple[str, str], list[dict]] = {
    # ----- operator (k8s adapter) -----------------------------------
    ("operator", "crd-cross-ns-ref"): [
        {
            "verb": "apply-manifest",
            "summary": "Confused-deputy: cross-namespace SecretRef in CR",
            "payload_template": (
                "apiVersion: {api}\nkind: {kind}\nmetadata:\n"
                "  name: vf-probe-xns\n  namespace: {tenant_ns}\nspec:\n"
                "  {ref_field}:\n    name: vf-canary\n    namespace: {victim_ns}\n"
            ),
            "expected": "operator reads/uses Secret from {victim_ns} on behalf of {tenant_ns}",
            "cwes": ["CWE-441", "CWE-610"],
            "mitre": ["T1552.007"],
            "classification": "mutating",
        },
    ],
    ("operator", "crd-url-field"): [
        {
            "verb": "apply-manifest",
            "summary": "SSRF via URL-typed CR field to harness listener",
            "payload_template": (
                "apiVersion: {api}\nkind: {kind}\nmetadata:\n"
                "  name: vf-probe-ssrf\n  namespace: {tenant_ns}\nspec:\n"
                "  {url_field}: http://127.0.0.1:{listener_port}/vf-ssrf-canary\n"
            ),
            "expected": "harness listener receives request originated by operator pod",
            "cwes": ["CWE-918"],
            "mitre": ["T1090"],
            "classification": "mutating",
        },
    ],
    ("operator", "webhook-bypass"): [
        {
            "verb": "apply-manifest",
            "summary": "Admission-webhook bypass via objectSelector label",
            "payload_template": (
                "# Apply a CR carrying the label/annotation that the\n"
                "# ValidatingWebhookConfiguration objectSelector excludes.\n"
                "apiVersion: {api}\nkind: {kind}\nmetadata:\n"
                "  name: vf-probe-wh\n  namespace: {tenant_ns}\n"
                '  labels: {{ {bypass_label}: "true" }}\nspec: {invalid_spec}\n'
            ),
            "expected": "invalid CR admitted despite webhook; controller acts on it",
            "cwes": ["CWE-285"],
            "mitre": ["T1685"],
            "classification": "mutating",
        },
    ],
    ("operator", "rbac-overbroad"): [
        {
            "verb": "rbac-can-i",
            "summary": "Operator SA can-i escalate / impersonate / * on secrets",
            "cmd_template": (
                "kubectl --context {context} auth can-i --list "
                "--as=system:serviceaccount:{operator_ns}:{operator_sa}"
            ),
            "expected": "no '*' verbs on secrets/* or escalate/impersonate/bind",
            "cwes": ["CWE-269"],
            "mitre": ["T1098"],
            "classification": "safe",
        },
    ],
    ("operator", "status-toctou"): [
        {
            "verb": "raw",
            "summary": "TOCTOU on status subresource (spec re-read after status write)",
            "cmd_template": (
                "# Race: patch spec immediately after controller writes status.\n"
                "# Requires two terminals or a small Go client; emit as plan-only.\n"
                "echo 'manual: see step notes'\n"
            ),
            "expected": "controller acts on stale spec snapshot",
            "cwes": ["CWE-367"],
            "mitre": ["T1499"],
            "classification": "mutating",
            "manual": True,
        },
    ],
    # ----- pod / container -----------------------------------------
    ("pod", "hostpath-writable"): [
        {
            "verb": "exec",
            "summary": "Writable hostPath mount allows node-level file write",
            "cmd_template": "touch {mount_path}/vf-canary-$$ && ls -l {mount_path}/vf-canary-$$",
            "expected": "file created on node filesystem",
            "cwes": ["CWE-732", "CWE-668"],
            "mitre": ["T1611"],
            "classification": "mutating",
        },
    ],
    ("pod", "cap-sysadmin"): [
        {
            "verb": "exec",
            "summary": "CAP_SYS_ADMIN present — mount/cgroup escape primitives",
            "cmd_template": "grep CapEff /proc/self/status",
            "expected": "CapEff bitmask includes 0x200000 (CAP_SYS_ADMIN)",
            "cwes": ["CWE-250"],
            "mitre": ["T1611"],
            "classification": "safe",
        },
    ],
    ("pod", "sa-token-reach"): [
        {
            "verb": "exec",
            "summary": "Mounted SA token grants cluster-scoped read",
            "cmd_template": (
                "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && "
                'curl -sk -H "Authorization: Bearer $TOKEN" '
                "https://kubernetes.default.svc/api/v1/namespaces | head -c 200"
            ),
            "expected": "401/403 (good) — 200 with namespace list = over-privileged",
            "cwes": ["CWE-269"],
            "mitre": ["T1528", "T1078.004"],
            "classification": "safe",
        },
    ],
    ("container", "cri-socket"): [
        {
            "verb": "exec",
            "summary": "CRI/Docker socket mounted inside container",
            "cmd_template": (
                "ls -l /var/run/docker.sock /run/crio/crio.sock"
                " /run/containerd/containerd.sock 2>/dev/null"
            ),
            "expected": "no socket present",
            "cwes": ["CWE-668"],
            "mitre": ["T1610", "T1611"],
            "classification": "safe",
        },
    ],
    ("container", "procfs-host"): [
        {
            "verb": "exec",
            "summary": "Host procfs / shared PID namespace",
            "cmd_template": "readlink /proc/1/ns/pid; ls /proc/1/root/etc/hostname 2>/dev/null",
            "expected": "PID ns differs from host; /proc/1/root not host root",
            "cwes": ["CWE-668"],
            "mitre": ["T1611"],
            "classification": "safe",
        },
    ],
    # ----- cluster component ---------------------------------------
    ("component", "unauth-control"): [
        {
            "verb": "port-forward+http",
            "summary": "Unauthenticated state-changing HTTP endpoint",
            "cmd_template": "curl -s -o /dev/null -w '%{{http_code}}' -X POST http://127.0.0.1:{port}{path}",
            "expected": "401/403 — 2xx indicates unauth control plane",
            "cwes": ["CWE-306"],
            "mitre": ["T1133"],
            "classification": "safe",
        },
    ],
    ("component", "kubelet-anon"): [
        {
            "verb": "raw",
            "summary": "Kubelet anonymous-auth / read-only port",
            "cmd_template": "curl -sk https://{node_ip}:10250/pods | head -c 200",
            "expected": "401 Unauthorized",
            "cwes": ["CWE-306"],
            "mitre": ["T1552.007"],
            "classification": "safe",
        },
    ],
    # ----- wasm -----------------------------------------------------
    ("wasm", "wasi-preopen"): [
        {
            "verb": "capability-probe",
            "summary": "WASI preopen grants broader filesystem than required",
            "cmd_template": "wasmtime run --dir . {artifact} --invoke __vf_list_preopens",
            "expected": "preopens limited to declared dirs",
            "cwes": ["CWE-732"],
            "mitre": ["T1083"],
            "classification": "safe",
        },
    ],
    ("wasm", "hostcall-unguarded"): [
        {
            "verb": "invoke-export",
            "summary": "Exported function reaches host import without capability check",
            "cmd_template": "wasmtime run {artifact} --invoke {export} {boundary_args}",
            "expected": "trap or rejection on out-of-policy host import",
            "cwes": ["CWE-285"],
            "mitre": ["T1106"],
            "classification": "safe",
        },
    ],
    ("wasm", "no-fuel"): [
        {
            "verb": "invoke-export",
            "summary": "Missing fuel/epoch limit — infinite-loop DoS",
            "cmd_template": "timeout 5 wasmtime run --fuel 0 {artifact} --invoke {export}",
            "expected": "engine enforces fuel; without --fuel the host wrapper must",
            "cwes": ["CWE-400"],
            "mitre": ["T1499"],
            "classification": "safe",
            "destructive": False,
        },
    ],
    # ----- PQC posture probes ---------------------------
    # Posture observations, not exploit attempts: all safe/read-only.
    # Structured stdout is consumed by the pqc-readiness skill (it maps
    # results onto chain.PQC_CAPS and closes runtime_verification_required).
    ("service", "pqc-tls-negotiation"): [
        {
            "verb": "raw",
            "summary": "TLS 1.3 group negotiation — hybrid ML-KEM offer vs classical fallback",
            "cmd_template": (
                "echo | openssl s_client -connect {host}:{port} -tls1_3 "
                "-groups X25519MLKEM768:X25519 -brief 2>&1 "
                "| grep -E 'Peer Temp Key|Negotiated TLS1.3 group|Protocol|Ciphersuite'; "
                "echo | openssl s_client -connect {host}:{port} -brief 2>&1 "
                "| grep -E 'Peer Temp Key|Negotiated TLS1.3 group|Protocol|Ciphersuite'"
            ),
            "expected": "negotiated group names X25519MLKEM768 (hybrid-capable) "
            "or a classical group only (tls-classical-ke-only)",
            "cwes": ["CWE-327"],
            "mitre": [],
            "classification": "safe",
            "pqc": True,
        },
    ],
    ("service", "pqc-cert-algorithm"): [
        {
            "verb": "raw",
            "summary": "Served certificate chain signature/key algorithms",
            "cmd_template": (
                "echo | openssl s_client -connect {host}:{port} -showcerts "
                "2>/dev/null | openssl x509 -noout -text 2>/dev/null "
                "| grep -E 'Signature Algorithm|Public-Key|ASN1 OID'"
            ),
            "expected": "classical (RSA/ECDSA) vs PQC (ML-DSA/SLH-DSA) chain; "
            "key sizes for 2030-clock parameters",
            "cwes": ["CWE-327"],
            "mitre": [],
            "classification": "safe",
            "pqc": True,
        },
    ],
    ("pod", "pqc-crypto-policy"): [
        {
            "verb": "exec",
            "summary": "Node/container crypto-policy and FIPS mode",
            "cmd_template": (
                "sh -c 'cat /etc/crypto-policies/state/current 2>/dev/null; "
                "cat /proc/sys/crypto/fips_enabled 2>/dev/null; "
                "openssl version 2>/dev/null'"
            ),
            "expected": "active policy (LEGACY flags crypto-policy-legacy), "
            "FIPS bit, OpenSSL version vs the >=3.5 ML-KEM floor",
            "cwes": ["CWE-327"],
            "mitre": [],
            "classification": "safe",
            "pqc": True,
        },
    ],
    ("service", "pqc-backend-tls"): [
        {
            "verb": "exec",
            "summary": "Downstream backend hop TLS posture (behind the ingress)",
            "cmd_template": (
                "sh -c 'echo | openssl s_client -connect "
                "{backend_host}:{backend_port} -brief 2>&1 "
                '| grep -E "Peer Temp Key|Negotiated TLS1.3 group|Protocol|Ciphersuite"\''
            ),
            "expected": "backend negotiates hybrid group or is classical-only "
            "(backend-tls-classical) — edge PQC can mask a "
            "classical interior hop",
            "cwes": ["CWE-327"],
            "mitre": [],
            "classification": "safe",
            "pqc": True,
        },
    ],
}


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------


@dataclass
class ReconStep:
    step_id: str
    adapter: str
    verb: str
    target: dict
    cmd: str
    classification: str = "safe"
    technique: str = "recon"
    expected: str = "raw inventory captured"

    def to_dict(self):
        return asdict(self)


def recon_steps(scope, *, id_prefix: str = "recon") -> list[ReconStep]:
    """Emit read-only recon steps for every bound target type."""
    out: list[ReconStep] = []
    n = 0

    def sid():
        nonlocal n
        n += 1
        return f"{id_prefix}-{n:03d}"

    # --- k8s clusters
    for ctx, cs in scope.clusters.items():
        kc = "" if ctx == "__current__" else f"--context {ctx} "
        ns_sel = (
            "-A"
            if "*" in cs.namespaces
            else " ".join(f"-n {ns}" for ns in cs.namespaces[:5]) or "-A"
        )
        out.append(ReconStep(sid(), "k8s", "raw", {"context": ctx}, f"kubectl {kc}get crd -o json"))
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx},
                f"kubectl {kc}get clusterrolebindings,rolebindings {ns_sel} -o json",
            )
        )
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx},
                (
                    f"kubectl {kc}get"
                    " validatingwebhookconfigurations,mutatingwebhookconfigurations -o json"
                ),
            )
        )
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx},
                f"kubectl {kc}get networkpolicies,svc,endpoints {ns_sel} -o json",
            )
        )
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx},
                f"kubectl {kc}get pods {ns_sel} "
                "-o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} "
                "sa={.spec.serviceAccountName} "
                "priv={.spec.containers[*].securityContext.privileged} "
                "caps={.spec.containers[*].securityContext.capabilities.add} "
                "hostNet={.spec.hostNetwork} hostPID={.spec.hostPID} "
                'vols={.spec.volumes[*].hostPath.path}{"\\n"}{end}\'',
            )
        )

    # --- containers
    for pat in scope.containers:
        rt = scope.container_runtimes[0] if scope.container_runtimes else "podman"
        out.append(
            ReconStep(
                sid(), "container", "inspect", {"name": pat, "runtime": rt}, f"{rt} inspect {pat}"
            )
        )
        out.append(
            ReconStep(
                sid(),
                "container",
                "exec",
                {"name": pat, "runtime": rt},
                (
                    f"{rt} exec {pat} sh -c "
                    "'grep CapEff /proc/self/status; cat /proc/mounts;"
                    " ls -l /var/run/*.sock 2>/dev/null'"
                ),
            )
        )

    # --- wasm
    for art in scope.wasm_artifacts:
        out.append(
            ReconStep(
                sid(),
                "wasm",
                "capability-probe",
                {"artifact": art},
                f"wasm-tools print {art} | grep -E '\\(import|\\(export' || true",
            )
        )

    # --- PQC posture recon (all safe/read-only). Outputs feed
    # the pqc-readiness skill to close runtime_verification_required.
    for ctx, _cs in scope.clusters.items():
        kc = "" if ctx == "__current__" else f"--context {ctx} "
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx, "pqc": True},
                f"kubectl {kc}get ingress -A -o json; "
                f"kubectl {kc}get ingresscontroller -n openshift-ingress-operator "
                f"-o json 2>/dev/null || true",
                expected="ingress TLS configuration inventory (tlsSecurityProfile, "
                "minTLSVersion, custom ciphers/groups)",
            )
        )
        # Metadata + PUBLIC cert only — never `-o json`, which would expose
        # cluster TLS private keys. The probe needs tls.crt, not tls.key.
        out.append(
            ReconStep(
                sid(),
                "k8s",
                "raw",
                {"context": ctx, "pqc": True},
                f"kubectl {kc}get secrets -A --field-selector "
                f"type=kubernetes.io/tls "
                '-o jsonpath={range .items[*]}{.metadata.namespace}{"|"}'
                '{.metadata.name}{"|"}{.data.tls\\.crt}{"\\n"}{end}',
                expected="service TLS certificate inventory — ns|name|"
                "base64(cert) lines, public certs only (algorithms "
                "decoded by the cert-algorithm probe)",
            )
        )
    for pat in scope.containers:
        rt = scope.container_runtimes[0] if scope.container_runtimes else "podman"
        out.append(
            ReconStep(
                sid(),
                "container",
                "exec",
                {"name": pat, "runtime": rt, "pqc": True},
                f"{rt} exec {pat} sh -c "
                "'openssl version -a 2>/dev/null; "
                "cat /etc/crypto-policies/state/current 2>/dev/null; "
                "cat /proc/sys/crypto/fips_enabled 2>/dev/null'",
                expected="OpenSSL version (>=3.5 = ML-KEM capable), active "
                "crypto-policy, FIPS mode",
            )
        )
        out.append(
            ReconStep(
                sid(),
                "container",
                "exec",
                {"name": pat, "runtime": rt, "pqc": True},
                f"{rt} exec {pat} sh -c "
                "'go version /proc/1/exe 2>/dev/null || "
                'strings -n 12 /proc/1/exe 2>/dev/null | grep -m1 "^go1\\." '
                "|| true'",
                expected="Go toolchain of the main binary (>=1.24 = hybrid X25519MLKEM768 default)",
            )
        )

    return out


# ---------------------------------------------------------------------------
# diffing recon vs threat model → candidate probes
# ---------------------------------------------------------------------------


def diff_surfaces(recon_inventory: dict, threat_model) -> list[tuple[str, str, dict]]:
    """
    Return [(target_type, surface_class, params), ...] for surfaces present
    in live recon but absent from the threat-model entry_points/controls.

    recon_inventory shape (built by execute.py from recon artifacts):
      {
        "crds": [{"api","kind","ref_fields":[...],"url_fields":[...],"webhook_selector":...}],
        "rbac": [{"sa","ns","rules":[...]}],
        "pods": [{"ns","name","caps":[...],"hostpath":[...],"sa":...,"hostPID":bool}],
        "components": [{"name","port","paths":[...]}],
        "wasm": [{"artifact","imports":[...],"exports":[...],"preopens":[...]}],
        "containers": [{"name","mounts":[...],"caps":[...],"sockets":[...]}],
      }
    """
    modeled = {ep.get("name", "").lower() for ep in threat_model.entry_points} | {
        t.get("surface", "").lower() for t in threat_model.threats
    }

    candidates: list[tuple[str, str, dict]] = []

    for crd in recon_inventory.get("crds", []):
        key = f"{crd.get('kind', '').lower()} crd"
        if key in modeled:
            continue
        for rf in crd.get("ref_fields", []):
            candidates.append(
                (
                    "operator",
                    "crd-cross-ns-ref",
                    {"api": crd["api"], "kind": crd["kind"], "ref_field": rf},
                )
            )
        for uf in crd.get("url_fields", []):
            candidates.append(
                (
                    "operator",
                    "crd-url-field",
                    {"api": crd["api"], "kind": crd["kind"], "url_field": uf},
                )
            )
        if crd.get("webhook_selector"):
            candidates.append(
                (
                    "operator",
                    "webhook-bypass",
                    {
                        "api": crd["api"],
                        "kind": crd["kind"],
                        "bypass_label": crd["webhook_selector"],
                    },
                )
            )

    for sa in recon_inventory.get("rbac", []):
        candidates.append(
            ("operator", "rbac-overbroad", {"operator_ns": sa["ns"], "operator_sa": sa["sa"]})
        )

    for pod in recon_inventory.get("pods", []):
        for hp in pod.get("hostpath", []):
            candidates.append(
                (
                    "pod",
                    "hostpath-writable",
                    {"namespace": pod["ns"], "pod": pod["name"], "mount_path": hp},
                )
            )
        if any(c.upper() == "CAP_SYS_ADMIN" for c in pod.get("caps", [])):
            candidates.append(("pod", "cap-sysadmin", {"namespace": pod["ns"], "pod": pod["name"]}))
        if pod.get("sa"):
            candidates.append(
                ("pod", "sa-token-reach", {"namespace": pod["ns"], "pod": pod["name"]})
            )

    for c in recon_inventory.get("containers", []):
        if c.get("sockets"):
            candidates.append(("container", "cri-socket", {"name": c["name"]}))
        if c.get("hostPID") or c.get("shared_pid"):
            candidates.append(("container", "procfs-host", {"name": c["name"]}))

    for comp in recon_inventory.get("components", []):
        for path in comp.get("paths", []):
            candidates.append(
                (
                    "component",
                    "unauth-control",
                    {"port": comp["port"], "path": path, "name": comp["name"]},
                )
            )

    for w in recon_inventory.get("wasm", []):
        if w.get("preopens"):
            candidates.append(("wasm", "wasi-preopen", {"artifact": w["artifact"]}))
        for exp in w.get("exports", []):
            candidates.append(
                ("wasm", "hostcall-unguarded", {"artifact": w["artifact"], "export": exp})
            )

    return candidates


def probe_steps(
    candidates: Iterable[tuple[str, str, dict]],
    *,
    tenant_ns: str = "vf-tenant",
    victim_ns: str = "vf-victim",
    listener_port: int = 18999,
    context: str = "__current__",
    id_prefix: str = "novel",
) -> list[dict]:
    """Materialize PROBE_CATALOGUE entries into concrete plan steps."""
    out: list[dict] = []
    n = 0
    for ttype, sclass, params in candidates:
        for tmpl in PROBE_CATALOGUE.get((ttype, sclass), []):
            n += 1
            sid = f"{id_prefix}-{n:03d}"
            p = {
                "tenant_ns": tenant_ns,
                "victim_ns": victim_ns,
                "listener_port": listener_port,
                "context": context,
                "boundary_args": "",
                "invalid_spec": "{}",
                **params,
            }
            step = {
                "id": sid,
                "novel_ref": sid,
                "technique": "novel",
                "adapter": _adapter_for(ttype),
                "verb": tmpl["verb"],
                "summary": tmpl["summary"],
                "target": _target_for(ttype, p),
                "classification": tmpl.get("classification", "safe"),
                "expected": tmpl["expected"].format(**p),
                "cwes": tmpl.get("cwes", []),
                "mitre": tmpl.get("mitre", []),
                "manual": tmpl.get("manual", False),
            }
            if "payload_template" in tmpl:
                step["payload"] = tmpl["payload_template"].format(**p)
            if "cmd_template" in tmpl:
                step["cmd"] = tmpl["cmd_template"].format(**p)
            if tmpl.get("verb") == "apply-manifest":
                step["rollback"] = (
                    f"kubectl --context {p['context']} -n {p.get('tenant_ns', tenant_ns)} "
                    f"delete {p.get('kind', '').lower()} {sid_to_name(sid, p)}"
                )
            out.append(step)
    return out


def sid_to_name(_sid: str, p: dict) -> str:
    # name embedded in payload templates (vf-probe-*)
    return next(
        (
            tok
            for tok in ("vf-probe-xns", "vf-probe-ssrf", "vf-probe-wh")
            if tok in p.get("payload", "") or True
        ),  # default first
        "vf-probe",
    )


def _adapter_for(ttype: str) -> str:
    return {
        "operator": "k8s",
        "pod": "k8s",
        "component": "k8s",
        "container": "container",
        "wasm": "wasm",
    }.get(ttype, "k8s")


def _target_for(ttype: str, p: dict) -> dict:
    if ttype in ("operator", "component"):
        return {"context": p.get("context"), "namespace": p.get("tenant_ns")}
    if ttype == "pod":
        return {"context": p.get("context"), "namespace": p.get("namespace"), "name": p.get("pod")}
    if ttype == "container":
        return {"name": p.get("name")}
    if ttype == "wasm":
        return {"artifact": p.get("artifact")}
    return {}


if __name__ == "__main__":  # pragma: no cover
    print(
        json.dumps(
            [asdict(s) for s in recon_steps.__wrapped__]
            if False
            else {"catalogue": sorted(f"{k[0]}/{k[1]}" for k in PROBE_CATALOGUE)},
            indent=2,
        )
    )
