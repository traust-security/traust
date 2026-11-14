#!/usr/bin/env python3
"""
Attack-chain synthesis for the validate-findings harness.

Builds a directed graph over {entry_points, findings, assets} and searches
for kill-chains: paths from an externally-reachable entry point to a
high-sensitivity asset, where each finding's exploitation yields a
capability that satisfies the next finding's preconditions.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import count
from pathlib import Path

# ---------------------------------------------------------------------------
# capability vocabulary — what a successful exploit YIELDS, and what a
# finding REQUIRES. Edges finding_A -> finding_B exist when
# yields(A) ∩ requires(B) ≠ ∅.
# ---------------------------------------------------------------------------

CAPABILITIES = {
    # identity / authz
    "sa-token": (
        r"\b(service.?account|sa)\b.*\btoken\b"
        r"|\btoken\b.*\b(service.?account|sa)\b"
    ),
    "kubeconfig": r"\bkubeconfig\b",
    "cluster-admin": r"\bcluster-?admin\b|\b\*\s*\*\s*\*\b",
    "rbac-escalation": r"\b(escalat|bind|impersonat)\w*\b.*\b(role|rbac|clusterrole)\b",
    # tenancy
    "ns-escape": (
        r"\b(cross|other|any|arbitrary).?namespace\b"
        r"|\bnamespace\b.*\b(escape|bypass|cross)\b"
    ),
    "tenant-escape": r"\btenant\b.*\b(escape|bypass|cross)\b",
    # data
    "secret-read": r"\bsecret\w*\b.*\b(read|exfiltrat|leak|disclos|access)\b",
    "configmap-read": r"\bconfigmap\b",
    "etcd-access": r"\betcd\b",
    # exec
    "pod-exec": r"\b(pods?/exec|kubectl\s+exec|oc\s+exec|remote\s+code|RCE)\b",
    "host-exec": r"\b(host|node)\b.*\b(exec|root|breakout|escape)\b|\bprivileged\b",
    "container-exec": r"\b(docker|podman|crictl)\s+exec\b",
    # network
    "ssrf": r"\bSSRF\b|\bserver.?side\s+request\b",
    "net-position": r"\b(port.?forward|mitm|man.?in.?the.?middle|proxy)\b",
    # filesystem
    "file-write": r"\b(write|overwrite|inject)\b.*\b(file|path|hostpath|volume)\b",
    "file-read": r"\b(read|disclos|leak)\b.*\b(file|path|/etc/|/var/)\b",
    # wasm
    "wasm-hostcall": r"\bhost(call| function)\b",
    "wasm-memory": r"\b(linear\s+memory|OOB|out.?of.?bounds)\b",
}

# CWE → likely yielded capabilities
CWE_YIELDS = {
    "CWE-22": {"file-read", "file-write"},
    "CWE-77": {"pod-exec", "container-exec"},
    "CWE-78": {"pod-exec", "host-exec"},
    "CWE-94": {"pod-exec"},
    "CWE-200": {"secret-read", "file-read"},
    "CWE-269": {"rbac-escalation", "ns-escape"},
    "CWE-284": {"rbac-escalation"},
    "CWE-285": {"rbac-escalation", "ns-escape"},
    "CWE-306": {"net-position"},
    "CWE-441": {"ns-escape", "secret-read"},  # confused deputy
    "CWE-522": {"secret-read", "sa-token"},
    "CWE-610": {"ns-escape", "secret-read"},  # external ref
    "CWE-732": {"file-write"},
    "CWE-798": {"secret-read", "kubeconfig"},
    "CWE-918": {"ssrf", "net-position"},
    "CWE-1188": {"net-position"},
}

# capability satisfaction graph: gaining LHS implicitly grants RHS
CAP_IMPLIES = {
    "cluster-admin": {"rbac-escalation", "ns-escape", "secret-read", "pod-exec", "sa-token"},
    "host-exec": {"pod-exec", "container-exec", "file-read", "file-write", "secret-read"},
    "etcd-access": {"secret-read", "cluster-admin"},
    "kubeconfig": {"sa-token"},
    "ns-escape": {"tenant-escape"},
}

# MITRE ATT&CK capability → technique IDs. Loaded from the shared pinned
# tables (harnessing/attack-coverage/) so validation reports, threat models,
# and the coverage layer cite one vetted ATT&CK release. attack_refs
# validates every ID against the pinned table at import — a revoked or
# deprecated technique fails here, not silently in a report.
# harnessing/<stage>/<skill>/chain.py -> harnessing/attack-coverage/scripts.
# Three parents reach the shared attack-coverage scripts from this stage.
sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent.parent / "attack-coverage" / "scripts")
)
import attack_refs  # noqa: E402

MITRE_MAP = attack_refs.capability_map()
_bad = attack_refs.validate_ids(sorted({t for ids in MITRE_MAP.values() for t in ids}))
if _bad:
    raise RuntimeError(f"attack-mapping capability_map invalid: {_bad}")

# PQC posture capabilities. Emitted by the pqc-* probes in
# novel.PROBE_CATALOGUE and consumed by the pqc-readiness skill to close a
# repo's runtime_verification_required flag. These are POSTURE OBSERVATIONS,
# not attacker capabilities: they never enter CAP_IMPLIES closures, never
# map to MITRE techniques, and never seed attack chains.
PQC_CAPS = {
    "tls-hybrid-ke": "ML-KEM (hybrid) group negotiated at the probed endpoint",
    "tls-classical-ke-only": "hybrid offer fell back to a classical group",
    "cert-classical-sig": "served chain signed with RSA/ECDSA",
    "cert-pqc-sig": "ML-DSA/SLH-DSA present in the served chain",
    "fips-mode-enabled": "kernel FIPS bit set on the probed workload",
    "crypto-policy-legacy": "LEGACY (or SHA1-widened) crypto-policy active",
    "backend-tls-classical": "a downstream hop behind the edge is classical-only",
}


def pqc_caps_from_probe(probe_summary: str, observed: str) -> set[str]:
    """Deterministic mapping from a PQC probe's observed output to PQC_CAPS.
    Pure string rules — interpretation stays in the pqc-readiness skill."""
    caps: set[str] = set()
    text = observed or ""
    if "MLKEM" in text or "ML-KEM" in text:
        caps.add("tls-hybrid-ke")
    elif "Negotiated TLS1.3 group" in text:
        caps.add("tls-classical-ke-only")
    if re.search(r"Signature Algorithm:.*(rsa|ecdsa)", text, re.I):
        caps.add("cert-classical-sig")
    if re.search(r"ML-DSA|SLH-DSA|Dilithium|SPHINCS", text, re.I):
        caps.add("cert-pqc-sig")
    if re.search(r"^1$", text, re.M) and "fips" in probe_summary.lower():
        caps.add("fips-mode-enabled")
    if re.search(r"^LEGACY", text, re.M):
        caps.add("crypto-policy-legacy")
    if "backend" in probe_summary.lower() and "tls-classical-ke-only" in caps:
        caps.discard("tls-classical-ke-only")
        caps.add("backend-tls-classical")
    return caps


def _close(caps: set[str]) -> set[str]:
    """Transitive closure over CAP_IMPLIES."""
    out = set(caps)
    changed = True
    while changed:
        changed = False
        for c in list(out):
            for impl in CAP_IMPLIES.get(c, ()):
                if impl not in out:
                    out.add(impl)
                    changed = True
    return out


def _match_caps(text: str) -> set[str]:
    text = text or ""
    found = set()
    for cap, pat in CAPABILITIES.items():
        if re.search(pat, text, re.IGNORECASE):
            found.add(cap)
    return found


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


@dataclass(eq=True, frozen=True)
class Node:
    kind: str  # entry | finding | asset
    key: str  # entry-point name | finding id | asset name

    def __str__(self):
        return f"{self.kind}:{self.key}"


@dataclass
class Chain:
    chain_id: str
    entry_point: str
    terminal_asset: str
    path: list[Node]
    finding_ids: list[str]
    capabilities: list[str]
    mitre: list[str]
    name: str = ""
    narrative: str = ""

    def to_dict(self):
        return {
            "chain_id": self.chain_id,
            "name": self.name or f"{self.entry_point} → {self.terminal_asset}",
            "entry_point": self.entry_point,
            "terminal_asset": self.terminal_asset,
            "finding_ids": self.finding_ids,
            "mitre_attack_refs": self.mitre,
            "narrative": self.narrative,
            "path": [str(n) for n in self.path],
        }


def _finding_caps(f) -> tuple[set[str], set[str]]:
    """Return (requires, yields) capability sets for a Finding."""
    req_text = " ".join(f.preconditions) if getattr(f, "preconditions", None) else ""
    yield_text = " ".join(
        [
            f.title or "",
            f.description or "",
            f.attack_pattern or "",
            getattr(f, "verify_verdict", "") or "",
        ]
    )
    requires = _match_caps(req_text)
    yields = _match_caps(yield_text)
    for cwe in getattr(f, "cwes", []) or []:
        yields |= CWE_YIELDS.get(cwe, set())
    return requires, _close(yields)


def _entry_caps(ep: dict) -> set[str]:
    """What an attacker at this entry point already has."""
    tb = (ep.get("trust_boundary") or "").lower()
    desc = (ep.get("description") or "").lower()
    caps = set()
    if "unauth" in tb or "anonymous" in tb or "public" in desc:
        caps.add("net-position")
    if "tenant" in tb or "namespace" in desc or "authenticated" in tb:
        caps |= {"sa-token", "tenant-escape"}  # tenant-level creds
    if "admin" in tb or "cluster-admin" in desc:
        caps.add("cluster-admin")
    return _close(caps)


def build_graph(findings: Iterable, threat_model) -> tuple[set[Node], dict[Node, set[Node]], dict]:
    nodes: set[Node] = set()
    edges: dict[Node, set[Node]] = {}
    meta: dict[Node, dict] = {}

    def add_edge(a: Node, b: Node):
        nodes.add(a)
        nodes.add(b)
        edges.setdefault(a, set()).add(b)

    f_by_id = {}
    for f in findings:
        if getattr(f, "triage_verdict", None) == "false_positive":
            continue
        fn = Node("finding", f.id)
        req, yld = _finding_caps(f)
        meta[fn] = {"requires": req, "yields": yld, "obj": f}
        f_by_id[f.id] = fn
        nodes.add(fn)

    for a in threat_model.assets:
        an = Node("asset", a["name"])
        meta[an] = {"sensitivity": a.get("sensitivity", "")}
        nodes.add(an)

    for ep in threat_model.entry_points:
        en = Node("entry", ep["name"])
        meta[en] = {"yields": _entry_caps(ep), "obj": ep}
        nodes.add(en)
        # entry → finding when entry caps satisfy finding requires (or finding has no requires)
        for fn in f_by_id.values():
            req = meta[fn]["requires"]
            if not req or req <= meta[en]["yields"]:
                add_edge(en, fn)
        # entry → asset (direct reachability declared in threat model)
        for asset_name in ep.get("reachable_assets", []):
            an = Node("asset", asset_name)
            if an in nodes:
                add_edge(en, an)

    # finding → finding when A.yields ⊇ B.requires (and B has requires)
    fnodes = list(f_by_id.values())
    for a in fnodes:
        for b in fnodes:
            if a is b:
                continue
            req_b = meta[b]["requires"]
            if req_b and req_b <= meta[a]["yields"]:
                add_edge(a, b)

    # finding → asset when finding text mentions the asset, or finding's
    # linked threat targets that asset
    asset_names = {n.key.lower(): n for n in nodes if n.kind == "asset"}
    threat_assets = {t["id"]: t.get("asset", "") for t in threat_model.threats}
    for fn in fnodes:
        f = meta[fn]["obj"]
        hay = " ".join(
            [f.title, f.description, f.attack_pattern, " ".join(f.preconditions)]
        ).lower()
        for name, an in asset_names.items():
            if name and name in hay:
                add_edge(fn, an)
        for tid in getattr(f, "threat_ids", []):
            t_asset = threat_assets.get(tid, "")
            for name, an in asset_names.items():
                if name and name in t_asset.lower():
                    add_edge(fn, an)

    return nodes, edges, meta


def find_chains(
    findings,
    threat_model,
    *,
    max_len: int = 6,
    max_chain_findings: int = 200,
    max_edges_per_node: int = 8,
    max_chains: int = 100,
) -> list[Chain]:
    """Discover attack chains via DFS over the finding/asset graph.

    Scalability guards (the unbounded version is intractable above a
    few hundred findings — O(n²) edge build × depth-6 DFS):

      * ``max_chain_findings`` — only the top-N findings by severity
        (after dropping triage-FP and non-runtime surfaces) are graphed.
        The rest are still validated via replay; they just don't
        participate in chain synthesis.
      * ``max_edges_per_node`` — cap out-degree; keep the
        highest-severity neighbours.
      * ``max_chains`` — stop the DFS once this many chains are found.
    """
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    pool = [
        f
        for f in findings
        if getattr(f, "triage_verdict", None) != "false_positive"
        and getattr(f, "surface", "runtime") == "runtime"
    ]
    if len(pool) > max_chain_findings:
        pool = sorted(pool, key=lambda f: sev_rank.get(f.severity, 5))[:max_chain_findings]
    nodes, edges, meta = build_graph(pool, threat_model)

    # Cap out-degree: keep highest-severity neighbours per node.
    def _nrank(n):
        if n.kind == "finding":
            return sev_rank.get(meta[n]["obj"].severity, 5)
        return 0  # entry/asset nodes always kept

    for src in list(edges):
        nbrs = edges[src]
        if len(nbrs) > max_edges_per_node:
            edges[src] = set(sorted(nbrs, key=_nrank)[:max_edges_per_node])
    entries = [n for n in nodes if n.kind == "entry"]
    targets = [
        n
        for n in nodes
        if n.kind == "asset" and meta.get(n, {}).get("sensitivity") in ("critical", "high")
    ]
    if not entries:
        entries = [Node("entry", "unauthenticated")]
        meta[entries[0]] = {"yields": {"net-position"}}
        for fn in (n for n in nodes if n.kind == "finding"):
            if not meta[fn]["requires"]:
                edges.setdefault(entries[0], set()).add(fn)
    if not targets:
        # fall back: terminal = any finding that yields cluster-admin/host-exec
        targets = [
            n
            for n in nodes
            if n.kind == "finding"
            and {"cluster-admin", "host-exec", "etcd-access"} & meta[n]["yields"]
        ]

    chains: list[Chain] = []
    seen_paths: set[frozenset] = set()
    ids = count(1)

    def dfs(node: Node, path: list[Node], caps: set[str]):
        if len(chains) >= max_chains:
            return
        if len(path) > max_len:
            return
        if node in targets and len(path) > 1:
            sig = frozenset(p for p in path if p.kind == "finding")
            if not sig or sig in seen_paths:
                return
            seen_paths.add(sig)
            f_ids = [p.key for p in path if p.kind == "finding"]
            mitre = sorted({t for c in caps for t in MITRE_MAP.get(c, [])})
            chains.append(
                Chain(
                    chain_id=f"CHAIN-{next(ids):03d}",
                    entry_point=path[0].key,
                    terminal_asset=node.key,
                    path=list(path),
                    finding_ids=f_ids,
                    capabilities=sorted(caps),
                    mitre=mitre,
                    narrative=" → ".join(str(p) for p in path),
                )
            )
            return
        for nxt in edges.get(node, ()):
            if nxt in path:
                continue
            new_caps = caps | meta.get(nxt, {}).get("yields", set())
            dfs(nxt, [*path, nxt], new_caps)

    for e in entries:
        if len(chains) >= max_chains:
            break
        dfs(e, [e], meta.get(e, {}).get("yields", set()))

    # rank: longer finding-paths first, then by terminal sensitivity
    chains.sort(key=lambda c: (-len(c.finding_ids), c.terminal_asset))
    return chains
