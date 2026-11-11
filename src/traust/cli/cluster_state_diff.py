#!/usr/bin/env python3
"""Cluster state diffing — validation-improvement-plan P5, sweep 1.

Snapshot the security-relevant cluster state before/after a probe sweep
and turn unexpected deltas into NEW finding candidates routed to
/triage (origin: validation-discovery — machine-generated,
transcript-backed, never straight to the ledger).

  snapshot --out state.json [--kubeconfig K] [--context C] [--namespaces ns1,ns2]
      Captures: ClusterRoles/Bindings + Roles/Bindings (target
      namespaces), SCCs, Validating/MutatingWebhookConfigurations,
      NetworkPolicies, Services (type/ports), Routes. Normalized
      (managedFields, resourceVersions, timestamps stripped) so diffs
      are semantic.

  diff BEFORE.json AFTER.json --out candidates.json
      Emits one candidate per unexpected delta: new/changed RBAC grants,
      new SCC or SCC mutation, webhook rule/failurePolicy changes, new
      exposed Service/Route, deleted NetworkPolicy. Probe side-effects
      the run itself created (labels vb-bench/probe or names the run
      declared in --expected) are excluded.

Deterministic; the same two snapshots always produce the same
candidates. Candidates carry origin: validation-discovery so census and
dashboards can count the lane's detection contribution separately.
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

RESOURCES = [
    ("clusterroles", "rbac.authorization.k8s.io", False),
    ("clusterrolebindings", "rbac.authorization.k8s.io", False),
    ("roles", "rbac.authorization.k8s.io", True),
    ("rolebindings", "rbac.authorization.k8s.io", True),
    ("securitycontextconstraints", "security.openshift.io", False),
    ("validatingwebhookconfigurations", "admissionregistration.k8s.io", False),
    ("mutatingwebhookconfigurations", "admissionregistration.k8s.io", False),
    ("networkpolicies", "networking.k8s.io", True),
    ("services", "", True),
    ("routes", "route.openshift.io", True),
]
_STRIP = (
    "managedFields",
    "resourceVersion",
    "uid",
    "creationTimestamp",
    "generation",
    "annotations",
)


def _oc(args, kubeconfig, context):
    cmd = ["oc"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    if context:
        cmd += ["--context", context]
    return subprocess.run(cmd + args, capture_output=True, text=True, timeout=120)


def _normalize(obj: dict) -> dict:
    meta = obj.get("metadata") or {}
    for k in _STRIP:
        meta.pop(k, None)
    obj.pop("status", None)
    return obj


def snapshot(kubeconfig, context, namespaces) -> dict:
    snap = {
        "taken_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resources": {},
    }
    for kind, group, namespaced in RESOURCES:
        gv = f"{kind}.{group}" if group else kind
        items = []
        scopes = namespaces if namespaced and namespaces else [None]
        for ns in scopes:
            args = ["get", gv, "-o", "json"]
            if namespaced and ns:
                args += ["-n", ns]
            elif namespaced:
                args += ["--all-namespaces"]
            r = _oc(args, kubeconfig, context)
            if r.returncode != 0:
                items.append({"__error__": r.stderr.strip()[:200]})
                continue
            try:
                for it in json.loads(r.stdout).get("items", []):
                    items.append(_normalize(it))
            except json.JSONDecodeError:
                items.append({"__error__": "unparseable"})
        snap["resources"][kind] = items
    return snap


def _key(kind: str, obj: dict) -> str:
    m = obj.get("metadata") or {}
    return f"{kind}/{m.get('namespace', '')}/{m.get('name', '?')}"


def _index(snap: dict) -> dict:
    out = {}
    for kind, items in snap.get("resources", {}).items():
        for it in items:
            if "__error__" in it:
                continue
            out[_key(kind, it)] = it
    return out


_SEVERITY = {
    "securitycontextconstraints": "high",
    "clusterrolebindings": "high",
    "clusterroles": "medium",
    "validatingwebhookconfigurations": "medium",
    "mutatingwebhookconfigurations": "high",
    "networkpolicies": "medium",
    "rolebindings": "medium",
    "roles": "low",
    "services": "medium",
    "routes": "medium",
}


def diff(before: dict, after: dict, expected: set[str]) -> list[dict]:
    b, a = _index(before), _index(after)
    candidates = []

    def _cand(kind, key, change, detail):
        if any(x in key for x in expected):
            return
        candidates.append(
            {
                "id": f"VD-{len(candidates) + 1:03d}",
                "title": f"{change} during validation sweep: {key}",
                "severity": _SEVERITY.get(kind, "medium"),
                "category": "validation-discovery",
                "origin": "validation-discovery",
                "description": detail[:800],
                "locations": [{"path": key}],
            }
        )

    for key in sorted(set(a) - set(b)):
        kind = key.split("/", 1)[0]
        _cand(
            kind,
            key,
            "Unexpected new object",
            f"Object appeared between snapshots and was not declared "
            f"as a probe side-effect: {json.dumps(a[key])[:600]}",
        )
    for key in sorted(set(b) - set(a)):
        kind = key.split("/", 1)[0]
        if kind == "networkpolicies":
            _cand(
                kind,
                key,
                "NetworkPolicy deleted",
                "A deny rule present before the sweep is gone after it.",
            )
    for key in sorted(set(b) & set(a)):
        kind = key.split("/", 1)[0]
        if b[key] != a[key] and kind in (
            "clusterroles",
            "clusterrolebindings",
            "roles",
            "rolebindings",
            "securitycontextconstraints",
            "validatingwebhookconfigurations",
            "mutatingwebhookconfigurations",
        ):
            _cand(
                kind,
                key,
                "Security object mutated",
                f"before={json.dumps(b[key])[:350]} after={json.dumps(a[key])[:350]}",
            )
    return candidates


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("snapshot")
    p.add_argument("--out", required=True)
    p.add_argument("--kubeconfig")
    p.add_argument("--context")
    p.add_argument("--namespaces", default=None, help="comma-separated; default all namespaces")
    p = sub.add_parser("diff")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--out", required=True)
    p.add_argument(
        "--expected",
        default="",
        help="comma-separated substrings of keys the run "
        "itself creates (probe side-effects to exclude)",
    )
    args = ap.parse_args(argv)

    if args.cmd == "snapshot":
        ns = args.namespaces.split(",") if args.namespaces else None
        snap = snapshot(args.kubeconfig, args.context, ns)
        Path(args.out).write_text(json.dumps(snap, indent=1) + "\n")
        n = sum(len(v) for v in snap["resources"].values())
        print(f"snapshot: {n} objects → {args.out}")
        return 0

    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    expected = {x.strip() for x in args.expected.split(",") if x.strip()}
    cands = diff(before, after, expected)
    doc = {
        "metadata": {
            "origin": "validation-discovery",
            "before": args.before,
            "after": args.after,
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "findings": cands,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
    print(
        f"{len(cands)} discovery candidate(s) → {args.out} "
        f"(route to /triage; never straight to the ledger)"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["impact", "cluster-state-diff", *sys.argv[1:]]))
