#!/usr/bin/env python3
"""Tier 3 — runtime privilege capture for an installed operator.

Collects the ground truth the static profile cannot: which SCC the
cluster ACTUALLY assigned to each pod (the `openshift.io/scc`
annotation), the ServiceAccount inventory, each SA's effective
permissions (`oc auth can-i --list`), and the namespace's PSA labels.
Merges naturally with the tier-1/2 static profile by repo/operator name.

EXECUTION IS GATED: refuses to run without --i-am-authorized, an explicit
--namespace, and a reachable cluster. Read-only throughout (get/auth
calls only; no mutations). Run only against clusters covered by the
campaign's authorization (see validate-findings scope rules).

Usage:
  capture_runtime_privileges.py --namespace <ns> --name <operator-name> \
      --out-dir <dir> --i-am-authorized [--kubeconfig <path>]

Home: tools package (plan 15). Not ported: a live-cluster capture would go through
ClusterProvider and ValidationService, which the skill port leaves alone.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def oc(args, kubeconfig=None, allow_fail=False):
    cmd = ["oc"] + (["--kubeconfig", kubeconfig] if kubeconfig else []) + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 and not allow_fail:
        raise RuntimeError(f"oc {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--name", required=True, help="operator/repo name for the artifact")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--kubeconfig")
    ap.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="assert the target cluster is in the campaign's authorized scope",
    )
    args = ap.parse_args()

    if not args.i_am_authorized:
        print(
            "REFUSED: pass --i-am-authorized only for clusters within the "
            "campaign's authorization (fail-closed by design).",
            file=sys.stderr,
        )
        return 2

    kc = args.kubeconfig
    ns = args.namespace
    audit = {"namespace": ns, "read_only": True, "commands": []}

    def logged(cmd_args, allow_fail=False):
        audit["commands"].append("oc " + " ".join(cmd_args))
        return oc(cmd_args, kc, allow_fail)

    pods = json.loads(logged(["get", "pods", "-n", ns, "-o", "json"]))
    pod_rows = []
    sas = set()
    for p in pods.get("items", []):
        meta = p["metadata"]
        sa = p["spec"].get("serviceAccountName") or "default"
        sas.add(sa)
        pod_rows.append(
            {
                "pod": meta["name"],
                "scc_assigned": (meta.get("annotations") or {}).get("openshift.io/scc"),
                "serviceAccount": sa,
                "node": p["spec"].get("nodeName"),
                "containers": [
                    {"name": c.get("name"), "securityContext": c.get("securityContext") or {}}
                    for c in p["spec"].get("containers", [])
                ],
            }
        )

    ns_obj = json.loads(logged(["get", "namespace", ns, "-o", "json"]))
    psa = {
        k: v
        for k, v in (ns_obj["metadata"].get("labels") or {}).items()
        if k.startswith("pod-security.kubernetes.io/")
    }

    sa_perms = {}
    for sa in sorted(sas):
        out = logged(
            ["auth", "can-i", "--list", "-n", ns, f"--as=system:serviceaccount:{ns}:{sa}"],
            allow_fail=True,
        )
        sa_perms[sa] = out.splitlines()[:400]

    result = {
        "name": args.name,
        "tier": "runtime (3)",
        "namespace": ns,
        "psa_labels": psa,
        "pods": pod_rows,
        "serviceaccount_effective_permissions": sa_perms,
        "audit_trail": audit,
    }
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.name}-runtime-privileges.json").write_text(json.dumps(result, indent=1) + "\n")
    sccs = sorted({r["scc_assigned"] for r in pod_rows if r["scc_assigned"]})
    print(
        f"{args.name}: {len(pod_rows)} pods in {ns}; SCCs assigned: "
        f"{', '.join(sccs) or 'none observed'}; PSA: {psa or 'none'}; "
        f"{len(sas)} ServiceAccounts enumerated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
