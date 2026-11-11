#!/usr/bin/env python3
"""Pre-flight target attestation — validation-improvement-plan P2.

Fail-closed environment gate for the validation lanes: BEFORE any probe
runs, record the required target checks as machine-checkable
`target-attestation.json` beside the validation run.
Core's ValidationService.record consumes the full artifact and owns the
run-level gate: explicit failed attestation voids every verdict at any age,
and current-policy recording requires attestation independent of version.

Checks (each recorded individually; `attested` is the AND of required
checks):
  cluster fingerprint   oc version + infrastructure platform/cluster id
  csv-succeeded         --csv NAME --namespace NS: CSV phase == Succeeded
  pods-ready            --namespace NS [--selector S]: all pods Ready
  version-in-range      --version V --affected-range '<v1.2.3' (or
                        --fixed-version): target within the finding's
                        affected range — outside it, verdicts are
                        meaningless for the claim
  feature-gate          --require-featuregate NAME (repeatable)
  url-reachable         --url U (browser lane): non-5xx HTTP answer only,
                        not authentication, authorization or browser usability

Usage:
  attest_target.py --out <dir>/target-attestation.json \
      [--namespace ns --csv name] [--selector app=x] \
      [--version v --affected-range '<v2'] [--require-featuregate F] \
      [--url https://…] [--kubeconfig path] [--context ctx]

Exit 0: attestation written (attested true OR false — the FILE is the
gate, not the exit code). Exit 2: usage error.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from traust.paths import HARNESS_ROOT


def _harness_version() -> str:
    try:
        pyproject = (HARNESS_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        v = m.group(1) if m else "0.1.0"
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        return f"{v}-{sha}" if sha else v
    except OSError:
        return "0.1.0"


def _oc(args: list[str], kubeconfig: str | None, context: str | None):
    cmd = ["oc"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    if context:
        cmd += ["--context", context]
    return subprocess.run(cmd + args, capture_output=True, text=True, timeout=60)


def _check(name: str, ok: bool, detail: str, required: bool = True) -> dict:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail[:400]}


def _url_answer_check(status: int) -> dict:
    """App-owned preflight claim, not Core's retried provider-fetch success policy."""
    return _check("url-reachable", status < 500, f"HTTP {status}")


def parse_semverish(v: str):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", v or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def version_in_range(version: str, affected_range: str | None, fixed_version: str | None):
    ver = parse_semverish(version)
    if ver is None:
        return None
    if fixed_version:
        fix = parse_semverish(fixed_version)
        if fix is not None:
            return ver < fix
    m = re.match(r"^\s*(<|<=|>=|>)\s*v?(\d+\.\d+(?:\.\d+)?)\s*$", affected_range or "")
    if m:
        bound = parse_semverish(m.group(2))
        if bound is not None:
            ops = {"<": ver.__lt__, "<=": ver.__le__, ">=": ver.__ge__, ">": ver.__gt__}
            return ops[m.group(1)](bound)
    return None


def fingerprint(kubeconfig, context) -> tuple[dict, list[dict]]:
    checks = []
    fp: dict = {}
    r = _oc(["version", "-o", "json"], kubeconfig, context)
    if r.returncode == 0:
        try:
            v = json.loads(r.stdout)
            fp["openshift_version"] = v.get("openshiftVersion") or (
                v.get("serverVersion") or {}
            ).get("gitVersion")
            checks.append(_check("cluster-reachable", True, f"server {fp['openshift_version']}"))
        except json.JSONDecodeError:
            checks.append(_check("cluster-reachable", False, "unparseable oc version"))
    else:
        checks.append(_check("cluster-reachable", False, r.stderr.strip() or "oc version failed"))
        return fp, checks
    r = _oc(["get", "infrastructure", "cluster", "-o", "json"], kubeconfig, context)
    if r.returncode == 0:
        try:
            infra = json.loads(r.stdout)
            fp["platform"] = ((infra.get("status") or {}).get("platformStatus") or {}).get("type")
            fp["infrastructure_name"] = (infra.get("status") or {}).get("infrastructureName")
        except json.JSONDecodeError:
            pass
    return fp, checks


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--namespace")
    ap.add_argument("--csv", help="ClusterServiceVersion name (operator lanes)")
    ap.add_argument("--selector", help="pod label selector for readiness")
    ap.add_argument("--version", help="deployed component version under test")
    ap.add_argument("--affected-range")
    ap.add_argument("--fixed-version")
    ap.add_argument("--require-featuregate", action="append", default=[])
    ap.add_argument("--url", help="browser-lane endpoint")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--context")
    args = ap.parse_args(argv)

    checks: list[dict] = []
    fp: dict = {}

    cluster_mode = any([args.namespace, args.csv, args.selector, args.require_featuregate])
    if cluster_mode:
        fp, fchecks = fingerprint(args.kubeconfig, args.context)
        checks += fchecks

        if args.csv and args.namespace:
            r = _oc(
                ["get", "csv", args.csv, "-n", args.namespace, "-o", "jsonpath={.status.phase}"],
                args.kubeconfig,
                args.context,
            )
            phase = r.stdout.strip()
            checks.append(
                _check(
                    "csv-succeeded",
                    phase == "Succeeded",
                    f"phase={phase or r.stderr.strip()[:120]}",
                )
            )
        if args.namespace:
            r = _oc(
                ["get", "pods", "-n", args.namespace]
                + (["-l", args.selector] if args.selector else [])
                + ["-o", "json"],
                args.kubeconfig,
                args.context,
            )
            ready = total = 0
            if r.returncode == 0:
                try:
                    for pod in json.loads(r.stdout).get("items", []):
                        total += 1
                        conds = {
                            c["type"]: c["status"]
                            for c in (pod.get("status") or {}).get("conditions", [])
                        }
                        if conds.get("Ready") == "True":
                            ready += 1
                except json.JSONDecodeError:
                    pass
            checks.append(
                _check(
                    "pods-ready",
                    total > 0 and ready == total,
                    f"{ready}/{total} Ready in {args.namespace}"
                    + (f" ({args.selector})" if args.selector else ""),
                )
            )
        for fg in args.require_featuregate:
            r = _oc(["get", "featuregate", "cluster", "-o", "json"], args.kubeconfig, args.context)
            on = False
            if r.returncode == 0:
                on = fg in r.stdout
            checks.append(
                _check(
                    f"feature-gate:{fg}",
                    on,
                    "present in FeatureGate cluster" if on else "not found",
                )
            )

    if args.version and (args.affected_range or args.fixed_version):
        in_range = version_in_range(args.version, args.affected_range, args.fixed_version)
        fp["component_version"] = args.version
        checks.append(
            _check(
                "version-in-affected-range",
                bool(in_range),
                f"{args.version} vs {args.affected_range or '< ' + str(args.fixed_version)}"
                + ("" if in_range is not None else " (unparseable — fail closed)"),
            )
        )

    if args.url:
        # Deliberate status-only preflight: no response body and no application
        # retries/Retry-After waits. Context.http owns retried provider fetches;
        # it does not expose this status-only policy (see validation-process.md).
        try:
            req = urllib.request.Request(args.url, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                checks.append(_url_answer_check(resp.status))
            fp["url"] = args.url
        except urllib.error.HTTPError as e:
            with e:
                checks.append(_url_answer_check(e.code))
            fp["url"] = args.url
        except Exception as e:
            checks.append(_check("url-reachable", False, str(e)[:200]))

    if not checks:
        print("nothing to attest — pass at least one target flag", file=sys.stderr)
        return 2

    attested = all(c["ok"] for c in checks if c["required"])
    doc = {
        "artifact": "target-attestation",
        "attested": attested,
        "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": _harness_version(),
        "fingerprint": fp,
        "checks": checks,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(
        f"attestation: {'ATTESTED' if attested else 'FAILED'} "
        f"({sum(c['ok'] for c in checks)}/{len(checks)} checks) → {out}"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["admin", "attest-target", *sys.argv[1:]]))
