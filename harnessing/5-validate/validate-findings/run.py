#!/usr/bin/env python3
"""
Unattended single-process driver for the validate-findings harness.

Runs ingest → scope → plan → execute → typed report → core record.
The existing unattended executor is restricted to explicitly authorized isolated
lab scope. Preparation/planning/authorization/execution are not yet service ports.

Usage:
  run.py <source>[,<source>...] --targets <yaml> --context <ctx>
         --target-attestation <json> --record-bindings <json>
         [--replay-only] [--destructive] --out <dir> [--name <slug>]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from uuid import uuid4

from traust_core.v1.models.common import Provenance
from traust_core.v1.models.validation import (
    TargetAttestation,
    ValidationRecordingPolicy,
    ValidationRecordInput,
)
from traust_core.v1.models.vocabulary import SourceType

from traust.cli.validation import record_report
from traust.context import add_config_home_arg

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import execute as ex  # noqa: E402
import ingest as ing  # noqa: E402
import plan as pl  # noqa: E402
import report as rp  # noqa: E402
import scope as sc  # noqa: E402


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", help="findings dir(s), comma-separated")
    add_config_home_arg(ap)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--context", action="append", default=[])
    ap.add_argument("--ns", action="append", default=[])
    ap.add_argument("--replay-only", action="store_true")
    ap.add_argument("--destructive", action="store_true")
    ap.add_argument("--max-novel", type=int, default=10)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", help="slug for output filenames (default: derived from source)")
    ap.add_argument(
        "--credentials-needed",
        help="path to credentials-needed.json from operand setup; "
        "findings whose PoCs reference a blocks_validation "
        "entry are skipped with reason needs-credential:<ref>",
    )
    ap.add_argument("--target-attestation", type=Path, required=True)
    ap.add_argument(
        "--record-bindings", type=Path, required=True, help="Core source/finding bindings."
    )
    ap.add_argument("--install-failure", type=Path, help="Explicit deployment failure evidence.")
    ap.add_argument(
        "--finding-assessments", type=Path, help="Explicit grades/review proposals by planner ID."
    )
    args = ap.parse_args(argv)
    attestation = TargetAttestation.model_validate_json(args.target_attestation.read_bytes())
    bindings = ValidationRecordInput.model_validate_json(args.record_bindings.read_bytes())
    if bindings.policy != ValidationRecordingPolicy.CURRENT:
        ap.error("new runs require current recording policy")
    provenance = Provenance(
        run_id=uuid4(), source=SourceType.VALIDATION_REPORT, occurred_at=dt.datetime.now(dt.UTC)
    )
    finding_assessments = (
        json.loads(args.finding_assessments.read_bytes()) if args.finding_assessments else None
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # ---- Phase 1: ingest ------------------------------------------------
    sources = [s for s in args.source.split(",") if s]
    if not sources:
        ap.error("at least one source is required")
    if len(sources) > 1:
        n = ing.ingest_many(sources, target_name=args.name, config_home=args.config_home)
    else:
        n = ing.ingest(sources[0], config_home=args.config_home)
    if args.name:
        n.target_name = args.name
    print(
        f"[run] ingested {len(n.findings)} finding(s) from {len(n.source_reports)} report(s)",
        file=sys.stderr,
    )

    # ---- Scope ----------------------------------------------------------
    scope = sc.build(
        targets_file=args.targets,
        contexts=args.context,
        namespaces=args.ns,
        images=[],
        containers=[],
        wasm=[],
        inferred=None,
    )
    if scope.environment != "lab":
        ap.error("unattended execution requires targets.yaml environment: lab")
    if scope.expires is not None and dt.date.today() > scope.expires:
        ap.error("the authorized engagement has expired")

    # ---- Credentials-needed (from operand setup) -----------------------
    creds = []
    cn_path = args.credentials_needed or str(out / "credentials-needed.json")
    try:
        if Path(cn_path).is_file():
            creds = json.loads(Path(cn_path).read_text())
            n_block = sum(1 for c in creds if c.get("blocks_validation"))
            print(
                f"[run] credentials-needed: {len(creds)} entries ({n_block} blocking)",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"[run] WARN: could not read {cn_path}: {e}", file=sys.stderr)

    # ---- Phase 2: plan --------------------------------------------------
    steps, chains = pl.build_plan(
        n,
        scope,
        replay=True,
        chained=not args.replay_only,
        novel=not args.replay_only,
        permit_destructive=args.destructive,
        credentials_needed=creds,
    )
    plan_path = out / f"{n.target_name}-attack-plan.yaml"
    pl.write_plan(steps, chains, plan_path, target_name=n.target_name, scope=scope)
    print(pl.summarize(steps), file=sys.stderr)
    print(f"[run] plan written: {plan_path}", file=sys.stderr)

    # ---- Preflight fingerprints ----------------------------------------
    fingerprints = []
    if hasattr(ex, "preflight"):
        try:
            fingerprints = ex.preflight(scope)  # type: ignore[attr-defined]
        except Exception as e:
            print(f"[run] WARN: preflight failed: {e}", file=sys.stderr)

    # ---- Phase 4: execute (Phase 3 review gate skipped — --auto) -------
    results, audit = ex.run(plan_path, scope, out, permit_destructive=args.destructive)
    by_verdict = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
    print(f"[run] execute complete: {by_verdict}", file=sys.stderr)

    # ---- Phase 5: report ------------------------------------------------
    flags = ["--auto"]
    if args.destructive:
        flags.append("--destructive")
    if args.replay_only:
        flags.append("--replay-only")
    approval = {
        "by": "automated (validate-operator-live/run_one.sh)",
        "at": dt.datetime.now(dt.UTC).isoformat(),
        "mode": "auto",
        "environment": "lab",
    }
    # catalogue-driven novel findings are recorded as steps;
    # AI-assisted pass is out of scope for unattended runs
    novel_findings = []

    doc = rp.build_validation_json(
        n,
        scope,
        results,
        chains,
        fingerprints,
        audit_path=(
            str(audit.path.relative_to(out)) if hasattr(audit, "path") else "validation-audit.jsonl"
        ),
        audit_sha256=audit.sha256() if hasattr(audit, "sha256") else "",
        flags=flags,
        approval=approval,
        novel_findings=novel_findings,
        target_attestation=attestation.model_dump(mode="json"),
        finding_assessments=finding_assessments,
    )
    jpath, _mpath = rp.write(doc, out, n.target_name)
    print(f"[run] report: {jpath}", file=sys.stderr)
    receipt = record_report(
        jpath,
        bindings,
        provenance,
        config_home=args.config_home,
        target_attestation=args.target_attestation,
        install_failure=args.install_failure,
    )

    # ---- Summary to stdout (machine-readable) --------------------------
    summary = {
        "target": n.target_name,
        "findings_ingested": len(n.findings),
        "steps": len(steps),
        "verdicts": by_verdict,
        "confirmed": by_verdict.get("confirmed", 0),
        "refuted": by_verdict.get("refuted", 0),
        "report": str(jpath),
        "recording": receipt,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
