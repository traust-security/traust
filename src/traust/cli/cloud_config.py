"""``traust cloud-config run|check|record``: the cloud-config-audit skill's doors on traust-core.

run     the pinned Checkov over a checkout, offline, as the facts JSON the audit cites
check   the audit report's gate: its schema, then every disposition cites and explains
record  a gated audit report as a cloud-config assessment of the commit, with its findings
        and the audit's disposition on each as a decision
"""

from __future__ import annotations

import argparse
import uuid
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.models.artifacts import CloudConfigAuditArtifact
from traust_core.v1.models.cloud_config import CHECKOV, CloudConfigFacts
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from traust.cli import _doors
from traust.cli._doors import add_branch_arg, add_run_order_arg, parser, register_commit, run
from traust.context import load


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    return parser("cloud-config", op, about)


def run_(argv: list[str] | None = None) -> int:
    ap = _parser("run", "Scan a checkout with the pinned Checkov, offline, into the facts JSON.")
    ap.add_argument("--target-dir", type=Path, required=True, help="IaC checkout (read-only)")
    ap.add_argument(
        "--framework",
        default=None,
        help="comma-separated Checkov framework filter (default: all except secrets)",
    )
    ap.add_argument("--out", type=Path, help="default: ./<target>-cloud-facts.json")
    args = ap.parse_args(argv)

    def call() -> dict:
        facts = (
            load(args.config_home)
            .services()
            .assessment.run_tools(args.target_dir, [CHECKOV])
            .data(CHECKOV, CloudConfigFacts)
        )
        if args.framework:
            facts = facts.restrict([f.strip() for f in args.framework.split(",") if f.strip()])
        out = args.out or Path.cwd() / f"{facts.target}-cloud-facts.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(facts.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return {
            "wrote": str(out),
            "snapshot_id": facts.snapshot_id,
            "counts": facts.counts.model_dump(mode="json"),
            "notes": dict(facts.notes),
            "gaps": list(facts.gaps),
        }

    return run(call)


def check(argv: list[str] | None = None) -> int:
    ap = _parser("check", "Gate an audit report: schema, then cited and explained dispositions.")
    ap.add_argument("report", type=Path, help="the <target>-cloud-config-audit.json")
    args = ap.parse_args(argv)
    failed = False

    def call() -> str:
        nonlocal failed
        doc = CloudConfigAuditArtifact.parse(args.report.read_bytes())
        violations = load(args.config_home).services().assessment.check_audit(doc).violations
        failed = bool(violations)
        lines = [f"ERROR {v.item}: {v.message}" for v in violations]
        return "\n".join([*lines, f"{len(violations)} errors"])

    rc = run(call)
    return 1 if rc == 0 and failed else rc


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a gated audit report as an assessment of the scanned commit.")
    ap.add_argument("report", type=Path, help="the <target>-cloud-config-audit.json")
    ap.add_argument("--repo-url", required=True, help="https URL of the scanned repository")
    ap.add_argument("--sha", required=True, help="the scanned commit (the facts' target_head)")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    add_branch_arg(ap)
    add_run_order_arg(ap)
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = CloudConfigAuditArtifact.parse(args.report.read_bytes())
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        # The audit's run time makes a re-record the same run; a report without one is a new run.
        when = _doors.when(doc.metadata.generated_at) or datetime.now(UTC)
        assessment, decisions = services.assessment.record_audit(
            doc,
            ref.id,
            Provenance(
                run_id=args.run_id or uuid.uuid4(),
                source=SourceType.VULN_SCAN_REPORT,
                occurred_at=when,
            ),
            run_order_id=args.run_id,
        )
        return {
            "assessment_id": assessment.id,
            "status": assessment.status,
            "decisions": len(decisions),
            "needs_review": sum(d.validity is None for d in decisions),
        }

    return run(call)
