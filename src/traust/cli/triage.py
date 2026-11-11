"""``traust triage intake|prepare|record|render``: the triage skill's doors on traust-core.

intake   third-party scanner output (SARIF, Dependabot, govulncheck) as an assessment of a commit
prepare  everything a triage of one assessment judges (findings, locations, precedents), as JSON
record   a validated triage: decisions per verdict, review items where a person must look
render   a triage as Markdown, a projection of the JSON
"""

from __future__ import annotations

import argparse
import uuid
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import CandidateFormat
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import add_branch_arg, parser, register_commit, run
from traust.context import load


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    return parser("triage", op, about)


def intake(argv: list[str] | None = None) -> int:
    ap = _parser("intake", "Record third-party scanner output as an assessment of a commit.")
    ap.add_argument("scan", type=Path, help="the scanner output file")
    ap.add_argument("--format", required=True, choices=[f.value for f in CandidateFormat])
    ap.add_argument("--repo-url", required=True, help="https URL of the scanned repository")
    ap.add_argument("--sha", required=True, help="the scanned commit")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    ap.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed SARIF results as unjudged review candidates (SARIF only).",
    )
    add_branch_arg(ap)
    args = ap.parse_args(argv)
    if args.include_suppressed and args.format != CandidateFormat.SARIF.value:
        ap.error("--include-suppressed requires --format sarif")

    def call() -> dict:
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        when = datetime.now(UTC)
        assessment, taken = services.assessment.record_scan(
            ref.id,
            args.scan.read_bytes(),
            CandidateFormat(args.format),
            Provenance(run_id=uuid.uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=when),
            include_suppressed=args.include_suppressed,
        )
        found, new = len(taken.findings), len(taken.created)
        return {"assessment_id": assessment.id, "findings": found, "new": new}

    return run(call)


def prepare(argv: list[str] | None = None) -> int:
    ap = _parser("prepare", "Print the triage input for one assessment as JSON.")
    ap.add_argument("assessment_id", type=uuid.UUID)
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        decisions = load(args.config_home).services().findings.decisions
        prepared = decisions.prepare(args.assessment_id)
        text = prepared.model_dump_json(indent=2)
        if args.out is None:
            return text
        args.out.write_text(text + "\n", encoding="utf-8")
        return None

    return run(call)


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a validated triage of one assessment.")
    ap.add_argument("assessment_id", type=uuid.UUID)
    ap.add_argument("triage", type=Path, help="the validated triage JSON")
    ap.add_argument("--repo", type=Path, required=True, help="target repo checkout (read-only)")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = TriageArtifact.parse(args.triage.read_bytes())
        when = datetime.now(UTC)
        made = (
            load(args.config_home)
            .services()
            .findings.decisions.record(
                args.assessment_id,
                doc,
                Provenance(run_id=uuid.uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=when),
                args.repo,
            )
        )
        return {
            "decisions": len(made),
            "awaiting_countersign": sum(
                d.validity == "false_positive" and not d.auto_accept_tier for d in made
            ),
            "auto_accepted": sum(d.auto_accept_tier for d in made),
            "baseline_assessment_id": args.assessment_id,
            "records": [
                {
                    "decision_id": decision.id,
                    "assessment_id": decision.assessment_id,
                    "artifact_id": decision.artifact_id,
                    "finding_id": decision.finding_id,
                }
                for decision in made
            ],
        }

    return run(call)


def render(argv: list[str] | None = None) -> int:
    ap = _parser("render", "Render a validated triage JSON as Markdown.")
    ap.add_argument("triage", type=Path)
    ap.add_argument("-o", "--out", type=Path, help="write the Markdown here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        doc = TriageArtifact.parse(args.triage.read_bytes())
        markdown = load(args.config_home).services().findings.decisions.render(doc).decode()
        if args.out is None:
            return markdown
        args.out.write_text(markdown, encoding="utf-8")
        return None

    return run(call)
