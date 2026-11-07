"""``traust dashboard view``: publish one traust-core insight view for a scope and write its
`<stem>.{md,html,json}`; core builds and renders it and stores nothing.

``traust dashboard sla-policy``: record the deployment's SLA policy, the SLA view's from then on
over the security pack's default."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import SlaPolicyArtifact
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewName

from traust.cli import _doors
from traust.cli._doors import parser, run, when
from traust.cli.pqc import _fragment
from traust.context import load
from traust.ops.materializers import write_view


def main(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "view", "Write one insight view (e.g. findings-trend, program).")
    ap.add_argument("view", choices=[v.value for v in ViewName])
    _scope_flags(ap)
    ap.add_argument("--out", type=Path, required=True, help="the folder the view is written to")
    args = ap.parse_args(argv)
    if args.panel and args.view != ViewName.EXECUTIVE_SUMMARY:
        ap.error("--panel requires the executive-summary view")

    def call() -> dict[str, Any]:
        services = _core(ViewName(args.view), args).services()
        scope = _scope(services, args)
        rendered = services.insight.publish(ViewName(args.view), scope)
        written = write_view(rendered, args.out / rendered.stem, model=True)
        return {
            "written": [str(p) for p in written],
            "model": rendered.model.model_dump(mode="json"),
        }

    return run(call)


def _scope_flags(ap: Any) -> None:
    ap.add_argument("--product", action="append", default=[], help="a product slug (repeatable)")
    ap.add_argument(
        "--repository-ref-id",
        action="append",
        type=uuid.UUID,
        help="a registered commit ID; omitted means all (repeatable)",
    )
    ap.add_argument(
        "--chokepoint",
        action="append",
        default=[],
        type=_fragment,
        metavar="URL_FRAGMENT",
        help="a PQC worklist priority repository URL fragment (repeatable)",
    )
    ap.add_argument("--team-id", action="append", default=[], type=uuid.UUID, help="(repeatable)")
    ap.add_argument(
        "--category",
        action="append",
        default=[],
        help="a category label to scope to, e.g. authorization (repeatable)",
    )
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("--since", help="window start, ISO time with a zone")
    ap.add_argument("--until", help="window end (default: --as-of, else now)")
    ap.add_argument("--bucket", choices=[b.value for b in TimeBucket], default="month")
    ap.add_argument(
        "--compare-as-of",
        help="refused: traust-core's loc view reads only the latest measurement",
    )
    ap.add_argument("--first-party-divisor", type=_decimal, help="LoC first-party estimate divisor")
    ap.add_argument(
        "--artifact-id", type=uuid.UUID, help="the document a one-item view renders (oscal)"
    )
    ap.add_argument("--assessment-id", type=uuid.UUID, help="container report-family anchor")
    ap.add_argument("--report-stem", help="full container report stem: <image>-container-audit")
    ap.add_argument(
        "--panel",
        action="append",
        default=[],
        choices=[p.value for p in ExecutivePanel],
        help="compose a domain panel in executive-summary (repeatable)",
    )
    ap.add_argument(
        "--sla-policy",
        type=Path,
        help="the sla view's policy for this run (default: the recorded one, else the pack's)",
    )
    ap.add_argument(
        "--invoice",
        type=Path,
        help="the spend view's billed amounts: CSV period,amount_usd[,note]",
    )


def _decimal(value: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation:
        raise ValueError("expected a decimal number") from None


def _scope(services: Any, args: Any) -> ViewFilter:
    if args.view == ViewName.PQC_WORKLIST:
        unsupported = (
            "team_id",
            "category",
            "as_of",
            "since",
            "until",
            "compare_as_of",
            "first_party_divisor",
            "artifact_id",
            "assessment_id",
            "report_stem",
            "panel",
            "sla_policy",
            "invoice",
        )
        for flag in unsupported:
            if getattr(args, flag):
                raise ValidationError(
                    f"--{flag.replace('_', '-')} is not supported by pqc-worklist"
                )
    if args.compare_as_of is not None:
        # traust-core's LocView reads the latest measurement only: no historical LoC read yet.
        raise ValidationError("--compare-as-of: the loc view has no historical comparison")
    if args.view != ViewName.LOC and args.first_party_divisor is not None:
        raise ValidationError("--first-party-divisor requires loc")
    as_of, since = when(args.as_of), when(args.since)
    until = when(args.until) or as_of or datetime.now(UTC)
    return ViewFilter(
        product_ids=tuple(p.id for p in _doors.products(services, args.product)),
        repository_ref_ids=(
            None if args.repository_ref_id is None else tuple(args.repository_ref_id)
        ),
        pqc_chokepoints=tuple(args.chokepoint),
        team_ids=tuple(args.team_id),
        categories=tuple(args.category),
        as_of=as_of,
        window=None if since is None else TimeWindow(start=since, end=until),
        bucket=TimeBucket(args.bucket),
        artifact_id=args.artifact_id,
        assessment_id=args.assessment_id,
        report_stem=args.report_stem,
        executive_panels=tuple(ExecutivePanel(p) for p in args.panel),
        first_party_divisor=args.first_party_divisor,
    )


def sla_policy(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "sla-policy", "Record the deployment's SLA policy.")
    ap.add_argument("policy", type=Path, help="an sla-policy document (YAML)")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        doc = SlaPolicyArtifact.from_document(yaml.safe_load(args.policy.read_text()))
        insight = load(args.config_home).services().insight
        return {"artifact_id": insight.record_sla_policy(doc, _doors.interactive()).artifact_id}

    return run(call)


def _core(view: ViewName, args: Any) -> Context:
    core = load(args.config_home, sla_policy=args.sla_policy, invoices=args.invoice)
    if view is ViewName.FRESHNESS:
        # freshness reads the feed snapshots. NEED(core: feeds registered lazily by name)
        core.register_feeds()
    return core
