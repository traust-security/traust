"""Thin CLI adapters for insight projections, immutable reported snapshots and SLA policy."""

from __future__ import annotations

import json
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
from traust_core.v1.models.insight import (
    ExecutivePanel,
    ReportComparisonTarget,
    ReportSnapshot,
    ViewFilter,
    ViewName,
)

from traust.cli import _doors
from traust.cli._doors import parser, run, when
from traust.context import load
from traust.ops.materializers import write_view


def main(argv: list[str] | None = None) -> int:
    return _view(argv, capture=False)


def capture(argv: list[str] | None = None) -> int:
    return _view(argv, capture=True)


def _view(argv: list[str] | None, *, capture: bool) -> int:
    op = "capture" if capture else "view"
    ap = parser("dashboard", op, "Write an insight view, optionally retaining its reported bytes.")
    ap.add_argument("view", choices=[v.value for v in ViewName])
    _scope_flags(ap)
    ap.add_argument("--out", type=Path, required=True, help="the folder the view is written to")
    if capture:
        ap.add_argument("--note", required=True, help="counting methodology or change explanation")
    args = ap.parse_args(argv)
    _validate_inventory_options(ap, args)

    def call() -> dict[str, Any]:
        services = _core(ViewName(args.view), args).services()
        scope = _scope(services, args)
        if capture:
            snapshot = services.insight.capture(ViewName(args.view), scope, args.note)
            written = _write_snapshot(services.insight, snapshot, args.out)
            return {
                "written": [str(p) for p in written],
                "artifact_id": snapshot.artifact_id,
                "digest": snapshot.digest,
                "model": json.loads(snapshot.document.model_json),
            }
        rendered = services.insight.publish(ViewName(args.view), scope)
        written = write_view(rendered, args.out / rendered.stem, model=True)
        return {
            "written": [str(p) for p in written],
            "model": rendered.model.model_dump(mode="json"),
        }

    return run(call)


def _scope_flags(ap: Any) -> None:
    ap.add_argument("--product", action="append", default=[], help="a product slug (repeatable)")
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
    ap.add_argument("--compare-as-of", help="LoC comparison time, ISO time with a zone")
    ap.add_argument("--first-party-divisor", type=_decimal, help="LoC first-party estimate divisor")
    ap.add_argument("--reprice", action="store_true", help="spend: compare current model rates")
    ap.add_argument(
        "--workstation-spend", action="store_true", help="spend: enrich from local session evidence"
    )
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
    ap.add_argument("--by-segment", action="store_true", help="executive input-segment matrix")
    ap.add_argument(
        "--exclude-segment",
        action="append",
        default=None,
        help="exclude a segment from the executive matrix (default: ansible; repeatable)",
    )
    ap.add_argument(
        "--inputs-root",
        type=Path,
        help="override locations.inputs for the segment matrix",
    )
    ap.add_argument(
        "--sla-policy",
        type=Path,
        help="the sla view's policy for this run (default: the recorded one, else the pack's)",
    )
    ap.add_argument(
        "--pd-cache-dir",
        type=Path,
        help="SLA accountable contacts snapshot (default: locations.feeds_cache)",
    )
    ap.add_argument(
        "--invoice",
        type=Path,
        help="the spend view's billed amounts: CSV period,amount_usd[,note]",
    )


def _validate_inventory_options(ap: Any, args: Any) -> None:
    if (args.panel or args.by_segment) and args.view != ViewName.EXECUTIVE_SUMMARY:
        ap.error("--panel and --by-segment require the executive-summary view")
    if (args.exclude_segment is not None or args.inputs_root is not None) and args.view not in (
        ViewName.EXECUTIVE_SUMMARY,
        "repository-graph",
    ):
        ap.error("input inventory options require executive-summary or repository-graph")


def _decimal(value: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation:
        raise ValueError("expected a decimal number") from None


def _scope(services: Any, args: Any) -> ViewFilter:
    if args.view != ViewName.LOC and (
        args.compare_as_of is not None or args.first_party_divisor is not None
    ):
        raise ValidationError("--compare-as-of and --first-party-divisor require loc")
    if args.view != ViewName.SPEND and (args.reprice or args.workstation_spend):
        raise ValidationError("--reprice and --workstation-spend require spend")
    as_of, since = when(args.as_of), when(args.since)
    until = when(args.until) or as_of or datetime.now(UTC)
    return ViewFilter(
        product_ids=tuple(p.id for p in _doors.products(services, args.product)),
        team_ids=tuple(args.team_id),
        categories=tuple(args.category),
        as_of=as_of,
        window=None if since is None else TimeWindow(start=since, end=until),
        bucket=TimeBucket(args.bucket),
        artifact_id=args.artifact_id,
        assessment_id=args.assessment_id,
        report_stem=args.report_stem,
        executive_panels=tuple(ExecutivePanel(p) for p in args.panel),
        by_segment=args.by_segment,
        exclude_segments=tuple(
            ("ansible",) if args.exclude_segment is None else args.exclude_segment
        ),
        compare_as_of=when(args.compare_as_of),
        first_party_divisor=args.first_party_divisor,
        reprice_spend=args.reprice,
        workstation_spend=args.workstation_spend,
    )


def history(argv: list[str] | None = None) -> int:
    ap = parser(
        "dashboard", "history", "List as-reported snapshots; optionally render their values."
    )
    ap.add_argument("view", choices=[v.value for v in ViewName])
    _scope_flags(ap)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--out", type=Path, help="write a portable history report")
    args = ap.parse_args(argv)
    _validate_inventory_options(ap, args)

    def call() -> dict[str, Any]:
        insight_services = _core(ViewName(args.view), args).services()
        scope = _scope(insight_services, args)
        insight = insight_services.insight
        snapshots = insight.history(ViewName(args.view), scope, limit=args.limit)
        written = ()
        if args.out is not None:
            rendered = insight.report_history(ViewName(args.view), scope, limit=args.limit)
            written = write_view(rendered, args.out / rendered.stem, model=True)
        return {
            "snapshots": [
                {
                    "artifact_id": s.artifact_id,
                    "digest": s.digest,
                    "recorded_at": s.recorded_at,
                    "generated_at": s.document.generated_at,
                    "methodology_note": s.document.methodology_note,
                    "core_version": s.document.core_version,
                    "previous_artifact_id": s.document.previous_artifact_id,
                }
                for s in snapshots
            ],
            "written": [str(p) for p in written],
        }

    return run(call)


def read_report(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "read-report", "Read/export an immutable as-reported snapshot.")
    ap.add_argument("artifact_id", type=uuid.UUID)
    ap.add_argument("--out", type=Path, help="export the original report and bundle bytes")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        insight = load(args.config_home).services().insight
        snapshot = insight.snapshot(args.artifact_id)
        written = () if args.out is None else _write_snapshot(insight, snapshot, args.out)
        return {"snapshot": snapshot.model_dump(mode="json"), "written": [str(p) for p in written]}

    return run(call)


def compare(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "compare", "Compare reported values without rewriting saved reports.")
    ap.add_argument("artifact_id", type=uuid.UUID)
    ap.add_argument(
        "--against", choices=[v.value for v in ReportComparisonTarget], default="previous"
    )
    ap.add_argument("--out", type=Path, help="write a portable comparison report")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        insight = load(args.config_home).services().insight
        target = ReportComparisonTarget(args.against)
        if args.out is None:
            return insight.compare(args.artifact_id, target).model_dump(mode="json")
        rendered = insight.report_comparison(args.artifact_id, target)
        written = write_view(rendered, args.out / rendered.stem, model=True)
        return {
            "comparison": rendered.model.model_dump(mode="json"),
            "written": [str(p) for p in written],
        }

    return run(call)


def _write_snapshot(insight: Any, snapshot: ReportSnapshot, out: Path) -> tuple[Path, ...]:
    doc = snapshot.document
    out.mkdir(parents=True, exist_ok=True)
    exports = {"md": doc.markdown, "html": doc.html, "json": doc.model_json}
    if doc.csv is not None:
        exports["csv"] = doc.csv
    written = []
    for suffix, text in exports.items():
        path = out / f"{doc.stem}.{suffix}"
        path.write_bytes(text.encode("utf-8"))
        written.append(path)
    bundle = out / f"{snapshot.artifact_id}.snapshot.json"
    bundle.write_bytes(insight.snapshot_bytes(snapshot.artifact_id))
    return (*written, bundle)


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
    if args.pd_cache_dir is not None:
        core.product_contacts = core.product_definitions(args.pd_cache_dir)
    if args.inputs_root is not None:
        core.register_input_segments(args.inputs_root)
    if view is ViewName.FRESHNESS:
        # freshness reads the feed snapshots. NEED(core: feeds registered lazily by name)
        core.register_feeds()
    return core
