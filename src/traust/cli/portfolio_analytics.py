"""Read-only portfolio proposals, fleet IaC discovery and source-organization navigation."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from traust_core.v1.models.insight import ViewFilter, ViewName

from traust.cli import _doors
from traust.context import load
from traust.ops.materializers import write_view


def _publish(view: ViewName, operation: str, argv: list[str] | None) -> int:
    ap = _doors.parser("portfolio", operation, __doc__)
    ap.add_argument("--product", action="append", default=[], help="product slug (repeatable)")
    ap.add_argument("--team-id", action="append", default=[], type=UUID, help="repeatable")
    ap.add_argument("--as-of", help="assessment cutoff, ISO timestamp with a time zone")
    ap.add_argument("--out", type=Path, help="write JSON, Markdown and HTML into this directory")
    if view is ViewName.CROWN_JEWEL_DRAFT:
        ap.add_argument(
            "--tier1-size", type=int, default=20, help="pilot size, 1–100 (default: 20)"
        )
    args = ap.parse_args(argv)

    def call() -> object:
        services = load(args.config_home).services()
        scope = ViewFilter(
            product_ids=tuple(p.id for p in _doors.products(services, args.product)),
            team_ids=tuple(args.team_id),
            as_of=_doors.when(args.as_of),
            crown_jewel_tier1_size=args.tier1_size if view is ViewName.CROWN_JEWEL_DRAFT else 20,
        )
        rendered = services.insight.publish(view, scope)
        if args.out is None:
            return rendered.model.model_dump_json(indent=2)
        written = write_view(rendered, args.out / rendered.stem, model=True)
        return {
            "written": [str(path) for path in written],
            "model": rendered.model.model_dump(mode="json"),
        }

    return _doors.run(call)


def crown_jewel_draft(argv: list[str] | None = None) -> int:
    return _publish(ViewName.CROWN_JEWEL_DRAFT, "crown-jewel-draft", argv)


def iac_census(argv: list[str] | None = None) -> int:
    return _publish(ViewName.IAC_CENSUS, "iac-census", argv)


def org_index(argv: list[str] | None = None) -> int:
    return _publish(ViewName.ORGANIZATION_INDEX, "org-index", argv)
