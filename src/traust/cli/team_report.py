"""``traust dashboard team-report``: generate-team-report's door on traust-core. Publishes the
findings rollup for products (and/or teams) and writes the `Executive-Summary-<…>` pair where the
user asks; core renders it (escaping, CSP) and stores nothing."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.insight import ViewFilter, ViewName

from traust.cli import _doors
from traust.cli._doors import parser, run, when
from traust.context import load
from traust.ops.materializers import write_view

_NOT_NAME = re.compile(r"[^A-Za-z0-9]+")


def main(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "team-report", "Write a product or team's executive-summary pair.")
    ap.add_argument("--product", action="append", default=[], help="a product slug (repeatable)")
    ap.add_argument("--team-id", action="append", default=[], type=uuid.UUID, help="(repeatable)")
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("--out", type=Path, required=True, help="the folder the pair is written to")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        if not (args.product or args.team_id):
            raise ValidationError("name a --product or a --team-id")
        services = load(args.config_home).services()
        products = _doors.products(services, args.product)
        scope = ViewFilter(
            product_ids=tuple(p.id for p in products),
            team_ids=tuple(args.team_id),
            as_of=when(args.as_of),
        )
        rendered = services.insight.publish(ViewName.FINDINGS_ROLLUP, scope)
        names = "-".join(_NOT_NAME.sub("-", p.name).strip("-") for p in products) or "Teams"
        written = write_view(rendered, args.out / f"Executive-Summary-{names}")
        return {
            "written": [str(p) for p in written],
            "model": rendered.model.model_dump(mode="json"),
        }

    return run(call)
