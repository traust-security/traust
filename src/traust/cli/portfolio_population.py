"""``traust portfolio population``: census's report population on traust-core.

Every registered repository, what was assessed by ``--as-of`` (newest default-line assessment,
default-line and branch re-audit counts per kind) and which were never assessed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter

from traust.cli._doors import parser, run
from traust.context import load


def _as_of(raw: str) -> datetime:
    when = datetime.fromisoformat(raw)
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "population", "What the registered repositories had assessed.")
    ap.add_argument("--kind", choices=[k.value for k in AssessmentKind], help="default: any")
    ap.add_argument("--status", help="only assessments with this status (default: any)")
    ap.add_argument("--as-of", type=_as_of, help="ISO time (default: now; naive is UTC)")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load(args.config_home).services()
        urls = {
            r.id: r.url
            for r in every_item(
                lambda page: services.portfolio.list_repositories(RepositoryFilter(), page)
            )
        }
        kind = None if args.kind is None else AssessmentKind(args.kind)
        population = services.assessment.population(
            args.as_of or datetime.now(UTC),
            AssessmentFilter(kind=kind, status=args.status),
            list(urls),
        )
        return {
            "as_of": population.as_of.isoformat(),
            "repositories": len(urls),
            "rows": [
                {
                    "repository": urls[row.repository_id],
                    "kind": row.kind,
                    "latest": None
                    if row.latest is None
                    else {
                        "assessment_id": str(row.latest.id),
                        "status": row.latest.status,
                        "occurred_at": row.latest.occurred_at.isoformat(),
                    },
                    "default_line": row.default_line,
                    "branches": row.branches,
                }
                for row in population.rows
            ],
            "never_assessed": [urls[i] for i in population.never_assessed_repository_ids],
        }

    return run(call)
