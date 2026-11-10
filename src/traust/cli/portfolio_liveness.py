"""``traust portfolio liveness``: the census view of Core-owned availability evidence."""

from __future__ import annotations

from collections import Counter

from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "liveness", "Each repository's last observed forge availability.")
    args = ap.parse_args(argv)

    def call() -> dict[str, object]:
        services = load(args.config_home).services()
        rows = tuple(every_item(lambda page: services.portfolio.liveness(RepositoryFilter(), page)))
        return {
            "counts": dict(sorted(Counter(row.status.value for row in rows).items())),
            "repos": {
                row.url: row.model_dump(
                    mode="json", exclude_none=True, exclude={"repository_id", "url"}
                )
                for row in rows
            },
        }

    return run(call)
