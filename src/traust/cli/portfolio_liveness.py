"""``traust portfolio liveness``: the census artifact from recorded forge availability."""

from __future__ import annotations

from collections import Counter
from typing import Any

from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "liveness", "Each repository's last observed forge availability.")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load(args.config_home).services()
        repos = {
            row.url: row.model_dump(
                mode="json", exclude={"url", "repository_id"}, exclude_none=True
            )
            for row in every_item(
                lambda page: services.portfolio.liveness(RepositoryFilter(), page)
            )
        }
        counts = Counter(entry["status"] for entry in repos.values())
        return {"counts": dict(sorted(counts.items())), "repos": dict(sorted(repos.items()))}

    return run(call)
