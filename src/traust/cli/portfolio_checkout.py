"""``traust portfolio checkout-refresh`` / ``mirror-evict``: the git mirror cache's pack assets
(`repo_checkout_refresh`, `mirror_evict`), by hand or from a runner. Each prints the JobResult;
the exit code is its outcome."""

from __future__ import annotations

from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import answer, parser
from traust.context import load
from traust.ops.materializers import (
    MANUAL,
    MirrorEvictMaterializer,
    RepoCheckoutRefreshMaterializer,
)


def refresh(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "checkout-refresh",
        "Fetch a repository's git mirror to its observed head, when repo_state says it moved.",
    )
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this refresh is for")
    args = ap.parse_args(argv)
    core = load(args.config_home)
    with core.repository_observation() as observation:
        materializer = RepoCheckoutRefreshMaterializer(
            core.services(), observation.query, core.config.forge_hosts
        )
        return answer(
            materializer.materialize(
                AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.repo)
            )
        )


def evict(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "mirror-evict", "Drop git mirrors no checkout has touched in 30 days.")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this eviction is for")
    args = ap.parse_args(argv)
    core = load(args.config_home)
    materializer = MirrorEvictMaterializer(core.services())
    return answer(
        materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
    )
