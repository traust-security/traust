"""``traust feeds fetch [--feed NAME|all]``: the `feeds_cache` asset's materializer, by hand or
from a runner. Snapshots the security feeds through traust-core; prints the JobResult, whose
outcome is the exit code."""

from __future__ import annotations

from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import answer, parser
from traust.cli.fetch_feeds import NAME as PRODUCT_DEFINITIONS
from traust.context import load
from traust.ops.materializers import MANUAL, FeedsCacheMaterializer

ALL = "all"


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "feeds", "fetch", "Snapshot the security feeds (EPSS, KEV, Red Hat CVEs, VEX index)."
    )
    ap.add_argument("--feed", default=ALL, help="one registry feed, or `all` (default)")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this refresh is for")
    args = ap.parse_args(argv)
    if args.feed == PRODUCT_DEFINITIONS:
        ap.error("product-definitions isn't a security feed: `traust feeds fetch-products`")
    core = load(args.config_home)
    core.register_feeds()  # NEED(core: feeds registered lazily)
    materializer = FeedsCacheMaterializer(core.services())
    return answer(
        materializer.materialize(
            AssetRequest(
                asset=materializer.asset,
                run_id=args.run_id,
                partition=None if args.feed == ALL else args.feed,
            )
        )
    )
