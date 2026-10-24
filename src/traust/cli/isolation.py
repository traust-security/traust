"""``traust isolation repos``: isolation-review's repo set on traust-core, the commits a service
(a product) ships, grouped by repository."""

from __future__ import annotations

from datetime import UTC, datetime

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.values import ProductSlug

from traust.cli._doors import parser, run
from traust.context import load_services


def repos(argv: list[str] | None = None) -> int:
    ap = parser("isolation", "repos", "The repositories a service (product) ships.")
    ap.add_argument("service", help="the service's product slug")
    args = ap.parse_args(argv)

    def call() -> dict:
        portfolio = load_services(args.config_home).portfolio
        product = portfolio.find_product(ProductSlug(args.service))
        if product is None or product.id is None:
            raise NotFoundError(f"{args.service} is not a registered product")
        shipped: dict[str, list[str]] = {}
        for ref in portfolio.list_product_refs(product.id):
            assert ref.id is not None
            _, repo = portfolio.inventory.resolve(ref.id)
            shipped.setdefault(repo.url, []).append(ref.sha)
        read_at = datetime.now(UTC).isoformat(timespec="seconds")
        return {
            "service": product.slug,
            "graph_ref": f"traust-core product {product.slug} @ {read_at}",
            "repos": [{"url": url, "shas": sorted(shas)} for url, shas in sorted(shipped.items())],
        }

    return run(call)
