"""``traust products list|add|update``: corpus-intake's doors on traust-core.

list    every product with its corpus ownership and business unit
add     register a product (name = slug, label = display name) with its ownership;
        the same fields again is a no-op, different fields a ConflictError (use update)
update  change a registered product's label, ownership or business unit

The label lives on the product row (products.name); the registry subject's label stays unset.
NEED(contracts: corpus-registry subject `notes`): the subject has no notes field, so a BU
boundary cutting through a tree is flagged by the skill, not recorded.
"""

from __future__ import annotations

from typing import Any

from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.inventory import Product
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass

from traust.cli._doors import parser, run
from traust.context import load

OWNERSHIP = [o.value for o in OwnershipClass]


def _row(product: Product, subject: CorpusSubject | None) -> dict[str, Any]:
    return {
        "name": product.slug,
        "label": product.name,
        "ownership": None if subject is None else subject.ownership,
        "business_unit": None if subject is None else subject.business_unit,
        "product_id": product.id,
    }


def list_(argv: list[str] | None = None) -> int:
    args = parser("products", "list", "Every product with its corpus ownership.").parse_args(argv)

    def call() -> list[dict[str, Any]]:
        portfolio = load(args.config_home).services().portfolio
        doc = portfolio.corpus_registry()
        registry = CorpusRegistry() if doc is None else CorpusRegistry.of(doc)
        out, page = [], PageRequest()
        while True:
            got = portfolio.list_products(page)
            out += [_row(p, registry.subject(str(p.id))) for p in got.items]
            if got.next is None:
                return out
            page = PageRequest(cursor=got.next)

    return run(call)


def add(argv: list[str] | None = None) -> int:
    ap = parser("products", "add", "Register a product with its corpus ownership.")
    ap.add_argument("name", help="the product slug: letters, digits, . _ - only")
    ap.add_argument("--label", required=True, help="the display name")
    ap.add_argument("--ownership", required=True, choices=OWNERSHIP)
    ap.add_argument("--business-unit", required=True)
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        return _row(
            *load(args.config_home)
            .services()
            .portfolio.register_corpus_product(
                ProductSlug.parse(args.name),
                args.label,
                OwnershipClass(args.ownership),
                args.business_unit,
            )
        )

    return run(call)


def update(argv: list[str] | None = None) -> int:
    ap = parser("products", "update", "Change a registered product's label or ownership.")
    ap.add_argument("name")
    ap.add_argument("--label")
    ap.add_argument("--ownership", choices=OWNERSHIP)
    ap.add_argument("--business-unit")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        return _row(
            *load(args.config_home)
            .services()
            .portfolio.update_corpus_product(
                ProductSlug.parse(args.name),
                label=args.label,
                ownership=None if args.ownership is None else OwnershipClass(args.ownership),
                business_unit=args.business_unit,
            )
        )

    return run(call)
