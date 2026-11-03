"""``traust products list|add|update``: corpus-intake's doors on traust-core.

list    every product with its corpus ownership and business unit
add     register a product (name = slug, label = display name) with its ownership;
        the same fields again is a no-op, different fields a ConflictError (use update)
update  change a registered product's label, ownership or business unit

The label lives on the product row (products.name); the registry subject's label stays unset.
Caveats are subject-labelled entries in the existing corpus registry document note.
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


def _row(
    product: Product, subject: CorpusSubject | None, note: str | None = None
) -> dict[str, Any]:
    return {
        "name": product.slug,
        "label": product.name,
        "ownership": None if subject is None else subject.ownership,
        "business_unit": None if subject is None else subject.business_unit,
        "product_id": product.id,
        "note": note,
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
            out += [
                _row(p, registry.subject(str(p.id)), registry.subject_note(str(p.id)))
                for p in got.items
            ]
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
    ap.add_argument("--note", help="boundary caveat, retained in CorpusRegistry.note")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        portfolio = load(args.config_home).services().portfolio
        product, subject = portfolio.register_corpus_product(
            ProductSlug.parse(args.name),
            args.label,
            OwnershipClass(args.ownership),
            args.business_unit,
            note=args.note,
        )
        doc = portfolio.corpus_registry()
        assert doc is not None
        registry = CorpusRegistry.of(doc)
        return _row(product, subject, registry.subject_note(str(product.id)))

    return run(call)


def update(argv: list[str] | None = None) -> int:
    ap = parser("products", "update", "Change a registered product's label or ownership.")
    ap.add_argument("name")
    ap.add_argument("--label")
    ap.add_argument("--ownership", choices=OWNERSHIP)
    ap.add_argument("--business-unit")
    ap.add_argument("--note", help="replace the boundary caveat; empty text clears it")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        portfolio = load(args.config_home).services().portfolio
        product, subject = portfolio.update_corpus_product(
            ProductSlug.parse(args.name),
            label=args.label,
            ownership=None if args.ownership is None else OwnershipClass(args.ownership),
            business_unit=args.business_unit,
            note=args.note,
        )
        doc = portfolio.corpus_registry()
        registry = CorpusRegistry() if doc is None else CorpusRegistry.of(doc)
        return _row(product, subject, registry.subject_note(str(product.id)))

    return run(call)
