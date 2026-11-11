"""``traust products …``: corpus-intake's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

PRODUCTS: dict[str, object] = {
    "list": passthrough_op("products", "Every product with its corpus ownership.", "list_"),
    "add": passthrough_op("products", "Register a product with its corpus ownership.", "add"),
    "update": passthrough_op("products", "Change a product's label or ownership.", "update"),
}
