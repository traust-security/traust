"""``traust feeds …`` — security feed snapshots and the product-definitions cache."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("fetch", "feeds_fetch", "Snapshot the security feeds (the feeds_cache asset)."),
    ("fetch-products", "fetch_feeds", "Pull-through cache for the product-definitions registry."),
    (
        "reconcile-cve-provenance",
        "reconcile_cve_provenance",
        "Match recorded code audits to later CVEs (dry-run unless --apply).",
    ),
)

FEEDS: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
