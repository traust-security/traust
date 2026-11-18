"""``traust db …`` — the store's db-contract channel, on the operator's command."""

from __future__ import annotations

from traust.cli.groups._registry import OpSpec, passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    (
        "upgrades",
        "db_upgrades",
        "Plan and apply the store's db-contract upgrades (names, hashes, destructive reasons).",
    ),
)

DB: dict[str, OpSpec] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
