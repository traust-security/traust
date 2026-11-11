"""``traust ledger …`` — the ledger audit and the doc-variance register (ledger events are
core's `LedgerService`)."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("audit", "ledger_audit", "Verify every ledger layer (the ledger_audit asset)."),
    (
        "doc-variance",
        "emit_doc_variance",
        "Doc-variance register writer (doc-variance lane — the ONLY writer).",
    ),
)

LEDGER: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
