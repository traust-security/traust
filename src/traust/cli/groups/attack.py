"""``traust attack …``: the pack's pinned ATT&CK release."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

ATTACK: dict[str, object] = {
    "validate": passthrough_op("attack", "Check ATT&CK technique ids against the pinned release."),
}
