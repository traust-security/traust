"""``traust isolation …``: isolation-review's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

ISOLATION: dict[str, object] = {
    "repos": passthrough_op("isolation", "The repositories a service (product) ships.", "repos"),
}
