"""``traust tools …``: the one door over traust-core's tool registry."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

TOOLS: dict[str, object] = {
    "list": passthrough_op(
        "tools", "Every registered tool: readiness, version, database.", "list_"
    ),
    "run": passthrough_op("tools", "Run one registered tool over one target.", "run_"),
}
