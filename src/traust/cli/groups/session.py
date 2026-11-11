"""``traust session …`` — skill sessions started headless for continuous-ops orders."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

SESSION: dict[str, object] = {
    "prepare": passthrough_op("session", "Stage an artifact-only skill's inputs.", "prepare"),
    "record": passthrough_op(
        "session", "Record the declared output of a staged session.", "record"
    ),
    "run": passthrough_op("session", "Start a skill session headless for a pack order.", "run"),
}
