"""``traust config …`` — the config home's one file, ``traust.yaml``."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

CONFIG: dict[str, object] = {
    "migrate": passthrough_op(
        "config_migrate", "Write one traust.yaml from an old config home; list what's left."
    ),
}
