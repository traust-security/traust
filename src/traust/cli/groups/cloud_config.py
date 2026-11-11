"""``traust cloud-config …``: cloud-config-audit's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

CLOUD_CONFIG: dict[str, object] = {
    "run": passthrough_op("cloud_config", "Scan a checkout with the pinned Checkov.", "run_"),
    "check": passthrough_op("cloud_config", "Gate a cloud-config audit report.", "check"),
    "record": passthrough_op("cloud_config", "Record a gated cloud-config audit.", "record"),
}
