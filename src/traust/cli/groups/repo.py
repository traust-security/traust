"""``traust repo …`` — repository content through core's checkout service."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REPO: dict[str, object] = {
    "checkout": passthrough_op("repo", "Print a commit's checked-out workspace path.", "checkout"),
}
