"""``traust triage …`` — the triage skill's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

TRIAGE: dict[str, object] = {
    "check": passthrough_op("triage_check", "Lint a triage's verdict citations."),
    "intake": passthrough_op("triage", "Record scanner output as an assessment.", "intake"),
    "prepare": passthrough_op("triage", "Print the triage input for an assessment.", "prepare"),
    "record": passthrough_op("triage", "Record a validated triage.", "record"),
    "render": passthrough_op("triage", "Render a triage as Markdown.", "render"),
}
