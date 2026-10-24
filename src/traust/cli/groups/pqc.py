"""``traust pqc …`` — the pqc-readiness skill's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

PQC: dict[str, object] = {
    "record": passthrough_op("pqc", "Record a commit's pqc-facts or readiness report.", "record"),
    "check": passthrough_op("pqc", "Check a readiness report against its gate.", "check"),
    "prepare": passthrough_op("pqc", "What Layer 2 scores from: facts, route, prior.", "prepare"),
    "summary": passthrough_op("pqc", "Latest readiness per commit, rolled up.", "summary"),
    "blockers": passthrough_op(
        "pqc", "Remediations of each commit's latest readiness.", "blockers"
    ),
    "dashboard": passthrough_op("pqc", "Write the PQC view as an md/html pair.", "dashboard"),
}
