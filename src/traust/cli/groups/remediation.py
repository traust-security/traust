"""``traust remediation …``: the remediation loop's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REMEDIATION: dict[str, object] = {
    "next": passthrough_op("remediation", "A repository's next work item to patch.", "next_"),
    "prepare": passthrough_op("remediation", "What a patch of one work item fixes.", "prepare"),
    "verify-sweep": passthrough_op(
        "remediation", "Which repositories are worth re-verifying.", "verify_sweep"
    ),
    "verify-prepare": passthrough_op(
        "remediation", "What a verification of one work item re-checks.", "verify_prepare"
    ),
    "verify-differential": passthrough_op(
        "remediation", "A work item's backing scanner on a patched commit.", "verify_differential"
    ),
    "verify-record": passthrough_op(
        "remediation", "Record a validated verification report.", "verify_record"
    ),
    "verifications": passthrough_op(
        "remediation", "A repository's recorded verifications.", "verifications"
    ),
}
