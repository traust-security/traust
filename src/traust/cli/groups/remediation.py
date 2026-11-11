"""``traust remediation …``: the remediation loop's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REMEDIATION: dict[str, object] = {
    "open": passthrough_op("remediation", "Open a work item for confirmed findings.", "open_"),
    "work-items": passthrough_op("remediation", "A repository's work items.", "work_items"),
    "next": passthrough_op("remediation", "A repository's next work item to patch.", "next_"),
    "prepare": passthrough_op("remediation", "What a patch of one work item fixes.", "prepare"),
    "fork": passthrough_op("remediation", "The private fork fixes are pushed to.", "fork"),
    "progress": passthrough_op("remediation", "Move a work item to a status.", "progress"),
    "mutation-evidence": passthrough_op(
        "remediation", "A mewt campaign as one patch_evidence item.", "mutation_evidence_"
    ),
    "assemble": passthrough_op(
        "remediation", "Draft a work item's report from its worktree.", "assemble"
    ),
    "candidates": passthrough_op(
        "remediation", "A product's findings no work item covers yet.", "candidates"
    ),
    "property-evidence": passthrough_op(
        "remediation",
        "A property test's two runs as one patch_evidence item.",
        "property_evidence_",
    ),
    "record": passthrough_op("remediation", "Record a validated remediation report.", "record"),
    "fleet-submit": passthrough_op(
        "remediation", "A fleet fix's run orders, held for approval.", "fleet_submit"
    ),
    "fleet-approve": passthrough_op(
        "remediation", "Approve fleet-fix run orders (a verified person).", "fleet_approve"
    ),
    "fleet-claim": passthrough_op(
        "remediation", "Apply the next approved fleet-fix order (diff only).", "fleet_claim"
    ),
    "fleet-record": passthrough_op(
        "remediation", "Record a fleet-fix spec once its goldens pass.", "fleet_record"
    ),
    "fleet-targets": passthrough_op(
        "remediation", "The repositories a fleet fix targets.", "fleet_targets"
    ),
    "verify-sweep": passthrough_op(
        "remediation", "Which repositories are worth re-verifying.", "verify_sweep"
    ),
    "verify-prepare": passthrough_op(
        "remediation", "What a verification of one work item re-checks.", "verify_prepare"
    ),
    "verify-differential": passthrough_op(
        "remediation", "The findings' backing scanner on a patched commit.", "verify_differential"
    ),
    "verify-record": passthrough_op(
        "remediation", "Record a validated verification report.", "verify_record"
    ),
    "verifications": passthrough_op(
        "remediation", "A repository's recorded verifications.", "verifications"
    ),
}
