"""Machine-validation recording doors on traust-core."""

from traust.cli.groups._registry import passthrough_op

VALIDATION: dict[str, object] = {
    "prepare": passthrough_op(
        "validation", "Prepare validation inputs for one or more findings.", "prepare"
    ),
    "plan": passthrough_op(
        "validation", "Publish an immutable proposed validation plan artifact.", "plan"
    ),
    "record": passthrough_op(
        "validation", "Record validation evidence with explicit source bindings.", "record"
    ),
}
