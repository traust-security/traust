"""``traust assessments …``: the audit skills' doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

ASSESSMENTS: dict[str, object] = {
    "prepare": passthrough_op(
        "assessments", "What an assessment of one commit starts from.", "prepare"
    ),
    "coverage": passthrough_op(
        "assessments", "What the latest audits say they could not examine.", "coverage"
    ),
}
