"""``traust findings …``: track-findings' doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

FINDINGS: dict[str, object] = {
    "find": passthrough_op("findings", "Find the recorded finding a report entry is.", "find"),
    "correction-request": passthrough_op(
        "findings", "Queue an immutable corrected claim for human review.", "correction_request"
    ),
    "rebaseline": passthrough_op(
        "findings", "Accept and apply a stored corrected claim.", "rebaseline"
    ),
    "claim": passthrough_op("findings", "Read an accepted corrected claim.", "claim"),
    "status": passthrough_op("findings", "Show one finding's current state.", "status"),
    "history": passthrough_op("findings", "List every decision on a finding.", "history"),
    "baseline": passthrough_op("findings", "A repository's findings at a time.", "baseline"),
    "decide": passthrough_op("findings", "Record your statement on a finding.", "decide"),
    "import": passthrough_op("findings", "Import statements from an MR or ticket.", "import_"),
    "queue": passthrough_op("findings", "Statements waiting for a person.", "queue"),
    "review-cases": passthrough_op(
        "findings", "Read paged full review cards and evidence.", "review_cases"
    ),
    "request": passthrough_op("findings", "Request human review of a finding.", "request"),
    "record": passthrough_op("findings", "Record a verified human's judgement.", "record"),
    "apply": passthrough_op("findings", "Apply reviewed JSON or Markdown answers.", "apply"),
    "confirm": passthrough_op("findings", "Confirm a queued statement.", "confirm"),
    "reject": passthrough_op(
        "findings", "Reject a queued proposal with your judged decision.", "reject"
    ),
    "refuted": passthrough_op("findings", "A repository's false positives.", "refuted"),
    "surfaces": passthrough_op("findings", "Review-surface coverage.", "surfaces"),
    "sarif": passthrough_op("findings", "Export findings as SARIF.", "sarif"),
    "tickets": passthrough_op("findings", "Jira tickets on a repository's findings.", "tickets"),
    "summary": passthrough_op("findings", "Findings counted by state per group.", "summary"),
    "timeline": passthrough_op("findings", "Findings replayed by day, week or month.", "timeline"),
    "verified-fix-mtta": passthrough_op(
        "findings", "Verified-fix MTTA grouped by original severity.", "verified_fix_mtta"
    ),
}
