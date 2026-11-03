"""``traust dashboard …`` — current projections and immutable as-reported report history."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REFRESH = passthrough_op(
    "refresh_dashboards",
    "Rebuild every deterministic dashboard in dependency order.",
)

TEAM_REPORT = passthrough_op(
    "team_report", "Write a product or team's executive-summary pair.", "main"
)

VIEW = passthrough_op("dashboard_view", "Write one insight view for a scope.", "main")

SLA_POLICY = passthrough_op("dashboard_view", "Record the deployment's SLA policy.", "sla_policy")

CAPTURE = passthrough_op("dashboard_view", "Capture an immutable as-reported insight.", "capture")
HISTORY = passthrough_op("dashboard_view", "List or render as-reported insight history.", "history")
READ_REPORT = passthrough_op(
    "dashboard_view", "Read an immutable reported snapshot.", "read_report"
)
COMPARE = passthrough_op("dashboard_view", "Compare reported and recomputed values.", "compare")
EXPLORE_LOC = passthrough_op("loc_explore", "Write a trusted local LoC JSON explorer.", "main")

DASHBOARD: dict[str, object] = {
    "refresh": REFRESH,
    "team-report": TEAM_REPORT,
    "view": VIEW,
    "sla-policy": SLA_POLICY,
    "capture": CAPTURE,
    "history": HISTORY,
    "read-report": READ_REPORT,
    "compare": COMPARE,
    "explore-loc": EXPLORE_LOC,
}
