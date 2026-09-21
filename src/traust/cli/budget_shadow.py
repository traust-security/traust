#!/usr/bin/env python3
"""Budget shadow accounting — Phase 1 of the budget-guard widening plan
(progress-tracker/plans/budget-guard-widening-plan.md).

OBSERVE MODE: compute the verdict, record it, **withhold nothing**.
Owner decision 2026-08-05 — "do item 1 but not actually block for now…
log initially to determine how often I would hit the cap."

Why this is a separate module from the router's `apply_budget()`: that
function DROPS rows. Observe mode must never be able to reach it, so the
two live apart and the shadow returns a *report*, never a filtered work
list. `read_policy_budget()` deliberately reports `observe` as a
NON-binding ceiling for the same reason — the drop path cannot see an
observe ceiling even if a future caller passes it around carelessly.

The month-to-date term comes from the Phase-0 attribution rows
(`spend-attribution:<skill>` in the metrics ledger), NOT from the raw
transcript total. That distinction is the whole point of Phase 0:
a month's workstation-wide spend can run several times its harness lane
spend, and the ceiling is derived for steady-state *scanning*.
Judging a scanning ceiling against the workstation total would fire
constantly and mean nothing.

SACRIFICE ORDER (owner decision 2026-08-05): risk-ordered and
lane-agnostic — least exposure first, then lowest tier, regardless of
which lane the row belongs to. Two protections, also by decision:
event-injected rows (PSIRT/researcher/CVE/methodology) and rule-3
sensitive-path rows are never selected. A ceiling with carve-outs can be
exceeded with nothing left to withhold; that is an accepted cost, so the
report says so explicitly rather than implying the cap held.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from traust.context import load_engine

if TYPE_CHECKING:
    from traust_engine import HarnessEngine

ATTRIBUTION_PREFIX = "spend-attribution:"
UNATTRIBUTED = "unattributed"
SHADOW_LEDGER_SOURCE = "budget-shadow"

# Per-run unit costs (USD, medians measured from this deployment's session
# transcripts; the derivation lives in the deployment's cost report, not in
# the harness docs — docs/continuous-operations.md "Lane weights" describes
# only the relative weights).
# A lane whose cost is genuinely unmeasured maps to None and is COUNTED
# but not priced — never silently treated as free.
LANE_UNIT_COST = {
    "full-audit": 29.04,
    "full-audit+validate": 29.04,
    "diff-scan": 4.73,
    "diff-scan-quarterly": 6.24,
    "iac-lane": 10.00,
    "iac-baseline": 10.00,
    "threat-model-review": None,  # unmeasured (shipped v0.241.0)
    "threat-model-quarterly": None,  # unmeasured
    "impact-lane": 0.0,
    "deps-lane": 0.0,
    "release-passthrough": 0.0,
    "none": 0.0,
}

# Least-risky first — the order rows are given up in. Mirrors the
# router's EXPOSURE_ORDER reversed.
_EXPOSURE_SACRIFICE = ("private-internal", "public-internal", "private-external", "public-external")
_TIER_SACRIFICE = ("P3", "P2", "P1", "P0")

PROTECTED_RULES = ("rule-3",)


def _metrics(engine: HarnessEngine | None):
    return (engine or load_engine()).metrics


def month_to_date_lane_usd(
    ws: Path,
    month: str | None = None,
    *,
    engine: HarnessEngine | None = None,
) -> dict:
    """Harness-lane spend so far this month, from the Phase-0
    attribution rows. -> {month, lane_usd, unattributed_usd, days}."""
    month = month or datetime.date.today().strftime("%Y-%m")
    lane = unatt = 0.0
    days: set = set()
    for r in _metrics(engine).rows():
        if not str(r.get("source") or "").startswith(ATTRIBUTION_PREFIX):
            continue
        m = r.get("metrics") or {}
        date = str(m.get("date") or "")
        if not date.startswith(month):
            continue
        days.add(date)
        usd = m.get("cost_usd")
        if usd is None:
            continue
        if m.get("skill") == UNATTRIBUTED:
            unatt += float(usd)
        else:
            lane += float(usd)
    return {
        "month": month,
        "lane_usd": round(lane, 2),
        "unattributed_usd": round(unatt, 2),
        "days_recorded": len(days),
    }


def estimate_rows(rows: list[dict]) -> dict:
    """-> {usd, priced, unpriced_rows, unpriced_lanes}. Rows in a lane
    with no measured unit cost are counted and named, not priced as $0."""
    usd = 0.0
    priced = 0
    unpriced_rows = 0
    unpriced_lanes: set = set()
    for r in rows:
        lane = r.get("lane")
        unit = LANE_UNIT_COST.get(lane)
        if unit is None:
            unpriced_rows += 1
            unpriced_lanes.add(lane)
            continue
        usd += unit
        priced += 1
    return {
        "usd": round(usd, 2),
        "priced": priced,
        "unpriced_rows": unpriced_rows,
        "unpriced_lanes": sorted(x for x in unpriced_lanes if x),
    }


def is_protected(row: dict) -> str | None:
    """-> reason a row may never be withheld, or None."""
    if row.get("event_source"):
        return "event-injected (external report / CVE / methodology)"
    if str(row.get("rule") or "").startswith(PROTECTED_RULES):
        return "rule-3 sensitive-path (highest-yield trigger; never throttled)"
    return None


def _sacrifice_key(row: dict) -> tuple:
    exp = row.get("exposure") or "private-internal"
    tier = row.get("tier") or "P3"
    exp_i = _EXPOSURE_SACRIFICE.index(exp) if exp in _EXPOSURE_SACRIFICE else 0
    tier_i = _TIER_SACRIFICE.index(tier) if tier in _TIER_SACRIFICE else 0
    # lowest exposure, then lowest tier, then cheapest-to-lose last so
    # a big row does not get dropped ahead of several small equal-risk
    # ones purely by position
    return (exp_i, tier_i, -(row.get("C") or 0))


def select_withheld(rows: list[dict], overage_usd: float) -> tuple[list, list]:
    """Risk-ordered, lane-agnostic. -> (would_withhold, protected).

    Selects least-risky rows until the projected overage is covered.
    Returns the protected set too, so a report can state plainly when
    the ceiling could NOT have been met."""
    protected, candidates = [], []
    for r in rows:
        why = is_protected(r)
        (protected if why else candidates).append(dict(r, protected_reason=why) if why else r)
    if overage_usd <= 0:
        return [], protected
    candidates.sort(key=_sacrifice_key)
    withheld, freed = [], 0.0
    for r in candidates:
        if freed >= overage_usd:
            break
        unit = LANE_UNIT_COST.get(r.get("lane"))
        if not unit:
            continue  # unpriced or free: withholding it frees nothing
        withheld.append(r)
        freed += unit
    return withheld, protected


def shadow_verdict(
    ws: Path,
    rows: list[dict],
    ceiling: float | None,
    why: str,
    month: str | None = None,
    backlog_rows: list[dict] | None = None,
    *,
    engine: HarnessEngine | None = None,
) -> dict:
    """The full observe-mode report. NOTHING here filters `rows` — the
    caller emits its work list unchanged."""
    mtd = month_to_date_lane_usd(ws, month, engine=engine)
    est = estimate_rows(rows)
    projected = round(mtd["lane_usd"] + est["usd"], 2)
    out = {
        "mode": "observe",
        "withheld_anything": False,
        "ceiling_usd": ceiling,
        "ceiling_source": why,
        "month": mtd["month"],
        "month_to_date_lane_usd": mtd["lane_usd"],
        "month_to_date_unattributed_usd": mtd["unattributed_usd"],
        "days_recorded": mtd["days_recorded"],
        "tranche_estimate_usd": est["usd"],
        "tranche_rows": len(rows),
        "projected_with_tranche_usd": projected,
        "note": (
            "observe mode — the verdict is recorded, no row is "
            "withheld. Sacrifice order: least exposure, then "
            "lowest tier, lane-agnostic."
        ),
    }
    if est["unpriced_rows"]:
        out["unpriced_rows"] = est["unpriced_rows"]
        out["unpriced_lanes"] = est["unpriced_lanes"]
        out["unpriced_note"] = (
            f"{est['unpriced_rows']} row(s) in lanes with no measured "
            f"unit cost ({', '.join(est['unpriced_lanes'])}) are counted "
            f"but excluded from the estimate — not treated as free"
        )
    if backlog_rows is not None:
        b = estimate_rows(backlog_rows)
        out["unscheduled_full_audit_backlog_usd"] = b["usd"]
        out["unscheduled_full_audit_rows"] = len(backlog_rows)
    if ceiling is None:
        out["verdict"] = "no_ceiling"
        return out
    overage = round(projected - ceiling, 2)
    out["headroom_usd"] = round(ceiling - projected, 2)
    if overage <= 0:
        out["verdict"] = "within"
        return out
    out["verdict"] = "would_exceed"
    out["overage_usd"] = overage
    withheld, protected = select_withheld(rows, overage)
    freed = round(sum(LANE_UNIT_COST.get(r["lane"]) or 0 for r in withheld), 2)
    out["would_withhold"] = [
        {k: r.get(k) for k in ("repo_key", "repo_url", "lane", "tier", "exposure", "rule")}
        for r in withheld
    ]
    out["would_withhold_frees_usd"] = freed
    out["protected_not_withheld"] = [
        {k: r.get(k) for k in ("repo_key", "lane", "rule", "protected_reason")} for r in protected
    ]
    if freed < overage:
        out["ceiling_unmeetable"] = True
        out["ceiling_unmeetable_note"] = (
            f"withholding every eligible row frees ${freed:,.2f} but the "
            f"overage is ${overage:,.2f} — the ceiling could NOT be met "
            f"even by dropping everything droppable. Protected rows "
            f"({len(protected)}) are exempt by policy."
        )
    return out


def append_verdict(
    ws: Path,
    week: str,
    verdict: dict,
    *,
    engine: HarnessEngine | None = None,
) -> bool:
    """Record one shadow verdict so 'how often would it bind' is
    answered by counting rows, not re-deriving."""
    payload = {
        "week": week,
        "mode": verdict.get("mode"),
        "verdict": verdict.get("verdict"),
        "ceiling_usd": verdict.get("ceiling_usd"),
        "month": verdict.get("month"),
        "month_to_date_lane_usd": verdict.get("month_to_date_lane_usd"),
        "tranche_estimate_usd": verdict.get("tranche_estimate_usd"),
        "projected_with_tranche_usd": verdict.get("projected_with_tranche_usd"),
        "would_withhold_rows": len(verdict.get("would_withhold") or []),
        "ceiling_unmeetable": bool(verdict.get("ceiling_unmeetable")),
    }
    try:
        _metrics(engine).append(SHADOW_LEDGER_SOURCE, payload)
    except OSError:
        return False
    return True
