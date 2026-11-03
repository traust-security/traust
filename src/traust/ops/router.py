"""The security pack's router: a repository's routing state (traust-core `RepoState`) to its
work lanes, the retired daily rescan worklist's stage 2 per repository: the decision table,
the tripwire, the refusal pre-route, the threat-model `pr` stamp, then the additive IaC and
threat-model rows, and a threat-model review for each recorded release that re-models."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from traust_core.v1.models.inventory import ExposureClass, RecordedRelease, RepoState, RiskTier
from traust_core.v1.models.observation import MAX_CHANGED_FILE_RATIO
from traust_core.v1.models.operations import LaneName, Refusal, Route
from traust_core.v1.models.vocabulary import ComparisonStatus

log = logging.getLogger(__name__)

CHURN_FULL_LINES = 8000
CHURN_FULL_RATIO = 0.10
SENSITIVE_MIN_LINES = 200
# Held in lockstep with traust-core's THREAT_MODEL_MAX_AGE: the freshness view's threat-model row
# is the dead-timer that fires only if this lane stops draining.
THREAT_MODEL_QUARTERLY_DAYS = 92
TIER_CEILING_DAYS = {RiskTier.P0: 180, RiskTier.P1: 270, RiskTier.P2: 365}
# The external band (customer-facing impact) tightens the ceiling one notch (policy v1.4).
TIGHTENED_CEILING_DAYS = {RiskTier.P0: 180, RiskTier.P1: 180, RiskTier.P2: 270}
EXTERNAL = frozenset({ExposureClass.PUBLIC_EXTERNAL, ExposureClass.PRIVATE_EXTERNAL})

# contracts' work_lane values, in the legacy worklist's dispatch order: an order's priority.
LANES = (
    "full-audit+validate",
    "full-audit",
    "impact-lane",
    "iac-lane",
    "iac-baseline",
    "release-passthrough",
    "threat-model-review",
    "deps-lane",
    "diff-scan",
    "diff-scan-quarterly",
    "threat-model-quarterly",
    "none",
)
EXPOSURE_ORDER = (
    ExposureClass.PUBLIC_EXTERNAL,
    ExposureClass.PRIVATE_EXTERNAL,
    ExposureClass.PUBLIC_INTERNAL,
    ExposureClass.PRIVATE_INTERNAL,
)
TIER_ORDER = (RiskTier.P0, RiskTier.P1, RiskTier.P2, RiskTier.P3)
# Routed orders rank after the pack's standing jobs (priorities below 100).
PRIORITY_BASE = 100
# Classified but not queued: rule 3b's manifest-only change is covered advisory-first by the
# `dependency_watch` asset, which never read the worklist rows.
UNQUEUED = frozenset({"deps-lane", "none"})
DIFF_LANES = frozenset({"diff-scan", "diff-scan-quarterly"})
# Lever 1: the below-threshold lanes a secret in the change's patch escalates to an immediate
# diff scan, which adjudicates the hit.
TRIPWIRE_LANES = frozenset({"deps-lane", "diff-scan-quarterly"})
# The threat-model `pr` stamp rides the diff order's rule (the legacy row's `threat_model_pr`):
# the diff assets pass `{rule}` to `traust session run`, which runs `/threat-model pr` on the diff
# scan's checkout, report-only.
THREAT_MODEL_PR = "+threat-model-pr"


@dataclass(frozen=True)
class Rule:
    id: str
    applies: Callable[[RepoState], bool]
    lane: Callable[[RepoState], str]
    reason: str


def _lines(s: RepoState) -> int:
    return s.changed_lines or 0


def _over_ceiling(s: RepoState) -> bool:
    table = TIGHTENED_CEILING_DAYS if s.exposure in EXTERNAL else TIER_CEILING_DAYS
    ceiling = table.get(s.risk_tier)
    return ceiling is not None and s.audit_age_days is not None and s.audit_age_days > ceiling


# First match wins. The status rules come first: their metrics are missing or unmeasurable.
RULES: tuple[Rule, ...] = (
    Rule(
        "rule-1-bootstrap",
        lambda s: s.status == ComparisonStatus.NEVER_AUDITED,
        lambda s: "full-audit",
        "never audited: full audit + threat-model bootstrap (self-heals into change detection)",
    ),
    Rule(
        "quota-deferred",
        lambda s: s.status == ComparisonStatus.QUOTA_DEFERRED,
        lambda s: "none",
        "changed, but the compare was deferred to the next observation (API quota)",
    ),
    Rule(
        "no-pinned-sha",
        lambda s: s.status == ComparisonStatus.NO_PINNED_SHA and bool(s.push_changed),
        lambda s: "full-audit",
        "changed since audit but churn unmeasurable: a full audit re-establishes the anchor",
    ),
    Rule(
        "no-pinned-sha",
        lambda s: s.status == ComparisonStatus.NO_PINNED_SHA,
        lambda s: "none",
        "no push signal; the anchor is re-established at the next audit",
    ),
    Rule(
        "rule-2",
        lambda s: (
            (s.churn_ratio is not None and s.churn_ratio >= CHURN_FULL_RATIO)
            or _lines(s) >= CHURN_FULL_LINES
        ),
        lambda s: "full-audit",
        "coverage-map churn (R>=10% or C>=8000 first-party lines)",
    ),
    Rule(
        "rule-3",
        lambda s: bool(s.sensitive_changed) and (s.sensitive_lines or 0) >= SENSITIVE_MIN_LINES,
        lambda s: "full-audit" if s.risk_tier in (RiskTier.P0, RiskTier.P1) else "diff-scan",
        "sensitive-identifier files changed, >=200 lines",
    ),
    Rule(
        "rule-3b",
        lambda s: bool(s.deps_only),
        lambda s: "deps-lane",
        "dependency manifests only (deterministic osv/impact lane)",
    ),
    Rule(
        "rule-4",
        _over_ceiling,
        lambda s: "full-audit",
        "audit age over tier ceiling (P0 180d / P1 270d / P2 365d)",
    ),
    Rule(
        "rule-5",
        lambda s: _lines(s) > 0,
        lambda s: "diff-scan-quarterly",
        "below-threshold change (accumulates for the quarterly batch)",
    ),
    Rule(
        "rule-6",
        lambda s: bool(s.push_changed) and s.ahead_by == 0,
        lambda s: "none",
        "pushed_at moved but 0 commits ahead (tag/branch noise)",
    ),
    Rule(
        "rule-7",
        lambda s: True,
        lambda s: "none",
        "no qualifying change (dormant repos re-enter on push)",
    ),
)


def decide(state: RepoState) -> tuple[Rule, str]:
    """The first rule that applies, and the lane it picks (a work_lane value)."""
    rule = next(r for r in RULES if r.applies(state))
    return rule, rule.lane(state)


def tripwire(state: RepoState) -> bool:
    """Secret-scanner hits in a change's patch (traust-core scans it during the observation)."""
    return bool(state.secret_hits) and _lines(state) > 0


def preroute(state: RepoState) -> str | None:
    """Why the diff resolver would refuse this repository's diff at dispatch, so a diff lane goes
    to a full audit instead; None when it wouldn't."""
    if state.compare_truncated:
        return "compare truncated"
    changed, tree = state.first_party_files or 0, state.tree_first_party_files
    # traust-core counts the tree only on GitHub, untruncated, with enough files changed.
    if tree and changed / tree > MAX_CHANGED_FILE_RATIO:
        return "changed-file ratio"
    return None


def threat_model_pr(state: RepoState) -> bool:
    """A diff that touches a trust boundary or an interface-bearing path, with a model to assess
    it against."""
    touched = bool(state.sensitive_changed) or bool(state.threat_model_files)
    return touched and state.threat_model_age_days is not None


def additive(state: RepoState) -> tuple[tuple[str, str], ...]:
    """The (rule, lane) rows that ride beside the table's lane: lever 6's IaC lanes (a full audit
    never runs Checkov's IaC policies) and the threat-model calendar backstop."""
    rows = []
    if state.status == ComparisonStatus.OK and state.iac_files:
        rows.append(("lever-6", "iac-lane" if state.has_cloud_config_baseline else "iac-baseline"))
    elif (
        "cloud-config-audit" in state.companion_lanes
        and not state.has_cloud_config_baseline
        and state.repo is not None
    ):
        rows.append(("lever-6-companion", "iac-baseline"))
    age = state.threat_model_age_days
    # A never-audited repository's full audit bootstraps its threat model.
    audited = state.status != ComparisonStatus.NEVER_AUDITED
    if audited and age is not None and age >= THREAT_MODEL_QUARTERLY_DAYS:
        rows.append(("threat-model-3", "threat-model-quarterly"))
    return tuple(rows)


def released(events: Sequence[RecordedRelease]) -> tuple[tuple[str, str], ...]:
    """The legacy `threat-model-2` row: a release that is a major or minor bump over its product's
    previous one re-models every repository it ships, once however many such releases arrive."""
    remodels = any(e.change is not None and e.change.remodels() for e in events)
    return (("threat-model-2", "threat-model-review"),) if remodels else ()


def priority(lane: str, state: RepoState) -> int:
    """Lower runs sooner: lane, then exposure, then tier, as the legacy worklist sorted."""
    return PRIORITY_BASE + (
        LANES.index(lane) * 16
        + EXPOSURE_ORDER.index(state.exposure) * 4
        + TIER_ORDER.index(state.risk_tier)
    )


class SecurityRouter:
    """The pack router `traust-engine` calls when a repository's `repo_state` materializes."""

    def route(
        self, state: RepoState, events: Sequence[RecordedRelease], refusals: Sequence[Refusal]
    ) -> tuple[Route, ...]:
        # Artifact release observations inject passthrough orders; source releases only re-model.
        # NEED(refusals): a refused lane isn't re-decided here; the engine won't plan it again.
        rule, lane = decide(state)
        reason = rule.id
        if lane in TRIPWIRE_LANES and tripwire(state):
            log.info(
                "%s: %s secret hit(s), escalated to diff-scan",
                state.repository_id,
                state.secret_hits,
            )
            reason, lane = "tripwire", "diff-scan"
        if lane in DIFF_LANES and (why := preroute(state)):
            log.info("%s: %s, pre-routed to full-audit", state.repository_id, why)
            reason, lane = f"{reason}+preroute", "full-audit"
        if lane in DIFF_LANES and threat_model_pr(state):
            reason += THREAT_MODEL_PR
        rows = ((reason, lane), *additive(state), *released(events))
        return tuple(
            Route(
                lane=None if lane in UNQUEUED else LaneName(lane),
                priority=priority(lane, state),
                reason=reason,
            )
            for reason, lane in rows
        )
