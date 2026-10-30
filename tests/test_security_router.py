"""The security pack's router against the legacy router's characterization corpus
(`fixtures/routing/`, see its README): every decision-table, risk-tier and status case gives
the same rule and lane through traust-core's `RepoState` and `PortfolioPolicy`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from traust_core.v1.models.inventory import (
    ExposureClass,
    RecordedRelease,
    Release,
    ReleaseBump,
    ReleaseChange,
    RepoState,
    RiskTier,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus
from traust_core.v1.services.observation import PREROUTE_MIN_FILES
from traust_core.v1.services.portfolio import PortfolioPolicy

from traust.cli import build_rescan_worklist as rw
from traust.ops.router import (
    LANES,
    THREAT_MODEL_PR,
    UNQUEUED,
    SecurityRouter,
    decide,
    priority,
)

FIXTURES = Path(__file__).parent / "fixtures" / "routing"
DECISIONS = json.loads((FIXTURES / "python_decisions.json").read_text(encoding="utf-8"))
PRIMARY = json.loads((FIXTURES / "python_primary.json").read_text(encoding="utf-8"))
POLICY = PortfolioPolicy()
OBSERVED = datetime(2026, 9, 28, tzinfo=UTC)
REPO = HttpsRepoUrl.parse("https://github.com/example/app", ["github.com"])


def _state(**fields: Any) -> RepoState:
    base: dict[str, Any] = {
        "repository_id": uuid4(),
        "repo": None,
        "status": ComparisonStatus.OK,
        "risk_tier": RiskTier.P2,
        "exposure": ExposureClass.PRIVATE_INTERNAL,
        "open_critical_high": 0,
        "audit_age_days": None,
        "changed_lines": None,
        "churn_ratio": None,
        "sensitive_changed": None,
        "sensitive_lines": None,
        "deps_only": None,
        "ahead_by": None,
        "compare_truncated": None,
        "push_changed": None,
        "observed_at": OBSERVED,
    }
    return RepoState(**(base | fields))


def _exposure(value: str) -> ExposureClass:
    # The legacy corpus leaves exposure blank when it doesn't matter: never the external band.
    return ExposureClass(value) if value else ExposureClass.PRIVATE_INTERNAL


def _table_state(ctx: dict[str, Any]) -> RepoState:
    return _state(
        risk_tier=RiskTier(ctx["tier"]),
        exposure=_exposure(ctx["exposure"]),
        changed_lines=ctx["C"],
        churn_ratio=ctx["R"],
        sensitive_changed=ctx["S"],
        sensitive_lines=ctx["S_lines"],
        deps_only=ctx["deps_only"],
        audit_age_days=ctx["audit_age_days"],
        push_changed=ctx["changed"],
        ahead_by=ctx["ahead_by"],
    )


def _primary_state(supplied: dict[str, Any]) -> RepoState:
    audit = supplied.get("Audit")
    if audit is None:
        designation = (supplied["Inventory"] or {}).get("Designation")
        return _state(
            status=ComparisonStatus.NEVER_AUDITED,
            # the legacy fixture's `external` designation is "ships in a product" (core#191)
            exposure=POLICY.exposure_class(designation == "external", False, False),
        )
    risk, change = audit.get("Risk", {}), audit.get("Change") or {}
    live = risk.get("LiveCriticalHigh", 0)
    lines = change.get("ChangedLines", 0) if "Change" in audit else None
    ratio = change.get("CoverageChangeRatio") or None
    return _state(
        status=ComparisonStatus(audit["Status"]),
        risk_tier=POLICY.risk_tier(live, risk.get("Archived", False), risk.get("Dormant", False)),
        open_critical_high=live,
        exposure=_exposure(audit.get("Exposure", "")),
        audit_age_days=audit.get("AuditAgeDays"),
        push_changed=audit.get("PushChanged", False),
        changed_lines=lines,
        churn_ratio=ratio,
        sensitive_changed=change.get("SensitiveChange"),
        sensitive_lines=change.get("SensitiveChangedLines"),
        deps_only=change.get("DependenciesOnly"),
        ahead_by=change.get("CommitsAhead"),
    )


# One decision, from the table or a status rule. Event rows (rule 1) wait on the feed.
STATUS_CASES = [
    c
    for c in PRIMARY["primary"]
    if len(c["want"]["Decisions"]) == 1 and c["want"]["Decisions"][0]["EventIndex"] is None
]


@pytest.mark.parametrize("case", DECISIONS["table"], ids=lambda c: c["name"])
def test_decision_table_matches_the_legacy_router(case: dict[str, Any]) -> None:
    rule, lane = decide(_table_state(case["input"]))
    assert (rule.id, lane) == (case["want"]["Rule"], case["want"]["Lane"])


@pytest.mark.parametrize("case", DECISIONS["risk"], ids=lambda c: c["name"])
def test_core_risk_tier_matches_the_legacy_router(case: dict[str, Any]) -> None:
    risk = case["input"]
    tier = POLICY.risk_tier(risk["LiveCriticalHigh"], risk["Archived"], risk["Dormant"])
    assert tier == case["want"]


@pytest.mark.parametrize("case", STATUS_CASES, ids=lambda c: c["name"])
def test_status_rules_match_the_legacy_router(case: dict[str, Any]) -> None:
    (want,) = case["want"]["Decisions"]
    state = _primary_state(case["input"])
    rule, lane = decide(state)
    assert (rule.id, lane, state.risk_tier) == (want["Rule"], want["Lane"], want["RiskTier"])
    if want["Exposure"]:
        assert state.exposure == want["Exposure"]


def test_the_corpus_covers_every_status() -> None:
    covered = {_primary_state(c["input"]).status for c in STATUS_CASES}
    assert covered == set(ComparisonStatus)


@pytest.mark.parametrize(
    ("fields", "lane"),
    [
        ({"changed_lines": 8000}, "full-audit"),
        ({"changed_lines": 1}, "diff-scan-quarterly"),
        ({"sensitive_changed": True, "sensitive_lines": 200}, "diff-scan"),
        ({"status": ComparisonStatus.NEVER_AUDITED}, "full-audit"),
    ],
)
def test_route_names_the_lane_and_the_rule(fields: dict[str, Any], lane: str) -> None:
    state = _state(**fields)
    (route,) = SecurityRouter().route(state, (), ())
    rule, _ = decide(state)
    assert (route.lane, route.reason, route.priority) == (lane, rule.id, priority(lane, state))


@pytest.mark.parametrize(
    "fields",
    [
        {"deps_only": True, "changed_lines": 10},  # rule 3b: dependency_watch covers it
        {"status": ComparisonStatus.QUOTA_DEFERRED, "changed_lines": 9000},
        {"push_changed": True, "ahead_by": 0},
        {},
    ],
)
def test_classifications_without_a_queue_plan_nothing(fields: dict[str, Any]) -> None:
    (route,) = SecurityRouter().route(_state(**fields), (), ())
    assert route.lane is None and route.reason == decide(_state(**fields))[0].id


def test_priority_orders_by_lane_then_exposure_then_tier() -> None:
    ranked = sorted(
        (
            (priority(lane, _state(exposure=e, risk_tier=t)), lane, e, t)
            for lane in LANES
            for e in ExposureClass
            for t in RiskTier
        ),
        key=lambda r: r[0],
    )
    keys = [r[0] for r in ranked]
    assert len(set(keys)) == len(keys)
    assert [r[1] for r in ranked] == sorted((r[1] for r in ranked), key=LANES.index)
    first = [r for r in ranked if r[1] == "diff-scan-quarterly"][:2]
    assert [(r[2], r[3]) for r in first] == [
        (ExposureClass.PUBLIC_EXTERNAL, RiskTier.P0),
        (ExposureClass.PUBLIC_EXTERNAL, RiskTier.P1),
    ]


# Router inputs beside the decision table, each case run through the legacy worklist's own pass
# (`build_rescan_worklist`) and through the router on the `RepoState` traust-core records.
def _routes(state: RepoState) -> list[tuple[str, str | None]]:
    return [(r.reason, r.lane) for r in SecurityRouter().route(state, (), ())]


QUARTERLY = {"changed_lines": 12}  # rule 5
SENSITIVE = {"changed_lines": 300, "sensitive_changed": True, "sensitive_lines": 250}  # rule 3


@pytest.mark.parametrize(
    ("fields", "changed", "tree", "truncated"),
    [
        (QUARTERLY, 1, None, True),
        (QUARTERLY, 5, 10, False),
        (QUARTERLY, 3, 10, False),  # exactly 30%: the resolver refuses only above it
        (QUARTERLY, 2, 4, False),  # under the floor: no tree is counted
        (QUARTERLY, 4, 0, False),
        (SENSITIVE, 4, 10, False),
        (SENSITIVE, 4, 100, False),
        ({"changed_lines": 9000}, 1, None, True),  # rule 2: not a diff lane
    ],
)
def test_refusal_preroute_matches_the_legacy_router(
    fields: dict[str, Any], changed: int, tree: int | None, truncated: bool
) -> None:
    state = _state(
        **fields,
        compare_truncated=truncated,
        first_party_files=changed,
        # traust-core counts the tree only for an untruncated compare over the floor.
        tree_first_party_files=None if truncated or changed < PREROUTE_MIN_FILES else tree,
    )
    rule, lane = decide(state)
    row = {"repo_key": "k", "lane": lane, "rule": rule.id, "reason": "", "truncated": truncated}
    by_key = {"k": {"host_kind": "github", "project": "o/r", "fp_files": changed}}
    count = {"ok": True, "fp_files": tree or 0, "truncated": False}
    rw.run_preroute([row], by_key, 1, lambda p, r: count, lambda: 100_000)
    assert _routes(state)[0] == (row["rule"], row["lane"])


DEPS_ONLY = {"changed_lines": 10, "deps_only": True}  # rule 3b


@pytest.mark.parametrize(
    ("fields", "hits"),
    [
        (QUARTERLY, 2),
        (QUARTERLY, 0),
        (QUARTERLY, None),  # not scanned: never escalates
        (DEPS_ONLY, 1),
        (DEPS_ONLY, None),
        (SENSITIVE, 3),  # rule 3 on P2: already an immediate diff scan
        ({"changed_lines": 9000}, 5),  # rule 2: a full audit
        ({"changed_lines": 0}, 4),
        (QUARTERLY | {"compare_truncated": True}, 1),  # escalated, then pre-routed
        (QUARTERLY | {"sensitive_changed": True, "sensitive_lines": 5}, 1),  # then stamped
        (QUARTERLY | {"threat_model_files": 1}, 1),
    ],
)
def test_tripwire_matches_the_legacy_router(
    monkeypatch: pytest.MonkeyPatch, fields: dict[str, Any], hits: int | None
) -> None:
    state = _state(**fields, secret_hits=hits, threat_model_age_days=10)
    rule, lane = decide(state)
    row = {
        "repo_key": "k",
        "lane": lane,
        "rule": rule.id,
        "reason": "",
        "C": state.changed_lines,
        "truncated": state.compare_truncated,
    }
    entry = {
        "host_kind": "github",
        "project": "o/r",
        "pinned_sha": "a" * 40,
        "fp_files": 0,
        "S": state.sensitive_changed,
        "tm_files": state.threat_model_files,
        "tm_path": "m.md",
    }
    rw.run_tripwire([row], {"k": entry}, 1, lambda p, s: "+patch", lambda _: hits, lambda: 100_000)
    rw.run_preroute([row], {"k": entry}, 1, None, lambda: 0)
    rw.stamp_threat_model_pr([row], {"k": entry})
    legacy = row["rule"] + (THREAT_MODEL_PR if "threat_model_pr" in row else "")
    (route,) = SecurityRouter().route(state, (), ())
    assert (route.reason, route.lane) == (legacy, None if row["lane"] in UNQUEUED else row["lane"])
    assert route.priority == priority(row["lane"], state)


@pytest.mark.parametrize(
    ("fields", "sensitive", "tm_files", "model"),
    [
        (SENSITIVE, True, 0, True),
        (QUARTERLY, False, 2, True),
        (QUARTERLY, False, 0, True),
        (SENSITIVE, True, 0, False),  # no model to assess the diff against
        (SENSITIVE | {"risk_tier": RiskTier.P0}, True, 0, True),  # rule 3 on P0: a full audit
        (SENSITIVE | {"compare_truncated": True}, True, 0, True),  # pre-routed first
    ],
)
def test_threat_model_pr_stamp_matches_the_legacy_router(
    fields: dict[str, Any], sensitive: bool, tm_files: int, model: bool
) -> None:
    state = _state(
        **fields, threat_model_files=tm_files, threat_model_age_days=10 if model else None
    )
    rule, lane = decide(state)
    truncated = state.compare_truncated
    row = {"repo_key": "k", "lane": lane, "rule": rule.id, "reason": "", "truncated": truncated}
    rw.run_preroute([row], {"k": {"fp_files": 0}}, 1, None, lambda: 0)
    entry = {"S": sensitive, "tm_files": tm_files, "tm_path": "m.md" if model else None}
    rw.stamp_threat_model_pr([row], {"k": entry})
    stamped = "threat_model_pr" in row
    reason, _ = _routes(state)[0]
    assert reason == row["rule"] + (THREAT_MODEL_PR if stamped else "")


@pytest.mark.parametrize(
    "fields",
    [
        {"iac_files": 2, "has_cloud_config_baseline": True},
        {"iac_files": 2, "has_cloud_config_baseline": False},
        {"iac_files": 0, "has_cloud_config_baseline": False},
        {"status": ComparisonStatus.QUOTA_DEFERRED, "iac_files": 2},
        {"companion_lanes": ("cloud-config-audit",), "has_cloud_config_baseline": False},
        {"companion_lanes": ("cloud-config-audit",), "has_cloud_config_baseline": True},
        {"companion_lanes": ("cloud-config-audit",), "iac_files": 1},
        {"companion_lanes": ("cloud-config-audit",), "repo": None},
        {"threat_model_age_days": 92},
        {"threat_model_age_days": 91},
        {"threat_model_age_days": 400, "iac_files": 3, "has_cloud_config_baseline": True},
    ],
)
def test_additive_rows_match_the_legacy_router(fields: dict[str, Any]) -> None:
    state = _state(**({"repo": REPO} | fields))
    url = str(state.repo) if state.repo else None
    entry = {
        "repo_key": "k",
        "repo_url": url,
        "status": str(state.status),
        "iac_files": state.iac_files,
        "companion_lanes": list(state.companion_lanes),
        "tm_path": "m.md" if state.threat_model_age_days is not None else None,
        "tm_age_days": state.threat_model_age_days,
    }
    baselines = {url} if state.has_cloud_config_baseline else set()
    iac = rw.iac_rows([entry], baselines)
    legacy = [
        *iac,
        *rw.companion_rows([entry], baselines, {r["repo_url"] for r in iac}),
        *rw.threat_model_quarterly_rows([entry], set(), rw.THREAT_MODEL_QUARTERLY_DAYS),
    ]
    assert _routes(state)[1:] == [(r["rule"], r["lane"]) for r in legacy]


def test_additive_rows_ride_beside_a_classification_without_a_queue() -> None:
    state = _state(deps_only=True, changed_lines=10, iac_files=1, threat_model_age_days=100)
    assert _routes(state) == [
        ("rule-3b", None),
        ("lever-6", "iac-baseline"),
        ("threat-model-3", "threat-model-quarterly"),
    ]


def test_a_never_audited_repository_gets_no_calendar_backstop() -> None:
    state = _state(status=ComparisonStatus.NEVER_AUDITED, threat_model_age_days=400)
    assert _routes(state) == [("rule-1-bootstrap", "full-audit")]


def _release(bump: ReleaseBump | None) -> RecordedRelease:
    """A recorded release; no bump is the product's first recorded release."""
    release = Release(id=uuid4(), product_id=uuid4(), version="4.20")
    change = None
    if bump is not None:
        change = ReleaseChange(
            release_id=release.id,  # type: ignore[arg-type]
            previous_id=uuid4(),
            version="4.20",
            previous_version="4.19",
            bump=bump,
        )
    return RecordedRelease(release=release, repository_ids=(uuid4(),), change=change)


@pytest.mark.parametrize("bump", [*ReleaseBump, None])
def test_a_release_re_models_only_on_a_major_or_minor_bump_as_the_legacy_router(
    bump: ReleaseBump | None,
) -> None:
    legacy = bump is not None and str(bump) in rw.RELEASE_REMODEL_CHANGES
    routes = [(r.reason, r.lane) for r in SecurityRouter().route(_state(), (_release(bump),), ())]
    assert (("threat-model-2", "threat-model-review") in routes) == legacy
    assert routes[0] == ("rule-7", None)


def test_a_release_review_rides_beside_the_table_and_additive_rows_once() -> None:
    state = _state(changed_lines=12, threat_model_age_days=100)
    events = tuple(map(_release, (ReleaseBump.MINOR, ReleaseBump.MAJOR, ReleaseBump.PATCH)))
    routes = SecurityRouter().route(state, events, ())
    assert [(r.reason, r.lane) for r in routes] == [
        ("rule-5", "diff-scan-quarterly"),
        ("threat-model-3", "threat-model-quarterly"),
        ("threat-model-2", "threat-model-review"),
    ]
    assert routes[-1].priority == priority("threat-model-review", state)
