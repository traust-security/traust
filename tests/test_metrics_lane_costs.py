"""`traust metrics lane-costs`: core's per-lane median settled cost over the last --days."""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import LaneCost, LaneName

from traust.cli import lane_costs
from traust.cli.__main__ import main

COSTS = [
    LaneCost(lane=LaneName("diff-scan"), orders=12, events=14, median_usd=Decimal("0.85")),
    LaneCost(lane=LaneName("full-audit"), orders=3, events=6, median_usd=Decimal("6.40")),
]


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[TimeWindow]:
    windows: list[TimeWindow] = []

    def lane_costs_of(window: TimeWindow) -> list[LaneCost]:
        windows.append(window)
        return COSTS

    spend = SimpleNamespace(lane_costs=lane_costs_of)
    core = SimpleNamespace(services=lambda: SimpleNamespace(spend=spend))
    monkeypatch.setattr(lane_costs, "load", lambda _home: core)
    return windows


def test_prints_each_lanes_median_and_counts_over_the_last_days(
    asked: list[TimeWindow], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["metrics", "lane-costs", "--days", "7"]) == 0
    out: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert out["lanes"] == [
        {"lane": "diff-scan", "orders": 12, "events": 14, "median_usd": "0.85"},
        {"lane": "full-audit", "orders": 3, "events": 6, "median_usd": "6.40"},
    ]
    (window,) = asked
    assert window.end - window.start == timedelta(days=7)


def test_the_window_defaults_to_thirty_days(asked: list[TimeWindow]) -> None:
    lane_costs.main([])
    assert asked[0].end - asked[0].start == timedelta(days=30)


def test_a_window_needs_at_least_a_day() -> None:
    with pytest.raises(SystemExit):
        lane_costs.main(["--days", "0"])
