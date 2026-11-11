"""`traust metrics collect-spend --append` / `attribute-spend --reconcile` on traust-core; the
transcript reader, pricing, attribution and views are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    SpendBreakdown,
    SpendDimension,
    SpendFilter,
    SpendRollup,
)
from traust_core.v1.providers.transcripts import SessionTranscripts

from tests.test_products_doors import _postgres
from traust.cli.groups import metrics

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
DAY1, DAY2 = "2026-10-05", "2026-10-06"
WORKSPACE = Path("/w/workspace")


def record(ts: str, model: str = "claude-haiku-5-5", **usage: int) -> dict[str, Any]:
    tokens = {"input_tokens": 1000, "output_tokens": 100, **usage}
    return {"timestamp": f"{ts}T10:00:00.000Z", "message": {"model": model, "usage": tokens}}


def skill_call(name: str) -> dict[str, Any]:
    block = {"type": "tool_use", "name": "Skill", "input": {"skill": name}}
    return {"timestamp": f"{DAY1}T09:00:00Z", "message": {"content": [block]}}


def transcripts(tmp_path: Path) -> list[Path]:
    """One session that runs `triage` midway, with a synthetic message and a torn line."""
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    lines = [
        json.dumps(record(DAY1)),
        json.dumps(skill_call("triage")),
        json.dumps(record(DAY1, cache_read_input_tokens=50)),
        json.dumps(record(DAY1, model="<synthetic>")),
        '{"usage": torn',
        json.dumps(record(DAY2)),
    ]
    (project / "session.jsonl").write_text("\n".join(lines) + "\n")
    return [project]


class Spend:
    def __init__(self, recorded: int = 3, lossless: bool = True) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.recorded, self.lossless = recorded, lossless

    def collect(self, source: Any, window: TimeWindow) -> int:
        self.calls.append((source, window))
        return self.recorded

    def attribute_by(self, filter: SpendFilter, by: SpendDimension) -> SpendBreakdown:
        self.calls.append((filter, by))
        part = SpendRollup(events=1, tokens_in=1, tokens_out=1, cost_usd=Decimal(1))
        total = SpendRollup(
            events=2 if self.lossless else 3, tokens_in=2, tokens_out=2, cost_usd=Decimal(2)
        )
        return SpendBreakdown(filter=filter, by=by, rows=(part,), unattributed=part, total=total)


@pytest.fixture
def spend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Spend:
    door = Spend()
    core = SimpleNamespace(
        services=lambda: SimpleNamespace(spend=door),
        session_transcripts=SessionTranscripts(tmp_path / "projects"),
    )
    monkeypatch.setattr(metrics, "load_spend_core", lambda home: core)
    workspace(monkeypatch)
    return door


def workspace(monkeypatch: pytest.MonkeyPatch, projects: Path | None = None) -> None:
    """The configured workspace is WORKSPACE; known skills are `triage`; transcripts are read
    under `projects` when given."""
    monkeypatch.setattr(metrics, "workspace_dir", lambda core: WORKSPACE)
    monkeypatch.setattr(metrics, "skill_names", lambda: {"triage"})
    if projects is not None:
        monkeypatch.setattr(Context, "session_transcripts", SessionTranscripts(projects))


def args(**kw: Any) -> Any:
    values = {"config_home": None, "workspace": None, "date": None, "month": None, "json": False}
    return SimpleNamespace(**{**values, **kw})


def call(fn: Any, *a: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


def test_append_collects_every_transcript_day_into_core(spend: Spend, tmp_path: Path) -> None:
    transcripts(tmp_path)
    rc, out = call(metrics.call_collect_spend, args(append=True))
    assert (rc, out.strip()) == (0, "recorded 3 day×model×skill spend event(s)")
    [(source, window)] = spend.calls
    assert [u.skill for u in source.usages] == [None, "triage", "triage"]
    assert window.start == datetime(2026, 10, 5, tzinfo=UTC)
    assert window.end > datetime.now(UTC) - timedelta(minutes=1)


def test_append_of_no_usage_records_nothing(spend: Spend, tmp_path: Path) -> None:
    (tmp_path / "projects" / "-w-workspace").mkdir(parents=True)
    rc, out = call(metrics.call_collect_spend, args(append=True))
    assert (rc, spend.calls) == (0, []) and "recorded 0" in out


@pytest.mark.parametrize(
    ("kw", "window"),
    [
        ({"month": "2026-09"}, TimeWindow.month_of(datetime(2026, 9, 1, tzinfo=UTC))),
        (
            {"date": "2026-09-14"},
            TimeWindow(
                start=datetime(2026, 9, 14, tzinfo=UTC), end=datetime(2026, 9, 15, tzinfo=UTC)
            ),
        ),
    ],
)
def test_reconcile_splits_the_period_by_skill(
    spend: Spend, kw: dict[str, str], window: TimeWindow
) -> None:
    rc, out = call(metrics.call_attribute_spend, args(reconcile=True, **kw))
    assert rc == 0 and "lossless: True" in out
    assert spend.calls == [(SpendFilter(window=window), SpendDimension.SKILL)]


def test_reconcile_exits_1_when_the_split_is_not_lossless(spend: Spend) -> None:
    spend.lossless = False
    rc, out = call(metrics.call_attribute_spend, args(reconcile=True, json=True))
    assert rc == 1 and json.loads(out)["lossless"] is False


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_capture_on_core_is_idempotent_and_reconciles(
    tmp_path: Path, database: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "model-registry.yaml").write_text(REGISTRY.read_text())
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    workspace(monkeypatch, transcripts(tmp_path)[0].parent)
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        append = args(append=True, config_home=config)
        assert call(metrics.call_collect_spend, append)[1].startswith("recorded 3")
        assert call(metrics.call_collect_spend, append)[1].startswith("recorded 0")
        reconciled = args(reconcile=True, config_home=config, month="2026-10", json=True)
        rc, out = call(metrics.call_attribute_spend, reconciled)
    answer = json.loads(out)
    assert rc == 0 and answer["lossless"] is True
    assert answer["total"]["events"] == 3 and answer["unattributed"]["events"] == 1
    # three requests priced at the registry's claude-haiku-5-5 list rates, one with cache reads
    assert Decimal(answer["total"]["cost_usd"]) == Decimal("0.0004505")


def test_capture_without_a_model_registry_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    err = io.StringIO()
    workspace(monkeypatch, transcripts(tmp_path)[0].parent)
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(err):
        metrics.call_collect_spend(args(append=True, config_home=config))
    assert exit.value.code == 2 and "spend not resolvable" in err.getvalue()
