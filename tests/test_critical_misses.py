from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from traust_core.v1.context import ArtifactsConfig, Config, Context
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.detection_quality import CriticalMiss, MissReason
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.detection_quality import DetectionQualityService

from traust.cli import critical_misses

NOW = datetime(2026, 10, 20, tzinfo=UTC)


def write_json(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Context]:
    context = Context(
        Config(
            home=tmp_path / "store",
            artifacts=ArtifactsConfig(path=tmp_path / "artifacts"),
        ),
        clock=FixedClock(NOW),
    )
    monkeypatch.setattr(critical_misses, "load", lambda _: context)
    yield context
    context.database.dispose()


def test_cli_writes_json_only_to_an_explicit_destination(
    core: Context,
    tmp_path: Path,
) -> None:
    json_out = tmp_path / "data/critical.json"
    window = ["--start", "2026-10-01T00:00:00Z", "--end", "2026-11-01T00:00:00Z"]
    assert critical_misses.main(["--json-out", str(json_out), *window]) == 0
    assert json.loads(json_out.read_bytes()) == []
    assert [p.name for p in json_out.parent.iterdir()] == ["critical.json"]


def test_the_default_destination_is_the_results_tree(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    monkeypatch.setattr(critical_misses, "analysis_results_dir", lambda _: results)
    assert (
        critical_misses.main(["--start", "2026-10-01T00:00:00Z", "--end", "2026-11-01T00:00Z"]) == 0
    )
    assert [p.name for p in results.iterdir()] == ["CRITICAL-MISSES.json"]


@pytest.mark.parametrize(
    "window",
    [
        ["--start", "2026-10-01T00:00:00Z"],
        ["--start", "2026-10-01T00:00:00", "--end", "2026-11-01T00:00:00"],
        ["--start", "2026-11-01T00:00:00Z", "--end", "2026-10-01T00:00:00Z"],
    ],
)
def test_invalid_recorded_windows_are_refused_without_writes(
    core: Context,
    tmp_path: Path,
    window: list[str],
) -> None:
    out = tmp_path / "CRITICAL-MISSES.json"
    assert critical_misses.main(["--json-out", str(out), *window]) == 2
    assert not out.exists()


HOSTILE = "a | b `tick` <img src=x onerror=alert(1)> [docs](javascript:alert(1))"


def recorded_misses() -> list[CriticalMiss]:
    """Two misses as core's model carries them: one plain, one with hostile text in every
    free-text field (the title comes from an audited report)."""
    return [
        CriticalMiss(
            finding_id=uuid4(),
            repository_id=uuid4(),
            title="token compared with ==",
            found_by=uuid4(),
            found_at=datetime(2026, 10, 5, 12, tzinfo=UTC),
            missed_by=uuid4(),
            reason=MissReason.MISSED,
        ),
        CriticalMiss(
            finding_id=uuid4(),
            repository_id=uuid4(),
            title=HOSTILE,
            found_by=uuid4(),
            found_at=datetime(2026, 10, 6, 12, tzinfo=UTC),
            missed_by=uuid4(),
            reason=MissReason.AREA_REPORTED,
            validity=HOSTILE,
        ),
    ]


def test_recorded_misses_are_exported_as_core_models(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    misses = recorded_misses()
    windows: list[TimeWindow] = []

    def critical(self: DetectionQualityService, window: TimeWindow) -> list[CriticalMiss]:
        windows.append(window)
        return misses

    monkeypatch.setattr(DetectionQualityService, "critical_misses", critical)
    json_out = tmp_path / "critical.json"
    window = ["--start", "2026-10-01T00:00:00Z", "--end", "2026-11-01T00:00:00Z"]
    assert critical_misses.main(["--json-out", str(json_out), *window]) == 0
    assert windows == [
        TimeWindow(start=datetime(2026, 10, 1, tzinfo=UTC), end=datetime(2026, 11, 1, tzinfo=UTC))
    ]
    document = json.loads(json_out.read_bytes())
    assert [CriticalMiss.model_validate(row) for row in document] == misses
    assert document[1]["title"] == document[1]["validity"] == HOSTILE  # JSON keeps the text
    assert document[1]["reason"] == "area_reported"
    # the Markdown render waits on its Insight view (plan 15 follow-up)
    assert [p.name for p in tmp_path.iterdir() if p.is_file()] == ["critical.json"]
