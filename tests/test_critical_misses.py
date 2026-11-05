from __future__ import annotations

import json
import re
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


def test_cli_writes_json_to_an_explicit_independent_destination(
    core: Context,
    tmp_path: Path,
) -> None:
    out, json_out = tmp_path / "reports/CRITICAL-MISSES.md", tmp_path / "data/critical.json"
    assert (
        critical_misses.main(
            [
                "--out",
                str(out),
                "--json-out",
                str(json_out),
                "--start",
                "2026-10-01T00:00:00Z",
                "--end",
                "2026-11-01T00:00:00Z",
            ]
        )
        == 0
    )
    assert json.loads(json_out.read_bytes()) == []
    assert out.is_file()
    assert not out.with_suffix(".json").exists()


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
    out = tmp_path / "CRITICAL-MISSES.md"
    assert (
        critical_misses.main(
            [
                "--out",
                str(out),
                *window,
            ]
        )
        == 2
    )
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


def test_recorded_misses_render_to_json_and_escaped_markdown(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    misses = recorded_misses()
    windows: list[TimeWindow] = []

    def critical(self: DetectionQualityService, window: TimeWindow) -> list[CriticalMiss]:
        windows.append(window)
        return misses

    monkeypatch.setattr(DetectionQualityService, "critical_misses", critical)
    out, json_out = tmp_path / "CRITICAL-MISSES.md", tmp_path / "critical.json"
    argv = ["--out", str(out), "--json-out", str(json_out)]
    window = ["--start", "2026-10-01T00:00:00Z", "--end", "2026-11-01T00:00:00Z"]
    assert critical_misses.main([*argv, *window]) == 0
    assert windows == [
        TimeWindow(start=datetime(2026, 10, 1, tzinfo=UTC), end=datetime(2026, 11, 1, tzinfo=UTC))
    ]

    document = json.loads(json_out.read_bytes())
    assert [CriticalMiss.model_validate(row) for row in document] == misses
    assert document[1]["title"] == document[1]["validity"] == HOSTILE  # JSON keeps the text

    markdown = out.read_text(encoding="utf-8")
    rows = [line for line in markdown.splitlines() if line.startswith("| ") and "---" not in line]
    header, plain, hostile = rows
    cells = lambda row: re.split(r"(?<!\\)\|", row)[1:-1]  # noqa: E731
    assert [c.strip() for c in cells(header)] == [
        *("Repository", "Finding", "Title", "Found at", "Found by", "Missed by"),
        *("Reason", "Validity"),
    ]
    assert [c.strip() for c in cells(plain)] == [
        str(misses[0].repository_id),
        str(misses[0].finding_id),
        "token compared with ==",
        "2026-10-05T12:00:00+00:00",
        str(misses[0].found_by),
        str(misses[0].missed_by),
        "missed",
        "",
    ]
    columns = [c.strip() for c in cells(hostile)]
    assert len(columns) == 8 and columns[6] == "area_reported"
    escaped = (
        "a \\| b \\`tick\\` &lt;img src=x onerror=alert\\(1\\)&gt; "
        "\\[docs\\]\\(javascript:alert\\(1\\)\\)"
    )
    assert columns[2] == columns[7] == escaped
    assert "<img" not in markdown and "](" not in markdown
    assert "Misses: 2;" in markdown
