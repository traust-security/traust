from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from traust_core.v1.context import ArtifactsConfig, Config, Context
from traust_core.v1.providers.clock import FixedClock

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
