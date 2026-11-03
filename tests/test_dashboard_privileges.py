"""`traust dashboard view privileges`: the CLI layer only, on a stubbed view. One
`InsightService.publish` of the privileges view; md/html/json and its CSV export land where
asked. The view (ranking, columns, CSV) is core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.insight import (
    FindingsTrend,
    PrivilegesRollup,
    RenderedView,
    ViewFilter,
    ViewName,
)

from traust.cli import dashboard_view

AS_OF = datetime(2026, 10, 1, tzinfo=UTC)
STEM = "operator-least-privilege-rollup"
CSV = "repo,sccs_requested\nhttps://github.com/example/noisy-operator,anyuid;privileged\n"
RENDERED = RenderedView(
    view=ViewName.PRIVILEGES,
    stem=STEM,
    model=PrivilegesRollup(as_of=AS_OF),
    markdown="# Operator least-privilege rollup\n",
    html="<!doctype html><title>Operator least-privilege rollup</title>",
    csv=CSV,
)


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def publish(*args: Any) -> RenderedView:
        calls.append(args)
        return RENDERED if args[0] == ViewName.PRIVILEGES else RENDERED.model_copy(
            update={"view": args[0], "stem": "findings-trend", "csv": None,
                    "model": FindingsTrend(as_of=AS_OF, repositories=0)}
        )  # fmt: skip

    services = SimpleNamespace(insight=SimpleNamespace(publish=publish))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return calls


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = dashboard_view.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_one_publish_of_the_privileges_view_writes_four_files(
    published: list[tuple[Any, ...]], home: Path, tmp_path: Path
) -> None:
    out = tmp_path / "operator-least-priv"
    rc, answer = run(home, "privileges", "--as-of", AS_OF.isoformat(), "--out", str(out))
    assert rc == 0
    assert published == [(ViewName.PRIVILEGES, ViewFilter(as_of=AS_OF))]
    assert sorted(p.name for p in out.iterdir()) == [
        f"{STEM}.csv", f"{STEM}.html", f"{STEM}.json", f"{STEM}.md",
    ]  # fmt: skip
    assert (out / f"{STEM}.csv").read_text() == CSV
    assert json.loads((out / f"{STEM}.json").read_text())["rows"] == []
    assert sorted(answer["written"]) == sorted(str(p) for p in out.iterdir())


def test_a_view_without_an_export_writes_no_csv(
    published: list[tuple[Any, ...]], home: Path, tmp_path: Path
) -> None:
    rc, _ = run(home, "findings-trend", "--out", str(tmp_path / "t"))
    assert rc == 0
    assert sorted(p.suffix for p in (tmp_path / "t").iterdir()) == [".html", ".json", ".md"]


def test_a_time_without_a_zone_is_exit_2_and_writes_nothing(
    published: list[tuple[Any, ...]], home: Path, tmp_path: Path
) -> None:
    out = tmp_path / "x"
    rc, _ = run(home, "privileges", "--as-of", "2026-10-01T00:00:00", "--out", str(out))
    assert rc == 2
    assert published == [] and not out.exists()


def test_the_retired_privileges_op_is_gone() -> None:
    from traust.cli.groups.dashboard import DASHBOARD

    assert "privileges" not in DASHBOARD
