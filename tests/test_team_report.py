"""`traust dashboard team-report`: the CLI layer only. Slugs become products, then one
`InsightService.publish`; the pair lands where asked. The rollup and its renders are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.insight import (
    FindingsRollup,
    FindingTally,
    RenderedView,
    ViewFilter,
    ViewName,
)

from traust.cli import team_report

ALPHA = SimpleNamespace(id=uuid.uuid4(), slug="alpha", name="Alpha Hub")
BETA = SimpleNamespace(id=uuid.uuid4(), slug="beta", name="Beta")
TEAM = uuid.uuid4()
RENDERED = RenderedView(
    view=ViewName.FINDINGS_ROLLUP,
    stem="findings-rollup-alpha-hub",
    model=FindingsRollup(total=FindingTally()),
    markdown="# Findings rollup: Alpha Hub\n",
    html="<!doctype html><title>Findings rollup</title>",
)


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    products = {"alpha": ALPHA, "beta": BETA}
    stub = SimpleNamespace(
        publish=Door(RENDERED), find_product=lambda slug: products.get(str(slug))
    )
    services = SimpleNamespace(
        insight=SimpleNamespace(publish=stub.publish),
        portfolio=SimpleNamespace(find_product=stub.find_product),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = team_report.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_one_product_is_one_publish_and_the_pair(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    out = tmp_path / "team-reports" / "alpha-findings"
    rc, answer = run(home, "--product", "alpha", "--out", str(out))
    assert rc == 0
    assert doors.publish.calls == [(ViewName.FINDINGS_ROLLUP, ViewFilter(product_ids=(ALPHA.id,)))]
    assert sorted(p.name for p in out.iterdir()) == [
        "Executive-Summary-Alpha-Hub.html",
        "Executive-Summary-Alpha-Hub.md",
    ]
    assert (out / "Executive-Summary-Alpha-Hub.md").read_text() == RENDERED.markdown
    assert answer["written"] == [
        str(out / f"Executive-Summary-Alpha-Hub{s}") for s in (".md", ".html")
    ]
    assert answer["model"]["total"]["hardening"] == 0


def test_products_teams_and_as_of_go_into_one_filter(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    argv = ("--product", "alpha", "--product", "beta", "--product", "alpha")
    as_of = datetime(2026, 9, 1, tzinfo=UTC)
    rc, answer = run(
        home, *argv, "--team-id", str(TEAM), "--as-of", as_of.isoformat(), "--out", str(tmp_path)
    )
    assert rc == 0
    [(_, scope)] = doors.publish.calls
    assert scope == ViewFilter(product_ids=(ALPHA.id, BETA.id), team_ids=(TEAM,), as_of=as_of)
    assert Path(answer["written"][0]).name == "Executive-Summary-Alpha-Hub-Beta.md"


def test_a_team_only_report_is_named_for_teams(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    rc, answer = run(home, "--team-id", str(TEAM), "--out", str(tmp_path))
    assert rc == 0 and Path(answer["written"][1]).name == "Executive-Summary-Teams.html"


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        ((), "name a --product or a --team-id"),
        (("--product", "gamma"), "product gamma is not registered"),
        (("--product", "alpha", "--as-of", "2026-09-01T00:00:00"), "time zone"),
    ],
)
def test_a_refused_request_is_exit_2_and_writes_nothing(
    doors: SimpleNamespace, home: Path, tmp_path: Path, argv: tuple[str, ...], reason: str
) -> None:
    out = tmp_path / "out"
    rc, err = run(home, *argv, "--out", str(out))
    assert rc == 2 and reason in err
    assert doors.publish.calls == [] and not out.exists()


def test_a_door_refusal_is_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    doors.publish.result = ConfigError("no rating config")
    rc, err = run(home, "--product", "alpha", "--out", str(tmp_path / "out"))
    assert rc == 2 and "no rating config" in err
    assert not (tmp_path / "out").exists()
