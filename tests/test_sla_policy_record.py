"""`traust dashboard sla-policy`: the recorded policy replaces the pack's default for the SLA view;
`--sla-policy` still wins for one run."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest
import yaml
from traust_core.v1.models.insight import ViewFilter, ViewName

from traust.cli import dashboard_view
from traust.context import SLA_POLICY, load


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "config"
    path.mkdir()
    (path / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return path


def policy(tmp_path: Path, name: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(SLA_POLICY.read_text().replace("fedramp-rev5-ra-5", name))
    return path


def shown(home: Path, sla_policy: Path | None = None) -> str:
    view = load(home, sla_policy=sla_policy).services().insight.build(ViewName.SLA, ViewFilter())
    return view.policy_name  # type: ignore[attr-defined]


def record(home: Path, path: Path) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return dashboard_view.sla_policy(["--config-home", str(home), str(path)])


def test_the_pack_default_until_a_policy_is_recorded(home: Path, tmp_path: Path) -> None:
    assert shown(home) == "fedramp-rev5-ra-5"
    assert record(home, policy(tmp_path, "ours")) == 0
    assert shown(home) == "ours"
    assert record(home, policy(tmp_path, "revised")) == 0
    assert shown(home) == "revised"


def test_the_flag_wins_over_the_recorded_policy(home: Path, tmp_path: Path) -> None:
    assert record(home, policy(tmp_path, "ours")) == 0
    assert shown(home, policy(tmp_path, "what-if")) == "what-if"


def test_an_invalid_policy_is_refused_and_nothing_changes(home: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("policy_name: x\n")
    assert record(home, bad) != 0
    assert shown(home) == "fedramp-rev5-ra-5"


def test_the_pack_default_cites_its_sources() -> None:
    source = yaml.safe_load(SLA_POLICY.read_text())["source"]
    assert source["url"].startswith("https://") and "https://www.cisa.gov/" in source["note"]
