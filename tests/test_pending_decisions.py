"""Commands whose traust-core home waits on a plan 15 decision refuse, naming the decision.

They never fall back and never succeed quietly: exit 2 with the typed error on stderr, and
nothing on stdout.
"""

from __future__ import annotations

import contextlib
import io
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from traust.cli import cve_replay, findings, portfolio_liveness


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def refused(door: Callable[[list[str]], int], home: Path, *argv: str) -> str:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    assert (rc, out.getvalue()) == (2, "")
    return err.getvalue()


@pytest.mark.parametrize(
    "argv",
    [
        ("monitor",),
        ("candidates",),
        ("trends",),
        ("oracle", str(uuid4()), "CVE-2026-0001", "--present-at-audit", "true"),
    ],
)
def test_cve_replay_refuses_every_operation(home: Path, argv: tuple[str, ...]) -> None:
    err = refused(cve_replay.main, home, *argv)
    assert "CVE replay needs a traust-core decision (plan 15, decision 2)" in err


def test_claim_correction_commands_refuse(home: Path, tmp_path: Path) -> None:
    report = tmp_path / "corrected.json"
    report.write_text("{}")
    finding, assessment = str(uuid4()), str(uuid4())
    for door, argv in (
        (
            findings.correction_request,
            (str(report), "--finding", finding, "--assessment", assessment, "--label", "X-1"),
        ),
        (findings.rebaseline, (str(uuid4()),)),
        (findings.claim, (finding,)),
    ):
        authority = ("--ticket", "SEC-1", "--rationale", "reviewed")
        extra = authority if door is not findings.claim else ()
        err = refused(door, home, *argv, *extra)
        assert "Claim correction needs a traust-core decision (plan 15, decision 1)" in err


def test_liveness_refuses_rather_than_derive_a_status(home: Path) -> None:
    err = refused(portfolio_liveness.main, home)
    assert "Liveness status needs a traust-core decision (plan 15, decision 3)" in err
