"""`traust sweep propose-rule`: the CLI layer only. It reads the rule and example files into one
`DetectionQualityService.propose_rule` call; the gate itself is traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.rule_mining import (
    ProposalCheck,
    ProposalCheckName,
    ProposalVerdict,
    RuleProposal,
)

from traust.cli.groups import sweep

ADMITTED = ProposalVerdict(
    rule_id="traust-proposed-x",
    admitted=True,
    checks=tuple(ProposalCheck(name=n, passed=True) for n in ProposalCheckName),
    draft="traust-proposed-x",
    hits=2,
    files_scanned=40,
)
REFUSED = ProposalVerdict(
    rule_id="traust-proposed-x",
    admitted=False,
    checks=(ProposalCheck(name=ProposalCheckName.REGEX, passed=False, detail="a backreference"),),
)


@pytest.fixture
def proposals(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(calls=[], result=ADMITTED)

    def propose_rule(p: RuleProposal) -> ProposalVerdict:
        stub.calls.append(p)
        if isinstance(stub.result, Exception):
            raise stub.result
        return stub.result

    stub.propose_rule = propose_rule
    core = SimpleNamespace(
        rule_drafts=object(), services=lambda: SimpleNamespace(detection_quality=stub)
    )
    monkeypatch.setattr(sweep, "load", lambda home, **kw: core)
    return stub


def call(tmp_path: Path, **args: Any) -> tuple[int, str, str]:
    (tmp_path / "rule.yaml").write_text("rules: []\n")
    (tmp_path / "example.py").write_text("# ruleid: traust-proposed-x\nx()\n")
    (tmp_path / "repo").mkdir(exist_ok=True)
    ns = SimpleNamespace(
        **{
            "config_home": None,
            "pack": None,
            "drafts_dir": None,
            "rule": tmp_path / "rule.yaml",
            "example": tmp_path / "example.py",
            "shape": "x() with request data",
            "checkout": tmp_path / "repo",
            "opengrep": "opengrep",
            "timeout": 60,
            "json": False,
            **args,
        }
    )
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sweep.call_propose(ns)
    return rc, out.getvalue(), err.getvalue()


def test_an_admitted_proposal_is_exit_0_and_names_its_draft(
    proposals: SimpleNamespace, tmp_path: Path
) -> None:
    rc, out, _ = call(tmp_path)
    assert rc == 0 and "staged as draft traust-proposed-x" in out
    (p,) = proposals.calls
    assert (p.example_name, p.shape, p.rule) == (
        "example.py",
        "x() with request data",
        "rules: []\n",
    )


def test_a_refused_proposal_is_exit_1_with_the_failing_check(
    proposals: SimpleNamespace, tmp_path: Path
) -> None:
    proposals.result = REFUSED
    rc, out, _ = call(tmp_path)
    assert rc == 1 and "FAIL regex: a backreference" in out and "refused" in out


def test_json_prints_the_verdict(proposals: SimpleNamespace, tmp_path: Path) -> None:
    rc, out, _ = call(tmp_path, json=True)
    assert rc == 0 and ProposalVerdict.model_validate(json.loads(out)) == ADMITTED


def test_a_refusing_door_is_exit_2(proposals: SimpleNamespace, tmp_path: Path) -> None:
    proposals.result = ConfigError("opengrep not found")
    rc, _, err = call(tmp_path)
    assert rc == 2 and "opengrep not found" in err
