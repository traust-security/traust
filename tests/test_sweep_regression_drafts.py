"""`traust sweep regression-drafts` / `verify-draft`: the CLI layer only. Drafts are staged by one
`DetectionQualityService.stage_regression_drafts` (stubbed; traust-core writes the draft dirs);
the verify gate counts core's opengrep facts on before/ and after/."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.detection_quality import (
    PairFile,
    PairSkip,
    RegressionPair,
    RegressionPairFilter,
    RegressionPairs,
    SkippedPair,
)

from traust.cli.groups import sweep

FINDING = UUID("00000000-0000-0000-0000-000000000001")
GONE = UUID("00000000-0000-0000-0000-000000000002")
VULN = 'import os\n\n\ndef run(arg):\n    os.system("ls " + arg)\n'
SAFE = 'import subprocess\n\n\ndef run(arg):\n    subprocess.run(["ls", arg])\n'
PAIR = RegressionPair(
    finding_id=FINDING,
    repository_url="https://github.com/org/repo-a",
    fingerprint="0123456789abcdef",
    title="Command injection in run",
    cwes=("CWE-78",),
    severity="high",
    language="python",
    pre_fix_sha="a" * 40,
    fix_sha="b" * 40,
    rationale="Commit bbbbbbb passes argv",
    files=(
        PairFile(path="app/run.py", before=VULN, after=SAFE),
        PairFile(path="app/old.py", before=VULN, after=None),
    ),
)
GAP = SkippedPair(finding_id=GONE, reason=PairSkip.UNREADABLE, detail="HTTP 404")


@pytest.fixture
def quality(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    calls: list[tuple[RegressionPairFilter, bool]] = []
    loaded: list[dict[str, Any]] = []

    def stage_regression_drafts(
        filter: RegressionPairFilter, *, skip_existing: bool
    ) -> RegressionPairs:
        calls.append((filter, skip_existing))
        if isinstance(stub.result, Exception):
            raise stub.result
        return stub.result

    stub = SimpleNamespace(
        stage_regression_drafts=stage_regression_drafts,
        calls=calls,
        loaded=loaded,
        result=RegressionPairs(pairs=(PAIR,), skipped=(GAP,)),
    )

    def load(home: Path | None, **kw: Any) -> SimpleNamespace:
        loaded.append(kw)
        return SimpleNamespace(
            services=lambda: SimpleNamespace(detection_quality=stub),
            rule_drafts=SimpleNamespace(root=kw.get("rule_drafts")),
        )

    monkeypatch.setattr(sweep, "load", load)
    return stub


def stage(drafts: Path, **args: Any) -> tuple[int, Any]:
    ns = SimpleNamespace(
        **{
            "config_home": None,
            "drafts_dir": drafts,
            "cwe": None,
            "limit": 6,
            "skip_existing": False,
            **args,
        }
    )
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sweep.call_regression_drafts(ns)
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def verify(draft: Path, rule: Path | None = None) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sweep.call_verify_draft(SimpleNamespace(draft=draft, rule=rule, config_home=None))
    return rc, out.getvalue() + err.getvalue()


def test_each_staged_pair_is_listed(quality: SimpleNamespace, tmp_path: Path) -> None:
    rc, out = stage(tmp_path, cwe="CWE-78", limit=2)
    assert rc == 0
    assert quality.calls == [(RegressionPairFilter(cwe="CWE-78", limit=2), False)]
    assert quality.loaded[-1]["rule_drafts"] == tmp_path
    assert out["drafts_dir"] == str(tmp_path)
    assert out["drafted"] == [{"draft": PAIR.id, "language": "python", "cwe": "CWE-78", "files": 2}]


def test_a_fix_that_gave_no_pair_is_reported_not_dropped(
    quality: SimpleNamespace, tmp_path: Path
) -> None:
    _, out = stage(tmp_path)
    assert out["skipped_by_reason"] == {"unreadable": 1}
    assert out["skipped"] == [
        {"finding_id": str(GONE), "reason": "unreadable", "detail": "HTTP 404"}
    ]


def test_skip_existing_reaches_the_door(quality: SimpleNamespace, tmp_path: Path) -> None:
    stage(tmp_path, skip_existing=True)
    assert quality.calls[-1][1] is True


def test_a_refusing_door_is_exit_2(quality: SimpleNamespace, tmp_path: Path) -> None:
    quality.result = ConfigError("no forge reads configured")
    rc, err = stage(tmp_path)
    assert rc == 2 and "forge reads" in err


@pytest.mark.parametrize(
    ("before", "after", "rc", "verdict"),
    [(1, 0, 0, "PASS"), (0, 0, 1, "FAIL"), (1, 1, 1, "FAIL")],
)
def test_the_gate_needs_a_match_before_and_none_after(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, before: int, after: int, rc: int, verdict: str
) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("rules: []\n")
    seen: list[tuple[str, list[str]]] = []

    def report(core: Any, target: Path, rules: list[str]) -> dict[str, Any]:
        seen.append((target.name, rules))
        return {"facts": [{}] * (before if target.name == "before" else after)}

    monkeypatch.setattr(sweep, "load", lambda home: object())
    monkeypatch.setattr(sweep, "opengrep_report", report)
    got, out = verify(tmp_path, rule)
    assert (got, verdict in out) == (rc, True)
    assert seen == [("before", [str(rule)]), ("after", [str(rule)])]


def test_a_draft_without_a_rule_is_exit_2(tmp_path: Path) -> None:
    rc, out = verify(tmp_path)
    assert rc == 2 and "no rule file" in out


RULE = """rules:
  - id: harness-python-regression-test
    languages: [python]
    severity: ERROR
    message: os.system with a concatenated argument
    patterns:
      - pattern: os.system("..." + $X)
"""


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep not on PATH")
def test_a_draft_verifies_with_opengrep(tmp_path: Path) -> None:
    draft = tmp_path / PAIR.id
    for side, files in (("before", PAIR.files), ("after", PAIR.files[:1])):
        for f in files:
            target = draft / side / f.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f.before if side == "before" else f.after or "")
    (draft / "rule.skeleton.yaml").write_text(RULE)
    # app/old.py was deleted by the fix: it fires before, and after/ holds only the fixed file.
    rc, out = verify(draft)
    assert rc == 0, out
    assert "before=2" in out and "after=0" in out and "PASS" in out
