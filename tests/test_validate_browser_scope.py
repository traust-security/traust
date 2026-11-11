#!/usr/bin/env python3
"""Tests for validate-browser-finding's targets.yaml scope (core ValidationScope) and gates."""

from __future__ import annotations

import datetime as dt
import importlib.util
import sys
from types import SimpleNamespace

import pytest

from traust.paths import skill_dir

ROOT = skill_dir("validate-browser-finding") / "scripts"


def _load(name: str, filename: str):
    """Load a module by file path under a unique name (avoids clash with validate-findings)."""
    path = ROOT / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# run.py does `from adapter import …` — seed that name only while loading it.
_prev_adapter = sys.modules.get("adapter")
_adapter = _load("vbf_adapter", "adapter.py")
sys.modules["adapter"] = _adapter
_run = _load("vbf_run", "run.py")
if _prev_adapter is not None:
    sys.modules["adapter"] = _prev_adapter
else:
    sys.modules.pop("adapter", None)

Targets = _run.Targets
PlanExecutor = _run.PlanExecutor

YAML = """
metadata:
  engagement: lab-1
  authorized_by: shaun
  expires: {expires}
browser:
  - victim_origin: http://victim.example.com
    attacker_origins: [http://attacker.example.com]
    allowed_verbs: {verbs}
    credentials: {{username: u, password: p}}
  - victim_origin: http://victim.example.com
    attacker_origins: []
    allowed_verbs: [navigate]
    credentials: {{username: other, password: second}}
"""


def _targets(tmp_path, *, verbs="[navigate, screenshot, csrf-replay]", expires="2999-01-01"):
    path = tmp_path / "targets.yaml"
    path.write_text(YAML.format(verbs=verbs, expires=expires))
    return Targets.from_file(path)


class _FakeAdapter:
    current_url = ""

    def execute(self, step, artifacts_dir):
        return SimpleNamespace(verdict="confirmed", observed="", duration_ms=0, evidence=[])


class _RecordingAudit:
    def __init__(self):
        self.rows = []

    def record(self, **kw):
        self.rows.append(kw)


def _executor(tmp_path, audit=None, **kwargs):
    audit = audit or SimpleNamespace(record=lambda **_: None)
    return PlanExecutor(_FakeAdapter(), _targets(tmp_path, **kwargs), audit)


def _step(verb="navigate", url="http://victim.example.com/x", **extra):
    return {"id": "s1", "verb": verb, "target": {"url": url}, **extra}


def test_from_file_reads_engagement_and_expiry(tmp_path):
    scope = _targets(tmp_path).scope
    assert (scope.engagement, scope.authorized_by, scope.environment) == ("lab-1", "shaun", "lab")
    assert scope.expires == dt.date(2999, 1, 1)


def test_credentials_stay_out_of_core_scope(tmp_path):
    targets = _targets(tmp_path)
    assert "password" not in targets.scope.model_dump_json()
    # duplicate victim_origin: the entry that authorised (the first) owns the
    # credentials; the second entry's never win
    assert targets.credentials_for("http://victim.example.com/login") == {
        "username": "u",
        "password": "p",
    }
    assert targets.credentials_for("http://other.example.com/") == {}


def test_authenticate_injects_credentials_but_audit_stays_clean(tmp_path):
    audit = _RecordingAudit()
    seen = {}

    class _CapturingAdapter(_FakeAdapter):
        def execute(self, step, artifacts_dir):
            seen.update(step)
            return super().execute(step, artifacts_dir)

    ex = PlanExecutor(_CapturingAdapter(), _targets(tmp_path, verbs="[authenticate]"), audit)
    result = ex._execute_step(
        {"id": "s2", "verb": "authenticate", "target": {"url": "http://victim.example.com/x"}},
        tmp_path,
        destructive=False,
    )
    assert result.verdict == "confirmed"
    assert seen["payload"] == {"username": "u", "password": "p"}
    assert all("password" not in str(row) for row in audit.rows)


@pytest.mark.parametrize(
    ("verb", "url", "blocked_reason"),
    [
        ("navigate", "http://victim.example.com/x", None),
        ("navigate", "http://attacker.example.com/poc", None),
        ("navigate", "http://victim.example.com.evil.net/app", "not in scope"),
        ("navigate", "http://other.example.com/", "not in scope"),
        ("xss-inject", "http://victim.example.com/x", "not allowed"),
        ("navigate", "", "no url"),
    ],
)
def test_scope_gate(tmp_path, verb, url, blocked_reason):
    result = _executor(tmp_path)._execute_step(_step(verb, url), tmp_path, destructive=False)
    if blocked_reason is None:
        assert result.verdict == "confirmed"
    else:
        assert result.verdict == "blocked_by_scope"
        assert blocked_reason in result.observed


def test_empty_allowed_verbs_deny_everything(tmp_path):
    result = _executor(tmp_path, verbs="[]")._execute_step(_step(), tmp_path, destructive=False)
    assert result.verdict == "blocked_by_scope"


def test_expired_engagement_blocks(tmp_path):
    result = _executor(tmp_path, expires="2000-01-01")._execute_step(
        _step(), tmp_path, destructive=False
    )
    assert result.verdict == "blocked_by_scope"
    assert "expired" in result.observed


def test_invalid_url_is_blocked_and_audited(tmp_path):
    audit = _RecordingAudit()
    result = _executor(tmp_path, audit=audit)._execute_step(
        _step(url="http://[bad"), tmp_path, destructive=False
    )
    assert result.verdict == "blocked_by_scope"
    assert "invalid action" in result.observed
    assert audit.rows[-1]["verdict"] == "blocked_by_scope"


def test_missing_verb_is_blocked_and_audited(tmp_path):
    audit = _RecordingAudit()
    step = {"id": "s1", "target": {"url": "http://victim.example.com/x"}}
    result = _executor(tmp_path, audit=audit)._execute_step(step, tmp_path, destructive=False)
    assert result.verdict == "blocked_by_scope"
    assert "invalid action" in result.observed
    assert audit.rows[-1]["verdict"] == "blocked_by_scope"


@pytest.mark.parametrize(
    ("done", "preconditions", "blocked"),
    [
        ({"step-001": "confirmed"}, ["step-01"], True),
        ({"step-001": "inconclusive"}, ["step-001"], True),
        ({"step-001": "confirmed"}, ["step-001"], False),
    ],
)
def test_preconditions_fail_closed(tmp_path, done, preconditions, blocked):
    ex = _executor(tmp_path)
    ex._done = {k: SimpleNamespace(verdict=v) for k, v in done.items()}
    reason = ex._check_preconditions({"preconditions": preconditions})
    assert (reason is not None) is blocked
