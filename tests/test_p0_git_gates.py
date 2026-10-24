"""P0 regression tests — the git-transport/traversal/credential fixes
from progress-tracker/plans/harness-security-remediation-plan.md.

Each test encodes an attack shape the 2026-07-24 self-audit confirmed
(or class-confirmed): if any of these start failing, the RCE class is
back."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


aff = _load("apply_fleet_fix_p0", "harnessing/7-remediate/fleet-fix/scripts/apply_fleet_fix.py")


class _Boom:
    """subprocess.run stand-in that fails the test if reached."""

    def __call__(self, *a, **k):
        raise AssertionError(f"subprocess invoked for gated input: {a}")


MALICIOUS_URLS = [
    "ext::sh -c 'touch /tmp/pwned'",
    "--upload-pack=touch /tmp/pwned",
    "ssh://git@evil.example/x.git",
    "git@github.com:org/repo.git",
    "-oProxyCommand=evil",
    "",
    None,
]


@pytest.mark.parametrize("url", MALICIOUS_URLS)
def test_fleet_fix_ls_remote_rejects_before_subprocess(monkeypatch, url):
    monkeypatch.setattr(aff.subprocess, "run", _Boom())
    assert aff.ls_remote_sha(url, "main") is None


def test_fleet_fix_ls_remote_rejects_bad_ref(monkeypatch):
    monkeypatch.setattr(aff.subprocess, "run", _Boom())
    assert aff.ls_remote_sha("https://github.com/o/r", "-evil") is None
    assert aff.ls_remote_sha("https://github.com/o/r", "") is None


def test_fleet_fix_ls_remote_env_caps_protocol(monkeypatch):
    seen = {}

    def fake(argv, **kw):
        seen["env"] = kw.get("env") or {}
        seen["argv"] = argv

        class R:
            stdout = "a" * 40 + "\trefs/heads/main\n"

        return R()

    monkeypatch.setattr(aff.subprocess, "run", fake)
    assert aff.ls_remote_sha("https://github.com/o/r", "main") == "a" * 40
    assert seen["env"].get("GIT_ALLOW_PROTOCOL") == "https"
    assert "--" in seen["argv"]


def test_credential_liveness_commit_hex_gate():
    src = (_ROOT / "harnessing/5-validate/validate-findings/credential_liveness.py").read_text()
    # both git-show sites must be behind the hex fullmatch
    assert src.count('r"[0-9a-f]{7,40}"') >= 2


ENSURE_FORK = _ROOT / "harnessing/7-remediate/remediate-finding/ensure_fork.sh"


@pytest.mark.parametrize(
    "upstream",
    [
        "ext::sh -c 'touch /tmp/pwned'",
        "ssh://git@github.com/org/repo.git",
        "https://evil.example/org/repo.git",
        "--upload-pack=evil",
    ],
)
def test_ensure_fork_rejects_bad_upstream(upstream, tmp_path):
    r = subprocess.run(
        ["bash", str(ENSURE_FORK), upstream, "https://github.com/org/repo"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GITHUB_TOKEN": "dummy", "FORK_STAGING": str(tmp_path)},
    )
    assert r.returncode == 1
    assert "upstream must be https" in r.stderr


def test_ensure_fork_rejects_bad_sha(tmp_path):
    r = subprocess.run(
        [
            "bash",
            str(ENSURE_FORK),
            "https://github.com/org/repo",
            "https://github.com/org/repo",
            "--not-a-sha",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GITHUB_TOKEN": "dummy", "FORK_STAGING": str(tmp_path)},
    )
    assert r.returncode == 1
    assert "audited-sha" in r.stderr


def test_run_checks_strips_credentials(tmp_path):
    """C1 interim: target test code must not see tokens (plan P0.3)."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "go.mod").write_text("module x\n")
    (work / "Makefile").write_text("test:\n\t@env | grep -E 'GITHUB_TOKEN|AWS_SECRET' || true\n")
    out = tmp_path / "out"
    r = subprocess.run(
        [
            "bash",
            str(_ROOT / "harnessing/7-remediate/remediate-finding/run_checks.sh"),
            str(work),
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env={
            **os.environ,
            "GITHUB_TOKEN": "sekrit-token-value",
            "AWS_SECRET_ACCESS_KEY": "sekrit-aws-value",
        },
    )
    log = out / "check-make-test.log"
    assert log.is_file(), r.stdout + r.stderr
    text = log.read_text()
    assert "sekrit-token-value" not in text
    assert "sekrit-aws-value" not in text
