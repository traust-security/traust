"""Container/credential hardening: only the one credential file the container
actually needs, and a git wrapper that rejects exec-path dispatch.

Run: ../traust/.venv/bin/python -m pytest tests/test_backport_hardening.py
"""
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys

import pytest

pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
SKILL = REPO / "harnessing" / "7-remediate" / "backport-fix"
RUNNER = SKILL / "scripts" / "run_backport.sh"
GIT = subprocess.run(["sh", "-c", "command -v git"], capture_output=True,
                     text=True).stdout.strip()


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def _exec(p: pathlib.Path, text: str) -> None:
    p.write_text(text)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def _valid_result(tmp_path: pathlib.Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "--allow-empty", "-m", "fix")
    sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "branch", "amalgamator/backport-x")

    results = tmp_path / "results" / "release-a"
    results.mkdir(parents=True)
    (results / "candidate.patch").write_text(
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    (results / "config.yaml").write_text(
        f"repository:\n  source_path: {repo}\nfix:\n  commit: {sha}\n"
        "branches:\n  source: origin/main\n  target: origin/release-a\n")
    (results / "summary.json").write_text(json.dumps({"targets": [{
        "outcome": "success", "issue_id": "backport-x",
        "target_branch": "origin/release-a"}]}))
    (results / "result.json").write_text(json.dumps({
        "issue_id": "backport-x", "target_branch": "release-a",
        "outcome": "success", "head_sha": sha}))
    return repo, tmp_path / "results", sha


def _container_plan(tmp_path, extra_env):
    """Run the container branch with a podman shim and return the logged argv."""
    repo, _results, sha = _valid_result(tmp_path)
    home = tmp_path / "home"
    (home / ".config" / "gcloud").mkdir(parents=True)
    (home / ".config" / "gcloud" / "application_default_credentials.json").write_text("{}")
    explicit = tmp_path / "svc-key.json"
    explicit.write_text("{}")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    podman_log = tmp_path / "podman.log"
    _exec(bin_dir / "podman", f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "{podman_log}"
case "$1" in cp) exit 1 ;; *) exit 0 ;; esac
""")

    cfg = tmp_path / "cfg" / "release-a.yaml"
    cfg.parent.mkdir()
    cfg.write_text(
        f"issue_id: backport-x\nbug_description: t\n"
        f"repository: {{source_path: {repo}, workdir: {tmp_path}/wd}}\n"
        "branches: {source: origin/main, target: origin/release-a}\n"
        f"fix: {{commit: {sha}}}\nbuild: {{command: '', test_command: ''}}\n")

    env = os.environ.copy()
    for k in ("ANTHROPIC_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
              "CLAUDE_CODE_USE_VERTEX", "ANTHROPIC_VERTEX_PROJECT_ID",
              "CLOUD_ML_REGION"):
        env.pop(k, None)
    env.update({
        "HOME": str(home),
        "PATH": f"{bin_dir}:{pathlib.Path(sys.executable).parent}:{env['PATH']}",
        "PYTHONPATH": str(SKILL / "test-data" / "mock" / "mock_amalgamator"),
    })
    env.update(extra_env)
    subprocess.run(
        ["bash", str(RUNNER), "--config", str(cfg), "--output-dir",
         str(tmp_path / "res"), "--container-image", "example:latest",
         "--repo", str(repo)],
        capture_output=True, text=True, env=env,
    )
    return podman_log.read_text(), explicit


def test_container_mounts_only_the_explicit_adc_file(tmp_path):
    plan, explicit = _container_plan(tmp_path, {
        "CLAUDE_CODE_USE_VERTEX": "1",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "svc-key.json"),
    })
    # The explicit ADC wins over the default gcloud directory...
    assert f"-v {explicit}:/workspace/adc.json:ro" in plan
    assert "GOOGLE_APPLICATION_CREDENTIALS=/workspace/adc.json" in plan
    # ...and the whole gcloud tree is never mounted.
    assert "/workspace/gcloud" not in plan
    assert ".config/gcloud" not in plan


def test_vertex_mode_does_not_forward_the_api_key(tmp_path):
    plan, _ = _container_plan(tmp_path, {
        "CLAUDE_CODE_USE_VERTEX": "1",
        "ANTHROPIC_API_KEY": "sk-ant-must-not-be-forwarded",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "svc-key.json"),
    })
    assert "/workspace/adc.json" in plan
    # Only the mechanism in use is forwarded.
    assert "-e ANTHROPIC_API_KEY" not in plan
    assert "sk-ant-must-not-be-forwarded" not in plan


def test_api_key_mode_does_not_mount_adc(tmp_path):
    plan, _ = _container_plan(tmp_path, {
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "svc-key.json"),
    })
    assert "-e ANTHROPIC_API_KEY" in plan
    assert "/workspace/adc.json" not in plan


def test_safe_git_rejects_global_option_overrides(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "--allow-empty", "-m", "x")
    wrapper = SKILL / "scripts" / "safe_git.sh"

    ok = subprocess.run(
        ["bash", str(wrapper), "-C", str(repo), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True,
    )
    assert ok.returncode == 0 and ok.stdout.strip(), ok.stderr

    rejected = (
        ["rev-parse", "--exec-path=/tmp"],
        ["--exec-path=/tmp", "rev-parse"],
        ["rev-parse", "-c", "core.pager=sh"],
        ["rev-parse", "--git-dir=/tmp"],
        ["push", "origin"],            # not a read-only subcommand
    )
    for args in rejected:
        r = subprocess.run(
            ["bash", str(wrapper), "-C", str(repo), *args],
            capture_output=True, text=True,
        )
        assert r.returncode == 2, (args, r.stdout, r.stderr)
