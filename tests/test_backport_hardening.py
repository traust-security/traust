"""Container/credential hardening: only the one credential file the container
actually needs, and a git wrapper that rejects exec-path dispatch.

Run: ../traust/.venv/bin/python -m pytest tests/test_backport_hardening.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

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


def _container_plan(tmp_path, extra_env, extra_args=(), labeled=False):
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
              "CLOUD_ML_REGION", "BACKPORT_SELINUX"):
        env.pop(k, None)
    env.update({
        "HOME": str(home),
        "PATH": f"{bin_dir}:{pathlib.Path(sys.executable).parent}:{env['PATH']}",
        "PYTHONPATH": str(SKILL / "test-data" / "mock" / "mock_amalgamator"),
    })
    env.update(extra_env)
    if labeled:
        real_stat = shutil.which("stat") or "/usr/bin/stat"
        _exec(bin_dir / "stat", f"""#!/usr/bin/env bash
if [[ "${{1:-}}" == "-c" && "${{2:-}}" == "%C" ]]; then
  echo "system_u:object_r:container_file_t:s0"
  exit 0
fi
exec {real_stat} "$@"
""")
    proc = subprocess.run(
        ["bash", str(RUNNER), "--config", str(cfg), "--output-dir",
         str(tmp_path / "res"), "--container-image", "example:latest",
         "--repo", str(repo), *extra_args],
        capture_output=True, text=True, env=env,
    )
    plan = podman_log.read_text() if podman_log.exists() else ""
    return plan, explicit, proc


def test_container_mounts_only_the_explicit_adc_file(tmp_path):
    plan, explicit, _proc = _container_plan(tmp_path, {
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
    plan, _, _ = _container_plan(tmp_path, {
        "CLAUDE_CODE_USE_VERTEX": "1",
        "ANTHROPIC_API_KEY": "sk-ant-must-not-be-forwarded",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "svc-key.json"),
    })
    assert "/workspace/adc.json" in plan
    # Only the mechanism in use is forwarded.
    assert "-e ANTHROPIC_API_KEY" not in plan
    assert "sk-ant-must-not-be-forwarded" not in plan


def test_api_key_mode_does_not_mount_adc(tmp_path):
    plan, _, _ = _container_plan(tmp_path, {
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


def test_safe_git_never_runs_repository_diff_helpers(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitattributes").write_text("*.txt diff=evil\n")
    (repo / "f.txt").write_text("hi\n")
    _git(repo, "add", ".gitattributes", "f.txt")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "-m", "x")

    marker = tmp_path / "HELPER_RAN"
    helper = tmp_path / "helper.sh"
    helper.write_text(f"#!/bin/sh\ntouch '{marker}'\necho PWN\n")
    helper.chmod(0o755)
    _git(repo, "config", "diff.evil.textconv", str(helper))
    _git(repo, "config", "diff.external", str(helper))
    wrapper = SKILL / "scripts" / "safe_git.sh"

    ok = subprocess.run(
        ["bash", str(wrapper), "-C", str(repo), "show", "HEAD:f.txt"],
        capture_output=True, text=True,
    )
    assert ok.returncode == 0, ok.stderr
    assert not marker.exists(), "textconv ran without being requested"

    refused = (
        ["show", "--textconv", "HEAD:f.txt"],
        ["show", "--ext-diff", "HEAD"],
        ["cat-file", "--filters", "HEAD:f.txt"],
        ["cat-file", "--textconv", "HEAD:f.txt"],
        ["cat-file", "--path=f.txt", "-t", "HEAD"],
        ["show", "--output=/tmp/x", "HEAD"],
        ["show", "--output", "/tmp/x", "HEAD"],
    )
    for args in refused:
        r = subprocess.run(
            ["bash", str(wrapper), "-C", str(repo), *args],
            capture_output=True, text=True,
        )
        assert r.returncode == 2, (args, r.stdout, r.stderr)
        assert not marker.exists(), (args, "repository helper executed")

    # Ownership checks stay in force: no safe.directory override in the wrapper.
    assert "-c safe.directory" not in wrapper.read_text()


def test_selinux_enforcing_refuses_unlabeled_host_mounts(tmp_path):
    plan, _explicit, proc = _container_plan(
        tmp_path, {"BACKPORT_SELINUX": "enforcing"})
    assert proc.returncode == 2, proc.stderr
    assert "not labeled container_file_t" in proc.stderr
    assert plan == "", "podman must not run with an unlabeled mount"


def test_selinux_relabel_flag_labels_user_mounts(tmp_path):
    explicit = tmp_path / "svc-key.json"
    plan, explicit, proc = _container_plan(
        tmp_path,
        {"BACKPORT_SELINUX": "enforcing",
         "CLAUDE_CODE_USE_VERTEX": "1",
         "GOOGLE_APPLICATION_CREDENTIALS": str(explicit)},
        extra_args=("--selinux-relabel",),
    )
    assert "--selinux-relabel" in proc.stderr
    assert f"-v {explicit}:/workspace/adc.json:ro,z" in plan
    assert "/workspace/repo:rw,z" in plan


def test_selinux_enforcing_accepts_prelabeled_mounts(tmp_path):
    explicit = tmp_path / "svc-key.json"
    plan, explicit, proc = _container_plan(
        tmp_path,
        {"BACKPORT_SELINUX": "enforcing",
         "CLAUDE_CODE_USE_VERTEX": "1",
         "GOOGLE_APPLICATION_CREDENTIALS": str(explicit)},
        labeled=True,
    )
    assert "not labeled container_file_t" not in proc.stderr
    assert f"-v {explicit}:/workspace/adc.json:ro" in plan
    assert "/workspace/adc.json:ro,z" not in plan
    assert "/workspace/repo:rw,z" not in plan
    # our own temp config dir is labeled regardless
    assert "/workspace/configs:ro,z" in plan


def test_selinux_disabled_does_not_label_mounts(tmp_path):
    plan, _explicit, proc = _container_plan(
        tmp_path, {"BACKPORT_SELINUX": "disabled"})
    assert "not labeled container_file_t" not in proc.stderr
    assert ",z" not in plan


def _abort_env(tmp_path, running, log):
    repo, _results, sha = _valid_result(tmp_path)
    cfg = tmp_path / "cfg" / "release-a.yaml"
    cfg.parent.mkdir()
    cfg.write_text(
        f"issue_id: backport-x\nbug_description: t\n"
        f"repository: {{source_path: {repo}, workdir: {tmp_path}/wd}}\n"
        "branches: {source: origin/main, target: origin/release-a}\n"
        f"fix: {{commit: {sha}}}\nbuild: {{command: '', test_command: ''}}\n")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _exec(bin_dir / "podman", f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "{log}"
case "$1" in
  run) touch "{running}"; sleep 60 ;;
  cp) exit 1 ;;
  *) exit 0 ;;
esac
""")
    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env.update({
        "HOME": str(tmp_path / "home"),
        "PATH": f"{bin_dir}:{pathlib.Path(sys.executable).parent}:{env['PATH']}",
        "BACKPORT_SELINUX": "disabled",
    })
    (tmp_path / "home").mkdir(exist_ok=True)
    return repo, cfg, env


def test_container_abort_cleans_up_container_and_temp_config(tmp_path):
    running = tmp_path / "RUNNING"
    log = tmp_path / "podman.log"
    repo, cfg, env = _abort_env(tmp_path, running, log)

    proc = subprocess.Popen(
        ["bash", str(RUNNER), "--config", str(cfg), "--output-dir",
         str(tmp_path / "res"), "--container-image", "example:latest",
         "--repo", str(repo)],
        start_new_session=True, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if running.exists():
                break
            time.sleep(0.05)
        assert running.exists(), "container run did not start"
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()

    plan = log.read_text()
    assert "rm -f backport-" in plan, plan
    match = re.search(r"-v (\S+):/workspace/configs", plan)
    assert match, plan
    assert not pathlib.Path(match.group(1)).exists(), "temp config dir left behind"


def test_container_normal_path_cleans_up(tmp_path):
    plan, _explicit, _proc = _container_plan(
        tmp_path, {"BACKPORT_SELINUX": "disabled"})
    assert "rm -f backport-" in plan, plan
    match = re.search(r"-v (\S+):/workspace/configs", plan)
    assert match, plan
    assert not pathlib.Path(match.group(1)).exists()


def test_local_mode_drops_github_credentials_even_when_allowlisted(tmp_path):
    repo, _results, sha = _valid_result(tmp_path)
    cfg = tmp_path / "cfg" / "release-a.yaml"
    cfg.parent.mkdir()
    cfg.write_text(
        f"issue_id: backport-x\nbug_description: t\n"
        f"repository: {{source_path: {repo}, workdir: {tmp_path}/wd}}\n"
        "branches: {source: origin/main, target: origin/release-a}\n"
        f"fix: {{commit: {sha}}}\nbuild: {{command: '', test_command: ''}}\n")

    seen = tmp_path / "engine_env.json"
    pkg = tmp_path / "fake_engine" / "auto_bug_fix"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "run_bug_fix.py").write_text(
        "import json, os, sys\n"
        f"json.dump(dict(os.environ), open({str(seen)!r}, 'w'))\n"
        "sys.exit(1)\n")

    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env.update({
        "PATH": f"{pathlib.Path(sys.executable).parent}:{env['PATH']}",
        "PYTHONPATH": str(tmp_path / "fake_engine"),
        "GH_TOKEN": "must-not-leak",
        "GITHUB_AGENT_TOKEN_X": "must-not-leak-either",
        "BACKPORT_ENV_ALLOW": "GH_TOKEN GITHUB_AGENT_TOKEN_X",
    })
    proc = subprocess.run(
        ["bash", str(RUNNER), "--config", str(cfg),
         "--output-dir", str(tmp_path / "res")],
        capture_output=True, text=True, env=env,
    )
    assert seen.exists(), proc.stdout + proc.stderr
    engine_env = json.loads(seen.read_text())
    assert "GH_TOKEN" not in engine_env
    assert "GITHUB_AGENT_TOKEN_X" not in engine_env
    assert "refusing to pass GH_TOKEN" in proc.stderr


def test_container_never_forwards_github_credentials(tmp_path):
    plan, _explicit, _proc = _container_plan(
        tmp_path,
        {"BACKPORT_SELINUX": "disabled",
         "GH_TOKEN": "must-not-leak", "GITHUB_TOKEN": "must-not-leak"},
    )
    assert "GH_TOKEN" not in plan
    assert "GITHUB_TOKEN" not in plan
