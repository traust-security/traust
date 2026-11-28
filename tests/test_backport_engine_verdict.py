"""A nonzero engine exit must not leave a success-shaped verdict behind.

Runs the real run_backport.sh collection path against the mock engine wrapped
to exit 1 *after* writing a success summary and candidate.patch, then checks
that the persisted verdict, the emitter and the delivery gate all honour it.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
SKILL = REPO / "harnessing" / "7-remediate" / "backport-fix"
FIXTURE = SKILL / "test-data" / "mock" / "build_fixture_seam_b.sh"
MOCK = SKILL / "test-data" / "mock" / "mock_amalgamator" / "auto_bug_fix" / "run_bug_fix.py"


def _env(**extra):
    env = os.environ.copy()
    env["PATH"] = f"{pathlib.Path(sys.executable).parent}:{env['PATH']}"
    env.pop("GITHUB_TOKEN", None)
    # Hermetic: a developer's real LLM credential must never reach the mock run.
    for key in (
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_USE_VERTEX",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        env.pop(key, None)
    env.update(extra)
    return env


def test_nonzero_engine_exit_overrides_success_shaped_artifacts(tmp_path):
    work = tmp_path
    repo = work / "seamB-repo"
    rem = work / "widget.f001-remediation.json"
    configs = work / "configs"
    results = work / "results"

    subprocess.run(
        ["bash", str(FIXTURE), str(work)], check=True, capture_output=True, text=True, env=_env()
    )
    subprocess.run(
        [
            sys.executable,
            str(SKILL / "scripts" / "generate_backport_configs.py"),
            "--remediation",
            str(rem),
            "--repo",
            str(repo),
            "--skip-scan",
            "--branches",
            "release-a",
            "--build-cmd",
            "make --version",
            "--test-cmd",
            "make --version",
            "--output-dir",
            str(configs),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=_env(),
    )

    # Fake engine: the real mock writes success artifacts, then we force exit 1.
    pkg = work / "fake_engine" / "auto_bug_fix"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "run_bug_fix.py").write_text(
        "import runpy, sys\n"
        f"try:\n    runpy.run_path({str(MOCK)!r}, run_name='__main__')\n"
        "except SystemExit:\n    pass\n"
        "sys.exit(1)\n"
    )
    env = _env(PYTHONPATH=str(work / "fake_engine"))

    proc = subprocess.run(
        [
            "bash",
            str(SKILL / "scripts" / "run_backport.sh"),
            "--config-dir",
            str(configs),
            "--output-dir",
            str(results),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(work),
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr

    bd = results / "release-a"
    summary = json.loads((bd / "summary.json").read_text())
    assert summary["targets"][0]["outcome"] == "success"  # success-shaped
    assert (bd / "candidate.patch").is_file()

    rec = json.loads((bd / "result.json").read_text())
    assert rec["outcome"] == "failed"
    assert rec["engine_exit_code"] == 1
    assert rec["summary_outcome"] == "success"

    # The batch summary must agree with that verdict, not with the engine's
    # success-shaped summary, or CI reads the run as successful.
    batch = json.loads((results / "run_summary.json").read_text())
    assert [row["branch"] for row in batch["branches"]] == ["release-a"]
    assert batch["branches"][0]["status"] == "failed"
    assert (batch["total"], batch["passed"], batch["failed"], batch["skipped"]) == (1, 0, 1, 0)

    report_path = work / "report.json"
    subprocess.run(
        [
            sys.executable,
            str(SKILL / "scripts" / "emit_backport_report.py"),
            "--results-dir",
            str(results),
            "--output",
            str(report_path),
            "--no-publish",
            # The contract schema ships with the traust-contracts PR; CI pins
            # an older release until that merges. Validation is covered by the
            # bundled-schema tests and returns with the pin bump.
            "--no-schema",
            "--repository",
            "https://github.com/o/r",
            "--logical-product",
            "p",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=_env(),
    )
    report = json.loads(report_path.read_text())
    row = report["target_branches"][0]
    assert row["status"] == "failed"
    assert report["summary"]["failed"] == 1
    assert report["summary"]["succeeded"] == 0


# --- Qodo #464 runner regressions -------------------------------------------


def _configs(work):
    repo, rem, configs = (
        work / "seamB-repo",
        work / "widget.f001-remediation.json",
        work / "configs",
    )
    subprocess.run(
        ["bash", str(FIXTURE), str(work)], check=True, capture_output=True, text=True, env=_env()
    )
    subprocess.run(
        [
            sys.executable,
            str(SKILL / "scripts" / "generate_backport_configs.py"),
            *("--remediation", str(rem), "--repo", str(repo), "--skip-scan"),
            *("--branches", "release-a", "--output-dir", str(configs)),
            *("--build-cmd", "make --version", "--test-cmd", "make --version"),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=_env(),
    )
    return repo, configs


def _fake_engine(work, tail=""):
    pkg = work / "fake_engine" / "auto_bug_fix"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "run_bug_fix.py").write_text(
        "import runpy, sys\n"
        f"try:\n    runpy.run_path({str(MOCK)!r}, run_name='__main__')\n"
        "except SystemExit:\n    pass\n" + tail
    )
    return str(work / "fake_engine")


def _run(work, configs, results, *extra, **env):
    return subprocess.run(
        [
            "bash",
            str(SKILL / "scripts" / "run_backport.sh"),
            "--config-dir",
            str(configs),
            "--output-dir",
            str(results),
            *extra,
        ],
        capture_output=True,
        text=True,
        env=_env(**env),
        cwd=str(work),
    )


def test_a_run_that_would_forward_a_credential_needs_an_attested_target(tmp_path):
    _, configs = _configs(tmp_path)
    engine = _fake_engine(tmp_path)
    results = tmp_path / "results"
    refused = _run(tmp_path, configs, results, PYTHONPATH=engine, ANTHROPIC_API_KEY="sk-test")
    assert refused.returncode != 0 and "--trusted-target" in refused.stderr
    assert not (results / "release-a").exists()  # nothing ran
    ok = _run(
        tmp_path,
        configs,
        results,
        "--trusted-target",
        PYTHONPATH=engine,
        ANTHROPIC_API_KEY="sk-test",
    )
    assert (results / "release-a" / "result.json").is_file(), ok.stdout + ok.stderr
    assert not (results / ".run_backport.lock").exists()  # released after the run


def test_a_second_run_on_the_same_output_directory_is_refused(tmp_path):
    _, configs = _configs(tmp_path)
    results = tmp_path / "results"
    (results / ".run_backport.lock").mkdir(parents=True)
    (results / "release-a").mkdir()
    (results / "release-a" / "keep").write_text("other run's result")
    r = _run(tmp_path, configs, results, PYTHONPATH=_fake_engine(tmp_path))
    assert r.returncode != 0 and "another run holds" in r.stderr
    assert (results / "release-a" / "keep").read_text() == "other run's result"
    assert (results / ".run_backport.lock").is_dir()  # not ours to remove


def test_a_failed_verdict_write_records_a_failed_branch(tmp_path):
    _, configs = _configs(tmp_path)
    results = tmp_path / "results"
    # the engine succeeds, then the branch's config copy turns unreadable, so
    # the runner's result.json writer fails (it used to be silenced)
    engine = _fake_engine(
        tmp_path, f"open({str(results / 'release-a' / 'config.yaml')!r}, 'w').write('{{{{')\n"
    )
    r = _run(tmp_path, configs, results, PYTHONPATH=engine)
    assert r.returncode != 0, r.stdout + r.stderr
    assert "could not write result.json" in r.stderr
    rec = json.loads((results / "release-a" / "result.json").read_text())
    assert rec["outcome"] == "failed"
    batch = json.loads((results / "run_summary.json").read_text())
    assert (batch["passed"], batch["failed"]) == (0, 1)


@pytest.mark.parametrize("failure", ["selinux preflight", "malformed config"])
def test_a_failed_container_run_leaves_no_temp_config(tmp_path, failure):
    # Qodo #464: the rewritten-config temp dir was created before its cleanup trap
    repo, configs = _configs(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "podman").write_text("#!/bin/sh\nexit 0\n")
    if failure == "selinux preflight":  # enforcing host, unlabeled mounts: fails closed
        (bin_dir / "getenforce").write_text("#!/bin/sh\necho Enforcing\n")
        (bin_dir / "stat").write_text("#!/bin/sh\nexit 1\n")  # no container_file_t label
    else:
        (configs / "release-a.yaml").write_text("build: [unclosed\n")
    for tool in bin_dir.iterdir():
        tool.chmod(0o755)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = _env(TMPDIR=str(scratch))
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    r = subprocess.run(
        [
            "bash",
            str(SKILL / "scripts" / "run_backport.sh"),
            *("--config-dir", str(configs), "--output-dir", str(tmp_path / "results")),
            *("--container-image", "img", "--repo", str(repo)),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )
    assert r.returncode != 0
    assert list(scratch.iterdir()) == [], (r.stderr[-400:], list(scratch.iterdir()))


def test_the_container_rewrite_keeps_isolation_and_quoted_operators(tmp_path):
    import shlex

    text = (SKILL / "scripts" / "run_backport.sh").read_text()
    code = text.split("    python3 -c '\nimport shlex, sys, yaml\n", 1)[1].split(
        '\n\' "$config_file"', 1
    )[0]
    script = tmp_path / "rewrite.py"
    script.write_text("import shlex, sys, yaml\n" + code)
    gen_cfg = tmp_path / "in.yaml"
    wrapped = (
        "/host/py -I -m traust.cli util safe-exec run --profile go-fuzz --timeout 9 -- "
        "make -n '&&' \"it's && ok\" && /host/py -I -m traust.cli util safe-exec run "
        "--profile go-fuzz --timeout 9 -- make -v"
    )
    import yaml as _yaml

    gen_cfg.write_text(_yaml.safe_dump({"build": {"command": wrapped, "test_command": ""}}))
    out = tmp_path / "out.yaml"
    subprocess.run([sys.executable, str(script), str(gen_cfg), str(out)], check=True)
    cmd = _yaml.safe_load(out.read_text())["build"]["command"]
    assert cmd.count("/opt/traust/bin/python -I -m traust.cli util safe-exec run") == 2
    first = cmd.split(" && /opt/traust", 1)[0]
    assert shlex.split(first)[-4:] == ["make", "-n", "&&", "it's && ok"]
    gen_cfg.write_text(_yaml.safe_dump({"build": {"command": "make build"}}))
    refused = subprocess.run([sys.executable, str(script), str(gen_cfg), str(out)])
    assert refused.returncode != 0
