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
    env.update(extra)
    return env


def test_nonzero_engine_exit_overrides_success_shaped_artifacts(tmp_path):
    work = tmp_path
    repo = work / "seamB-repo"
    rem = work / "cri-o.f001-remediation.json"
    configs = work / "configs"
    results = work / "results"

    subprocess.run(["bash", str(FIXTURE), str(work)],
                   check=True, capture_output=True, text=True, env=_env())
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "generate_backport_configs.py"),
         "--remediation", str(rem), "--repo", str(repo),
         "--skip-scan", "--branches", "release-a",
         "--build-cmd", "true", "--test-cmd", "true",
         "--output-dir", str(configs)],
        check=True, capture_output=True, text=True, env=_env(),
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
        ["bash", str(SKILL / "scripts" / "run_backport.sh"),
         "--config-dir", str(configs), "--output-dir", str(results)],
        capture_output=True, text=True, env=env, cwd=str(work),
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr

    bd = results / "release-a"
    summary = json.loads((bd / "summary.json").read_text())
    assert summary["targets"][0]["outcome"] == "success"      # success-shaped
    assert (bd / "candidate.patch").is_file()

    rec = json.loads((bd / "result.json").read_text())
    assert rec["outcome"] == "failed"
    assert rec["engine_exit_code"] == 1
    assert rec["summary_outcome"] == "success"

    report_path = work / "report.json"
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "emit_backport_report.py"),
         "--results-dir", str(results), "--output", str(report_path),
         "--no-publish", "--repository", "https://github.com/o/r",
         "--logical-product", "p"],
        check=True, capture_output=True, text=True, env=_env(),
    )
    report = json.loads(report_path.read_text())
    row = report["target_branches"][0]
    assert row["status"] == "failed"
    assert report["summary"]["failed"] == 1
    assert report["summary"]["succeeded"] == 0
