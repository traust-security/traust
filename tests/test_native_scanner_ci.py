"""Exercise the native CI gate with actual pytest subprocesses, not canned reports."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "test-native-scanners.py"
SPEC = importlib.util.spec_from_file_location("native_scanner_ci", SCRIPT)
assert SPEC and SPEC.loader
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


@pytest.mark.parametrize(
    ("present", "missing"),
    [
        ((), "opengrep"),
        (("opengrep",), "gitleaks"),
        (("opengrep", "gitleaks"), "Universal Ctags"),
    ],
)
def test_preflight_rejects_each_missing_scanner(monkeypatch, tmp_path, present, missing):
    # The real Python executable stands in for available paths, but is never
    # executed: absence must fail before any scanner version/scan can run.
    for name in present:
        (tmp_path / name).symlink_to(sys.executable)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(RuntimeError, match=missing):
        ci.required_tools()


def test_preflight_rejects_a_non_ctags_program():
    # Run a real incompatible executable, rather than a fake version-banner script.
    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        ci.check_ctags(sys.executable)


def test_successful_pytest_execution_produces_task_summary(tmp_path):
    test = tmp_path / "test_native_success.py"
    test.write_text("def test_sum():\n    assert sum([2, 3]) == 5\n", encoding="utf-8")
    artifacts = tmp_path / "artifacts"
    assert ci.run_pytest([str(test)], artifacts, required=set()) == 0
    assert json.loads((artifacts / "summary.json").read_text(encoding="utf-8")) == {
        "passed": 1,
        "skipped_inverse_missing_binary": 0,
    }


def test_missing_dependency_skip_cannot_make_native_gate_green(tmp_path):
    test = tmp_path / "test_native_missing.py"
    test.write_text(
        "import pytest\n\n"
        "def test_dependency():\n"
        "    pytest.importorskip('traust_intentionally_missing_native_dependency')\n",
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    with pytest.raises(RuntimeError, match="unexpected skipped test"):
        ci.run_pytest([str(test)], artifacts, required=set())
    assert not (artifacts / "summary.json").exists()


def test_deselected_required_case_cannot_make_native_gate_green(tmp_path):
    test = tmp_path / "test_native_other.py"
    test.write_text("def test_other():\n    assert 2 + 2 == 4\n", encoding="utf-8")
    artifacts = tmp_path / "artifacts"
    with pytest.raises(RuntimeError, match="required scanner cases did not pass"):
        ci.run_pytest([str(test)], artifacts, required=ci.REQUIRED_CASES)
    assert not (artifacts / "summary.json").exists()


def test_pytest_failure_is_preserved(tmp_path):
    test = tmp_path / "test_native_failure.py"
    test.write_text("def test_failure():\n    assert False\n", encoding="utf-8")
    artifacts = tmp_path / "artifacts"
    assert ci.run_pytest([str(test)], artifacts, required=set()) == 1
    assert not (artifacts / "summary.json").exists()


def test_actual_inverse_missing_binary_case_remains_valid(tmp_path):
    # With ctags installed the repository's real inverse case legitimately skips;
    # without it that same case runs and passes. Neither outcome is forced here.
    assert (
        ci.run_pytest(
            [
                "tests/test_symbol_index.py::TestEngineErrors::test_ctags_engine_without_binary_errors"
            ],
            tmp_path / "artifacts",
            required=set(),
        )
        == 0
    )
