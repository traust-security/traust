#!/usr/bin/env python3
"""Fail-closed native scanner coverage; invoked after the pinned toolchain install."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "tests/test_default_rule_packs.py",
    "tests/test_sweep_regression_drafts.py",
    "tests/test_symbol_index.py",
    "tests/test_native_scanner_ci.py",
)
REQUIRED_CASES = {
    ("tests.test_default_rule_packs", "test_default_opengrep_run_reports_a_current_rule"),
    ("tests.test_default_rule_packs", "test_default_gitleaks_run_reports_a_traust_detector"),
    ("tests.test_default_rule_packs", "test_target_nosem_comment_does_not_hide_a_fact"),
    ("tests.test_sweep_regression_drafts", "test_a_draft_verifies_with_opengrep"),
    ("tests.test_symbol_index.TestCtagsEngine", "test_ctags_build_finds_core_symbols"),
}
INVERSE_CASE = (
    "tests.test_symbol_index.TestEngineErrors",
    "test_ctags_engine_without_binary_errors",
)
INVERSE_REASON = "universal-ctags is installed"
SKIP_LINE = re.compile(r"^SKIPPED \[(\d+)\] (.+?):\d+: (.+)$", re.MULTILINE)


def probe(argv: list[str], *, cwd: Path | None = None) -> str:
    """Require an executable tool, a successful exit, and usable stdout."""
    done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=30, check=True)
    if not done.stdout.strip():
        raise RuntimeError(f"{argv[0]} returned no stdout")
    return done.stdout.strip()


def check_ctags(binary: str) -> str:
    """Check Universal identity AND the exact recursive JSON interface the index uses."""
    version = probe([binary, "--options=NONE", "--version"])
    if "Universal Ctags" not in version:
        raise RuntimeError(f"{binary} is not Universal Ctags (BSD ctags is incompatible)")
    with tempfile.TemporaryDirectory(prefix="traust-ctags-preflight-") as directory:
        root = Path(directory)
        (root / "nested").mkdir()
        (root / "nested" / "probe.py").write_text(
            "def native_scanner_canary():\n    return 1\n", encoding="utf-8"
        )
        output = probe(
            [
                binary,
                "--options=NONE",
                "--output-format=json",
                "--fields=+nKl",
                "-R",
                "-f",
                "-",
                ".",
            ],
            cwd=root,
        )
        tags = [json.loads(line) for line in output.splitlines()]
        if not any(
            tag.get("_type") == "tag"
            and tag.get("name") == "native_scanner_canary"
            and tag.get("path", "").removeprefix("./") == "nested/probe.py"
            and tag.get("line") == 1
            and tag.get("language") == "Python"
            for tag in tags
        ):
            raise RuntimeError("Universal Ctags did not produce compatible recursive JSON symbols")
    return version.splitlines()[0]


def required_tools() -> dict[str, str]:
    """Locate every required binary before trying version/scan subprocesses."""
    binaries = {}
    for tool in ("opengrep", "gitleaks"):
        binary = shutil.which(tool)
        if binary is None:
            raise RuntimeError(f"required scanner is missing: {tool}")
        binaries[tool] = binary
    # Preserve the consumer's discovery order and reject BSD ctags.
    from traust.cli.build_symbol_index import find_universal_ctags

    ctags = find_universal_ctags()
    if ctags is None:
        raise RuntimeError(
            "required compatible Universal Ctags is missing (BSD ctags does not count)"
        )
    binaries["universal-ctags"] = ctags
    return binaries


def preflight() -> dict[str, str]:
    import yaml
    from traust_core.v1.context.config import SHIPPED_EXTERNAL_TOOLS

    pins = {
        tool["name"]: tool["expected"]
        for tool in yaml.safe_load(SHIPPED_EXTERNAL_TOOLS.read_text(encoding="utf-8"))["tools"]
    }
    binaries = required_tools()
    versions = {}
    for tool, arguments in (("opengrep", ["--version"]), ("gitleaks", ["version"])):
        actual = probe([binaries[tool], *arguments])
        match = re.search(r"(?<![\d.])(\d+\.\d+\.\d+)(?![\d.])", actual)
        if match is None or match.group(1) != pins[tool]:
            raise RuntimeError(f"{tool} must match the shipped pin {pins[tool]}, got {actual!r}")
        versions[tool] = actual

    version = check_ctags(binaries["universal-ctags"])
    match = re.search(r"Universal Ctags (\d+\.\d+\.\d+)", version)
    expected = pins.get("universal-ctags")
    if expected is None or match is None or match.group(1) != expected:
        raise RuntimeError(
            f"Universal Ctags must match the shipped pin {expected}, got {version!r}"
        )
    versions["universal-ctags"] = version
    return versions


def check_report(output: str, junit: Path, *, required: set[tuple[str, str]]) -> dict[str, int]:
    """Parse real -rs reasons and JUnit identities; allow only the inverse binary test."""
    root = ET.parse(junit).getroot()
    cases = root.findall(".//testcase")
    passed = set()
    skips = []
    for case in cases:
        identity = (case.get("classname", ""), case.get("name", ""))
        skipped = case.find("skipped")
        if skipped is not None:
            if identity != INVERSE_CASE or skipped.get("message") != INVERSE_REASON:
                raise RuntimeError(f"unexpected skipped test: {identity}: {skipped.get('message')}")
            skips.append(identity)
        elif case.find("failure") is None and case.find("error") is None:
            passed.add(identity)
    if missing := required - passed:
        raise RuntimeError(f"required scanner cases did not pass: {sorted(missing)}")
    reasons = SKIP_LINE.findall(output)
    if sum(int(count) for count, _, _ in reasons) != len(skips):
        raise RuntimeError("pytest -rs skip reasons disagree with JUnit skip results")
    for count, location, reason in reasons:
        if int(count) != 1 or location != "tests/test_symbol_index.py" or reason != INVERSE_REASON:
            raise RuntimeError(f"unexpected pytest -rs skip: {location}: {reason}")
    return {"passed": len(passed), "skipped_inverse_missing_binary": len(skips)}


def run_pytest(paths: list[str], artifacts: Path, *, required: set[tuple[str, str]]) -> int:
    artifacts.mkdir(parents=True, exist_ok=True)
    junit = artifacts / "pytest.xml"
    env = {**os.environ, "PYTEST_ADDOPTS": "", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    done = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "-q", "-rs", "--color=no", f"--junitxml={junit}"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    print(done.stdout, end="", flush=True)
    (artifacts / "pytest.log").write_text(done.stdout, encoding="utf-8")
    if done.returncode:
        return done.returncode
    summary = check_report(done.stdout, junit, required=required)
    (artifacts / "summary.json").write_text(json.dumps(summary) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / ".native-scanner-results")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    versions = preflight()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts / "tool-versions.json").write_text(
        json.dumps(versions, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(versions, indent=2), flush=True)
    if args.preflight_only:
        return 0
    return run_pytest(list(MODULES), args.artifacts, required=REQUIRED_CASES)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, ET.ParseError) as error:
        print(f"native scanner gate: {error}", file=sys.stderr)
        raise SystemExit(1) from error
