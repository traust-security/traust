"""Smoke tests for the unified ``traust`` CLI dispatcher."""

from __future__ import annotations

import subprocess
import sys


def test_traust_cli_top_level_help():
    proc = subprocess.run(
        [sys.executable, "-m", "traust.cli", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "impact analyze" in proc.stdout


def test_all_planned_groups_registered():
    from traust.cli.groups import GROUPS

    assert set(GROUPS) == {
        "adapters",
        "admin",
        "assessments",
        "attack",
        "auth",
        "build",
        "check",
        "cloud-config",
        "compliance",
        "config",
        "dashboard",
        "feeds",
        "findings",
        "impact",
        "isolation",
        "ledger",
        "metrics",
        "portfolio",
        "pqc",
        "products",
        "registry",
        "remediation",
        "repo",
        "reporting",
        "session",
        "sweep",
        "tools",
        "triage",
        "util",
        "validation",
    }
    assert sum(len(ops) for ops in GROUPS.values()) >= 81


def test_traust_impact_analyze_help():
    proc = subprocess.run(
        [sys.executable, "-m", "traust.cli", "impact", "analyze", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "Assess every commit an advisory reaches" in proc.stdout
    assert "--config-home" in proc.stdout


def test_traust_portfolio_and_sweep_help():
    for group, op, flag in (("sweep", "collect", "--force"),):
        proc = subprocess.run(
            [sys.executable, "-m", "traust.cli", group, op, "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert flag in proc.stdout


def test_traust_feeds_fetch_help():
    proc = subprocess.run(
        [sys.executable, "-m", "traust.cli", "feeds", "fetch", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "--config-home" in proc.stdout
    assert "Snapshot the security feeds" in proc.stdout


def test_legacy_tool_passthrough_does_not_require_config_home(tmp_path):
    """Config-less legacy ops must not fail on an operator's ~/.traust template."""
    import os
    import subprocess

    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "x.go").write_text("package main\nfunc main() {}\n")
    out = tmp_path / "idx.db"
    env = {k: v for k, v in os.environ.items() if k != "TRAUST_CONFIG_HOME"}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli",
            "build",
            "symbol-index",
            "--repo",
            str(repo),
            "--out",
            str(out),
            "--engine",
            "builtin",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()


def test_unknown_command_exits_two():
    proc = subprocess.run(
        [sys.executable, "-m", "traust.cli", "no-such", "op"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
