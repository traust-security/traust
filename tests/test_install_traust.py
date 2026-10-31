"""scripts/install_traust — the adopter's starting point and its --doctor."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "install_traust"


def _run(args, env_extra=None, cwd=REPO):
    env = {**os.environ, "HOME": os.environ.get("HOME", "/tmp"), **(env_extra or {})}
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=cwd
    )


def test_help_exits_zero():
    r = _run(["--help"])
    assert r.returncode == 0 and "TRAUST_CONFIG_HOME" in r.stdout


def test_noninteractive_install_copies_traust_yaml_and_the_model_registry(tmp_path):
    home = tmp_path / "cfg"
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(p.name for p in home.iterdir()) == ["model-registry.yaml", "traust.yaml"]
    assert (home / "traust.yaml").read_text() == (
        REPO / "config" / "traust.example.yaml"
    ).read_text()
    assert (home / "model-registry.yaml").read_text() == (
        REPO / "config" / "model-registry.yaml"
    ).read_text()


def test_install_never_overwrites_without_force(tmp_path):
    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text("execution: {sandbox: podman}\n")
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0
    assert (home / "traust.yaml").read_text() == "execution: {sandbox: podman}\n"
    assert "kept existing traust.yaml" in r.stdout


def test_doctor_fails_closed_when_unset_and_default_absent(tmp_path):
    env = {"HOME": str(tmp_path)}
    r = subprocess.run(
        ["bash", str(SCRIPT), "--doctor"],
        capture_output=True,
        text=True,
        env={k: v for k, v in {**os.environ, **env}.items() if k != "TRAUST_CONFIG_HOME"},
        cwd=REPO,
    )
    assert r.returncode == 1 and "run scripts/install_traust" in r.stdout


def test_doctor_checks_the_config_home_the_wrapper_was_given(tmp_path):
    """--config-home names the home --doctor audits: the wrapper's flag wins over
    TRAUST_CONFIG_HOME, so it never reports on a different installation."""
    complete = tmp_path / "complete"
    complete.mkdir()
    (complete / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "locations": {
                    "workspace": str(tmp_path / "ws"),
                    "analysis_results": str(tmp_path / "ar"),
                    "progress_tracker": str(tmp_path / "pt"),
                },
                "ledger": {"public_key_path": str(tmp_path / "cosign.pub")},
            }
        )
    )
    (complete / "model-registry.yaml").write_text(
        (REPO / "config" / "model-registry.yaml").read_text()
    )
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "traust.yaml").write_text((REPO / "config" / "traust.example.yaml").read_text())
    (bare / "model-registry.yaml").write_text((REPO / "config" / "model-registry.yaml").read_text())
    r = _run(
        ["--doctor", "--config-home", str(bare)],
        env_extra={"TRAUST_CONFIG_HOME": str(complete), "HOME": str(tmp_path)},
    )
    assert r.returncode == 1, r.stdout + r.stderr
    assert "traust.yaml: locations.workspace unset" in r.stdout


def test_doctor_with_toolchain_runs_the_profiles_scanner_check(tmp_path):
    """--toolchain PROFILE keeps its meaning beside --doctor: the profile's scanner
    check (traust admin toolchain doctor) runs too, so a degraded profile surfaces."""
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    r = _run(
        ["--doctor", "--toolchain", "secure-code-audit"],
        env_extra={"TRAUST_CONFIG_HOME": str(home), "HOME": str(tmp_path)},
    )
    assert "Toolchain doctor for profile: secure-code-audit" in r.stdout


def test_doctor_with_toolchain_checks_the_config_home_the_wrapper_was_given(tmp_path):
    """--toolchain PROFILE doctors the chosen home too: the scanner check loads
    the same --config-home the preflight above it got, not the shell's
    TRAUST_CONFIG_HOME (which, when it doesn't resolve, exits 2 beside a home
    that is fine)."""
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "traust.yaml").write_text("not: [valid\n")  # unresolvable config
    r = _run(
        ["--doctor", "--toolchain", "secure-code-audit", "--config-home", str(home)],
        env_extra={"TRAUST_CONFIG_HOME": str(broken), "HOME": str(tmp_path)},
    )
    assert "Toolchain doctor for profile: secure-code-audit" in r.stdout
    assert "not resolvable" not in r.stdout + r.stderr


def test_doctor_resolves_a_relative_config_home_against_the_callers_cwd(tmp_path):
    """A relative --config-home names the caller's folder, not the repo root the
    doctor's subshell cds into (do_install absolutizes the same way): run from
    outside the repo, the check must audit the caller's home, not a
    $REPO_ROOT-shaped path that doesn't exist."""
    home = tmp_path / "caller" / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    caller = tmp_path / "caller"
    r = _run(
        ["--doctor", "--config-home", "cfg"],
        cwd=caller,
        env_extra={"HOME": str(tmp_path)},
    )
    assert r.returncode == 1, r.stdout + r.stderr
    # the doctor read the caller's cfg (a fresh install: the example's unset
    # keys), proving the home resolved against the caller's directory
    assert "traust.yaml: locations.workspace unset" in r.stdout


def test_doctor_delegates_to_traust_admin_doctor(tmp_path):
    """One code path: --doctor runs `traust admin doctor` (core's preflight), so a fresh
    install fails naming exactly the keys still to fill in."""
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    r = _run(["--doctor"], env_extra={"TRAUST_CONFIG_HOME": str(home), "HOME": str(tmp_path)})
    assert r.returncode == 1, r.stdout + r.stderr
    assert "harness doctor" in r.stdout
    assert "traust.yaml: locations.workspace unset" in r.stdout
    assert "preflight: every enabled asset's requirements are met" not in r.stdout


@pytest.mark.skipif(
    not os.environ.get("TRAUST_CONFIG_HOME") or os.environ.get("HARNESS_TEST_FIXTURE_CONFIG"),
    reason="no operational config in this environment (the suite fixture is a bare template)",
)
def test_doctor_passes_on_the_operational_config():
    """With a real TRAUST_CONFIG_HOME (developer workstation / SCI) the doctor's preflight
    finds no gap in the operator's own home."""
    r = _run(["--doctor"])
    assert "traust-core store reachable" in r.stdout, r.stdout
    assert "locations.workspace unset" not in r.stdout
