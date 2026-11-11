"""Composition root — config-home resolution."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load,
    resolve_results_root,
)


def _minimal_home(tmp_path: Path) -> Path:
    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "locations": {
                    "workspace": str(tmp_path / "ws"),
                    "analysis_results": str(tmp_path / "ar"),
                    "progress_tracker": str(tmp_path / "pt"),
                }
            }
        ),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            shutil.copy2(name, home / name.name)
    return home


def test_add_config_home_arg():
    import argparse

    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    args = ap.parse_args(["--config-home", "/tmp/cfg"])
    assert args.config_home == Path("/tmp/cfg")


def test_resolve_results_root_from_config(tmp_path, monkeypatch):
    import argparse

    home = _minimal_home(tmp_path)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args([])
    assert resolve_results_root(args) == analysis_results_dir(load())


def test_resolve_results_root_cli_overrides_config(tmp_path, monkeypatch):
    import argparse

    home = _minimal_home(tmp_path)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    override = tmp_path / "override-ar"
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args(["--results-root", str(override)])
    assert resolve_results_root(args) == override.resolve()


def test_resolve_results_root_env_overrides_config(tmp_path, monkeypatch):
    import argparse

    home = _minimal_home(tmp_path)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    env_root = tmp_path / "env-ar"
    monkeypatch.setenv("AUDIT_RESULTS_ROOT", str(env_root))
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args([])
    assert resolve_results_root(args) == env_root.resolve()


def test_resolve_results_root_cli_beats_env(tmp_path, monkeypatch):
    import argparse

    home = _minimal_home(tmp_path)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.setenv("AUDIT_RESULTS_ROOT", str(tmp_path / "env-ar"))
    cli_root = tmp_path / "cli-ar"
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args(["--results-root", str(cli_root)])
    assert resolve_results_root(args) == cli_root.resolve()


def test_resolve_results_root_missing_config_exits_2(tmp_path, monkeypatch):
    # Hermetic: point at a guaranteed-empty config home so the check does not
    # fall back to a real ~/.traust/config on a configured machine.
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(tmp_path / "empty-cfg"))
    monkeypatch.delenv("AUDIT_RESULTS_ROOT", raising=False)
    with pytest.raises(SystemExit) as exc:
        resolve_results_root()
    assert exc.value.code == 2
