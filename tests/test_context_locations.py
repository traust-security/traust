"""traust's location helpers read core's ``Config.locations`` and resolve every path the engine did.

``ENGINE`` holds the paths ``traust_engine.locations`` resolved for each ``locations`` row
(captured before the engine was dropped); a helper absent from a row raised
``DeploymentConfigMissing``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from traust_core.v1.errors import DeploymentConfigMissing

from traust import context
from traust.context import load
from traust.paths import HARNESS_ROOT

FIXTURE = Path(__file__).parent / "fixtures" / "config"
HELPERS = (
    "analysis_results_dir",
    "workspace_dir",
    "inputs_dir",
    "findings_db",
    "findings_tree_dir",
    "progress_tracker_dir",
    "rule_drafts_dir",
    "feeds_cache_dir",
)


def _home(tmp_path: Path, locations: dict | None) -> Path:
    home = tmp_path / "cfg"
    home.mkdir()
    for f in FIXTURE.iterdir():
        if f.is_file():
            shutil.copy2(f, home / f.name)
    if locations is not None:
        (home / "traust.yaml").write_text(
            yaml.safe_dump({"locations": locations}), encoding="utf-8"
        )
    return home


ROWS = {
    "absolute": {"workspace": "/w", "analysis_results": "/ar", "progress_tracker": "/pt"},
    "relative": {"workspace": "./ws", "analysis_results": "../ar", "progress_tracker": "a/../pt"},
    "file uri": {"workspace": "file:///w", "analysis_results": "file:///ar"},
    "remote": {"workspace": "s3://b/w", "analysis_results": "gs://b/ar", "feeds_cache": "az://c"},
    "explicit": {
        "workspace": "/w",
        "analysis_results": "/ar",
        "progress_tracker": "/pt",
        "rule_drafts": "./drafts",
        "feeds_cache": "/fc",
    },
    "inputs relative": {"workspace": "/w", "inputs": "./inv"},
    "inputs absolute": {"workspace": "/w", "inputs": "/inv"},
    "inputs file uri": {"workspace": "/w", "inputs": "file:///inv"},
    "empty strings": {"workspace": "", "analysis_results": "", "progress_tracker": ""},
    "no file": None,
}


ENGINE = {
    "absolute": {
        "analysis_results_dir": "/ar",
        "workspace_dir": "/w",
        "inputs_dir": "/w/inputs",
        "findings_db": "/ar/graph/findings.db",
        "findings_tree_dir": "/ar/findings",
        "progress_tracker_dir": "/pt",
        "rule_drafts_dir": "/pt/metrics/rule-mining/rule-drafts",
        "feeds_cache_dir": "/pt/feeds",
    },
    "relative": {
        "analysis_results_dir": "{home}/../ar",
        "workspace_dir": "{home}/ws",
        "inputs_dir": "{home}/ws/inputs",
        "findings_db": "{home}/../ar/graph/findings.db",
        "findings_tree_dir": "{home}/../ar/findings",
        "progress_tracker_dir": "{home}/pt",
        "rule_drafts_dir": "{home}/pt/metrics/rule-mining/rule-drafts",
        "feeds_cache_dir": "{home}/pt/feeds",
    },
    "file uri": {
        "analysis_results_dir": "/ar",
        "workspace_dir": "/w",
        "inputs_dir": "/w/inputs",
        "findings_db": "/ar/graph/findings.db",
        "findings_tree_dir": "/ar/findings",
    },
    "remote": {},
    "explicit": {
        "analysis_results_dir": "/ar",
        "workspace_dir": "/w",
        "inputs_dir": "/w/inputs",
        "findings_db": "/ar/graph/findings.db",
        "findings_tree_dir": "/ar/findings",
        "progress_tracker_dir": "/pt",
        "rule_drafts_dir": "{home}/drafts",
        "feeds_cache_dir": "/fc",
    },
    "inputs relative": {"workspace_dir": "/w", "inputs_dir": "{home}/inv"},
    "inputs absolute": {"workspace_dir": "/w", "inputs_dir": "/inv"},
    "inputs file uri": {"workspace_dir": "/w", "inputs_dir": "/inv"},
    "empty strings": {},
    "no file": {},
}


def _before(row: str, name: str, home: Path, feeds_env: str | None) -> Path | type:
    if name == "feeds_cache_dir" and feeds_env:
        return Path(feeds_env).expanduser().resolve()
    if (path := ENGINE[row].get(name)) is None:
        return DeploymentConfigMissing
    return Path(os.path.normpath(path.format(home=home)))


def _outcome(fn):
    try:
        return fn()
    except DeploymentConfigMissing:
        return DeploymentConfigMissing


@pytest.mark.parametrize("feeds_env", [None, "~/feeds"], ids=["config", "FEEDS_CACHE_DIR"])
@pytest.mark.parametrize("row", ROWS, ids=list(ROWS))
def test_core_locations_resolve_the_paths_the_engine_did(tmp_path, monkeypatch, row, feeds_env):
    home = _home(tmp_path, ROWS[row])
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    if feeds_env:
        monkeypatch.setenv("FEEDS_CACHE_DIR", feeds_env)
    else:
        monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    core = load(home)
    for name in HELPERS:
        helper = getattr(context, name)
        expected = _before(row, name, home.resolve(), feeds_env)
        assert _outcome(lambda helper=helper: helper(core)) == expected, name


def test_a_remote_inputs_location_is_refused(tmp_path, monkeypatch):
    """Behaviour change: the engine-era helper fell back to ``<workspace>/inputs``."""
    home = _home(tmp_path, {"workspace": "/w", "inputs": "s3://b/inv"})
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    with pytest.raises(DeploymentConfigMissing, match="inputs"):
        context.inputs_dir(load(home))


@pytest.mark.parametrize(
    ("workspace", "inputs", "registered"),
    [
        ("s3://example/workspace", None, False),
        ("/workspace", "s3://example/inputs", False),
        ("s3://example/workspace", "./inputs", True),
        ("s3://example/workspace", "file:///inventory", True),
        ("/workspace", None, True),
        ("file:///workspace", None, True),
    ],
)
def test_loading_registers_release_inventory_only_for_the_selected_local_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workspace: str,
    inputs: str | None,
    registered: bool,
) -> None:
    """Remote locations remain configured; only local inventory has a release provider."""
    locations = {"workspace": workspace}
    if inputs is not None:
        locations["inputs"] = inputs
    home = _home(tmp_path, locations)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    core = load(home)
    assert ("release-inventory" in core.feeds.names()) is registered
    if not registered:
        with pytest.raises(DeploymentConfigMissing):
            context.inputs_dir(core)
        assert core.config.locations.workspace == workspace
        assert core.config.locations.inputs == inputs


@pytest.mark.parametrize("key", ["workspace", "analysis_results", "findings"])
def test_traust_paths_sh_prints_the_configured_path(tmp_path, key):
    home = _home(tmp_path, {"workspace": "/w", "analysis_results": "./ar"})
    lib = HARNESS_ROOT / "harnessing" / "_lib" / "traust_paths.sh"
    out = subprocess.run(
        ["bash", "-c", f'source "{lib}" && _traust_path {key}'],
        env={**os.environ, "TRAUST_CONFIG_HOME": str(home)},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    expected = {
        "workspace": "/w",
        "analysis_results": home / "ar",
        "findings": home / "ar" / "findings",
    }
    assert out == str(Path(expected[key]).resolve())
