"""`load`: traust-core registers its own providers for its protocols, so the doors behind them
run instead of raising their "not registered" ConfigError."""

from __future__ import annotations

import shutil
from importlib.metadata import version
from pathlib import Path

import pytest
import yaml

from traust.context import load
from traust.paths import GITLEAKS_CONFIG, OPENGREP_RULES_DIR

FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURE_CONFIG, config)
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return config


def test_every_engine_provider_is_wired(home: Path) -> None:
    core = load(home)
    assert core.adr_source is not None and core.doc_source is not None
    assert core.rule_packs is not None and core.canaries is not None
    assert core.fleet_fix_applier is not None and core.fleet_fix_goldens is not None


def test_services_read_the_rule_packs_through_the_engine(home: Path) -> None:
    packs = load(home).services().detection_quality.rule_packs()
    assert packs and packs[0].rules


def test_canary_sources_are_the_named_recall_benchmark_dir(home: Path) -> None:
    core = load(home, canaries="seeded")
    assert not core.canaries.check().ready
    assert str(home / "recall-benchmark" / "seeded") in core.canaries.check().detail


def test_the_scanner_tools_and_their_inspector_are_wired(home: Path) -> None:
    core = load(home)
    assert set(core.tools.names()) >= {
        "checkov",
        "gitleaks",
        "gitleaks-history",
        "govulncheck",
        "grype",
        "joern",
        "opengrep",
        "osv",
        "osv_sbom",
        "yara",
    }
    assert core.tool_inspector is None  # each tool reports its own version and database
    core.tools.get("gitleaks")  # the pins load with the engine, on first use
    assert core.tool_floors.get("gitleaks")  # external-tools.yaml pins are the floors


def test_the_catalog_answers_readiness_for_every_registered_tool(home: Path) -> None:
    catalog = load(home).services().catalog
    names = {b.capability.name for b in catalog.readiness(None)}
    assert {"gitleaks", "grype", "opengrep", "checkov"} <= names


def test_run_tools_reaches_a_core_tool_through_load(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime

    from traust_core.v1.models.artifacts import AdapterResultArtifact
    from traust_core.v1.models.assessment import ToolName
    from traust_core.v1.providers.base import Readiness
    from traust_core.v1.providers.tools import grype
    from traust_core.v1.providers.tools.adapter import AdapterTool, adapter_result

    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    monkeypatch.setattr(
        grype,
        "scan",
        lambda t, *_, **__: adapter_result(str(t), "grype", [], scanned_at=datetime.now(UTC)),
    )
    run = load(home).services().assessment.run_tools(tmp_path, [ToolName("grype")])
    assert run.data("grype", AdapterResultArtifact).metadata.tool == "grype"


def test_unset_gitleaks_rules_resolve_to_the_packs_file(home: Path) -> None:
    path = load(home).config.locations.gitleaks_config_path()
    assert path == GITLEAKS_CONFIG and path.is_file()


def test_an_explicit_gitleaks_location_wins(home: Path, tmp_path: Path) -> None:
    rules = tmp_path / "gitleaks.toml"
    rules.write_text("")
    (home / "traust.yaml").write_text(
        yaml.safe_dump({"locations": {"gitleaks_config": str(rules)}})
    )
    assert load(home).config.locations.gitleaks_config_path() == rules


def test_the_rule_pack_defaults_to_the_packs_rules_at_the_traust_version(home: Path) -> None:
    core = load(home)
    assert core.rule_pack == OPENGREP_RULES_DIR
    assert {p.version for p in core.services().detection_quality.rule_packs()} == {
        version("traust")
    }


def test_an_explicit_rule_pack_location_wins(home: Path, tmp_path: Path) -> None:
    (home / "traust.yaml").write_text(yaml.safe_dump({"locations": {"opengrep_rules": "rules"}}))
    assert load(home).rule_pack == (home / "rules").resolve()
