"""`traust admin doctor`: core's preflight (the same findings the engine's start gate refuses
on) as FAIL rows, the store/catalog rows, and each value's source. The store and catalog are
core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context, validate_config
from traust_core.v1.errors import ConfigError, PreflightError
from traust_core.v1.models.operations import Requirement
from traust_core.v1.providers.base import Readiness
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind, ProviderBinding

from traust.cli import doctor
from traust.context import load

CHECKOV = ProviderBinding(
    capability=Capability(kind=CapabilityKind.TOOL, name="checkov"),
    readiness=Readiness(ready=True),
)
OSV = ProviderBinding(
    capability=Capability(kind=CapabilityKind.FEED, name="osv"),
    readiness=Readiness(ready=False, detail="offline"),
)

GRAMMARS = {
    "Java": Readiness(ready=True),
    "Ruby": Readiness(ready=False, detail="the Ruby grammar (tree-sitter-ruby) won't import"),
}


def stub(monkeypatch: pytest.MonkeyPatch, list_products: Any) -> list[Any]:
    asked: list[Any] = []
    services = SimpleNamespace(
        portfolio=SimpleNamespace(list_products=list_products),
        catalog=SimpleNamespace(
            readiness=lambda capability, network: (
                asked.append((capability, network)) or [CHECKOV, OSV]
            )
        ),
        code_facts=SimpleNamespace(grammar_readiness=lambda: GRAMMARS),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return asked


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    _fill(config, tmp_path)
    return config


def _fill(config: Path, tmp_path: Path) -> None:
    """A home the completeness audit accepts: traust.yaml with the estate keys set, plus the
    shipped model registry install_traust copies."""
    (config / "traust.yaml").write_text(
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
    repo = Path(__file__).resolve().parents[1]
    (config / "model-registry.yaml").write_text(
        (repo / "config" / "model-registry.yaml").read_text()
    )


@pytest.fixture
def gitleaks_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A gitleaks that passes the pin on a stubbed PATH: the pack's repo_state requires it
    (see assets.yaml), so the tests that assert the config-home rows stay independent of
    the machine's scanners — a runner without gitleaks would otherwise add a FAIL row."""
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "gitleaks").write_text("#!/bin/sh\necho 999.0.0\n")
    (stub / "gitleaks").chmod(0o755)
    monkeypatch.setenv("PATH", str(stub))


def test_a_reachable_store_and_every_providers_readiness(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    asked = stub(monkeypatch, lambda page: SimpleNamespace(items=[]))
    results: list[tuple[str, str]] = []
    doctor.check_core(results, home)
    assert asked == [(None, True)]
    assert results == [
        (doctor.OK, "traust-core store reachable"),
        (doctor.OK, "provider tool checkov ready"),
        (doctor.WARN, "provider feed osv not ready — offline"),
        (doctor.OK, "Java grammar loads"),
        (
            doctor.WARN,
            "the Ruby grammar (tree-sitter-ruby) won't import; its routes are a coverage gap",
        ),
    ]


def test_an_unreachable_store_fails_and_skips_the_catalog(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    def refused(page: Any) -> Any:
        raise ConfigError("no database")

    asked = stub(monkeypatch, refused)
    results: list[tuple[str, str]] = []
    assert doctor.check_core(results, home) is None
    assert asked == []
    assert results == [(doctor.FAIL, "traust-core store not reachable — no database")]


def test_main_reports_the_core_rows_and_exits_by_failures(
    monkeypatch: pytest.MonkeyPatch, home: Path, gitleaks_on_path: None
) -> None:
    asked = stub(monkeypatch, lambda page: SimpleNamespace(items=[]))
    for check in ("check_python", "check_tools", "check_gates"):
        monkeypatch.setattr(doctor, check, lambda results: None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = doctor.main(["--config-home", str(home), "--quick", "--json"])
    assert rc == 0
    rows = json.loads(out.getvalue())
    assert rows[0]["check"] == "traust-core store reachable"
    assert asked == [(None, False)]  # --quick skips the feed sources' network probes


def _doctor(home: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, list[dict[str, str]]]:
    stub(monkeypatch, lambda page: SimpleNamespace(items=[]))
    for check in ("check_python", "check_tools", "check_gates"):
        monkeypatch.setattr(doctor, check, lambda results: None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = doctor.main(["--config-home", str(home), "--quick", "--json"])
    return rc, json.loads(out.getvalue())


def test_a_required_gap_is_a_fail_row_and_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gitleaks_on_path: None
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    assert [r["check"] for r in rows if r["status"] == "FAIL"] == [
        "traust.yaml: locations.workspace unset",
        "traust.yaml: locations.analysis_results unset",
        "traust.yaml: locations.progress_tracker unset",
        "traust.yaml: ledger.public_key_path unset — layer signatures are not verified",
    ]


def _pack_requires(path: Path) -> list[Requirement]:
    """The pack fixture's requirements, parsed the way the engine's start gate does: the
    `requires:` blocks of every enabled asset (the pack file is the shared fixture)."""
    raw = yaml.safe_load(path.read_text())
    validate_config("pack", raw)
    return [
        Requirement(**asset["requires"])
        for asset in raw["assets"].values()
        if asset.get("enabled") is not False and asset.get("requires")
    ]


PACK_FIXTURE = """\
pack: fixture
assets:
  tool_asset:
    run: [/bin/true]
    requires: {tools: [gitleaks]}
  estate_asset:
    run: [/bin/true]
    requires: {config: [identity], facts: [sla-policy], secrets: [GITLAB_TOKEN]}
  disabled_asset:
    run: [/bin/true]
    enabled: false
    requires: {tools: [syft]}
"""


def test_doctor_and_the_engine_start_gate_agree_on_one_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One preflight path: doctor's FAIL rows are exactly the findings the engine's start
    gate (Context.preflight on the same pack) refuses on, for the same home."""
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    pack = tmp_path / "assets.yaml"
    pack.write_text(PACK_FIXTURE)
    monkeypatch.setattr(doctor, "PACK_ASSETS", pack)
    for var in ("GITLAB_TOKEN", "CCA_BICEP", "FEEDS_CACHE_DIR", "GIT_HOSTS"):
        monkeypatch.delenv(var, raising=False)

    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    reported = sorted(r["check"] for r in rows if r["status"] == "FAIL")

    # The engine's start gate: Context.preflight on the same pack, the home named by the
    # environment (core's preflight audits the env-resolved home, as it does for the engine).
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    with pytest.raises(PreflightError) as refused:
        load(home).preflight(_pack_requires(pack))
    gated = sorted(
        line[2:]
        for line in str(refused.value).splitlines()[1:]  # past "preflight: N unmet requirement(s):"
        if line.startswith("- ")
    )
    assert reported == gated
    assert any("facts: sla-policy is not recorded" in finding for finding in gated)
    assert any("secrets: $GITLAB_TOKEN is not set" in finding for finding in gated)
    assert any("config: `identity` is not set" in finding for finding in gated)


def test_a_fresh_home_from_traust_example_yaml_names_exactly_what_is_still_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gitleaks_on_path: None
) -> None:
    """Lean adoption: copy traust.example.yaml, run doctor — it fails naming exactly the keys
    still needed (no facts: traust's composition root registers the pack's defaults) and
    passes once they are set."""
    repo = Path(__file__).resolve().parents[1]
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text((repo / "config" / "traust.example.yaml").read_text())
    (home / "model-registry.yaml").write_text((repo / "config" / "model-registry.yaml").read_text())
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    assert [r["check"] for r in rows if r["status"] == "FAIL"] == [
        "traust.yaml: locations.workspace unset",
        "traust.yaml: locations.analysis_results unset",
        "traust.yaml: locations.progress_tracker unset",
        "traust.yaml: ledger.public_key_path unset — layer signatures are not verified",
    ]

    (home / "traust.yaml").write_text(
        (repo / "config" / "traust.example.yaml").read_text()
        + yaml.safe_dump(
            {
                "locations": {
                    "workspace": str(tmp_path / "ws"),
                    "analysis_results": str(tmp_path / "ar"),
                    "progress_tracker": str(tmp_path / "pt"),
                },
                "ledger": {"public_key_path": str(tmp_path / "cosign.pub")},
            }
        )
    )
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 0
    assert "preflight: every enabled asset's requirements are met" in [r["check"] for r in rows]


def test_a_missing_gitleaks_fails_for_the_packs_repo_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """repo_state requires gitleaks (core's observation scans each change's patch for
    secrets): a runner without it is a FAIL row naming the install pin — the gap the
    engine's start gate refuses on, never a WARN the report carries on past."""
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    fails = [r["check"] for r in rows if r["status"] == "FAIL"]
    assert [
        c for c in fails if c.startswith("gitleaks: not found on PATH")
    ] == fails  # the pack's one tool row, and nothing else, on a complete home
    assert "external-tools.yaml pin" in fails[0]


def test_the_convention_paths_show_as_defaults_in_use(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    monkeypatch.delenv("GIT_HOSTS", raising=False)
    results: list[tuple[str, str]] = []
    doctor.check_defaults(results, load(home))
    rows = {m.split(": ", 1)[0]: m for _, m in results}
    assert rows["feeds cache"].endswith("(default <progress_tracker>/feeds)")
    assert rows["extra forges (GIT_HOSTS)"] == (
        "extra forges (GIT_HOSTS): none — github.com/gitlab.com only"
    )
    assert rows["bicep"].startswith("bicep: ")

    monkeypatch.setenv("FEEDS_CACHE_DIR", "/shared/feeds")
    monkeypatch.setenv("GIT_HOSTS", "gitlab:gitlab.example.com")
    results = []
    doctor.check_defaults(results, load(home))
    rows = {m.split(": ", 1)[0]: m for _, m in results}
    assert rows["feeds cache"] == "feeds cache: /shared/feeds (env FEEDS_CACHE_DIR)"
    assert rows["extra forges (GIT_HOSTS)"] == (
        "extra forges (GIT_HOSTS): gitlab:gitlab.example.com"
    )


def _config_rows(home: Path | None) -> dict[str, str]:
    results: list[tuple[str, str]] = []
    doctor.check_config(results, home)
    return {m.split(" = ")[0]: m for s, m in results if s == doctor.OK}


def test_the_effective_config_names_each_values_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "database": {"url": "postgresql://u:secret@db/t", "password_env": "DB_PW"},
                "locations": {"workspace": "/w", "analysis_results": "/ar"},
                "feeds": {"osv_access": "air-gapped"},
            }
        )
    )
    monkeypatch.delenv("DB_PW", raising=False)
    monkeypatch.setenv("AUDIT_RESULTS_ROOT", "/elsewhere")
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    rows = _config_rows(home)
    assert rows["config file: " + str(home / "traust.yaml")]
    assert rows["config database.url"].endswith('"postgresql://u:***@db/t" (file)')
    assert "secret" not in rows["config database.url"]
    assert rows["config database.password_env"].endswith("(file, DB_PW UNSET)")
    assert rows["config locations.workspace"] == 'config locations.workspace = "/w" (file)'
    assert rows["config locations.analysis_results"].endswith(
        '"/elsewhere" (env AUDIT_RESULTS_ROOT)'
    )
    assert rows["config locations.feeds_cache"].endswith("null (default)")
    assert rows["config feeds.osv_access"].endswith('"air-gapped" (file)')
    assert rows["config execution.sandbox"].endswith('"none" (default)')
    assert rows["config overrides.rule_pack_allowlist"].endswith("null (default)")
    for name in ("external-tools.yaml", "safe-exec-profiles.yaml", "feeds.yaml"):
        assert f"config {name}: shipped with traust-core (not configurable)" in rows


def test_no_traust_yaml_is_the_zero_config_defaults(tmp_path: Path) -> None:
    rows = _config_rows(tmp_path)
    assert "config file: none (zero-config defaults)" in rows
    assert rows["config database.url"].endswith("null (default)")


def test_an_invalid_traust_yaml_fails_the_config_row(tmp_path: Path) -> None:
    (tmp_path / "traust.yaml").write_text("nonsense_key: 1\n")
    results: list[tuple[str, str]] = []
    doctor.check_config(results, tmp_path)
    assert [s for s, _ in results] == [doctor.FAIL]
    assert "traust.yaml not loadable" in results[0][1]
