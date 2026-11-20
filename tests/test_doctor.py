"""`traust admin doctor`: core's preflight (the same findings the engine's start gate refuses
on) as FAIL rows, the store/catalog rows, and each value's source. The store and catalog are
core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
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
    if signer := shutil.which("cosign"):
        (stub / "cosign").symlink_to(signer)
    monkeypatch.setenv("PATH", str(stub))


def _enable_writers(config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not shutil.which("cosign"):
        pytest.skip("positive decision-writer doctor test requires cosign")
    syft = tmp_path / "bin" / "syft"
    syft.write_text("#!/bin/sh\necho 999.0.0\n")
    syft.chmod(0o755)
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    monkeypatch.setenv("TEST_VALVE_SALT", "doctor-test-salt")
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(tmp_path / "cosign")],
        check=True,
        capture_output=True,
        timeout=30,
    )
    path = config / "traust.yaml"
    settings = yaml.safe_load(path.read_text()) | {
        "home": str(tmp_path / "store"),
        "identity": {"trust_local": True},
        "review": {"valve_salt_env": "TEST_VALVE_SALT"},
        "process": {"allowed_binaries": ["syft"]},
        "ledger": {
            "key_path": str(tmp_path / "cosign.key"),
            "public_key_path": str(tmp_path / "cosign.pub"),
            "required": True,
        },
    }
    path.write_text(yaml.safe_dump(settings))
    load(config).local_issuer.mint("doctor-test", machine=True)


BARE_HOME_GAPS = [
    "syft: not allowed -- add syft to process.allowed_binaries",
    "syft: not found on PATH (install it at the external-tools.yaml pin, syft >= 1.48.0)",
    *(
        f"config: `{key}` is not set -- set it in traust.yaml (copy traust.example.yaml to start)"
        for key in ("identity", "ledger", "review")
    ),
    "traust.yaml: locations.workspace unset",
    "traust.yaml: locations.analysis_results unset",
    "traust.yaml: locations.progress_tracker unset",
    "traust.yaml: ledger.public_key_path unset — layer signatures are not verified",
]


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
    _enable_writers(home, home.parent, monkeypatch)
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
    assert [r["check"] for r in rows if r["status"] == "FAIL"] == BARE_HOME_GAPS


def test_an_unset_feed_key_variable_is_a_fail_row_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gitleaks_on_path: None
) -> None:
    monkeypatch.delenv("TEST_NVD_KEY", raising=False)
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    document = yaml.safe_load((home / "traust.yaml").read_text())
    document["feeds"] = {"api_keys": {"nvd": "TEST_NVD_KEY"}}
    (home / "traust.yaml").write_text(yaml.safe_dump(document))
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    feeds = [(r["status"], r["check"]) for r in rows if r["check"].startswith("feeds: ")]
    assert feeds == [("FAIL", "feeds: feeds.api_keys.nvd names unset variable TEST_NVD_KEY")]


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


def test_remediation_alone_refuses_a_missing_writer_ledger(tmp_path: Path) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    asset = yaml.safe_load(doctor.PACK_ASSETS.read_text())["assets"]["remediate_finding"]
    with pytest.raises(PreflightError, match="config: `ledger` is not set"):
        load(home).preflight([Requirement(**asset.get("requires", {}))])


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
    assert [r["check"] for r in rows if r["status"] == "FAIL"] == BARE_HOME_GAPS

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
    _enable_writers(home, tmp_path, monkeypatch)
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 0
    assert "preflight: every enabled asset's requirements are met" in [r["check"] for r in rows]


def test_a_missing_gitleaks_fails_for_the_packs_repo_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gitleaks_on_path: None
) -> None:
    """repo_state requires gitleaks (core's observation scans each change's patch for
    secrets): a runner without it is a FAIL row naming the install pin — the gap the
    engine's start gate refuses on, never a WARN the report carries on past."""
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    _enable_writers(home, tmp_path, monkeypatch)
    (tmp_path / "bin" / "gitleaks").unlink()
    rc, rows = _doctor(home, monkeypatch)
    assert rc == 1
    fails = [r["check"] for r in rows if r["status"] == "FAIL"]
    assert len(fails) == 1
    assert fails[0].startswith("gitleaks: not found on PATH")
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
    assert rows["extra forges (traust.yaml + GIT_HOSTS)"] == (
        "extra forges (traust.yaml + GIT_HOSTS): none — github.com/gitlab.com only"
    )
    assert rows["bicep"].startswith("bicep: ")

    monkeypatch.setenv("FEEDS_CACHE_DIR", "/shared/feeds")
    monkeypatch.setenv("GIT_HOSTS", "gitlab:gitlab.example.com")
    results = []
    doctor.check_defaults(results, load(home))
    rows = {m.split(": ", 1)[0]: m for _, m in results}
    assert rows["feeds cache"] == "feeds cache: /shared/feeds (env FEEDS_CACHE_DIR)"
    assert rows["extra forges (traust.yaml + GIT_HOSTS)"] == (
        "extra forges (traust.yaml + GIT_HOSTS): gitlab:gitlab.example.com"
    )


@pytest.mark.parametrize(
    ("configured", "source"),
    [
        (None, "default <progress_tracker>/feeds"),
        ("", "default <progress_tracker>/feeds"),
        ("s3://example/feeds", "default <progress_tracker>/feeds"),
        ("./feed-cache", "traust.yaml locations.feeds_cache"),
        ("file:///shared/feeds", "traust.yaml locations.feeds_cache"),
        ("<progress_tracker>/feeds", "traust.yaml locations.feeds_cache"),
    ],
)
@pytest.mark.parametrize("override", [None, "   ", " /shared/feeds "])
def test_feeds_cache_provenance_uses_the_loaded_config_home(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    configured: str | None,
    source: str,
    override: str | None,
) -> None:
    path = home / "traust.yaml"
    raw = yaml.safe_load(path.read_text())
    tracker = Path(raw["locations"]["progress_tracker"])
    if configured == "<progress_tracker>/feeds":
        configured = str(tracker / "feeds")
    if configured is not None:
        raw["locations"]["feeds_cache"] = configured
    path.write_text(yaml.safe_dump(raw))
    if override is None:
        monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    else:
        monkeypatch.setenv("FEEDS_CACHE_DIR", override)
    core = load(home)
    # Attribution belongs to this context, not an unrelated ambient config home.
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(tmp_path / "other-config"))
    results: list[tuple[str, str]] = []
    doctor.check_defaults(results, core)
    row = next(message for _, message in results if message.startswith("feeds cache: "))
    if override and override.strip():
        expected, source = Path("/shared/feeds"), "env FEEDS_CACHE_DIR"
    elif configured and "://" not in configured:
        expected = (home / configured).resolve()
    elif configured and configured.startswith("file://"):
        expected = Path(configured.removeprefix("file://"))
    else:
        expected = tracker / "feeds"
    assert row == f"feeds cache: {expected} ({source})"


def test_missing_gh_names_the_github_router_requirement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor.shutil, "which", lambda name: None if name == "gh" else f"/bin/{name}"
    )
    results: list[tuple[str, str]] = []
    doctor.check_tools(results)
    assert (doctor.WARN, "tool gh not found (GitHub rescan router requires it)") in results


def test_the_forge_row_includes_hosts_from_traust_yaml(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GIT_HOSTS", raising=False)
    path = home / "traust.yaml"
    config = yaml.safe_load(path.read_text())
    config["forge_hosts"] = {"ghe.example.com": "github"}
    path.write_text(yaml.safe_dump(config))

    results: list[tuple[str, str]] = []
    doctor.check_defaults(results, load(home))
    assert (doctor.OK, "extra forges (traust.yaml + GIT_HOSTS): github:ghe.example.com") in results


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


def test_missing_model_registry_fails_the_config_row(home: Path) -> None:
    (home / "model-registry.yaml").unlink()
    results: list[tuple[str, str]] = []
    doctor.check_config(results, home)
    assert any(
        status == doctor.FAIL and "model-registry.yaml missing" in message
        for status, message in results
    )


def test_legacy_home_names_the_migration(tmp_path: Path) -> None:
    (tmp_path / "core.yaml").write_text("database: {}\n")
    results: list[tuple[str, str]] = []
    doctor.check_config(results, tmp_path)
    assert any(
        status == doctor.FAIL and f"traust config migrate {tmp_path}" in message
        for status, message in results
    )


def test_an_invalid_traust_yaml_fails_the_config_row(tmp_path: Path) -> None:
    (tmp_path / "traust.yaml").write_text("nonsense_key: 1\n")
    results: list[tuple[str, str]] = []
    doctor.check_config(results, tmp_path)
    assert [s for s, _ in results] == [doctor.FAIL]
    assert "traust.yaml not loadable" in results[0][1]


def test_a_feeds_error_never_hides_another_preflight_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_NVD_KEY", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "no-tools"))  # gitleaks isn't on PATH
    home = tmp_path / "config"
    home.mkdir()
    _fill(home, tmp_path)
    document = yaml.safe_load((home / "traust.yaml").read_text())
    document["feeds"] = {"api_keys": {"nvd": "TEST_NVD_KEY"}}
    (home / "traust.yaml").write_text(yaml.safe_dump(document))
    rc, rows = _doctor(home, monkeypatch)
    failed = [r["check"] for r in rows if r["status"] == "FAIL"]
    assert rc == 1
    assert "feeds: feeds.api_keys.nvd names unset variable TEST_NVD_KEY" in failed
    assert [f for f in failed if "gitleaks" in f]  # the other gap is still reported
    assert not [f for f in failed if "is not an enabled source" in f]  # nor repeated per feed
