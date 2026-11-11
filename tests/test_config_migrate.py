"""`traust config migrate`: an old config home becomes one traust.yaml, every file accounted for."""

from __future__ import annotations

import shutil
from decimal import Decimal
from pathlib import Path

import pytest
import yaml
from traust_core.v1.context import Config
from traust_core.v1.context.config import SHIPPED_EXTERNAL_TOOLS

from traust.cli import config_migrate

FIXTURE = Path(__file__).parent / "fixtures" / "config-migrate"


@pytest.fixture
def old(tmp_path: Path) -> Path:
    home = tmp_path / "old"
    shutil.copytree(FIXTURE, home, ignore=shutil.ignore_patterns("README.md"))
    shutil.copy(SHIPPED_EXTERNAL_TOOLS, home / "external-tools.yaml")
    return home


def test_the_old_home_becomes_one_traust_yaml(old: Path, capsys) -> None:
    assert config_migrate.main([str(old)]) == 0
    config = Config.from_file(old / "traust.yaml")
    assert config.database.password_env == "TRAUST_DB_PASSWORD"
    assert config.identity.trust_local and config.forge_hosts["gitlab.example.com"] == "gitlab"
    assert config.locations.workspace == "/srv/traust/workspace"
    assert config.locations.progress_tracker is None
    assert config.locations.rule_drafts == str((old / "drafts").resolve())
    assert config.ledger.key_path == Path("/run/secrets/traust/cosign.key")
    assert config.ledger.required
    assert config.ledger.public_key_path == (old / "ledger-signing-key.pub").resolve()
    (budget,) = config.budgets
    assert (budget.lane, budget.monthly_usd, budget.enforcement) == (
        "full-audit",
        Decimal("10000"),
        "observe",
    )
    assert config.execution.sandbox == "podman"
    assert config.remediation.fork_org == "example-mirrors"
    assert config.remediation.private_forge_hosts == ("gitlab.example.com",)
    assert config.campaign.tracking_reference == "SEC-2026-Q4" and not config.campaign.display_name
    assert config.feeds.osv_access == "air-gapped"
    assert config.overrides.rule_pack_allowlist == (old / "rule-pack-allowlist.yaml").resolve()
    assert (
        "safe_exec_profiles" not in yaml.safe_load((old / "traust.yaml").read_text())["overrides"]
    )

    report = capsys.readouterr().out
    files = sorted(p.name for p in old.iterdir() if p.name != "traust.yaml")
    assert all(f"  {name}: " in report for name in files)  # every file has a verdict
    for line in (
        "external-tools.yaml: dropped, traust-core ships it (not configurable)\n",
        "feeds.yaml: dropped, traust-core ships it (not configurable); differs from the "
        "shipped copy: review",
        "safe-exec-profiles.yaml: dropped, traust-core ships it (not configurable); differs",
        f"org-parameters.yaml: adopter fact, record it: traust compliance policy "
        f"org-parameters {old / 'org-parameters.yaml'}",
        f"adr-registry.yaml: adopter fact, record it: traust compliance policy adr-registry "
        f"{old / 'adr-registry.yaml'}",
        f"benchmark-targets.yaml: adopter fact, record it: traust sweep benchmark-targets "
        f"{old / 'benchmark-targets.yaml'}",
        "model-registry.yaml: kept",
        "jira-sync.yaml: not migrated, moves into traust-internal",
        "corpus-config.yaml: not migrated, no reader",
        "notes.yaml: not recognised: review",
    ):
        assert line in report


def test_an_existing_traust_yaml_is_never_overwritten(old: Path, capsys) -> None:
    (old / "traust.yaml").write_text("home: /keep\n")
    assert config_migrate.main([str(old)]) == 2
    assert (old / "traust.yaml").read_text() == "home: /keep\n"
    assert "refusing to overwrite" in capsys.readouterr().err


def test_a_home_already_on_traust_yaml_has_nothing_to_migrate(old: Path, tmp_path: Path) -> None:
    (old / "traust.yaml").write_text("{}\n")
    out = tmp_path / "new.yaml"
    assert config_migrate.main([str(old), "--out", str(out)]) == 2
    assert not out.exists()


def test_an_invalid_result_is_not_written(old: Path, capsys) -> None:
    (old / "execution-boundaries.yaml").write_text("sandbox: docker\n")
    assert config_migrate.main([str(old)]) == 2
    assert not (old / "traust.yaml").exists()
    assert "config migrate:" in capsys.readouterr().err


def test_an_empty_home_is_the_zero_config_file(tmp_path: Path) -> None:
    assert config_migrate.main([str(tmp_path)]) == 0
    assert Config.from_file(tmp_path / "traust.yaml").database.url is None
    assert yaml.safe_load((tmp_path / "traust.yaml").read_text()) == {}


def test_a_missing_home_is_exit_2(tmp_path: Path) -> None:
    assert config_migrate.main([str(tmp_path / "absent")]) == 2


def test_moved_files_get_their_new_home(old: Path, capsys) -> None:
    assert config_migrate.main([str(old)]) == 0
    report = capsys.readouterr().out
    for line in (
        f"sla-policy.yaml: adopter fact, record it: traust dashboard sla-policy "
        f"{old / 'sla-policy.yaml'}",
        "internal-vocabulary.yaml: not migrated, public-export tooling input",
        "--vocabulary` (tools/public-export/)",
        f"product-definitions-map.yaml: adopter fact, record it: traust registry product-map "
        f"{old / 'product-definitions-map.yaml'}",
    ):
        assert line in report
