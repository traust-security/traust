"""`traust check drift`: rule-pack, ADR and framework pins vs upstream, policy review dates.
The rest of drift-watch is traust-core's freshness view (core's tests)."""

import json

import pytest
import yaml
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    OrgParametersArtifact,
    SlaPolicyArtifact,
)

from traust.cli import _doors
from traust.cli import check_drift as pc
from traust.context import SLA_POLICY, load
from traust.paths import OPENGREP_RULES_DIR


def _remote(monkeypatch, head: str) -> None:
    monkeypatch.setattr(
        pc.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": f"{head}\tHEAD\n"})()
    )


def _unreachable(*a, **k):
    raise OSError("no network")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A config home of the test's own, on its own store."""
    path = tmp_path / "config-home"
    path.mkdir()
    (path / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(path))
    return path


@pytest.fixture
def services(home):
    return load().services()


def _adr_registry(services, *registers: dict) -> None:
    doc = AdrRegistryArtifact.from_document({"version": 1, "registers": list(registers)})
    services.compliance.record(doc, _doors.interactive())


def test_adr_registry_pending_then_checked(services, monkeypatch):
    assert pc.check_adr_registry(services)[0]["status"] == "pending"
    _adr_registry(
        services,
        {"name": "arch", "repo": "https://x/y.git", "paths": ["adr"], "pin": "aaaa1111"},
        {"name": "local", "repo": "file:///etc", "paths": ["adr"], "pin": "aaaa222"},
    )
    _remote(monkeypatch, "bbbb2222")
    rows = {r["item"]: r for r in pc.check_adr_registry(services)}
    assert rows["adr-registry:arch"]["status"] == "stale"
    assert "superseded" in rows["adr-registry:arch"]["detail"]
    assert rows["adr-registry:local"]["status"] == "unavailable"
    _remote(monkeypatch, "aaaa1111ffff")
    assert pc.check_adr_registry(services)[0]["status"] == "fresh"
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.check_adr_registry(services)[0]["status"] == "unavailable"


def test_the_newest_recorded_adr_registry_is_checked(services, monkeypatch):
    register = {"name": "arch", "repo": "https://x/y.git", "paths": ["adr"], "pin": "aaaa1111"}
    _adr_registry(services, register)
    _adr_registry(services, {**register, "pin": "bbbb2222"})
    _remote(monkeypatch, "bbbb2222")
    assert pc.check_adr_registry(services)[0]["status"] == "fresh"


def test_provenance_review_due(services, tmp_path):
    doc = yaml.safe_load(SLA_POLICY.read_text())
    doc["source"]["retrieved"] = "2020-01-01"
    services.insight.record_sla_policy(SlaPolicyArtifact.from_document(doc), _doors.interactive())
    params = {"version": 1, "declared_by": "the suite", "declared_on": f"{pc._now():%Y-%m-%d}"}
    services.compliance.record(
        OrgParametersArtifact.from_document(
            {
                **params,
                "parameters": {
                    "account_review_frequency_days": {
                        "value": 90,
                        "controls": ["nist-800-53-rev5:ac-2"],
                    }
                },
            }
        ),
        _doors.interactive(),
    )
    items = {i["item"]: i for i in pc.check_policy_provenance(tmp_path / "none", services)}
    assert items["provenance:sla-policy"]["status"] == "review_due"
    assert "re-verify" in items["provenance:sla-policy"]["refresh"]
    assert items["provenance:org-parameters"]["status"] == "fresh"
    assert items["provenance:compliance-spine"]["status"] == "pending"


def test_the_packs_sla_policy_is_dated_until_one_is_recorded(services, tmp_path):
    items = {i["item"]: i for i in pc.check_policy_provenance(tmp_path, services)}
    retrieved = yaml.safe_load(SLA_POLICY.read_text())["source"]["retrieved"]
    assert items["provenance:sla-policy"]["detail"].startswith(f"dated {retrieved}")
    assert items["provenance:org-parameters"]["status"] == "pending"


def test_catalog_reviewed_dates_covered(services, tmp_path):
    comp = tmp_path / "compliance-data"
    comp.mkdir()
    (comp / "catalog-pci-dss-v4.yaml").write_text("reviewed: '2020-01-01'\nframework: pci-dss-v4\n")
    (comp / "catalog-gdpr-technical.yaml").write_text("framework: gdpr\n")
    (comp / "provenance.json").write_text("{not json")
    items = {i["item"]: i for i in pc.check_policy_provenance(comp, services)}
    assert items["provenance:catalog-pci-dss"]["status"] == "review_due"
    assert items["provenance:catalog-soc2-tsc"]["status"] == "pending"
    assert items["provenance:catalog-gdpr"]["status"] == "unavailable"
    assert items["provenance:compliance-spine"]["status"] == "unavailable"


def test_framework_upstream_pin_check(tmp_path, monkeypatch):
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "pending"
    (tmp_path / "provenance.json").write_text(json.dumps({"upstream": "https://x/y"}))
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "unavailable"
    (tmp_path / "provenance.json").write_text(
        json.dumps({"upstream": "https://x/y", "upstream_head": "aaaa1111"})
    )
    _remote(monkeypatch, "bbbb2222")
    res = pc.check_framework_upstream(tmp_path)[0]
    assert res["status"] == "stale" and "re-deriv" in res["refresh"]
    _remote(monkeypatch, "aaaa1111ff")
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "fresh"
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "unavailable"


@pytest.mark.parametrize("check", [pc.check_yara_rules_pin, pc.check_argus_rules_pin])
def test_rule_pack_pins_parse_from_the_engine_adapters(check, monkeypatch):
    """The rows read the pins out of the adapters by regex; a renamed constant degrades the row
    to `unavailable`, never to fresh."""
    _remote(monkeypatch, "f" * 40)
    row = check()[0]
    assert row["status"] == "stale", row["detail"]
    assert "never auto-advanced" in row["refresh"]


def test_a_rule_pack_pin_that_cannot_be_parsed_is_unavailable(monkeypatch):
    monkeypatch.setattr(pc, "_module_text", lambda module: "nothing pinned here")
    assert pc.check_yara_rules_pin()[0]["status"] == "unavailable"
    monkeypatch.setattr(pc, "_module_text", lambda module: None)
    assert pc.check_argus_rules_pin()[0]["status"] == "pending"


def test_argus_pack_is_not_the_default_rules_source(home):
    """~500 rules uncalibrated against our triage-ledger ground truth must stay opt-in."""
    assert "ARGUS_RULES_REPO" in pc._module_text("traust_core.v1.providers.tools.opengrep")
    core = load()
    assert core.rule_pack == OPENGREP_RULES_DIR and core.rule_pack_supplements == ()
    assert "Traust-authored" in (OPENGREP_RULES_DIR / "README.md").read_text(encoding="utf-8")


def test_main_prints_every_row(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pc, "compliance_data_dir", lambda: tmp_path)
    monkeypatch.setattr(pc, "inputs_dir", lambda core: tmp_path / "inputs")
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.main([]) == 0
    rows = {r["item"] for r in json.loads(capsys.readouterr().out)["items"]}
    assert {"framework-spine:upstream", "provenance:sla-policy", "adr-registry"} <= rows
    assert {"yara-rules-pin", "argus-rules-pin", "docs-product-map"} <= rows
