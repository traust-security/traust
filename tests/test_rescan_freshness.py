"""Freshness backstop for the surviving daily worklist; inventory is read natively."""

import datetime
import json
from types import SimpleNamespace

import pytest
import yaml
from traust_core.v1.context import Config

from traust.cli import check_drift as pc

UTC = datetime.UTC
NOW = datetime.datetime(2026, 11, 3, 12, tzinfo=UTC)


def _worklist(path, age):
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = NOW - age
    path.write_text(json.dumps({"generated_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ")}))
    return path


@pytest.mark.parametrize(
    ("age", "status"),
    [
        (datetime.timedelta(days=3), "fresh"),
        (datetime.timedelta(days=3, seconds=1), "stale"),
        (datetime.timedelta(days=30), "stale"),
    ],
)
def test_worklist_uses_generated_at_not_file_age(tmp_path, monkeypatch, age, status):
    monkeypatch.setattr(pc, "_now", lambda: NOW)
    path = _worklist(tmp_path / "worklist.json", age)
    row = pc.check_rescan_worklist(path)[0]
    assert (row["item"], row["status"]) == ("rescan-worklist", status)
    assert ("refresh" in row) == (status == "stale")


def test_missing_worklist_is_stale_without_creating_it(tmp_path):
    path = tmp_path / "missing" / "worklist.json"
    row = pc.check_rescan_worklist(path)[0]
    assert row["status"] == "stale"
    assert row["refresh"]
    assert not path.parent.exists()


@pytest.mark.parametrize("content", ["{broken", "[]", "{}", '{"generated_at": 5}'])
def test_worklist_with_no_usable_stamp_is_unavailable(tmp_path, content):
    path = tmp_path / "worklist.json"
    path.write_text(content)
    assert pc.check_rescan_worklist(path)[0]["status"] == "unavailable"


def _configured_core(tmp_path):
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "locations": {
                    "workspace": str(tmp_path / "decoy-workspace"),
                    "inputs": "../inventory",
                    "analysis_results": "../separate-results",
                },
            }
        )
    )
    return home, SimpleNamespace(config=Config.from_home(home), services=lambda: None)


def _quiet_pack_checks(monkeypatch):
    for name in (
        "check_framework_upstream",
        "check_policy_provenance",
        "check_adr_registry",
        "check_yara_rules_pin",
        "check_argus_rules_pin",
        "check_docs_product_map",
    ):
        monkeypatch.setattr(pc, name, lambda *args: [])


def test_drift_follows_configured_split_paths_not_workspace(tmp_path, monkeypatch, capsys):
    home, core = _configured_core(tmp_path)
    (tmp_path / "inventory").mkdir()
    _worklist(
        tmp_path / "separate-results" / "findings" / "_manifest" / "rescan-worklist.json",
        datetime.timedelta(days=4),
    )
    decoy = tmp_path / "decoy-workspace" / "analysis-results"
    _worklist(decoy / "findings" / "_manifest" / "rescan-worklist.json", datetime.timedelta())
    monkeypatch.setattr(pc, "load", lambda config_home: core)
    monkeypatch.setattr(pc, "_now", lambda: NOW)
    _quiet_pack_checks(monkeypatch)
    assert pc.main(["--config-home", str(home)]) == 0
    rows = {r["item"]: r for r in json.loads(capsys.readouterr().out)["items"]}
    assert {name: row["status"] for name, row in rows.items()} == {
        "rescan-worklist": "stale",
    }


def test_drift_explicit_paths_override_configuration(tmp_path, monkeypatch, capsys):
    home, core = _configured_core(tmp_path)
    (tmp_path / "inventory").mkdir()
    worklist = _worklist(tmp_path / "override" / "routes.json", datetime.timedelta())
    monkeypatch.setattr(pc, "load", lambda config_home: core)
    monkeypatch.setattr(pc, "_now", lambda: NOW)
    _quiet_pack_checks(monkeypatch)
    assert (
        pc.main(
            [
                "--config-home",
                str(home),
                "--worklist",
                str(worklist),
            ]
        )
        == 0
    )
    rows = {r["item"]: r["status"] for r in json.loads(capsys.readouterr().out)["items"]}
    assert rows == {"rescan-worklist": "fresh"}
