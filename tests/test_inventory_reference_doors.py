from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path

import yaml
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.values import HttpsRepoUrl

from traust.cli import _doors
from traust.cli.__main__ import main
from traust.context import load

URL = "https://github.com/example-org/api"
OTHER = "https://github.com/example-org/web"


def invoke(home: Path, *arguments: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([*arguments, "--config-home", str(home)])
    return code, out.getvalue(), err.getvalue()


def test_grouped_reference_import_survives_reload_and_exports_real_joined_csv(
    tmp_path: Path,
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    core = load(home)
    for url in (URL, OTHER):
        core.services().portfolio.register_repository(
            HttpsRepoUrl.parse(url, core.config.forge_hosts),
            public=True,
        )
    source = tmp_path / "declarations.yaml"
    source.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "repositories": [
                    {
                        "operator_versions": ["1.0", "2.0"],
                        "payload_versions": ["4.0"],
                        "repo_url": URL + ".git/",
                        "service": "Gateway",
                        "resource_type": "adhoc",
                        "manager": "morgan",
                        "individual_owners": ["alice"],
                        "ownership_source": "OWNERS at reviewed commit",
                        "business_unit": "Commerce",
                        "jira_project": "PAY",
                        "jira_component": "API",
                        "escalation_contact": "oncall@example.com",
                    },
                    {"repo_url": OTHER, "service": "=SUM(1,2)", "resource_type": "adhoc"},
                ],
            }
        )
    )
    code, output, error = invoke(home, "portfolio", "import-reference", "--source", str(source))
    assert code == 0, error
    imported = {row["repo_url"]: row for row in json.loads(output)}
    assert imported[URL]["individual_owners"] == ["alice"]
    code, output, error = invoke(home, "portfolio", "inventory-export", "--format", "csv")
    assert code == 0, error
    rows = {row["URL"]: row for row in csv.DictReader(io.StringIO(output))}
    row = rows[URL]
    assert row["Repository"] == "example-org/api"
    assert row["Organization/Group"] == "example-org" and row["Repo Name"] == "api"
    assert row["App/Sub-Service"] == "Gateway"
    assert row["Resource Type"] == "adhoc"
    assert row["Manager"] == "morgan"
    assert row["Individual Owners"] == "alice"
    assert row["Ownership Source"] == "OWNERS at reviewed commit"
    assert row["Business Unit"] == "Commerce"
    assert row["Jira Project"] == "PAY" and row["Jira Component"] == "API"
    assert row["Escalation Contact"] == "oncall@example.com"
    assert row["Operator Versions"] == "1.0; 2.0"
    assert row["Payload Versions"] == "4.0"
    assert rows[OTHER]["Jira Project"] == rows[OTHER]["Escalation Contact"] == ""
    assert rows[OTHER]["App/Sub-Service"] == "'=SUM(1,2)"
    code, output, error = invoke(home, "portfolio", "inventory-export")
    assert code == 0, error
    json_rows = {row["url"]: row for row in json.loads(output)}
    assert json_rows[OTHER]["declaration"]["service"] == "=SUM(1,2)"
    assert json_rows[URL]["declaration"]["jira_project"] == "PAY"


def test_reference_cannot_create_unregistered_inventory_or_overwrite_on_invalid_input(
    tmp_path: Path,
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    source = tmp_path / "declarations.yaml"
    source.write_text(yaml.safe_dump({"repositories": [{"repo_url": URL, "jira_project": "PAY"}]}))
    code, _, _ = invoke(home, "portfolio", "import-reference", "--source", str(source))
    assert code == 2
    assert not (tmp_path / "store" / "inventory-reference.yaml").exists()
    assert load(home).services().portfolio.inventory_export() == ()


def test_sla_cache_override_joins_contacts_without_changing_deployment_defaults(
    tmp_path: Path,
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    core = load(home)
    portfolio = core.services().portfolio
    portfolio.register_repository(HttpsRepoUrl.parse(URL, core.config.forge_hosts), True)
    portfolio.record_product_map(
        ProductDefinitionsMapArtifact.from_document(
            {
                "mappings": {"repos": {URL: "widget"}},
            }
        ),
        _doors.interactive(),
    )
    cache = tmp_path / "trusted-snapshot"
    cache.mkdir()
    (cache / "product_definitions.json").write_text(
        json.dumps(
            {
                "ps_products": {"widget": {"ps_modules": ["module"]}},
                "ps_modules": {"module": {"private_tracker_cc": ["alice"]}},
                "ps_update_streams": {},
            }
        )
    )
    (cache / "feeds-meta.json").write_text(
        json.dumps(
            {
                "product-definitions": {
                    "retrieved_at": core.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                },
            }
        )
    )
    code, output, error = invoke(
        home,
        "dashboard",
        "view",
        "sla",
        "--pd-cache-dir",
        str(cache),
        "--out",
        str(tmp_path / "sla-override"),
    )
    assert code == 0, error
    answer = json.loads(output)
    resolution = answer["model"]["contacts"]
    assert resolution["source_status"] == "ok"
    (match,) = resolution["results"]
    assert match["query"]["value"] == URL
    assert match["contacts"][0]["kerberos_id"] == "alice"
    assert match["contacts"][0]["embargo_cleared"] is True
    saved = next(Path(path) for path in answer["written"] if path.endswith(".json"))
    assert json.loads(saved.read_text())["contacts"] == resolution
    code, output, error = invoke(
        home,
        "dashboard",
        "view",
        "sla",
        "--out",
        str(tmp_path / "sla-default"),
    )
    assert code == 0, error
    assert json.loads(output)["model"]["contacts"]["source_status"] == "unavailable"
