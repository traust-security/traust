from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml
from traust_core.v1.models.inventory import RefName, VersionLabel
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, ProductSlug
from traust_core.v1.models.vocabulary import RefKind

from traust.cli.__main__ import main
from traust.context import load


def test_grouped_graph_exports_real_recorded_relations_and_inventory_only_repositories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    portfolio = load(home).services().portfolio
    url = HttpsRepoUrl.parse("https://github.com/example/shared", ("github.com",))
    repository = portfolio.register_repository(url, public=True)
    ref = portfolio.register_ref(
        repository.id, GitSha.parse("a" * 40), RefName("main"), RefKind.BRANCH
    )
    for name in ("first", "second"):
        product = portfolio.register_product(ProductSlug.parse(name), name.title())
        release = portfolio.record_release(product.id, VersionLabel("1.0"))
        portfolio.add_component(release.id, ref.id)
    portfolio.assign_owner(repository.id, "Platform", datetime(2020, 1, 1, tzinfo=UTC))
    inputs = tmp_path / "inputs"
    (inputs / "services" / "api").mkdir(parents=True)
    (inputs / "inventory.yaml").write_text("segments:\n  services: services\n")
    (inputs / "services" / "api" / "api-repos.csv").write_text(
        "URL\nhttps://github.com/example/shared\nhttps://github.com/example/unregistered\n"
    )
    out = tmp_path / "out"
    assert (
        main(
            [
                "portfolio",
                "graph",
                "--config-home",
                str(home),
                "--inputs",
                str(inputs),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert {Path(path).name for path in result["written"]} == {
        "repo-graph.json",
        "repo-graph.dot",
        "repo-graph.gexf",
        "repo-graph.html",
        "repo-graph-stats.md",
    }
    graph = json.loads((out / "repo-graph.json").read_text())
    repositories = [node for node in graph["nodes"] if node["type"] == "repo"]
    assert {node["attrs"]["url"] for node in repositories} == {
        str(url),
        "https://github.com/example/unregistered",
    }
    assert graph["stats"]["repositories"] == 2
    assert graph["stats"]["repos_without_findings"] == 2
    assert graph["stats"]["top_hubs"][0]["repository_url"] == str(url)
    shared_id = next(node["id"] for node in repositories if node["attrs"]["url"] == str(url))
    assert (
        len([edge for edge in graph["edges"] if edge["rel"] == "ships" and edge["to"] == shared_id])
        == 3
    )
    xml = ElementTree.fromstring((out / "repo-graph.gexf").read_text())
    assert len(xml.findall("{*}graph/{*}nodes/{*}node")) == len(graph["nodes"])
