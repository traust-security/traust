"""`traust portfolio inventory-export`, composed from the portfolio's own lists, and the
traust-owned input-inventory reader that inventory discovery registers from."""

from __future__ import annotations

import contextlib
import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug

from traust.cli.__main__ import main
from traust.context import load
from traust.inventory import repository_inventory

URL = "https://github.com/example-org/api"
OTHER = "https://gitlab.com/example-group/sub/web"


def invoke(home: Path, *arguments: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([*arguments, "--config-home", str(home)])
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def test_export_joins_owners_and_products_and_keeps_cells_inert(home: Path) -> None:
    core = load(home)
    portfolio = core.services().portfolio
    hosts = (*core.config.forge_hosts, "gitlab.com")
    api = portfolio.register_repository(HttpsRepoUrl.parse(URL, hosts), public=True)
    web = portfolio.register_repository(HttpsRepoUrl.parse(OTHER, hosts), public=False)
    assert api.id is not None and web.id is not None
    portfolio.assign_owner(api.id, "Gateway Team", datetime(2026, 10, 1, tzinfo=UTC))
    portfolio.assign_owner(web.id, "=HYPERLINK(1)", datetime(2026, 10, 1, tzinfo=UTC))
    product = portfolio.register_product(ProductSlug("widget"), "Widget")
    assert product.id is not None

    code, output, error = invoke(home, "portfolio", "inventory-export", "--format", "csv")
    assert code == 0, error
    rows = {row["URL"]: row for row in csv.DictReader(io.StringIO(output))}
    assert set(rows) == {URL, OTHER}
    row = rows[URL]
    assert (row["Repository"], row["Host"]) == ("example-org/api", "github.com")
    assert (row["Organization/Group"], row["Repo Name"]) == ("example-org", "api")
    assert row["Owner Team"] == "Gateway Team"
    assert rows[OTHER]["Organization/Group"] == "example-group/sub"
    assert rows[OTHER]["Repo Name"] == "web"
    assert rows[OTHER]["Owner Team"] == "'=HYPERLINK(1)"  # a formula-shaped cell never runs
    assert rows[OTHER]["Products"] == rows[OTHER]["Accountable Contacts"] == ""

    code, output, error = invoke(home, "portfolio", "inventory-export")
    assert code == 0, error
    exported = {row["URL"]: row for row in json.loads(output)}
    assert exported[URL]["Owner Team"] == ["Gateway Team"]
    assert exported[OTHER]["Owner Team"] == ["=HYPERLINK(1)"]
    assert exported[URL]["Products"] == [] and exported[URL]["Accountable Contacts"] == []


def test_inventory_reader_lists_each_segment_in_descriptor_order(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "alpha" / "group").mkdir(parents=True)
    (inputs / "beta").mkdir()
    (inputs / "inventory.yaml").write_text("segments:\n  beta: {kind: services}\n")
    (inputs / "alpha" / "group" / "one-repos.csv").write_text(
        f"GitHub URL,Other\n{URL},x\n\n{URL},y\n"
    )
    (inputs / "alpha" / "group" / "owners-repos.csv").write_text("URL\nnot a url\n")
    (inputs / "beta" / "svc-repos.csv").write_text("URL\nhttps://github.com/example-org/svc\n")
    inventory = repository_inventory(inputs)
    assert [(s.name, s.repository_urls) for s in inventory.segments] == [
        ("beta", ("https://github.com/example-org/svc",)),
        ("alpha", (URL,)),
    ]


@pytest.mark.parametrize(
    "content", ["Name\nexample\n", "URL\nnot-a-url\n", "URL\nhttps://example.test/a,extra\n"]
)
def test_inventory_reader_refuses_what_it_cannot_read(tmp_path: Path, content: str) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "segment").mkdir(parents=True)
    (inputs / "segment" / "bad-repos.csv").write_text(content)
    with pytest.raises(ConfigError):
        repository_inventory(inputs)


def test_inventory_reader_refuses_a_missing_tree(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        repository_inventory(tmp_path / "absent")
