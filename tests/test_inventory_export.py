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


@pytest.mark.parametrize("content", ["", "\n\n"], ids=["empty", "blank-lines-only"])
def test_inventory_reader_refuses_a_file_without_a_header_naming_it(
    tmp_path: Path, content: str
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "segment").mkdir(parents=True)
    path = inputs / "segment" / "headless-repos.csv"
    path.write_text(content)
    with pytest.raises(ConfigError, match=f"{path}: no header row"):
        repository_inventory(inputs)


@pytest.mark.parametrize(
    ("content", "line"),
    [
        (f"URL,Team\n{URL},a\n,b\n", 3),  # an empty URL cell
        (f"Team,URL\na,{URL}\nb\n", 3),  # a row too short to have the URL cell
        (f"GitHub URL,URL,Team\n , ,c\n{URL},,a\n", 2),  # every URL column blank
    ],
    ids=["empty-cell", "missing-cell", "every-url-column-blank"],
)
def test_inventory_reader_refuses_a_row_without_a_url_naming_file_and_line(
    tmp_path: Path, content: str, line: int
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "segment").mkdir(parents=True)
    path = inputs / "segment" / "rows-repos.csv"
    path.write_text(content)
    with pytest.raises(ConfigError, match=f"{path}:{line}: empty or missing URL cell"):
        repository_inventory(inputs)


def test_discovery_fails_rather_than_register_an_inventory_that_dropped_a_row(
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "services").mkdir(parents=True)
    (inputs / "services" / "scope-repos.csv").write_text(f"URL,Team\n{URL},a\n,b\n")
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "identity": {"trust_local": True},
                "locations": {"inputs": str(inputs)},
            }
        )
    )
    assert invoke(home, "auth", "local", "--identity", "operator@example.com")[0] == 0
    code, output, error = invoke(home, "portfolio", "inventory-discover")
    assert code == 1, (output, error)
    assert json.loads(output)["outcome"] == "failed"
    core = load(home)
    hosts = core.config.forge_hosts
    assert core.services().portfolio.find_repository(HttpsRepoUrl.parse(URL, hosts)) is None


def test_a_catalog_base_image_row_without_a_url_is_listed_as_no_repository(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "catalog").mkdir(parents=True)
    (inputs / "catalog" / "operator-repos.csv").write_text(
        "Component,GitHub Repository,GitHub URL\n"
        f"operator,example/operator,{URL}\n"
        "runtime,N/A (base/runtime-image),\n"
    )
    [segment] = repository_inventory(inputs).segments
    assert (segment.name, segment.repository_urls) == ("catalog", (URL,))
    # a row without that marker still needs its URL
    (inputs / "catalog" / "operator-repos.csv").write_text(
        "Component,GitHub Repository,GitHub URL\nruntime,example/runtime,\n"
    )
    with pytest.raises(ConfigError, match="empty or missing URL cell"):
        repository_inventory(inputs)
