"""`traust portfolio inventory-export`, composed from the portfolio's own lists, and the
traust-owned input-inventory reader that inventory discovery registers from."""

from __future__ import annotations

import contextlib
import csv
import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.inventory import Component, Release
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, ProductSlug
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_products_doors import _postgres
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


@pytest.fixture(params=["sqlite", "postgres"])
def home(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    config = tmp_path / "config"
    config.mkdir()
    settings = {
        "home": str(tmp_path / "store"),
        "locations": {"feeds_cache": str(tmp_path / "configured-feeds")},
    }
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            settings["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(settings))
        yield config


def test_export_joins_owners_and_products_as_json(home: Path) -> None:
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

    code, output, error = invoke(home, "portfolio", "inventory-export")
    assert code == 0, error
    rows = {row["URL"]: row for row in json.loads(output)}
    assert set(rows) == {URL, OTHER}
    row = rows[URL]
    assert (row["Repository"], row["Host"]) == ("example-org/api", "github.com")
    assert (row["Organization/Group"], row["Repo Name"]) == ("example-org", "api")
    assert row["Owner Team"] == ["Gateway Team"]
    assert rows[OTHER]["Organization/Group"] == "example-group/sub"
    assert rows[OTHER]["Repo Name"] == "web"
    assert rows[OTHER]["Owner Team"] == ["=HYPERLINK(1)"]
    assert rows[OTHER]["Products"] == rows[OTHER]["Accountable Contacts"] == []


def contact_cache(folder: Path, identity: str) -> None:
    folder.mkdir()
    (folder / "product_definitions.json").write_text(
        json.dumps(
            {
                "ps_products": {"widget": {"ps_modules": ["widget-1"]}},
                "ps_modules": {
                    "widget-1": {
                        "ps_update_streams": ["widget-default"],
                        "private_tracker_cc": [identity],
                    }
                },
                "ps_update_streams": {
                    "widget-default": {
                        "managed_service_components": [{"name": "api", "git_repo_url": URL}]
                    }
                },
            }
        )
    )


def test_csv_export_preserves_products_and_cache_override_contacts(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = load(home)
    portfolio = core.services().portfolio
    repo = portfolio.register_repository(HttpsRepoUrl.parse(URL, core.config.forge_hosts), True)
    assert repo.id is not None
    portfolio.assign_owner(repo.id, "=HYPERLINK(1)", datetime(2026, 10, 1, tzinfo=UTC))
    product = portfolio.register_product(ProductSlug("widget"), "Widget")
    ref = portfolio.register_ref(repo.id, GitSha.parse("a" * 40), None, None)
    assert product.id is not None and ref.id is not None
    with SqlTraustUnitOfWork(core.database) as uow:
        release = uow.releases.add(Release(product_id=product.id, version="1.0"))
        assert release.id is not None
        uow.components.add(Component(release_id=release.id, repository_ref_id=ref.id))
        uow.commit()
    contact_cache(tmp_path / "configured-feeds", "configuredperson")
    contact_cache(tmp_path / "override-feeds", "overriddenperson")
    code, output, error = invoke(home, "portfolio", "inventory-export")
    assert code == 0, error
    (original,) = json.loads(output)
    assert original["Accountable Contacts"] == [
        "configuredperson (private_tracker_cc; embargo_cleared=True)"
    ]
    monkeypatch.chdir(tmp_path)
    code, output, error = invoke(
        home, "portfolio", "inventory-export", "--pd-cache-dir", "override-feeds"
    )
    assert code == 0, error
    (overridden,) = json.loads(output)
    assert overridden["Products"] == ["widget"]
    assert overridden["Owner Team"] == ["=HYPERLINK(1)"]
    assert overridden["Accountable Contacts"] == [
        "overriddenperson (private_tracker_cc; embargo_cleared=True)"
    ]
    code, output, error = invoke(
        home,
        "portfolio",
        "inventory-export",
        "--format",
        "csv",
        "--pd-cache-dir",
        "override-feeds",
    )
    assert code == 0, error
    (exported,) = list(csv.DictReader(io.StringIO(output)))
    assert exported["URL"] == URL
    assert exported["Products"] == "widget"
    assert exported["Owner Team"] == "'=HYPERLINK(1)"
    assert exported["Accountable Contacts"] == overridden["Accountable Contacts"][0]


def test_dashboard_exports_inventory_wrapper_and_refuses_historical_scope(
    home: Path, tmp_path: Path
) -> None:
    core = load(home)
    portfolio = core.services().portfolio
    portfolio.register_repository(HttpsRepoUrl.parse(URL, core.config.forge_hosts), True)
    destination = tmp_path / "dashboard"
    code, output, error = invoke(
        home, "dashboard", "view", "inventory-export", "--out", str(destination)
    )
    assert code == 0, error
    written = [Path(path) for path in json.loads(output)["written"]]
    assert {path.suffix for path in written} == {".json", ".md", ".html", ".csv"}
    wrapper = json.loads(next(path for path in written if path.suffix == ".json").read_text())
    assert set(wrapper) == {"rows"}
    assert [(row["URL"], row["Owner Team"], row["Products"]) for row in wrapper["rows"]] == [
        (URL, [], [])
    ]
    refused = tmp_path / "historical"
    code, _, _ = invoke(
        home,
        "dashboard",
        "view",
        "inventory-export",
        "--out",
        str(refused),
        "--as-of",
        "2026-10-01T00:00:00Z",
    )
    assert code == 2
    assert not refused.exists()
    with pytest.raises(SystemExit) as rejected:
        invoke(
            home,
            "dashboard",
            "view",
            "inventory-export",
            "--out",
            str(refused),
            "--until",
            "2026-10-01T00:00:00Z",
        )
    assert rejected.value.code == 2
    assert not refused.exists()


def test_empty_inventory_csv_still_has_its_columns(home: Path) -> None:
    code, output, error = invoke(home, "portfolio", "inventory-export", "--format", "csv")
    assert code == 0, error
    assert list(csv.reader(io.StringIO(output))) == [
        [
            "Repository",
            "URL",
            "Host",
            "Organization/Group",
            "Repo Name",
            "Owner Team",
            "Products",
            "Accountable Contacts",
        ]
    ]


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


@pytest.mark.parametrize(
    "marker", ["N/A", "N/A - pending", "n/a (later)", "N/A ()", "N/A (x) extra"]
)
def test_only_the_catalogs_exact_base_image_marker_excuses_a_missing_url(
    tmp_path: Path, marker: str
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "catalog").mkdir(parents=True)
    (inputs / "catalog" / "operator-repos.csv").write_text(
        f"Component,GitHub Repository,GitHub URL\nruntime,{marker},\n"
    )
    with pytest.raises(ConfigError, match="empty or missing URL cell"):
        repository_inventory(inputs)
