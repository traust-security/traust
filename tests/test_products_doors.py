"""`traust products list|add|update` end to end on traust-core, in-process on SQLite and Postgres."""

from __future__ import annotations

import contextlib
import io
import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
import yaml
from traust_core.v1 import contracts
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import Dialect

from traust.cli import products
from traust.cli.__main__ import main
from traust.context import load

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")


@contextlib.contextmanager
def _postgres() -> Iterator[str]:
    """A fresh database on the test server, dropped after: parallel workers never share one."""
    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    name = f"traust_corpus_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(PG_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name}")
    url = sa.make_url(PG_URL).set(database=name)
    engine = create_database_engine(url)
    apply_schema(engine, contracts.database_ddl(Dialect.of(engine)))
    engine.dispose()
    try:
        yield url.render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def add(home: Path, name: str, label: str, ownership: str, bu: str) -> tuple[int, Any]:
    return run(
        products.add, home, name, "--label", label, "--ownership", ownership, "--business-unit", bu
    )


def listed(home: Path) -> dict[str, dict[str, Any]]:
    rc, rows = run(products.list_, home)
    assert rc == 0, rows
    return {r["name"]: r for r in rows}


def test_empty_corpus_lists_nothing(home: Path) -> None:
    assert listed(home) == {}


def test_add_registers_the_product_with_its_ownership(home: Path) -> None:
    rc, row = add(home, "contoso-findings", "contoso", "external-bu", "Contoso")
    assert rc == 0, row
    assert row["label"] == "contoso"
    assert (row["ownership"], row["business_unit"]) == ("external-bu", "Contoso")
    assert listed(home) == {"contoso-findings": row}


def test_every_ownership_tag_is_accepted(home: Path) -> None:
    for tag in ("owned", "upstream", "external-bu", "harness-qa"):
        assert add(home, f"tree-{tag}", tag, tag, "BU")[0] == 0
    assert {n: r["ownership"] for n, r in listed(home).items()} == {
        f"tree-{t}": t for t in ("owned", "upstream", "external-bu", "harness-qa")
    }


def test_re_adding_a_name_with_the_same_fields_changes_nothing(home: Path) -> None:
    _, first = add(home, "findings", "example-platform", "owned", "Example")
    rc, again = add(home, "findings", "example-platform", "owned", "Example")
    assert rc == 0
    assert again == first
    assert listed(home) == {"findings": first}


@pytest.mark.parametrize(
    "fields",
    [
        ("renamed", "owned", "Example"),
        ("example-platform", "upstream", "Example"),
        ("example-platform", "owned", "Other"),
    ],
    ids=["label", "ownership", "business_unit"],
)
def test_re_adding_a_name_with_other_fields_is_refused(
    home: Path, fields: tuple[str, str, str]
) -> None:
    _, first = add(home, "findings", "example-platform", "owned", "Example")
    rc, err = add(home, "findings", *fields)
    assert rc == 2
    assert "already registered" in err and "with update" in err
    assert listed(home) == {"findings": first}


@pytest.mark.parametrize("name", ["", "../escape", "_under-first", "has space", "a/b"])
def test_invalid_names_are_refused(home: Path, name: str) -> None:
    rc, err = add(home, name, "label", "owned", "BU")
    assert rc == 2
    assert "product.slug" in err
    assert listed(home) == {}


def test_unknown_ownership_is_refused_before_any_write(home: Path) -> None:
    with pytest.raises(SystemExit) as exited:
        add(home, "findings", "label", "partner", "BU")
    assert exited.value.code == 2
    assert listed(home) == {}


def test_update_changes_only_the_fields_given(home: Path) -> None:
    add(home, "findings", "example-platform", "owned", "Example")
    rc, row = run(products.update, home, "findings", "--ownership", "upstream")
    assert rc == 0, row
    assert (row["label"], row["ownership"], row["business_unit"]) == (
        "example-platform",
        "upstream",
        "Example",
    )
    rc, row = run(products.update, home, "findings", "--label", "renamed", "--business-unit", "New")
    assert (row["label"], row["ownership"], row["business_unit"]) == ("renamed", "upstream", "New")
    assert listed(home) == {"findings": row}


def test_update_with_no_fields_returns_the_entry(home: Path) -> None:
    _, first = add(home, "findings", "example-platform", "owned", "Example")
    assert run(products.update, home, "findings") == (0, first)


def test_update_of_an_unknown_name_is_refused(home: Path) -> None:
    rc, err = run(products.update, home, "nope", "--ownership", "owned")
    assert rc == 2
    assert "no product named 'nope'" in err


def test_a_product_without_ownership_needs_both_fields(home: Path) -> None:
    load(home).services().portfolio.register_product(ProductSlug("findings"), "example-platform")
    assert listed(home)["findings"]["ownership"] is None
    rc, err = run(products.update, home, "findings", "--ownership", "owned")
    assert rc == 2
    assert "give both fields" in err
    rc, row = run(products.update, home, "findings", "--ownership", "owned", "--business-unit", "E")
    assert (rc, row["ownership"], row["business_unit"]) == (0, "owned", "E")


def test_add_completes_a_product_registered_without_ownership(home: Path) -> None:
    load(home).services().portfolio.register_product(ProductSlug("findings"), "example-platform")
    rc, err = add(home, "findings", "ignored", "owned", "Example")
    assert rc == 2
    assert "with update" in err
    rc, row = add(home, "findings", "example-platform", "owned", "Example")
    assert (rc, row["label"], row["ownership"]) == (0, "example-platform", "owned")


def test_reverting_ownership_publishes_again(home: Path) -> None:
    add(home, "findings", "example-platform", "owned", "Example")
    run(products.update, home, "findings", "--ownership", "upstream")
    rc, row = run(products.update, home, "findings", "--ownership", "owned")
    assert rc == 0, row
    assert listed(home)["findings"]["ownership"] == "owned"


def test_the_cli_routes_the_group(home: Path) -> None:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(["products", "list", "--config-home", str(home)])
    assert (rc, json.loads(out.getvalue())) == (0, [])
