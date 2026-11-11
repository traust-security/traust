"""`traust isolation repos`: the CLI layer only. The product's commits come from
`PortfolioService.list_product_refs`, grouped by repository; the reads are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context

from traust.cli import isolation

PRODUCT = SimpleNamespace(id=uuid.uuid4(), slug="example-service")
API, WORKER = "https://github.com/example/api-server", "https://github.com/example/worker"
REFS = {
    uuid.uuid4(): (API, "b" * 40),
    uuid.uuid4(): (WORKER, "c" * 40),
    uuid.uuid4(): (API, "a" * 40),
}


@pytest.fixture
def portfolio(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    calls: list[Any] = []
    stub = SimpleNamespace(
        calls=calls,
        products={"example-service": PRODUCT},
        refs=[SimpleNamespace(id=i, sha=sha) for i, (_, sha) in REFS.items()],
    )

    def list_product_refs(product_id: uuid.UUID) -> list[Any]:
        calls.append(product_id)
        return stub.refs

    services = SimpleNamespace(
        portfolio=SimpleNamespace(
            find_product=lambda slug: stub.products.get(str(slug)),
            list_product_refs=list_product_refs,
            inventory=SimpleNamespace(
                resolve=lambda ref_id: (None, SimpleNamespace(url=REFS[ref_id][0]))
            ),
        )
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = isolation.repos(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_repos_groups_the_shipped_commits_by_repository(portfolio, home):
    rc, out = run(home, "example-service")
    assert rc == 0
    assert out["service"] == "example-service"
    assert out["repos"] == [
        {"url": API, "shas": ["a" * 40, "b" * 40]},
        {"url": WORKER, "shas": ["c" * 40]},
    ]
    assert out["graph_ref"].startswith("traust-core product example-service @ ")
    assert portfolio.calls == [PRODUCT.id]


def test_repos_unknown_service_is_exit_2(portfolio, home):
    rc, err = run(home, "nope")
    assert rc == 2
    assert "nope is not a registered product" in err
    assert portfolio.calls == []


def test_repos_bad_slug_is_exit_2(portfolio, home):
    rc, err = run(home, "Bad Slug!")
    assert rc == 2
    assert "slug" in err


def test_repos_product_shipping_nothing(portfolio, home):
    portfolio.refs = []
    rc, out = run(home, "example-service")
    assert rc == 0
    assert out["repos"] == []
