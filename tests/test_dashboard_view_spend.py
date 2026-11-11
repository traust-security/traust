"""`traust dashboard view spend`: the config home's model registry builds the view and
`--invoice` registers the billed amounts it reconciles against; the view is core's test."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context

from tests.test_dashboard_view import RENDERED, Door, run
from tests.test_metrics_spend import REGISTRY
from tests.test_products_doors import _postgres
from traust.cli import dashboard_view


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[Context]:
    contexts: list[Context] = []
    services = SimpleNamespace(insight=SimpleNamespace(publish=Door(RENDERED)))

    def build(self: Context) -> SimpleNamespace:
        contexts.append(self)
        return services

    monkeypatch.setattr(Context, "services", build)
    return contexts


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def test_the_config_homes_registry_and_the_invoices_are_registered(
    seen: list[Context], home: Path, tmp_path: Path
) -> None:
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    bills = tmp_path / "bills.csv"
    bills.write_text("period,amount_usd\n2026-10,12.5\n")
    assert run(home, "spend", "--invoice", str(bills), "--out", str(tmp_path / "s"))[0] == 0
    assert run(home, "findings-trend", "--out", str(tmp_path / "t"))[0] == 0
    with_bills, without = seen
    assert with_bills.model_catalog is not None and without.model_catalog is not None
    assert [i.period for i in with_bills.invoices] == ["2026-10"] and without.invoices == ()


def test_no_registry_registers_no_catalog(seen: list[Context], home: Path, tmp_path: Path) -> None:
    assert run(home, "findings-trend", "--out", str(tmp_path))[0] == 0
    assert seen[0].model_catalog is None


@pytest.mark.parametrize(
    ("registry", "bills", "error"),
    [
        (None, "period,amount_usd\n2026-10,1\n", "invoices need the spend view"),
        ("version: 1\n", None, "spend not resolvable"),
        (REGISTRY.read_text(), "period,amount_usd\n2026-10,lots\n", "spend not resolvable"),
    ],
)
def test_an_unresolvable_registry_or_invoice_is_exit_2(
    seen: list[Context],
    home: Path,
    tmp_path: Path,
    registry: str | None,
    bills: str | None,
    error: str,
) -> None:
    argv: list[str] = ["spend", "--out", str(tmp_path / "out")]
    if registry is not None:
        (home / "model-registry.yaml").write_text(registry)
    if bills is not None:
        (tmp_path / "bills.csv").write_text(bills)
        argv += ["--invoice", str(tmp_path / "bills.csv")]
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()) as err:
        dashboard_view.main(["--config-home", str(home), *argv])
    assert exit.value.code == 2 and error in err.getvalue()
    assert seen == [] and not (tmp_path / "out").exists()


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_spend_on_core_renders_an_empty_window_with_its_limits(
    tmp_path: Path, database: str
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "model-registry.yaml").write_text(REGISTRY.read_text())
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        out = tmp_path / "out"
        window = ["--since", "2026-09-01T00:00:00Z", "--until", "2026-11-01T00:00:00Z"]
        rc, answer = run(config, "spend", *window, "--out", str(out))
    assert rc == 0, answer
    assert [m["month"] for m in answer["model"]["months"]] == ["2026-09", "2026-10"]
    md = (out / "spend.md").read_text()
    assert "list-price estimates, not invoiced actuals" in md
    assert "nothing here has been checked against real billing" in md
