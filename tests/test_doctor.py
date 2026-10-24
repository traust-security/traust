"""`traust admin doctor`: the traust-core rows only. One store read, then each registered
provider's readiness from `ProviderCatalog.readiness`; the store and catalog are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.base import Readiness
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind, ProviderBinding

from traust.cli import doctor

CHECKOV = ProviderBinding(
    capability=Capability(kind=CapabilityKind.TOOL, name="checkov"),
    readiness=Readiness(ready=True),
)
OSV = ProviderBinding(
    capability=Capability(kind=CapabilityKind.FEED, name="osv"),
    readiness=Readiness(ready=False, detail="offline"),
)


def stub(monkeypatch: pytest.MonkeyPatch, list_products: Any) -> list[Any]:
    asked: list[Any] = []
    services = SimpleNamespace(
        portfolio=SimpleNamespace(list_products=list_products),
        catalog=SimpleNamespace(
            readiness=lambda capability: asked.append(capability) or [CHECKOV, OSV]
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return asked


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def test_a_reachable_store_and_every_providers_readiness(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    asked = stub(monkeypatch, lambda page: SimpleNamespace(items=[]))
    results: list[tuple[str, str]] = []
    doctor.check_core(results, home)
    assert asked == [None]
    assert results == [
        (doctor.OK, "traust-core store reachable"),
        (doctor.OK, "provider tool checkov ready"),
        (doctor.WARN, "provider feed osv not ready — offline"),
    ]


def test_an_unreachable_store_fails_and_skips_the_catalog(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    def refused(page: Any) -> Any:
        raise ConfigError("no database")

    asked = stub(monkeypatch, refused)
    results: list[tuple[str, str]] = []
    doctor.check_core(results, home)
    assert asked == []
    assert results == [(doctor.FAIL, "traust-core store not reachable — no database")]


def test_main_reports_the_core_rows_and_exits_by_failures(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    stub(monkeypatch, lambda page: SimpleNamespace(items=[]))
    for check in ("check_python", "check_tools", "check_gates"):
        monkeypatch.setattr(doctor, check, lambda results: None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = doctor.main(["--config-home", str(home), "--quick", "--json"])
    assert rc == 0
    assert json.loads(out.getvalue())[0]["check"] == "traust-core store reachable"
