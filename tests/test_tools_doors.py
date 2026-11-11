"""`traust tools list|run`: the CLI over core's tool registry and ProviderCatalog, with a stubbed
context holding one fake tool; the registry, catalog and request validation are core's."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import ToolRequest, ToolTarget
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolProvider
from traust_core.v1.services.provider_catalog import ProviderCatalog

from traust.cli import tools
from traust.cli.__main__ import main

BUILT = datetime(2026, 10, 20, tzinfo=UTC)


@dataclass
class FakeTool:
    name: str
    target: ToolTarget = ToolTarget.CHECKOUT
    readiness: Readiness = field(default_factory=lambda: Readiness(ready=True))
    db: DatabaseStatus | None = None
    seen: list[ToolRequest] = field(default_factory=list)

    def check(self) -> Readiness:
        return self.readiness

    def acquire(self, request: ToolRequest) -> Result[dict[str, Any]]:
        if request.target is not self.target:
            raise ValidationError(f"{self.name} runs over a {self.target.value}")
        self.seen.append(request)
        return Result(
            {"target": request.target.value, "params": request.params},
            Acquisition(provider=self.name, acquired_at=BUILT, version="1.2.3"),
        )

    def version(self) -> str | None:
        return "1.2.3"

    def database(self) -> DatabaseStatus | None:
        return self.db

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(self.name)


@pytest.fixture
def registered(monkeypatch: pytest.MonkeyPatch) -> dict[str, FakeTool]:
    fakes = {
        "scan": FakeTool("scan", db=DatabaseStatus(tool="scan", exists=True, built_at=BUILT)),
        "reach": FakeTool("reach", target=ToolTarget.SYMBOLS),
        "absent": FakeTool("absent", readiness=Readiness(ready=False, detail="not on PATH")),
    }
    registry = ProviderRegistry[ToolProvider[Any]]("tool")
    for name, fake in fakes.items():
        registry.register(name, lambda fake=fake: fake)
    catalog = ProviderCatalog(registry, ProviderRegistry[FeedProvider]("feed"))
    ctx = SimpleNamespace(tools=registry, services=lambda: SimpleNamespace(catalog=catalog))
    monkeypatch.setattr(tools, "load", lambda home: ctx)
    return fakes


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, Any, str]:
    rc = main(["tools", *argv])
    out, err = capsys.readouterr()
    return rc, (json.loads(out) if out.strip() else None), err


def test_list_names_each_tool_with_readiness_version_and_database(
    registered: dict[str, FakeTool], capsys: pytest.CaptureFixture[str]
) -> None:
    rc, rows, _ = _run(["list"], capsys)
    assert rc == 0
    by_name = {r["tool"]: r for r in rows}
    assert set(by_name) == {"scan", "reach", "absent"}
    assert by_name["scan"]["version"] == "1.2.3"
    assert by_name["scan"]["database"]["built_at"] == "2026-10-20T00:00:00Z"
    assert by_name["absent"] == {
        "tool": "absent",
        "ready": False,
        "detail": "not on PATH",
        "version": None,
        "database": None,
    }


def test_run_prints_the_result_and_provenance_with_params(
    registered: dict[str, FakeTool], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, doc, _ = _run(
        ["run", "scan", "--workspace", str(tmp_path), "--param", "mode=history"], capsys
    )
    assert rc == 0
    assert doc["data"] == {"target": "checkout", "params": {"mode": "history"}}
    assert doc["acquisition"]["provider"] == "scan"
    assert registered["scan"].seen[0].workspace == tmp_path


def test_symbols_carry_the_checkout_they_search(
    registered: dict[str, FakeTool], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _, _ = _run(["run", "reach", "--workspace", str(tmp_path), "--symbols", "a", "b"], capsys)
    assert rc == 0
    query = registered["reach"].seen[0].symbols
    assert query is not None and query.workspace == tmp_path and query.names == ("a", "b")


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["run", "scan"], "exactly one target"),
        (["run", "scan", "--workspace", ".", "--image", "x"], "exactly one target"),
        (["run", "reach", "--symbols", "a"], "--symbols needs --workspace"),
        (["run", "scan", "--workspace", ".", "--param", "noequals"], "KEY=VALUE"),
        (["run", "scan", "--workspace", ".", "--param", "k=1", "--param", "k=2"], "given twice"),
        (["run", "scan", "--sbom", "s.json"], "runs over a checkout"),
        (["run", "absent", "--workspace", "."], "tool absent not ready: not on PATH"),
        (["run", "nope", "--workspace", "."], "unknown tool provider 'nope'"),
    ],
)
def test_refusals_exit_2_with_the_typed_error(
    registered: dict[str, FakeTool],
    argv: list[str],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, out, err = _run(argv, capsys)
    assert (rc, out) == (2, None)
    assert message in err
    assert not registered["absent"].seen
