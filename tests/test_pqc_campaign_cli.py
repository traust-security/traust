from __future__ import annotations

import json
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli import pqc


def test_worklist_cli_discovers_registered_unassessed_repositories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    services = core.services()
    for slug in ("widget", "oauth-gateway"):
        repository = services.portfolio.register_repository(
            HttpsRepoUrl.parse(f"https://github.com/example/{slug}", ["github.com"]),
            True,
        )
        services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.worklist(["--chokepoint", " OAuth-Gateway ", "--chokepoint", "oauth-gateway"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert [(e["priority_tier"], e["route"]) for e in entries] == [
        ("chokepoint", "source"),
        ("tail", "source"),
    ]
    assert all(e["scan"]["assessment_id"] is None for e in entries)
    assert entries[0]["repository"] == "https://github.com/example/oauth-gateway"


def test_sweep_cli_reports_access_work_and_rejects_invalid_batch_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    repository = core.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/awaiting-access", ["github.com"]),
        False,
    )
    assert pqc.sweep(["--limit", "1", "--refresh"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["remaining"] == 0 and result["next_cursor"] is None
    assert [
        (r["entry"]["repository_id"], r["status"], r["assessment_id"]) for r in result["results"]
    ] == [(str(repository.id), "access-request", None)]
    assert pqc.sweep(["--limit", "0"]) == 2
    capsys.readouterr()
    assert core.services().portfolio.inventory.list_refs(repository.id) == []


def test_sweep_cli_rejects_a_missing_provider_without_partial_scan_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    services = core.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/widget", ["github.com"]), True
    )
    target = services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.sweep([]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err
    assert services.portfolio.inventory.get_ref(target.id).manifest_sbom_id is None
    [state] = services.pqc.scan_states(PqcFilter())
    assert state.assessment_id is None
    assert services.pqc.list_readiness(PqcFilter()) == []


def test_without_a_chokepoint_every_repository_ranks_crypto_cwe_then_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    services = core.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/oauth-gateway", ["github.com"]), True
    )
    services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.worklist([]) == 0
    captured = capsys.readouterr()
    assert [e["priority_tier"] for e in json.loads(captured.out)] == ["tail"]
    assert captured.err.splitlines() == [
        "pqc: no chokepoint tier: no --chokepoint given; every repository ranks crypto-CWE then tail"
    ]
    assert pqc.worklist(["--chokepoint", "gateway"]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("blank", ["", "  "])
def test_a_blank_chokepoint_is_refused(blank: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as refused:
        pqc.worklist(["--chokepoint", blank])
    assert refused.value.code == 2
    assert "nonblank URL fragment" in capsys.readouterr().err
