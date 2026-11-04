from __future__ import annotations

import json
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli import pqc
from traust.cli.groups.pqc import PQC

FIXTURE = Path(__file__).parent / "fixtures/pqc/widget-pqc-readiness.json"


def test_worklist_cli_discovers_registered_unassessed_repositories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    monkeypatch.setattr(pqc, "pqc_priority", lambda _: ("oauth-gateway",))
    services = core.services()
    for slug in ("widget", "oauth-gateway"):
        repository = services.portfolio.register_repository(
            HttpsRepoUrl.parse(f"https://github.com/example/{slug}", ["github.com"]),
            True,
        )
        services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.worklist([]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert [(e["priority_tier"], e["route"]) for e in entries] == [
        ("chokepoint", "source"),
        ("tail", "source"),
    ]
    assert all(e["scan"]["assessment_id"] is None for e in entries)
    assert pqc.worklist(["--markdown"]) == 0
    markdown = capsys.readouterr().out
    assert "https://github.com/example/oauth-gateway" in markdown
    assert {"sweep", "worklist"} <= PQC.keys()


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


def test_sweep_cli_refuses_a_source_scan_until_the_scanner_decision(
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
    services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.sweep([]) == 2
    assert "pqc-scan scanner needs a traust-core decision (plan 15, decision 4)" in (
        capsys.readouterr().err
    )


def test_pqc_priority_reads_the_config_home_file(tmp_path: Path) -> None:
    from traust.context import pqc_priority

    assert pqc_priority(tmp_path) == ()
    (tmp_path / "pqc-priority.yaml").write_text("chokepoints: [Gateway, ' tls-proxy ', Gateway]\n")
    assert pqc_priority(tmp_path) == ("Gateway", "tls-proxy")
    (tmp_path / "pqc-priority.yaml").write_text("chokepoints: gateway\n")
    with pytest.raises(SystemExit) as refused:
        pqc_priority(tmp_path)
    assert refused.value.code == 2
