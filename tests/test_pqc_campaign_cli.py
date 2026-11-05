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


@pytest.mark.parametrize(
    "name",
    [
        "pqc-priority.yml",
        "pqc_priority.yaml",
        "pqc_priority.yml",
        "pqc-priority.example.yaml",
        "config/pqc-priority.yaml",
    ],
)
def test_a_misplaced_priority_file_is_refused_naming_where_it_belongs(
    tmp_path: Path, name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from traust.context import pqc_priority

    misplaced = tmp_path / name
    misplaced.parent.mkdir(parents=True, exist_ok=True)
    misplaced.write_text("chokepoints: [gateway]\n")
    with pytest.raises(SystemExit) as refused:
        pqc_priority(tmp_path)
    assert refused.value.code == 2
    err = capsys.readouterr().err
    assert (
        f"{misplaced}: the PQC priority file must be the file {tmp_path / 'pqc-priority.yaml'}"
        in err
    )
    (tmp_path / "pqc-priority.yaml").write_text("chokepoints: [gateway]\n")
    with pytest.raises(SystemExit):  # beside the right file it is still refused, never ignored
        pqc_priority(tmp_path)


def test_a_priority_path_that_is_not_a_file_is_refused(tmp_path: Path) -> None:
    from traust.context import pqc_priority

    (tmp_path / "pqc-priority.yaml").mkdir()
    with pytest.raises(SystemExit) as refused:
        pqc_priority(tmp_path)
    assert refused.value.code == 2


def test_without_a_priority_file_the_pqc_commands_say_so_naming_the_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    assert pqc.worklist(["--config-home", str(home)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert captured.err.splitlines() == [
        f"pqc: no chokepoint tier: no priority file at {home / 'pqc-priority.yaml'} "
        "(template config/pqc-priority.example.yaml)"
    ]
    (home / "pqc-priority.yaml").write_text("chokepoints: [gateway]\n")
    assert pqc.worklist(["--config-home", str(home)]) == 0
    assert capsys.readouterr().err == ""
