"""Thin CLI integration; observation and repository contracts live in Core."""

from __future__ import annotations

import ast
import hashlib
import json
import socket
import sqlite3
import subprocess
from pathlib import Path

import pytest
from traust_contracts.v1.storage import Store
from traust_core.v1.models.portfolio import ComparisonStatus
from traust_core.v1.providers.clock import SystemClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner

from traust.cli import build_rescan_worklist as legacy
from traust.cli import observe_repo_state as cli
from traust_pack_security.vocab import EventSource, Lane

REFERENCE = json.loads((Path(__file__).parent / "fixtures/observations/reference.json").read_text())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("observation test attempted network or subprocess")

    for obj, name in [
        (socket, "socket"),
        (socket, "create_connection"),
        (subprocess, "run"),
        (subprocess, "Popen"),
    ]:
        monkeypatch.setattr(obj, name, forbidden)


def setup_cli(tmp_path, monkeypatch, *, repo_url="https://github.com/o/r", audited=True):
    from datetime import datetime

    monkeypatch.setattr(SystemClock, "now", lambda self: datetime.fromisoformat(REFERENCE["now"]))
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"metadata": {"commit": "a" * 40, "additional": {"lines_reviewed": 1000}}})
    )
    findings = tmp_path / "findings.db"
    with sqlite3.connect(findings) as conn:
        conn.executescript("""CREATE TABLE repos (repo_key TEXT, repo_url TEXT, report_path TEXT,
                            audit_date TEXT, product TEXT, tree TEXT, ownership TEXT,
                            report_kind TEXT, is_branch_audit INTEGER);
                            CREATE TABLE findings (repo_key TEXT, severity TEXT, validity TEXT, resolution TEXT);""")
        if audited:
            conn.execute(
                "INSERT INTO repos VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "filing",
                    repo_url,
                    str(report),
                    "2026-01-01",
                    "p",
                    "findings",
                    None,
                    "code-audit",
                    0,
                ),
            )
    graph = tmp_path / "portfolio-graph.db"
    with sqlite3.connect(graph) as conn:
        conn.execute("CREATE TABLE nodes (id TEXT)")
        if repo_url:
            conn.execute(
                "INSERT INTO nodes VALUES (?)", ("repo:" + repo_url.removeprefix("https://"),)
            )
    state_db = tmp_path / "configured-core.db"
    with sqlite3.connect(state_db) as conn:
        Store(conn).init()
    config = tmp_path / "traust.yaml"
    config.write_text(
        f"database:\n  url: sqlite:///{state_db}\nprocess:\n  allowed_binaries: [gh, glab]\n"
    )
    args = ["--core-config", str(config), "--db", str(findings)]
    args += ["--repo-key", "filing"] if audited else ["--repo", repo_url]
    return args, state_db, findings, config


def test_vocab_matches_existing_worklist():
    assert tuple(Lane) == legacy.LANES
    assert tuple(EventSource) == legacy.EVENT_SOURCES
    assert {c["status"] for c in REFERENCE["cases"]} <= set(ComparisonStatus)


def test_no_network_passes_through_real_cli_and_service(tmp_path, monkeypatch, capsys):
    args, state_db, _, _ = setup_cli(tmp_path, monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("--no-network did not prevent forge execution")

    monkeypatch.setattr(ProcessRunner, "run", forbidden)
    assert cli.main([*args, "--no-network"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "network-skipped"
    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT status,changed_lines FROM portfolio_forge_facts"
        ).fetchone() == ("network-skipped", None)
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE name='security_repo_state'"
        ).fetchall()


@pytest.mark.parametrize(
    "status,stderr",
    [
        ("no-credentials", "HTTP 401 authentication"),
        ("unreachable", "dial tcp failed"),
        ("error", "HTTP 500"),
    ],
)
def test_forge_failure_is_stored_and_exits_zero(tmp_path, monkeypatch, capsys, status, stderr):
    args, state_db, _, _ = setup_cli(tmp_path, monkeypatch)
    monkeypatch.setattr(
        ProcessRunner,
        "run",
        lambda self, argv, **kw: ProcessResult(tuple(argv), 1, b"", stderr.encode(), 0),
    )
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == status
    with sqlite3.connect(state_db) as conn:
        assert conn.execute("SELECT status FROM portfolio_forge_facts").fetchone() == (status,)


@pytest.mark.parametrize(
    "url,audited,status",
    [
        (None, True, "no-repo-url"),
        ("https://unknown.example/o/r", True, "unsupported-host"),
        ("https://github.com/o/r", False, "never-audited"),
    ],
)
def test_unobservable_targets_make_no_forge_calls(
    tmp_path, monkeypatch, capsys, url, audited, status
):
    args, _, _, _ = setup_cli(tmp_path, monkeypatch, repo_url=url, audited=audited)
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == status


def test_input_projection_cannot_be_used_as_storage(tmp_path, monkeypatch, capsys):
    args, _, findings, config = setup_cli(tmp_path, monkeypatch)
    before = findings.read_bytes()
    config.write_text(f"database:\n  url: sqlite:///{findings}\n")
    assert cli.main([*args, "--no-network"]) == 2
    assert "separate" in capsys.readouterr().err
    assert findings.read_bytes() == before


def test_missing_storage_is_an_error_not_a_successful_degraded_observation(
    tmp_path, monkeypatch, capsys
):
    args, state_db, _, _ = setup_cli(tmp_path, monkeypatch)
    with sqlite3.connect(state_db) as conn:
        conn.execute("DROP TABLE portfolio_forge_facts")
    assert cli.main([*args, "--no-network"]) == 2
    assert "not initialized" in capsys.readouterr().err


def test_cli_replays_recorded_github_responses(tmp_path, monkeypatch, capsys):
    record = Path(__file__).parent / "fixtures/observations" / REFERENCE["recorded_forge"]["file"]
    assert hashlib.sha256(record.read_bytes()).hexdigest() == REFERENCE["recorded_forge"]["sha256"]
    capture = json.loads(record.read_text())
    case = next(c for c in REFERENCE["cases"] if c["name"] == "recorded-public-github")
    args, state_db, findings, _ = setup_cli(
        tmp_path, monkeypatch, repo_url=capture["repository_url"]
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "metadata": {
                    "commit": capture["base_sha"],
                    "additional": {"lines_reviewed": case["repo"]["lines_reviewed"]},
                }
            }
        )
    )
    with sqlite3.connect(findings) as conn:
        conn.execute("UPDATE repos SET audit_date=?", (case["repo"]["audit_date"],))
    replies = {
        "rate_limit": "100000",
        "info": json.dumps(capture["info"]["response"]),
        "compare": json.dumps(capture["compare"]["response"]),
    }
    calls = []

    def replay(self, argv, **kwargs):
        endpoint = argv[2]
        kind = (
            "rate_limit"
            if endpoint == "rate_limit"
            else "compare"
            if "/compare/" in endpoint
            else "info"
        )
        calls.append(kind)
        return ProcessResult(tuple(argv), 0, replies[kind].encode(), b"", 0)

    monkeypatch.setattr(ProcessRunner, "run", replay)
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["repo"] == capture["repository_url"]
    assert result["changed_lines"] == case["observed"]["C"]
    assert calls == ["info", "rate_limit", "compare"]
    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT changed_lines,audited_sha FROM portfolio_forge_facts"
        ).fetchone() == (case["observed"]["C"], capture["base_sha"])


def test_pack_has_no_observation_storage_or_forge_implementation():
    pack = Path(__file__).parents[1] / "src/traust_pack_security"
    assert not (pack / "repos").joinpath("repo_state.py").exists()
    assert not (pack / "observe.py").exists()
    tree = ast.parse(Path(cli.__file__).read_text())
    imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any(
        name
        and (name.startswith("sqlalchemy") or ".providers." in name or ".repositories." in name)
        for name in imports
    )
