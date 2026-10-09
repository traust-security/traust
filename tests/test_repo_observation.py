"""Offline observation parity, degraded results, and repository contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import URL
from traust_core.v1.domain import ValidationError
from traust_core.v1.repositories.sql import create_database_engine, schema_drift

from traust.cli import build_rescan_worklist as legacy
from traust.cli import observe_repo_state as cli
from traust_pack_security.models import AuditedRepo
from traust_pack_security.observe import observe_repo
from traust_pack_security.repos.observation_inputs import LegacyObservationInputs
from traust_pack_security.repos.repo_state import (
    InMemoryRepoStateRepository,
    RepoStateUnitOfWork,
    initialize_repo_state,
    metadata,
)
from traust_pack_security.vocab import ComparisonStatus, EventSource, Lane

REFERENCE = json.loads((Path(__file__).parent / "fixtures/observations/reference.json").read_text())
NOW = datetime.fromisoformat(REFERENCE["now"])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("observation tests cannot use network or subprocesses")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


class FakeForge:
    def __init__(self, *, info=None, compare=None, quota=100):
        self.info = info if info is not None else REFERENCE["cases"][0]["info"]
        self.comparison = compare if compare is not None else REFERENCE["cases"][0]["compare"]
        self.quota = quota
        self.calls = []

    def repo_info(self, *args):
        self.calls.append(("info", *args))
        return copy.deepcopy(self.info)

    def compare(self, *args):
        self.calls.append(("compare", *args))
        return copy.deepcopy(self.comparison)

    def remaining(self):
        self.calls.append(("remaining",))
        return self.quota


def baseline(**changes):
    return AuditedRepo(**{**REFERENCE["cases"][0]["repo"], **changes})


def test_vocab_matches_worklist_tuples():
    assert tuple(Lane) == legacy.LANES
    assert tuple(EventSource) == legacy.EVENT_SOURCES
    # Existing literal statuses plus the bootstrap-only status, redesign step 1.
    assert tuple(ComparisonStatus) == (
        "ok",
        "quota-deferred",
        "no-pinned-sha",
        "unsupported-host",
        "no-repo-url",
        "no-credentials",
        "unreachable",
        "error",
        "ban-suspected",
        "network-skipped",
        "never-audited",
    )


def assert_observation_matches_reference(state, case):
    assert state.status == case["status"]
    for field, old in {
        "changed_lines": "C",
        "sensitive_changed": "S",
        "sensitive_lines": "S_lines",
        "deps_only": "deps_only",
        "ahead_by": "ahead_by",
        "compare_truncated": "truncated",
    }.items():
        assert getattr(state, field) == case["observed"][old]
    assert state.risk_tier == case["ctx"]["tier"]
    assert state.exposure == case["ctx"]["exposure"]
    assert state.audit_age_days == case["ctx"]["audit_age_days"]
    assert bool(state.push_changed) == case["ctx"]["changed"]
    # Old ctx filled unavailable change counts with zero. The new record keeps
    # observation truth; only actual measurements are compared to the old ratio.
    assert state.churn_ratio == (case["ctx"]["R"] if state.changed_lines is not None else None)


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda case: case["name"])
def test_observe_matches_ctx(case):
    forge = FakeForge(info=case["info"], compare=case["compare"])
    state = observe_repo(AuditedRepo(**case["repo"]), forge, NOW)
    assert_observation_matches_reference(state, case)
    compares = [call for call in forge.calls if call[0] == "compare"]
    assert len(compares) == int(case["info"]["ok"] and case["ctx"]["changed"])


def test_cli_replays_recorded_github_responses(tmp_path, monkeypatch, capsys):
    fixture = Path(__file__).parent / "fixtures/observations" / REFERENCE["recorded_forge"]["file"]
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == REFERENCE["recorded_forge"]["sha256"]
    capture = json.loads(fixture.read_text())
    case = next(case for case in REFERENCE["cases"] if case["name"] == "recorded-public-github")
    repo = AuditedRepo(**case["repo"])
    project = capture["repository_url"].removeprefix("https://github.com/")
    replies = {
        f"repos/{project}": json.dumps(capture["info"]["response"]),
        f"repos/{project}/compare/{capture['base_sha']}...HEAD": json.dumps(
            capture["compare"]["response"]
        ),
        "rate_limit": "100000",  # Synthetic quota; no live quota or audit claims.
    }
    calls = []

    def replay(argv, **kwargs):
        assert argv[:2] == ["gh", "api"]
        calls.append(argv[2])
        return subprocess.CompletedProcess(argv, 0, stdout=replies[argv[2]], stderr="")

    monkeypatch.setattr(subprocess, "run", replay)
    monkeypatch.setattr(LegacyObservationInputs, "find", lambda self, **_: repo)
    monkeypatch.setattr(cli.SystemClock, "now", lambda self: NOW)
    state_db = tmp_path / "state.db"
    assert (
        cli.main(
            [
                "--repo",
                repo.repo_url,
                "--db",
                str(tmp_path / "findings.db"),
                "--state-db",
                str(state_db),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["repo"] == capture["repository_url"]
    assert result["status"] == case["status"]
    assert result["changed_lines"] == case["observed"]["C"]
    assert calls == [
        f"repos/{project}",
        "rate_limit",
        f"repos/{project}/compare/{capture['base_sha']}...HEAD",
    ]
    engine = create_database_engine(URL.create("sqlite", database=str(state_db)))
    try:
        with RepoStateUnitOfWork(engine) as uow:
            state = uow.repo_state.get_by_key(repo.repo_key)
            assert_observation_matches_reference(state, case)
            assert state.observed_at == NOW
    finally:
        engine.dispose()


def case_for_status(status):
    repo, forge, kwargs = baseline(), FakeForge(), {}
    if status == "no-repo-url":
        repo = baseline(repo_url=None)
    elif status == "unsupported-host":
        repo = baseline(repo_url="https://unknown.example/o/r")
    elif status == "never-audited":
        repo = baseline(has_audit=False, audit_date=None, pinned_sha=None, live_crit_high=0)
    elif status == "no-pinned-sha":
        repo = baseline(pinned_sha=None)
    elif status == "quota-deferred":
        forge.quota = 0
    elif status == "network-skipped":
        kwargs["network"] = False
    elif status == "ban-suspected":
        breaker = legacy._BanBreaker(threshold=1)
        breaker.record(False)
        kwargs["breaker"] = breaker
    elif status != "ok":
        forge.info = {"ok": False, "kind": status, "error": "fixture forge error"}
    return repo, forge, kwargs


@pytest.mark.parametrize("status", list(ComparisonStatus))
def test_status_and_unmeasured_values(status):
    repo, forge, kwargs = case_for_status(status)
    state = observe_repo(repo, forge, NOW, **kwargs)
    assert state.status == status
    if status != "ok":
        assert state.changed_lines is None
        assert state.sensitive_changed is None
        assert state.churn_ratio is None
        assert state.compare_truncated is None
    if status == "never-audited":
        assert state.audit_age_days is None
        assert not forge.calls
    if status in {"no-repo-url", "unsupported-host", "ban-suspected", "network-skipped"}:
        assert not forge.calls


@pytest.mark.parametrize("status", list(ComparisonStatus))
def test_cli_stores_status_and_exits_zero(status, tmp_path, monkeypatch, capsys):
    repo, forge, kwargs = case_for_status(status)
    monkeypatch.setattr(LegacyObservationInputs, "find", lambda self, **_: repo)
    monkeypatch.setattr(cli, "LegacyForgeClient", lambda: forge)
    real_observe = cli.observe_repo
    monkeypatch.setattr(
        cli, "observe_repo", lambda repo, forge, now, **_: real_observe(repo, forge, NOW, **kwargs)
    )
    state_db = tmp_path / "state.db"
    assert (
        cli.main(
            [
                "--repo-key",
                repo.repo_key,
                "--db",
                str(tmp_path / "findings.db"),
                "--state-db",
                str(state_db),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == status
    engine = create_database_engine(URL.create("sqlite", database=str(state_db)))
    try:
        with RepoStateUnitOfWork(engine) as uow:
            saved = uow.repo_state.get_by_key(repo.repo_key)
            assert saved.status == status
            assert saved.observed_at == NOW
    finally:
        engine.dispose()


def test_transport_exception_is_degraded():
    class OfflineForge(FakeForge):
        def repo_info(self, *args):
            raise TimeoutError("fixture timeout")

    state = observe_repo(baseline(), OfflineForge(), NOW)
    assert state.status == "unreachable"
    assert state.error == "fixture timeout"


@pytest.mark.parametrize(
    "source_url",
    [
        "https://github.com/o/repo/tree/main",
        "https://github.com/o/repo/blob/main/src/app.py",
        "https://GitHub.com/o/repo.git",
        "HTTPS://github.com/o/repo",
        "https://github.com/o/repo.git/tree/main",
    ],
)
def test_github_identity_matches_forge_target(source_url):
    forge = FakeForge()
    state = observe_repo(baseline(repo_url=source_url), forge, NOW)
    assert state.status == "ok"
    assert str(state.repo) == "https://github.com/o/repo"
    assert state.source_url == source_url
    assert forge.calls == [
        ("info", "github", "github.com", "o/repo"),
        ("remaining",),
        ("compare", "github", "github.com", "o/repo", "a" * 40, "HEAD"),
    ]


@pytest.mark.parametrize(
    "source_url",
    [
        "https://github.com/o/repo/tree/../../other",
        "https://github.com/o/.git/tree/main",
    ],
)
def test_github_normalization_does_not_bypass_url_validation(source_url):
    forge = FakeForge()
    state = observe_repo(baseline(repo_url=source_url, has_audit=False), forge, NOW)
    assert state.status == "unsupported-host"
    assert state.repo is None
    assert not forge.calls


def test_cli_no_network_records_skipped_without_forge_calls(tmp_path, monkeypatch, capsys):
    class ForbiddenForge:
        def repo_info(self, *args):
            raise AssertionError("--no-network must prevent every forge call")

        compare = repo_info
        remaining = repo_info

    repo = baseline()
    monkeypatch.setattr(LegacyObservationInputs, "find", lambda self, **_: repo)
    monkeypatch.setattr(cli, "LegacyForgeClient", ForbiddenForge)
    monkeypatch.setattr(cli.SystemClock, "now", lambda self: NOW)
    state_db = tmp_path / "state.db"
    assert (
        cli.main(
            [
                "--repo-key",
                repo.repo_key,
                "--db",
                str(tmp_path / "findings.db"),
                "--state-db",
                str(state_db),
                "--no-network",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "network-skipped"
    assert result["changed_lines"] is None
    engine = create_database_engine(URL.create("sqlite", database=str(state_db)))
    try:
        with RepoStateUnitOfWork(engine) as uow:
            saved = uow.repo_state.get_by_key(repo.repo_key)
            assert saved.status == "network-skipped"
            assert saved.observed_at == NOW
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "host,phase,payload",
    [
        ("github.com", "info", "{invalid"),
        ("github.com", "info", "[]"),
        ("github.com", "info", '{"pushed_at": 123}'),
        ("github.com", "info", '{"visibility": ["public"]}'),
        ("github.com", "compare", "null"),
        ("github.com", "compare", '{"ahead_by": "oops", "files": []}'),
        ("github.com", "compare", '{"ahead_by": 1, "files": [{}]}'),
        (
            "github.com",
            "compare",
            '{"ahead_by": 1, "files": [{"filename": "a.py", "changes": {}}]}',
        ),
        ("gitlab.com", "info", "[]"),
        ("gitlab.com", "info", '{"forked_from_project": ["invalid"]}'),
        ("gitlab.com", "compare", '{"diffs": [null]}'),
        ("gitlab.com", "compare", '{"diffs": [{"diff": 123}]}'),
    ],
)
def test_cli_stores_malformed_forge_response(host, phase, payload, tmp_path, monkeypatch, capsys):
    repo = baseline(repo_url=f"https://{host}/o/repo")
    monkeypatch.setattr(LegacyObservationInputs, "find", lambda self, **_: repo)
    monkeypatch.setattr(cli.SystemClock, "now", lambda self: NOW)
    monkeypatch.setattr(legacy.shutil, "which", lambda name: "/fixture/glab")

    def run(argv, **kwargs):
        if argv[0] == "gh" and argv[2] == "rate_limit":
            output = "100"
        else:
            request = argv[2] if argv[0] == "gh" else argv[-1]
            actual_phase = "compare" if "/compare" in request else "info"
            if actual_phase == phase:
                output = payload
            else:
                assert actual_phase == "info"
                info = REFERENCE["cases"][0]["info"]
                output = json.dumps(
                    info
                    if host == "github.com"
                    else {
                        "last_activity_at": info["pushed_at"],
                        "default_branch": "main",
                        "visibility": "public",
                    }
                )
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    state_db = tmp_path / "state.db"
    assert (
        cli.main(
            [
                "--repo-key",
                repo.repo_key,
                "--db",
                str(tmp_path / "findings.db"),
                "--state-db",
                str(state_db),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "error"
    assert result["error"]
    assert result["changed_lines"] is None
    assert result["ahead_by"] is None
    assert result["compare_truncated"] is None
    engine = create_database_engine(URL.create("sqlite", database=str(state_db)))
    try:
        with RepoStateUnitOfWork(engine) as uow:
            saved = uow.repo_state.get_by_key(repo.repo_key)
            assert saved.status == "error"
            assert saved.error == result["error"]
            assert saved.observed_at == NOW
    finally:
        engine.dispose()


@pytest.mark.parametrize("method", ["repo_info", "compare", "remaining"])
@pytest.mark.parametrize(
    "error_type", [AttributeError, KeyError, TypeError, ValueError, ValidationError]
)
def test_forge_adapter_decode_errors_are_degraded(method, error_type, monkeypatch):
    forge = FakeForge()

    def malformed(*args):
        raise error_type("fixture decoding failure")

    monkeypatch.setattr(forge, method, malformed)
    state = observe_repo(baseline(), forge, NOW)
    assert state.status == "error"
    assert state.changed_lines is None
    assert state.ahead_by is None
    assert "malformed forge response" in state.error


def test_malformed_normalized_comparison_is_degraded():
    state = observe_repo(baseline(), FakeForge(compare={"ok": True}), NOW)
    assert state.status == "error"
    assert state.changed_lines is None
    assert state.ahead_by is None


def test_malformed_quota_is_degraded_without_comparison():
    forge = FakeForge(quota="not a count")
    state = observe_repo(baseline(), forge, NOW)
    assert state.status == "error"
    assert [call[0] for call in forge.calls] == ["info", "remaining"]


def test_metric_programming_errors_are_not_forge_failures(monkeypatch):
    def broken_metrics(files):
        raise ValueError("fixture calculation bug")

    monkeypatch.setattr(legacy, "change_metrics", broken_metrics)
    with pytest.raises(ValueError, match="fixture calculation bug"):
        observe_repo(baseline(), FakeForge(), NOW)


def test_naive_clock_rejected():
    with pytest.raises(ValueError, match="timezone"):
        observe_repo(baseline(), FakeForge(), datetime(2026, 10, 6))


def test_gitlab_compare_uses_branch_without_github_quota():
    forge = FakeForge(quota=0)
    state = observe_repo(baseline(repo_url="https://gitlab.com/group/sub/repo"), forge, NOW)
    assert state.status == "ok"
    assert str(state.repo) == "https://gitlab.com/group/sub/repo"
    assert forge.calls == [
        ("info", "gitlab", "gitlab.com", "group/sub/repo"),
        ("compare", "gitlab", "gitlab.com", "group/sub/repo", "a" * 40, "main"),
    ]


@pytest.fixture(params=["memory", "sqlite"])
def repository(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepoStateRepository()
    else:
        engine = create_database_engine(URL.create("sqlite", database=str(tmp_path / "state.db")))
        initialize_repo_state(engine)
        assert schema_drift(engine, metadata) == []
        try:
            with RepoStateUnitOfWork(engine) as uow:
                yield uow.repo_state
        finally:
            engine.dispose()


def test_repository_contract(repository):
    state = observe_repo(baseline(), FakeForge(), NOW)
    assert repository.get(state.repo) is None
    assert repository.list() == []
    repository.save(state)
    assert repository.get(state.repo) == state
    changed = state.model_copy(update={"changed_lines": 0, "sensitive_changed": False})
    repository.save(changed)
    assert repository.list() == [changed]
    assert repository.get_by_key(state.repo_key) == changed


def test_missing_urls_are_distinct(repository):
    first = observe_repo(baseline(repo_key="one", repo_url=None), FakeForge(), NOW)
    second = observe_repo(baseline(repo_key="two", repo_url=None), FakeForge(), NOW)
    repository.save(first)
    repository.save(second)
    assert repository.list() == [first, second]
    assert repository.get_by_key("one") == first
    assert repository.get_by_key("two") == second


def test_new_freshest_filing_keeps_one_url_record(repository):
    state = observe_repo(baseline(), FakeForge(), NOW)
    repository.save(state)
    replacement = state.model_copy(update={"repo_key": "newer-filing"})
    repository.save(replacement)
    assert repository.list() == [replacement]
    assert repository.get_by_key(state.repo_key) is None


def test_github_deep_link_does_not_create_a_second_repository(repository):
    root = observe_repo(baseline(), FakeForge(), NOW)
    deep_link = observe_repo(
        baseline(repo_key="new-filing", repo_url="https://github.com/o/repo/tree/main"),
        FakeForge(),
        NOW,
    )
    repository.save(root)
    repository.save(deep_link)
    assert repository.list() == [deep_link]
    assert repository.get(root.repo) == deep_link


def test_missing_url_repaired_without_leaving_a_stale_record(repository):
    missing = observe_repo(baseline(repo_url=None), FakeForge(), NOW)
    repaired = observe_repo(baseline(), FakeForge(), NOW)
    repository.save(missing)
    repository.save(repaired)
    assert repository.list() == [repaired]
    assert repository.get_by_key(missing.repo_key) == repaired


def test_sql_commit_and_rollback(tmp_path):
    engine = create_database_engine(URL.create("sqlite", database=str(tmp_path / "state.db")))
    initialize_repo_state(engine)
    state = observe_repo(baseline(), FakeForge(), NOW)
    try:
        with RepoStateUnitOfWork(engine) as uow:
            uow.repo_state.save(state)
        with RepoStateUnitOfWork(engine) as uow:
            assert uow.repo_state.get(state.repo) is None
            uow.repo_state.save(state)
            uow.commit()
        with RepoStateUnitOfWork(engine) as uow:
            assert uow.repo_state.get(state.repo) == state
    finally:
        engine.dispose()


def test_cli_reads_real_projection_and_selected_report(tmp_path, monkeypatch, capsys):
    from tests.test_build_rescan_worklist import _mk_db, _mk_report

    report = _mk_report(tmp_path, "fixture")
    db = _mk_db(
        tmp_path,
        [
            {
                "repo_key": "old",
                "repo_url": "https://github.com/o/repo",
                "report_path": str(report),
                "audit_date": "2026-08-01",
            },
            {
                "repo_key": "new",
                "repo_url": "https://github.com/o/repo",
                "report_path": str(report),
                "audit_date": "2026-09-01",
            },
            {
                "repo_key": "other",
                "repo_url": "https://github.com/o/other",
                "report_path": None,
                "audit_date": None,
            },
        ],
        [{"repo_key": "old"}],
    )
    before = db.read_bytes()
    forge = FakeForge()
    monkeypatch.setattr(cli, "LegacyForgeClient", lambda: forge)
    assert (
        cli.main(
            [
                "--repo",
                "https://github.com/o/repo",
                "--db",
                str(db),
                "--state-db",
                str(tmp_path / "state.db"),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["repo_key"] == "new"
    assert result["risk_tier"] == "P1"  # live risk from the older sibling filing
    assert result["repo"] == "https://github.com/o/repo"
    assert result["changed_lines"] == 240
    assert db.read_bytes() == before
    assert [call[3] for call in forge.calls if call[0] in {"info", "compare"}] == [
        "o/repo",
        "o/repo",
    ]


def test_unknown_repository_is_not_invented_as_bootstrap(tmp_path):
    from tests.test_build_rescan_worklist import _mk_db

    db = _mk_db(tmp_path, [], [])
    source = LegacyObservationInputs(
        db, tmp_path / "missing-graph.db", tmp_path / "missing-designations.json"
    )
    with pytest.raises(LookupError, match="not found"):
        source.find(repo_url="https://github.com/o/unknown")


def test_inventory_bootstrap_reads_membership_and_designation_without_forge_calls(tmp_path):
    from tests.test_build_rescan_worklist import _mk_db

    db = _mk_db(tmp_path, [], [])
    graph = tmp_path / "graph.db"
    with sqlite3.connect(graph) as connection:
        connection.execute("CREATE TABLE nodes (id TEXT)")
        connection.execute("INSERT INTO nodes VALUES (?)", ("repo:github.com/o/new",))
    designations = tmp_path / "designations.json"
    designations.write_text(
        json.dumps(
            {
                "designations": [
                    {"match": "https://github.com/o/new", "exposure": "external"},
                ]
            }
        )
    )
    source = LegacyObservationInputs(db, graph, designations)
    repo = source.find(repo_url="https://github.com/o/new")
    forge = FakeForge()
    state = observe_repo(repo, forge, NOW)
    assert state.status == "never-audited"
    assert state.risk_tier == "P2"
    assert state.exposure == "private-external"
    assert state.audit_age_days is None
    assert not forge.calls


def test_cli_refuses_writing_into_findings(tmp_path):
    with pytest.raises(SystemExit) as failure:
        cli.main(
            [
                "--repo",
                "https://github.com/o/repo",
                "--db",
                str(tmp_path / "findings.db"),
                "--state-db",
                str(tmp_path / "findings.db"),
            ]
        )
    assert failure.value.code == 2


def test_unified_cli_help_shows_observation_flags(capsys):
    from traust.cli.__main__ import main

    with pytest.raises(SystemExit) as result:
        main(["observe", "repo-state", "--help"])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert "--repo-key" in help_text
    assert "--state-db" in help_text
    assert "--no-network" in help_text
