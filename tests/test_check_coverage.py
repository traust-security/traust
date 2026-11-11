"""`traust check coverage`: the pack's observe-mode policy over traust-core's coverage check, and
its wiring into /secure-code-audit and /threat-model. Core's comparison is core's tests."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from traust_core.v1.models.code_facts import (
    CodeFactKind,
    CoverageCheck,
    CoverageSource,
    CoverageStatus,
    EntryPointCoverage,
)

from traust.cli import check_coverage
from traust.cli.groups import GROUPS
from traust.paths import HARNESS_ROOT

S, SRC = CoverageStatus, CoverageSource


def _e(name, status, source=SRC.THREAT_MODEL, enumerator=None, reason=None):
    return EntryPointCoverage(
        source=source, entry_point=name, status=status, enumerator=enumerator, reason=reason
    )


CHECK = CoverageCheck(
    threat_model_found=True,
    entries=(
        _e("REST API", S.COVERED, enumerator=CodeFactKind.ROUTE_GUARD),
        _e("Client gRPC API", S.UNCOVERED, enumerator=CodeFactKind.GRPC_GUARD, reason="found none"),
        _e("Peer Raft API", S.UNCOVERED, reason="no pre-scan enumerates network-peer"),
        _e("Configuration surface", S.UNEXPLAINED, reason="entry point has no kind"),
        _e("fastapi", S.UNCOVERED, SRC.PRE_SCAN, CodeFactKind.ROUTE_GUARD, "UNENUMERATED"),
    ),
)


def test_only_uncovered_entries_a_pre_scan_could_cover_would_route():
    assert check_coverage.would_route(CHECK) == [
        "threat model: Client gRPC API (found none)",
        "pre-scan: fastapi (UNENUMERATED)",
    ]
    covered_only = CoverageCheck(threat_model_found=False, entries=CHECK.entries[:1])
    assert check_coverage.would_route(covered_only) == []


def test_the_document_reports_observe_mode_counts_and_the_lane():
    doc = check_coverage.document(CHECK)
    assert doc["mode"] == "observe"
    assert doc["summary"] == {"covered": 1, "uncovered": 3, "unexplained": 1}
    assert doc["would_route"]["lane"] == "coverage-repair"
    assert len(doc["entries"]) == 5


class Services:
    def __init__(self, repo_id=None):
        self.calls = []
        found = SimpleNamespace(id=repo_id) if repo_id else None
        self.portfolio = SimpleNamespace(
            find_repository=lambda url: found,
            register_ref=lambda rid, sha, a, b: SimpleNamespace(id=uuid.UUID(int=7)),
        )
        self.code_facts = SimpleNamespace(coverage=self._coverage)

    def _coverage(self, request, ref_id):
        self.calls.append((request.workspace, ref_id))
        return CHECK


@pytest.fixture
def services(monkeypatch):
    stub = Services(repo_id=uuid.UUID(int=1))
    core = SimpleNamespace(
        services=lambda: stub, config=SimpleNamespace(forge_hosts=("github.com",))
    )
    monkeypatch.setattr(check_coverage, "load", lambda home: core)
    return stub


def test_without_a_repository_it_compares_the_pre_scans_only(services, capsys, tmp_path):
    assert check_coverage.main([str(tmp_path)]) == 0
    assert services.calls == [(tmp_path, None)]
    assert json.loads(capsys.readouterr().out)["mode"] == "observe"


def test_a_repository_and_commit_bring_in_its_threat_model(services, capsys, tmp_path):
    out = tmp_path / "o" / "coverage.json"
    argv = [
        str(tmp_path),
        "--repo-url",
        "https://github.com/ex/svc",
        "--sha",
        "a" * 40,
        "-o",
        str(out),
    ]
    assert check_coverage.main(argv) == 0
    assert services.calls == [(tmp_path, uuid.UUID(int=7))]
    assert json.loads(capsys.readouterr().out)["would_route"] is True
    assert json.loads(out.read_text())["summary"]["unexplained"] == 1


def test_an_unregistered_repository_is_refused(monkeypatch, capsys, tmp_path):
    core = SimpleNamespace(services=Services, config=SimpleNamespace(forge_hosts=("github.com",)))
    monkeypatch.setattr(check_coverage, "load", lambda home: core)
    argv = [str(tmp_path), "--repo-url", "https://github.com/ex/svc", "--sha", "a" * 40]
    assert check_coverage.main(argv) == 2
    assert "not registered" in capsys.readouterr().err


def test_repo_url_needs_sha(tmp_path):
    with pytest.raises(SystemExit):
        check_coverage.main([str(tmp_path), "--repo-url", "https://github.com/ex/svc"])


def test_registered_and_wired():
    assert "coverage" in GROUPS["check"]
    audit = (HARNESS_ROOT / "harnessing/3-audit/secure-code-audit/SKILL.md").read_text()
    assert "check coverage" in audit and "observe mode" in audit
    model = (HARNESS_ROOT / "harnessing/2-threat-model/threat-model/SKILL.md").read_text()
    assert "`entry_point_kind` vocabulary" in model
