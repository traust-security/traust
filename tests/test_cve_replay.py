from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.artifacts import CveReplayArtifact, SecurityAuditArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.cve_replay import (
    CveReplayAudit,
    CveReplayCandidate,
    CveReplaySnapshot,
    CveReplayVerdict,
)
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind, ScannerSeverity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog, PublishSpec, PublishSpecs

from tests.test_validate_report import _canonical_report
from traust.cli import cve_replay
from traust.cli.__main__ import main as cli

NOW = datetime(2026, 11, 3, tzinfo=UTC)
HUMAN = Principal(
    identity="reviewer",
    display="Reviewer",
    kind=ActorKind.HUMAN,
    verified_by=IdentitySource.LOCAL_USER,
)


def candidate(
    audit: CveReplayAudit, identifier: str, verdict: CveReplayVerdict, presence: bool | None
) -> CveReplayCandidate:
    return CveReplayCandidate(
        **audit.model_dump(),
        advisory_id=identifier,
        published_at=datetime(2026, 11, 2, tzinfo=UTC),
        checked_at=NOW,
        severity=ScannerSeverity.CRITICAL,
        summary="Synthetic replay candidate",
        present_at_audit=presence,
        reviewer=HUMAN.ref if presence is not None else None,
        presence_identity_source=HUMAN.verified_by if presence is not None else None,
        presence_evidence="Recorded commit source inspection" if presence is not None else None,
        audit_verdict=verdict,
        reason="synthetic report evidence",
        source="fixture:osv",
    )


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Context:
    core = Context(
        Config(home=tmp_path / "core"),
        object_store=InMemoryObjectStore(),
        clock=FixedClock(NOW),
    )
    services = core.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/project", core.config.forge_hosts),
        False,
    )
    ref = services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    publisher = core.artifact_publisher(
        PublishSpecs(PublishSpec(SecurityAuditArtifact), PublishSpec(CveReplayArtifact))
    )
    body = _canonical_report()
    body["metadata"].update(repository=repository.url, commit=ref.sha)
    doc = SecurityAuditArtifact.from_document(body)
    published = publisher.publish_artifact(doc)
    log = AssessmentLog(SqlTraustUnitOfWork(core.database))
    assessment, artifact = log.add(
        Assessment(
            repository_ref_id=ref.id,
            kind=AssessmentKind.SECURE_CODE_CANONICAL,
            status="completed",
            assessor="skill:secure-code-audit",
            assessor_version="fixture",
            occurred_at=datetime(2026, 10, 1, tzinfo=UTC),
        ),
        published.artifact_id,
        sha256_hex(doc.payload),
    )
    audit = CveReplayAudit(
        repository_id=repository.id,
        repository_ref_id=ref.id,
        repository=repository.url,
        audited_commit=ref.sha,
        audit_id=assessment.id,
        report_artifact_id=artifact.id,
        audited_at=assessment.occurred_at,
    )
    snapshot = CveReplaySnapshot(
        audit=audit,
        revision=1,
        watermark=NOW,
        checks=(
            candidate(audit, "CVE-2026-99901", CveReplayVerdict.MISSED, True),
            candidate(audit, "CVE-2026-99902", CveReplayVerdict.UNCLEAR, None),
            candidate(audit, "CVE-2026-99903", CveReplayVerdict.NOT_APPLICABLE, False),
            candidate(audit, "CVE-2026-99904", CveReplayVerdict.DETECTED, True),
        ),
    )
    stored = CveReplayArtifact.from_document(snapshot.model_dump(mode="json"))
    published = publisher.publish_artifact(stored)
    log.add(
        Assessment(
            repository_ref_id=ref.id,
            baseline_assessment_id=assessment.id,
            kind=AssessmentKind.CVE_REPLAY,
            status="completed",
            assessor="cve-replay",
            assessor_version="fixture",
            occurred_at=NOW,
        ),
        published.artifact_id,
        sha256_hex(stored.payload),
    )
    monkeypatch.setattr(cve_replay, "load", lambda config_home: core)
    monkeypatch.setattr(cve_replay, "load_caller", lambda context: HUMAN)
    return core


def test_grouped_candidate_export_uses_real_core_policy_and_stays_human_gated(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(["sweep", "cve-replay", "candidates"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert [r["advisory_id"] for r in output["candidates"]] == ["CVE-2026-99901", "CVE-2026-99902"]
    assert all(r["requires_human_review"] is True for r in output["candidates"])
    assert core.services().detection_quality.cve_replay_trends().rows[0].advisory_id == (
        "CVE-2026-99901"
    )


def test_grouped_trend_export_excludes_unknown_presence_and_area_only_checks(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(["sweep", "cve-replay", "trends"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["series"] == "fn_cve_replay_missed"
    assert [r["advisory_id"] for r in output["rows"]] == ["CVE-2026-99901"]
    assert len(core.services().detection_quality.cve_replay_candidates().candidates) == 2


def test_monitor_without_registered_osv_provider_fails_without_changing_candidates(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    before = core.services().detection_quality.cve_replay_candidates()
    assert cli(["sweep", "cve-replay", "monitor"]) == 2
    assert capsys.readouterr().out == ""
    assert core.services().detection_quality.cve_replay_candidates() == before


def test_oracle_invalid_assessment_identifier_is_rejected_before_loading_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_load(config_home: Path | None) -> Context:
        raise AssertionError("invalid input must not load Core")

    monkeypatch.setattr(cve_replay, "load", unexpected_load)
    with pytest.raises(SystemExit) as failure:
        cli(["sweep", "cve-replay", "oracle", "not-a-uuid", "CVE-2026-99901"])
    assert failure.value.code == 2


@pytest.mark.parametrize("since", ["not-a-date", "2026-10-01T00:00:00"])
def test_malformed_or_naive_watermark_is_rejected_before_loading_core(
    monkeypatch: pytest.MonkeyPatch, since: str
) -> None:
    def unexpected_load(config_home: Path | None) -> Context:
        raise AssertionError("invalid input must not load Core")

    monkeypatch.setattr(cve_replay, "load", unexpected_load)
    if since == "not-a-date":
        with pytest.raises(SystemExit) as failure:
            cli(["sweep", "cve-replay", "monitor", "--since", since])
        assert failure.value.code == 2
    else:
        assert cli(["sweep", "cve-replay", "monitor", "--since", since]) == 2


def test_oracle_uses_real_exported_osv_record_and_verified_caller_for_adjudication(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "osv.json"
    path.write_text(
        json.dumps(
            {
                "id": "GHSA-2345-6789-cfgh",
                "aliases": ["CVE-2026-99902"],
                "published": "2026-11-02T00:00:00Z",
                "affected": [],
                "summary": "Synthetic fixture advisory",
                "database_specific": {"severity": "CRITICAL"},
            }
        )
    )
    core.use_exported_advisories([path])
    audit = core.services().detection_quality.cve_replay_candidates().candidates[1].audit_id
    assert (
        cli(
            [
                "sweep",
                "cve-replay",
                "oracle",
                str(audit),
                "CVE-2026-99902",
                "--present-at-audit",
                "true",
                "--evidence",
                "Original source at audit confirms presence",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["present_at_audit"] is True
    assert output["reviewer"] == HUMAN.ref
    assert output["audit_verdict"] == "missed"
    assert len(core.services().detection_quality.cve_replay_trends().rows) == 2


def test_oracle_presence_without_evidence_cannot_change_recorded_queue(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    before = core.services().detection_quality.cve_replay_candidates()
    audit = before.candidates[0].audit_id
    assert (
        cli(
            [
                "sweep",
                "cve-replay",
                "oracle",
                str(audit),
                "CVE-2026-99902",
                "--present-at-audit",
                "true",
            ]
        )
        == 2
    )
    assert capsys.readouterr().out == ""
    assert core.services().detection_quality.cve_replay_candidates() == before


def test_monitor_uses_real_http_osv_boundary_and_keeps_new_presence_unconfirmed(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
    from traust_core.v1.providers.osv import OsvAdvisoryLookup

    requests: list[dict[str, object]] = []
    response = json.dumps(
        {
            "vulns": [
                {
                    "id": "GO-2026-99905",
                    "aliases": ["CVE-2026-99905"],
                    "published": "2026-11-03T12:00:00Z",
                    "affected": [],
                    "summary": "Synthetic HTTP fixture advisory",
                    "database_specific": {"severity": "CRITICAL"},
                }
            ],
        }
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        core.clock = FixedClock(NOW.replace(day=4))
        core.advisories = OsvAdvisoryLookup(
            f"http://127.0.0.1:{server.server_port}/v1",
            http=HttpFetcher("cve-replay-cli-test", RetryPolicy(max_attempts=1)),
            clock=core.clock,
        )
        assert cli(["sweep", "cve-replay", "monitor"]) == 0
        output = json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert requests == [{"commit": "a" * 40}]
    [check] = output["checks"]
    assert check["advisory_id"] == "CVE-2026-99905"
    assert check["present_at_audit"] is None
    assert check["audit_verdict"] == "unclear"
    assert [row["advisory_id"] for row in output["trends"]["rows"]] == ["CVE-2026-99901"]


def test_machine_caller_cannot_adjudicate_presence_via_cli(
    core: Context, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = core.services().detection_quality.cve_replay_candidates()
    audit = before.candidates[0].audit_id
    machine = HUMAN.model_copy(update={"kind": ActorKind.MACHINE})
    monkeypatch.setattr(cve_replay, "load_caller", lambda context: machine)
    assert (
        cli(
            [
                "sweep",
                "cve-replay",
                "oracle",
                str(audit),
                "CVE-2026-99902",
                "--present-at-audit",
                "true",
                "--evidence",
                "claimed presence",
            ]
        )
        == 2
    )
    assert capsys.readouterr().out == ""
    assert core.services().detection_quality.cve_replay_candidates() == before
