"""`traust reporting record`: the CLI layer only. One `AssessmentService.record` call per
document; publishing, the kind/schema match and the same-run dedupe are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import (
    IsolationReviewArtifact,
    PrivProfileArtifact,
    SecurityAuditArtifact,
    ThreatModelArtifact,
    VulnFindingsArtifact,
)
from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from tests.test_isolation_review import _valid_report as isolation_review
from tests.test_products_doors import _postgres
from tests.test_validate_report import _valid_report as security_audit
from traust.cli import assessment_record
from traust.cli.__main__ import main as cli

SHA = "a" * 40
URL = "https://github.com/example/widget-operator"
REF = uuid.uuid4()
PRIV_PROFILE = {"repo": "widget-operator", "summary": {"workloads": 1, "rbac_rules": 3}}


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    recorded = SimpleNamespace(model_dump=lambda **_: {"id": "a-1", "status": "completed"})
    stub = SimpleNamespace(
        record=Door(recorded),
        register_repository=Door(SimpleNamespace(id=uuid.uuid4())),
        register_ref=Door(SimpleNamespace(id=REF)),
    )
    services = SimpleNamespace(
        assessment=SimpleNamespace(record=stub.record),
        portfolio=SimpleNamespace(
            register_repository=stub.register_repository, register_ref=stub.register_ref
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def document(tmp_path: Path, body: dict) -> Path:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(body))
    return path


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = assessment_record.main(["--config-home", str(home), *argv])
        except SystemExit as e:
            rc = e.code
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.mark.parametrize(
    ("kind", "body", "artifact", "skill"),
    [
        ("container", security_audit(), SecurityAuditArtifact, "secure-container-audit"),
        ("rpm", security_audit(), SecurityAuditArtifact, "secure-rpm-audit"),
        ("isolation-review", isolation_review(), IsolationReviewArtifact, "isolation-review"),
        ("priv-profile", PRIV_PROFILE, PrivProfileArtifact, "operator-priv-profile"),
    ],
)
def test_record_files_the_document_on_the_commit(
    doors, home, tmp_path, kind, body, artifact, skill
):
    path = document(tmp_path, body)
    rc, out = run(home, str(path), "--kind", kind, "--repo-url", URL, "--sha", SHA)
    assert rc == 0
    assert out == {"id": "a-1", "status": "completed"}
    [(doc, ref, recorded_kind, assessor, assessor_version, provenance)] = doors.record.calls
    assert isinstance(doc, artifact)
    assert doc.payload == path.read_bytes()
    assert (ref, recorded_kind, assessor) == (REF, AssessmentKind(kind), f"skill:{skill}")
    assert assessor_version
    assert provenance.artifact is None
    assert provenance.source == SourceType.VULN_SCAN_REPORT
    assert doors.register_repository.calls[0][1] is False
    assert str(doors.register_ref.calls[0][1]) == SHA


@pytest.mark.parametrize(
    ("kind", "body", "ran"),
    [
        ("container", security_audit(), datetime(2026, 5, 21, tzinfo=UTC)),
        ("isolation-review", isolation_review(), datetime(2026, 7, 20, tzinfo=UTC)),
    ],
)
def test_record_stamps_when_the_audit_ran(doors, home, tmp_path, kind, body, ran):
    path = document(tmp_path, body)
    for _ in range(2):
        assert run(home, str(path), "--kind", kind, "--repo-url", URL, "--sha", SHA)[0] == 0
    assert [call[-1].occurred_at for call in doors.record.calls] == [ran, ran]


def test_record_stamps_a_profile_when_recorded(doors, home, tmp_path):
    before = datetime.now(UTC)
    path = document(tmp_path, PRIV_PROFILE)
    assert run(home, str(path), "--kind", "priv-profile", "--repo-url", URL, "--sha", SHA)[0] == 0
    assert doors.record.calls[0][-1].occurred_at >= before


@pytest.mark.parametrize(
    ("kind", "body", "message"),
    [
        (
            "rpm",
            {**security_audit(), "metadata": {"date": "21 May", "scope": "x"}},
            "metadata/date",
        ),
        (
            "isolation-review",
            {
                **isolation_review(),
                "metadata": {
                    **isolation_review()["metadata"],
                    "reviewed_at": "2026-07-20T00:00:00",
                },
            },
            "time zone",
        ),
    ],
)
def test_record_refuses_a_run_time_off_its_schema(doors, home, tmp_path, kind, body, message):
    path = document(tmp_path, body)
    rc, err = run(home, str(path), "--kind", kind, "--repo-url", URL, "--sha", SHA)
    assert rc == 2
    assert message in err
    assert doors.record.calls == []


def test_record_marks_a_public_repository(doors, home, tmp_path):
    path = document(tmp_path, PRIV_PROFILE)
    rc, _ = run(
        home, str(path), "--kind", "priv-profile", "--repo-url", URL, "--sha", SHA, "--public"
    )
    assert rc == 0
    assert doors.register_repository.calls[0][1] is True


def test_record_refuses_a_document_off_its_schema(doors, home, tmp_path):
    path = document(tmp_path, PRIV_PROFILE)
    rc, err = run(home, str(path), "--kind", "container", "--repo-url", URL, "--sha", SHA)
    assert rc == 2
    assert "ERROR" in err
    assert doors.record.calls == []


def test_record_refuses_a_kind_it_does_not_record(doors, home, tmp_path):
    path = document(tmp_path, PRIV_PROFILE)
    rc, err = run(home, str(path), "--kind", "cloud-config", "--repo-url", URL, "--sha", SHA)
    assert rc == 2
    assert "invalid choice" in err
    assert doors.record.calls == []


def test_record_refuses_a_short_sha(doors, home, tmp_path):
    path = document(tmp_path, PRIV_PROFILE)
    rc, _ = run(home, str(path), "--kind", "priv-profile", "--repo-url", URL, "--sha", "abc")
    assert rc == 2
    assert doors.record.calls == []


def test_record_missing_document_is_exit_2(doors, home, tmp_path):
    rc, err = run(
        home, str(tmp_path / "nope.json"), "--kind", "rpm", "--repo-url", URL, "--sha", SHA
    )
    assert rc == 2
    assert "ERROR" in err


def test_record_refusal_from_core_is_exit_2(doors, home, tmp_path):
    doors.record.result = NotFoundError(f"repository ref {REF} not found")
    path = document(tmp_path, PRIV_PROFILE)
    rc, err = run(home, str(path), "--kind", "priv-profile", "--repo-url", URL, "--sha", SHA)
    assert rc == 2
    assert "not found" in err


def test_reporting_group_routes_record(doors, home, tmp_path, capsys):
    path = document(tmp_path, PRIV_PROFILE)
    argv = ["reporting", "record", "--config-home", str(home), str(path), "--kind", "priv-profile"]
    rc = cli([*argv, "--repo-url", URL, "--sha", SHA])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["id"] == "a-1"
    assert len(doors.record.calls) == 1


@pytest.fixture(params=["sqlite", "postgres"])
def core_home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "core.yaml").write_text(yaml.safe_dump(core))
        yield config


def test_record_on_core_files_one_assessment_on_the_bare_commit(core_home, tmp_path):
    home = core_home
    path = document(tmp_path, PRIV_PROFILE)
    rc, out = run(home, str(path), "--kind", "priv-profile", "--repo-url", URL, "--sha", SHA)
    assert rc == 0, out
    core = Context.from_file(home / "core.yaml")
    services = core.services()
    repo = services.portfolio.find_repository(HttpsRepoUrl.parse(URL, core.config.forge_hosts))
    ref = services.portfolio.register_ref(repo.id, GitSha.parse(SHA), None, None)
    latest = services.assessment.latest(ref.id, AssessmentKind.PRIV_PROFILE)
    assert latest is not None
    assert (str(latest.id), latest.assessor) == (out["id"], "skill:operator-priv-profile")
    # privileges reads the default line only; a bare commit recorded from traust isn't on it.
    assert services.assessment.privileges(AssessmentFilter(), [repo.id]) == []


def test_record_on_core_rerecording_a_report_is_the_same_run(core_home, tmp_path):
    path = document(tmp_path, security_audit())
    ids = set()
    for _ in range(2):
        rc, out = run(core_home, str(path), "--kind", "rpm", "--repo-url", URL, "--sha", SHA)
        assert rc == 0, out
        ids.add(out["id"])
    assert len(ids) == 1


VULN_FINDINGS = {
    "target": "widget-operator",
    "scanned_at": "2026-10-24T09:00:00Z",
    "focus_areas": ["parser"],
    "metadata": {
        "repo": "widget-operator",
        "repo_slug": "WIDGET_OPERATOR",
        "scanned_ref": SHA[:7],
        "harness_version": "0.1.0-abc1234",
        "baseline": None,
        "baseline_findings": 0,
    },
    "findings": [],
    "known_findings": [],
    "summary": dict.fromkeys(
        ("total", "critical", "high", "medium", "low", "informational", "known", "low_confidence"),
        0,
    ),
}


def test_record_files_a_vuln_scan_at_its_scan_time(doors, home, tmp_path):
    path = document(tmp_path, VULN_FINDINGS)
    for _ in range(2):
        rc, _ = run(home, str(path), "--kind", "vuln-scan", "--repo-url", URL, "--sha", SHA)
        assert rc == 0
    (doc, ref, kind, assessor, _, _provenance) = doors.record.calls[0]
    assert isinstance(doc, VulnFindingsArtifact)
    assert (ref, kind, assessor) == (REF, AssessmentKind.VULN_SCAN, "skill:vuln-scan")
    assert [c[-1].occurred_at for c in doors.record.calls] == [
        datetime(2026, 10, 24, 9, tzinfo=UTC)
    ] * 2


def test_record_refuses_a_vuln_scan_time_without_a_zone(doors, home, tmp_path):
    path = document(tmp_path, {**VULN_FINDINGS, "scanned_at": "2026-10-24T09:00:00"})
    rc, err = run(home, str(path), "--kind", "vuln-scan", "--repo-url", URL, "--sha", SHA)
    assert rc == 2
    assert "time zone" in err
    assert doors.record.calls == []


def test_record_files_a_secure_code_audit_at_its_report_date(doors, home, tmp_path):
    path = document(tmp_path, security_audit())
    rc, _ = run(home, str(path), "--kind", "secure-code", "--repo-url", URL, "--sha", SHA)
    assert rc == 0
    [(doc, ref, kind, assessor, _, provenance)] = doors.record.calls
    assert isinstance(doc, SecurityAuditArtifact)
    assert (ref, kind, assessor) == (REF, AssessmentKind.SECURE_CODE, "skill:secure-code-audit")
    assert provenance.occurred_at == datetime(2026, 5, 21, tzinfo=UTC)


def test_record_files_a_threat_model_at_its_provenance_date(doors, home, tmp_path):
    model = {
        "system": "widget-operator",
        "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": URL},
        "threats": [],
    }
    path = document(tmp_path, model)
    rc, _ = run(home, str(path), "--kind", "threat-model", "--repo-url", URL, "--sha", SHA)
    assert rc == 0
    [(doc, ref, kind, assessor, _, provenance)] = doors.record.calls
    assert isinstance(doc, ThreatModelArtifact)
    assert (ref, kind, assessor) == (REF, AssessmentKind.THREAT_MODEL, "skill:threat-model")
    assert provenance.occurred_at == datetime(2026, 10, 1, tzinfo=UTC)
