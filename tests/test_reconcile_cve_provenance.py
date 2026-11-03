"""The grouped provenance door uses real Core snapshots, audits and finding links on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.findings import Finding, Occurrence
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import ScannerSeverity
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from traust.cli import feeds_fetch
from traust.cli.__main__ import main
from traust.context import load

TITLE = "Server-Side Request Forgery via unvalidated request URI"
CVE = "CVE-2026-114620"
DAY = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def seed(home: Path, title: str = TITLE) -> UUID:
    core = load(home)
    with SqlTraustUnitOfWork(core.database) as uow:
        repository = uow.repositories.add(
            Repository(url="https://github.com/example/authlib", public=True)
        )
        assert repository.id is not None
        finding = uow.findings.add(
            Finding(
                repository_id=repository.id,
                fingerprint_algo="v3",
                fingerprint="provenance-test",
                title=title,
            )
        )
        assert finding.id is not None
        for offset, branch in ((0, "main"), (5, "release")):
            ref = uow.repository_refs.add(
                RepositoryRef(
                    repository_id=repository.id,
                    sha=str(offset) * 40,
                    name=branch,
                    kind="branch",
                )
            )
            assert ref.id is not None
            assessment = uow.assessments.add(
                Assessment(
                    repository_ref_id=ref.id,
                    kind=AssessmentKind.SECURE_CODE_CANONICAL,
                    status="completed",
                    assessor="skill:secure-code-audit",
                    assessor_version="test",
                    occurred_at=DAY + timedelta(days=offset),
                )
            )
            assert assessment.id is not None
            uow.occurrences.add(
                Occurrence(
                    finding_id=finding.id,
                    assessment_id=assessment.id,
                    severity=ScannerSeverity.HIGH,
                )
            )
        uow.commit()
    return finding.id


def fetch(home: Path, monkeypatch: pytest.MonkeyPatch, title: str = TITLE) -> None:
    payload = json.dumps(
        [{"CVE": CVE, "public_date": "2026-10-22", "bugzilla_description": "authlib: " + title}]
    ).encode()

    def get(self: HttpFetcher, url: str) -> bytes:
        assert url.startswith("https://access.redhat.com/hydra/rest/securitydata/cve.json")
        return payload

    monkeypatch.setattr(HttpFetcher, "get", get)
    with contextlib.redirect_stdout(io.StringIO()):
        assert feeds_fetch.main(["--config-home", str(home), "--feed", "rh-cve"]) == 0


def reconcile(home: Path, *argv: str) -> tuple[int, dict[str, object]]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = main(["feeds", "reconcile-cve-provenance", "--config-home", str(home), *argv])
    text = output.getvalue()
    return rc, json.loads(text) if text.strip() else {}


def test_grouped_command_defaults_to_dry_run_reports_branch_leads_and_applies_once(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = seed(home)
    fetch(home, monkeypatch)
    report = tmp_path / "reports" / "provenance.json"
    rc, result = reconcile(home, "--report", str(report))
    assert rc == 0
    assert result == json.loads(report.read_text())
    assert (result["apply"], result["distinct_cves"], result["links_planned"]) == (False, 1, 1)
    assert sorted(row["lead_days"] for row in result["matches"]) == [12, 17]
    assert (
        result["confirmed_lead_min"],
        result["confirmed_lead_median"],
        result["confirmed_lead_max"],
    ) == (12, 17, 17)
    core = load(home)
    with SqlTraustUnitOfWork(core.database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None
        assert uow.advisories.find_by_identifier(CVE) is None
        assert uow.finding_external_refs.list_for_finding(finding_id) == []
    rc, applied = reconcile(home, "--apply")
    assert (rc, applied["links_written"], applied["findings_linked"]) == (0, 1, 1)
    with SqlTraustUnitOfWork(core.database) as uow:
        finding = uow.findings.get(finding_id)
        assert finding.advisory_id is not None
        assert uow.advisories.get(finding.advisory_id).identifier == CVE
        assert finding.advisory_match == "confirmed"
        refs = uow.finding_external_refs.list_for_finding(finding_id)
        assert [(r.system, r.ref) for r in refs] == [("cve", CVE)]
        assert uow.decisions.list_for_finding(finding_id) == []
    rc, again = reconcile(home, "--apply")
    assert (
        rc,
        again["links_planned"],
        again["links_written"],
        again["findings_linked"],
    ) == (0, 0, 0, 0)
    with SqlTraustUnitOfWork(core.database) as uow:
        assert uow.findings.get(finding_id) == finding
        assert uow.finding_external_refs.list_for_finding(finding_id) == refs


def test_cli_threshold_rejects_a_weaker_match_before_any_apply(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = seed(home, "Tenant isolation bypass through admin console routes")
    fetch(home, monkeypatch, "Tenant isolation bypass in API")
    rc, strict = reconcile(home, "--min-score", "0.75", "--apply")
    assert (rc, strict["matches"], strict["links_written"]) == (0, [], 0)
    rc, probable = reconcile(home)
    assert (rc, probable["distinct_probable_only"], probable["links_planned"]) == (0, 1, 1)
    assert {row["match"] for row in probable["matches"]} == {"probable"}
    with SqlTraustUnitOfWork(load(home).database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None


@pytest.mark.parametrize("value", ["-0.1", "1.1", "nan", "inf"])
def test_cli_rejects_invalid_threshold_without_mutating_findings(home: Path, value: str) -> None:
    finding_id = seed(home)
    rc, result = reconcile(home, "--min-score", value, "--apply")
    assert (rc, result) == (2, {})
    with SqlTraustUnitOfWork(load(home).database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None


def test_missing_feed_is_a_real_refusal_not_an_empty_success(home: Path) -> None:
    finding_id = seed(home)
    rc, result = reconcile(home, "--apply")
    assert (rc, result) == (2, {})
    with SqlTraustUnitOfWork(load(home).database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None
