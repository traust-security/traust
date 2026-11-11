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


def test_grouped_command_links_each_named_finding_to_its_best_cve(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = seed(home)
    fetch(home, monkeypatch)
    report = tmp_path / "reports" / "provenance.json"
    rc, result = reconcile(home, "--finding", str(finding_id), "--apply", "--report", str(report))
    assert rc == 0
    assert result == json.loads(report.read_text())
    [check] = result["checks"]
    assert (check["finding_id"], check["recorded"], check["linked"]) == (str(finding_id), CVE, True)
    with SqlTraustUnitOfWork(load(home).database) as uow:
        finding = uow.findings.get(finding_id)
        assert finding.advisory_id is not None
        assert uow.advisories.get(finding.advisory_id).identifier == CVE


@pytest.mark.parametrize("argv", [(), ("--apply",), ("--finding", "{finding}")])
def test_reconcile_without_findings_or_apply_is_refused_before_recording(
    home: Path, monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]
) -> None:
    finding_id = seed(home)
    fetch(home, monkeypatch)
    rc, result = reconcile(home, *(a.format(finding=finding_id) for a in argv))
    assert (rc, result) == (2, {})
    with SqlTraustUnitOfWork(load(home).database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None


def test_missing_feed_is_a_real_refusal_not_an_empty_success(home: Path) -> None:
    finding_id = seed(home)
    rc, result = reconcile(home, "--finding", str(finding_id), "--apply")
    assert (rc, result) == (2, {})
    with SqlTraustUnitOfWork(load(home).database) as uow:
        assert uow.findings.get(finding_id).advisory_id is None
