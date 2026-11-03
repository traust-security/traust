from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import Decision, Finding, Occurrence
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from traust.cli.__main__ import main
from traust.context import load


def test_grouped_verified_fix_mtta_counts_only_assessment_backed_fixes(tmp_path: Path) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    core = load(home)
    at = datetime(2026, 10, 1, tzinfo=UTC)
    with SqlTraustUnitOfWork(core.database) as uow:
        repo = uow.repositories.add(Repository(url="https://github.com/example/app", public=True))
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repo.id, sha="a" * 40))
        audit = uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind="scanner",
                status="completed",
                assessor="scanner",
                assessor_version="1",
                occurred_at=at,
            )
        )
        verified = uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind="verification",
                status="completed",
                assessor="verifier",
                assessor_version="1",
                occurred_at=at + timedelta(days=4),
            )
        )
        for number, assessment_id in enumerate((verified.id, None)):
            finding = uow.findings.add(
                Finding(
                    repository_id=repo.id,
                    fingerprint_algo="v3",
                    fingerprint=str(number),
                    title="Synthetic finding with evidence-bound resolution",
                )
            )
            uow.occurrences.add(
                Occurrence(
                    finding_id=finding.id,
                    assessment_id=audit.id,
                    severity="high",
                )
            )
            uow.decisions.add(
                Decision(
                    finding_id=finding.id,
                    assessment_id=assessment_id,
                    actor="human:reviewer@example.com" if assessment_id is None else None,
                    statement_key=str(number),
                    resolution="resolved",
                    occurred_at=at + timedelta(days=4),
                )
            )
        uow.commit()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = main(
            [
                "findings",
                "verified-fix-mtta",
                "--config-home",
                str(home),
                "--repo-url",
                repo.url,
                "--as-of",
                (at + timedelta(days=5)).isoformat(),
            ]
        )
    assert rc == 0, output.getvalue()
    assert json.loads(output.getvalue()) == [{"severity": "high", "findings": 1, "mtta_days": 4.0}]
