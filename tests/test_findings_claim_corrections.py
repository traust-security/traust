"""Canonical claim correction through the installed grouped CLI and real SQLite services."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from uuid import UUID

import pytest

from tests.test_findings_doors import REPO, run, scanned
from tests.test_findings_doors import home as home
from tests.test_triage_doors import SHA
from tests.test_validate_report import _canonical_report
from traust.cli import auth
from traust.cli.__main__ import main
from traust.context import load


def grouped(home: Path, operation: str, *arguments: str) -> tuple[int, object]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = main(["findings", operation, "--config-home", str(home), *arguments])
    text = output.getvalue().strip()
    return status, json.loads(text) if text else None


def proposal_file(home: Path, tmp_path: Path, finding_id: str) -> tuple[Path, str]:
    services = load(home).services()
    occurrence = services.findings.occurrences(finding_ids=[UUID(finding_id)])[0]
    body = _canonical_report()
    body["metadata"].update(repository=REPO, commit=SHA)
    entry = body["findings"][0]
    entry.update(
        title="Corrected buffer-size claim",
        description=(
            "Human review established that the corrected claim concerns the destination "
            "buffer bound in this helper rather than the originally reported source bound."
        ),
        locations=[{"path": "corrected/buffer.c", "lines": "21-23"}],
        cwes=["CWE-120"],
        category="memory-safety",
        severity="low",
    )
    body["findings"] = [entry]
    path = tmp_path / "corrected-report.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path, str(occurrence.assessment_id)


def request(home: Path, path: Path, finding_id: str, assessment_id: str) -> tuple[int, object]:
    return grouped(
        home,
        "correction-request",
        str(path),
        "--finding",
        finding_id,
        "--assessment",
        assessment_id,
        "--label",
        "TEST-001",
        "--ticket",
        "SEC-417",
        "--rationale",
        "Reviewed the original scanner claim and corrected the affected helper.",
    )


def test_grouped_claim_correction_uses_immutable_reviewed_content(
    home: Path, tmp_path: Path
) -> None:
    finding_id = scanned(home, tmp_path)
    assert run(auth.local, home, "--identity", "reviewer@example.com")[0] == 0
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    original = load(home).services().findings.get(UUID(finding_id))
    original_occurrences = (
        load(home).services().findings.occurrences(finding_ids=[UUID(finding_id)])
    )
    status, pending = request(home, path, finding_id, assessment_id)
    assert status == 0
    assert (pending["finding_id"], pending["reason"], pending["status"]) == (
        finding_id,
        "rebaseline_mapping",
        "pending",
    )
    assert grouped(home, "claim", finding_id) == (0, None)
    body = json.loads(path.read_text())
    body["findings"][0]["title"] = "Mutable candidate must not replace the reviewed proposal"
    path.write_text(json.dumps(body), encoding="utf-8")
    status, corrected = grouped(
        home,
        "rebaseline",
        pending["id"],
        "--ticket",
        "SEC-417",
        "--rationale",
        "Authenticated human reviewed the retained corrected claim and its original evidence.",
    )
    assert status == 0
    assert corrected["finding"]["id"] == finding_id
    assert corrected["finding"]["title"] == "Corrected buffer-size claim"
    assert corrected["finding"]["fingerprint"] != original.finding.fingerprint
    assert corrected["effective_severity"] == "high"
    assert corrected["disposition"] is None
    assert corrected["cwes"] == ["CWE-120"]
    assert corrected["locations"][0]["path"] == "corrected/buffer.c"
    status, claim = grouped(home, "claim", finding_id)
    assert status == 0
    assert claim["title"] == "Corrected buffer-size claim"
    assert "destination buffer bound" in claim["description"]
    services = load(home).services()
    assert services.findings.occurrences(finding_ids=[UUID(finding_id)]) == original_occurrences
    accepted = services.findings.review.get(UUID(pending["id"]))
    assert accepted.status == "accepted"
    history = services.findings.history(UUID(finding_id))
    assert all(decision.assessment_id is None for decision in history)
    assert all(decision.severity is None and decision.validity is None for decision in history)
    assert {decision.ticket for decision in history} == {"SEC-417"}
    assert {decision.actor for decision in history} == {"human:reviewer@example.com"}


@pytest.mark.parametrize("machine", [False, True])
def test_grouped_correction_requires_authenticated_human(
    home: Path, tmp_path: Path, machine: bool
) -> None:
    finding_id = scanned(home, tmp_path)
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    if machine:
        assert run(auth.local, home, "--identity", "scanner/1", "--machine")[0] == 0
    assert request(home, path, finding_id, assessment_id)[0] == 2
    assert load(home).services().findings.history(UUID(finding_id)) == []
    assert load(home).services().findings.review.for_finding(UUID(finding_id)) == []


@pytest.mark.parametrize("field", ["--ticket", "--rationale"])
def test_grouped_rebaseline_requires_authority_fields(home: Path, field: str) -> None:
    with pytest.raises(SystemExit) as error:
        grouped(home, "rebaseline", "31dcc9b8-b569-4340-9032-3b335d53a9ef", field, "SEC-417")
    assert error.value.code == 2


def test_grouped_correction_refuses_unrelated_review_and_wrong_ticket(
    home: Path, tmp_path: Path
) -> None:
    finding_id = scanned(home, tmp_path)
    assert run(auth.local, home, "--identity", "reviewer@example.com")[0] == 0
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    status, pending = request(home, path, finding_id, assessment_id)
    assert status == 0
    assert (
        grouped(
            home,
            "rebaseline",
            pending["id"],
            "--ticket",
            "SEC-999",
            "--rationale",
            "A different ticket cannot authorize this retained proposal.",
        )[0]
        == 2
    )
    services = load(home).services()
    assert services.findings.review.get(UUID(pending["id"])).status == "pending"
    assert services.findings.claim(UUID(finding_id)) is None
    with pytest.raises(SystemExit) as error:
        grouped(
            home,
            "rebaseline",
            pending["id"],
            "--ticket",
            "SEC-417",
            "--rationale",
            "Human reviewed the retained claim.",
            "--candidate",
            str(path),
        )
    assert error.value.code == 2
