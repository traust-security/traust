"""Canonical claim correction through the installed grouped CLI and real SQLite services."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from traust_core.v1.models.findings import CandidateFormat, FindingCandidate

from tests.test_findings_doors import REPO, config_home, run, scanned
from tests.test_triage_doors import SARIF, SHA
from tests.test_validate_report import _canonical_report
from traust.cli import auth, findings
from traust.cli.__main__ import main
from traust.context import load

ORIGINAL_LABEL = SARIF["runs"][0]["results"][0]["ruleId"]


@pytest.fixture
def home(tmp_path: Path) -> Path:
    # Claim acceptance uses Core's restate role, not merely an auth.local actor string.
    return config_home(
        tmp_path,
        identity={"trust_local": True, "admins": ["reviewer@example.com"]},
    )


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
        id=ORIGINAL_LABEL,
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
        ORIGINAL_LABEL,
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
    candidates = FindingCandidate.parse_many(
        json.dumps(SARIF).encode(),
        CandidateFormat.SARIF,
        original.finding.repository_id,
        repository_url=REPO,
        sha=SHA,
    )
    replay = services.findings.intake.accept(UUID(assessment_id), candidates)
    assert replay.findings == {ORIGINAL_LABEL: UUID(finding_id)}
    assert replay.created == ()
    assert services.findings.occurrences(finding_ids=[UUID(finding_id)]) == original_occurrences


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


def accept(home: Path, review_item_id: str, **overrides: str) -> tuple[int, object]:
    return grouped(
        home,
        "rebaseline",
        review_item_id,
        "--ticket",
        overrides.get("ticket", "SEC-417"),
        "--rationale",
        overrides.get("rationale", "Reviewed the retained claim against the original evidence."),
    )


def test_direct_doors_retain_deleted_file_and_retry_without_new_history(
    home: Path, tmp_path: Path
) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "reviewer@example.com")
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    arguments = (
        str(path),
        "--finding",
        finding_id,
        "--assessment",
        assessment_id,
        "--label",
        ORIGINAL_LABEL,
        "--ticket",
        "SEC-417",
        "--rationale",
        "The human corrected this scanner claim.",
    )
    status, pending = run(findings.correction_request, home, *arguments)
    assert status == 0
    assert run(findings.correction_request, home, *arguments) == (0, pending)
    path.unlink()
    arguments = (
        pending["id"],
        "--ticket",
        "SEC-417",
        "--rationale",
        "Reviewed the retained claim against the original evidence.",
    )
    status, corrected = run(findings.rebaseline, home, *arguments)
    assert status == 0
    assert run(findings.rebaseline, home, *arguments) == (0, corrected)
    assert run(findings.claim, home, finding_id)[1]["title"] == "Corrected buffer-size claim"
    history = load(home).services().findings.history(UUID(finding_id))
    assert len(history) == 2
    assert history[0].artifact_id == history[1].artifact_id
    assert history[1].restates_id == history[0].id


@pytest.mark.parametrize("state", ["non-admin", "untrusted-local", "machine-admin"])
def test_claim_acceptance_requires_current_restatement_authority(
    home: Path, tmp_path: Path, state: str
) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "reviewer@example.com")
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    _, pending = request(home, path, finding_id, assessment_id)
    if state == "non-admin":
        run(auth.local, home, "--identity", "another-human@example.com")
    elif state == "machine-admin":
        run(auth.local, home, "--identity", "reviewer@example.com", "--machine")
    else:
        config = yaml.safe_load((home / "traust.yaml").read_text())
        config["identity"]["trust_local"] = False
        (home / "traust.yaml").write_text(yaml.safe_dump(config))
    assert accept(home, pending["id"])[0] == 2
    services = load(home).services()
    assert services.findings.claim(UUID(finding_id)) is None
    assert services.findings.review.get(UUID(pending["id"])).status == "pending"
    assert len(services.findings.history(UUID(finding_id))) == 1


def test_later_proposal_supersedes_prior_review_without_overwriting_it(
    home: Path, tmp_path: Path
) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "reviewer@example.com")
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    _, first = request(home, path, finding_id, assessment_id)
    document = json.loads(path.read_text())
    document["findings"][0]["title"] = "The second retained proposal"
    path.write_text(json.dumps(document))
    _, second = request(home, path, finding_id, assessment_id)
    assert first["id"] != second["id"]
    assert accept(home, first["id"])[0] == 2
    assert accept(home, second["id"])[1]["finding"]["title"] == "The second retained proposal"
    assert accept(home, first["id"])[0] == 2
    services = load(home).services()
    assert services.findings.review.get(UUID(first["id"])).status == "closed_unreviewed"
    assert services.findings.claim(UUID(finding_id)).title == "The second retained proposal"


@pytest.mark.parametrize("binding", ["repository", "commit", "label", "duplicate-label"])
def test_request_refuses_wrong_report_bindings_without_recording(
    home: Path, tmp_path: Path, binding: str
) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "reviewer@example.com")
    path, assessment_id = proposal_file(home, tmp_path, finding_id)
    document = json.loads(path.read_text())
    if binding in ("repository", "commit"):
        document["metadata"][binding] = (
            "https://github.com/example/other" if binding == "repository" else "b" * 40
        )
    elif binding == "label":
        document["findings"][0]["id"] = "OTHER-001"
    else:
        document["findings"].append(document["findings"][0].copy())
    path.write_text(json.dumps(document))
    assert request(home, path, finding_id, assessment_id)[0] == 2
    services = load(home).services()
    assert services.findings.history(UUID(finding_id)) == []
    assert services.findings.review.for_finding(UUID(finding_id)) == []


def test_unrelated_review_cannot_accept_a_correction(home: Path, tmp_path: Path) -> None:
    from traust_core.v1.models.vocabulary import ReviewReason

    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "reviewer@example.com")
    services = load(home).services()
    item = services.findings.review.request_signoff(UUID(finding_id), ReviewReason.MANUAL_QUEUE)
    assert accept(home, str(item.id))[0] == 2
    assert services.findings.review.get(item.id).status == "pending"
    assert services.findings.history(UUID(finding_id)) == []
