"""Registered recording uses real services and immutable, bound source artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from traust_core.v1.models.artifacts import (
    SecurityAuditArtifact,
    TriageArtifact,
    ValidationArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import CodeSpan, Provenance
from traust_core.v1.models.findings import FindingCandidate
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ScannerSeverity, SourceType
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

from tests.test_validate_report import _canonical_report as security_audit
from traust.cli.__main__ import main
from traust.context import load


def record_source(core, repo, ref, source, checkout):
    services = core.services()
    raw_scan = security_audit()
    raw_scan["metadata"]["repository"] = str(repo.url)
    observed = services.assessment.record(
        SecurityAuditArtifact.from_document(raw_scan),
        ref.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "fixture",
        "1",
        Provenance(
            run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=datetime.now(UTC)
        ),
    )
    claim = source.findings[0]
    taken = services.findings.intake.accept(
        observed.id,
        [
            FindingCandidate(
                label=claim.id,
                repository_id=repo.id,
                title=claim.title,
                locations=(CodeSpan(path=claim.file, line=claim.line),),
                reported_severity=ScannerSeverity.HIGH,
            )
        ],
    )
    finding_id = taken.findings[claim.id]
    finding = services.findings.get(finding_id).finding
    raw_source = json.loads(source.payload)
    raw_source["findings"][0].update(
        fingerprint_algo=finding.fingerprint_algo,
        fingerprint=finding.fingerprint,
        verify_verdict="needs_manual_test",
    )
    source = TriageArtifact.from_document(raw_source)
    checkout.mkdir(parents=True)
    (checkout / claim.file).write_text("\n" * claim.line)
    services.findings.decisions.record(
        observed.id,
        source,
        Provenance(run_id=uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=datetime.now(UTC)),
        checkout,
    )
    assessment = services.assessment.latest(ref.id, AssessmentKind.TRIAGE)
    assert assessment is not None
    publisher = core.artifact_publisher(PublishSpecs(PublishSpec(TriageArtifact)))
    (artifact,) = publisher.list_for_assessment(assessment.id)
    return source, assessment, artifact, finding_id


@pytest.fixture
def recording(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    core = load(config)
    services = core.services()
    url = "https://github.com/example/validation-fixture"
    repo = services.portfolio.register_repository(HttpsRepoUrl.parse(url, ("github.com",)), False)
    ref = services.portfolio.register_ref(repo.id, GitSha.parse("a" * 40), None, None)
    source = TriageArtifact.from_document(
        {
            "triage_completed": "2026-10-23",
            "triage_context": {
                "mode": "auto",
                "environment": "isolated fixture",
                "votes_per_finding": 3,
                "repo": url,
                "harness_version": "0.34.3",
            },
            "summary": {
                "input_count": 1,
                "true_positives": 1,
                "hardening": 0,
                "false_positives": 0,
                "undetermined": 0,
                "duplicates": 0,
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "informational": 0,
                },
            },
            "findings": [
                {
                    "id": "f001",
                    "title": "Bound original claim",
                    "verdict": "true_positive",
                    "severity": "high",
                    "file": "entry.c",
                    "line": 25,
                    "rationale": "Sanitized original source claim retained for validation.",
                }
            ],
        }
    )
    source, assessment, artifact, finding_id = record_source(
        core, repo, ref, source, tmp_path / "source-checkout"
    )
    report = {
        "title": "Live Validation Report — isolated recording fixture",
        "metadata": {
            "date": "2026-10-23",
            "harness_version": "0.34.3",
            "scope_binding_mode": "explicit",
            "target_fingerprint": [],
            "target_environment": "isolated-fixture",
            "target_attestation": {
                "attested": True,
                "checks": [
                    {
                        "name": "fixture",
                        "ok": True,
                        "required": True,
                        "detail": "No live target contacted",
                    }
                ],
            },
        },
        "source_reports": [
            {
                "kind": "triage",
                "path": "opaque:original/source",
                "sha256": hashlib.sha256(source.payload).hexdigest(),
            }
        ],
        "summary": {
            "by_verdict": {
                "confirmed": 1,
                "refuted": 0,
                "inconclusive": 0,
                "blocked_by_scope": 0,
                "not_attempted": 0,
            },
            "by_technique": {"replay": 1},
        },
        "validated_findings": [
            {
                "source_id": "f001",
                "source_report": "opaque:original/source",
                "verdict": "confirmed",
                "technique": "replay",
                "evidence_grade": "E1",
                "observed_impact": "Authenticated exploit action succeeded in isolated fixture",
                "steps": [
                    {
                        "step_id": "step-001",
                        "adapter": "k8s",
                        "verb": "get",
                        "classification": "safe",
                        "verdict": "confirmed",
                        "observed": "success",
                    }
                ],
            }
        ],
        "attack_chains": [],
        "novel_findings": [],
        "execution_log_ref": "opaque:audit",
    }
    bindings = {
        "sources": [
            {
                "source_report": "opaque:original/source",
                "assessment_id": str(assessment.id),
                "artifact_id": str(artifact.id),
                "findings": [{"source_id": "f001", "finding_id": str(finding_id)}],
            }
        ]
    }
    provenance = {
        "run_id": str(uuid4()),
        "source": "validation_report",
        "occurred_at": "2026-10-23T12:00:00Z",
    }
    return {
        "config": config,
        "root": tmp_path,
        "finding_id": finding_id,
        "report": report,
        "bindings": bindings,
        "provenance": provenance,
    }


def invoke(fixture, capsys, *, report=None, bindings=None, extra=()):
    paths = {}
    for name, value in (
        ("report", report or fixture["report"]),
        ("bindings", bindings or fixture["bindings"]),
        ("provenance", fixture["provenance"]),
    ):
        paths[name] = fixture["root"] / f"{name}.json"
        paths[name].write_text(json.dumps(value, indent=3) + "\n")
    code = main(
        [
            "validation",
            "record",
            "--config-home",
            str(fixture["config"]),
            *[item for name, path in paths.items() for item in (f"--{name}", str(path))],
            *extra,
        ]
    )
    output = capsys.readouterr()
    return code, json.loads(output.out) if output.out else None, output.err


def test_record_is_bound_persistent_and_idempotent(recording, capsys):
    code, receipt, error = invoke(recording, capsys)
    assert code == 0, error
    (row,) = receipt["findings"]
    assert row["finding_id"] == str(recording["finding_id"])
    assert row["decision_id"]
    services = load(recording["config"]).services()
    (saved,) = services.findings.history(recording["finding_id"])
    assert saved.actor is None
    assert saved.evidence_grade == "E1"
    assert saved.validity == "confirmed"
    assert saved.assessment_id in [UUID(value) for value in receipt["assessment_ids"]]
    assert invoke(recording, capsys)[:2] == (0, receipt)
    assert services.findings.history(recording["finding_id"]) == [saved]


@pytest.mark.parametrize(
    "attestation,flag",
    [(None, "attestation_missing"), ({"attested": False}, "environment_invalid")],
)
def test_current_invalid_environment_retains_review_without_decision(
    recording, capsys, attestation, flag
):
    report = copy.deepcopy(recording["report"])
    if attestation is None:
        report["metadata"].pop("target_attestation")
    else:
        report["metadata"]["target_attestation"] = attestation
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    (row,) = receipt["findings"]
    assert row["decision_id"] is None
    assert row["soundness_flag"] == flag
    assert row["review_item_ids"]
    services = load(recording["config"]).services()
    assert services.findings.history(recording["finding_id"]) == []
    assert receipt["evidence_artifact_ids"]
    core = load(recording["config"])
    # Report bytes remain available through the core artifact publisher, not a caller sidecar.
    publisher = core.artifact_publisher(PublishSpecs(PublishSpec(ValidationArtifact)))
    retained = publisher.get(UUID(receipt["artifact_ids"][0]))
    assert retained.payload == (recording["root"] / "report.json").read_bytes()


def test_voided_validation_full_review_card_retains_report_and_recording_companion(
    recording, capsys
):
    report = copy.deepcopy(recording["report"])
    report["metadata"]["target_attestation"] = {
        "attested": False,
        "checks": [{"name": "pods-ready", "ok": False, "detail": "actual failed observation"}],
    }
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    services = load(recording["config"]).services()
    assert services.findings.history(recording["finding_id"]) == []
    assert (
        main(
            [
                "findings",
                "review-cases",
                "--config-home",
                str(recording["config"]),
                "--finding",
                str(recording["finding_id"]),
            ]
        )
        == 0
    )
    page = json.loads(capsys.readouterr().out)
    review_ids = receipt["findings"][0]["review_item_ids"]
    [card] = [card for card in page["items"] if card["review_item"]["id"] in review_ids]
    assert card["history"] == []
    evidence = {entry["artifact_id"]: entry["document"] for entry in card["evidence"]}
    assert evidence[receipt["artifact_ids"][0]] == report
    evidence_id = receipt["evidence_artifact_ids"][0]
    assert evidence[evidence_id] == services.validation.evidence(
        UUID(evidence_id), finding_id=recording["finding_id"]
    ).model_dump(mode="json")
    assert services.findings.history(recording["finding_id"]) == []


@pytest.mark.parametrize(
    "change", ["unknown-finding", "wrong-digest", "opaque-reference", "truthy-attestation"]
)
def test_unsafe_binding_or_observation_refuses_without_decisions(recording, capsys, change):
    report, bindings = copy.deepcopy(recording["report"]), copy.deepcopy(recording["bindings"])
    if change == "unknown-finding":
        bindings["sources"][0]["findings"][0]["finding_id"] = str(uuid4())
    elif change == "wrong-digest":
        report["source_reports"][0]["sha256"] = "0" * 64
    elif change == "opaque-reference":
        bindings["sources"][0]["source_report"] = "source"
    else:
        report["metadata"]["target_attestation"]["attested"] = "false"
    code, receipt, _ = invoke(recording, capsys, report=report, bindings=bindings)
    assert code == 2
    assert receipt is None
    assert load(recording["config"]).services().findings.history(recording["finding_id"]) == []


def test_missing_grade_current_reviews_historical_stays_null(recording, capsys):
    report = copy.deepcopy(recording["report"])
    report["metadata"]["harness_version"] = "0.175.0"
    report["validated_findings"][0]["evidence_grade"] = None
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    assert receipt["findings"][0]["decision_id"] is None
    bindings = {**recording["bindings"], "policy": "historical"}
    recording["provenance"]["run_id"] = str(uuid4())
    code, receipt, error = invoke(recording, capsys, report=report, bindings=bindings)
    assert code == 0, error
    (saved,) = load(recording["config"]).services().findings.history(recording["finding_id"])
    assert saved.evidence_grade is None


@pytest.mark.parametrize(
    "controls,observed,flag",
    [
        ([{"name": "positive", "kind": "must_succeed", "ok": True}], "denied", None),
        ([], "denied", "missing-positive-control"),
        (
            [{"name": "positive", "kind": "must_succeed", "ok": False}],
            "denied",
            "failed-positive-control",
        ),
        (
            [{"name": "positive", "kind": "must_succeed", "ok": True}],
            "Error from server (Forbidden)",
            "error-signature:forbidden",
        ),
    ],
)
def test_refutation_controls_and_transcripts_reach_core(
    recording, capsys, controls, observed, flag
):
    report = copy.deepcopy(recording["report"])
    row = report["validated_findings"][0]
    row.update(verdict="refuted", evidence_grade=None)
    row["steps"][0].update(verdict="refuted", observed=observed, controls=controls)
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    (result,) = receipt["findings"]
    services = load(recording["config"]).services()
    history = services.findings.history(recording["finding_id"])
    if flag is None:
        (saved,) = history
        assert saved.validity == "false_positive"
        assert saved.evidence_grade is None
        assert services.findings.get(recording["finding_id"]).is_open()
    else:
        assert result["soundness_flag"] == flag
        assert result["decision_id"] is None
        assert history == []
    assert result["review_item_ids"]


def test_explicit_failed_attestation_and_install_evidence_are_consumed(recording, capsys):
    attestation = recording["root"] / "target-attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "attested": False,
                "checks": [{"name": "pods-ready", "ok": False, "detail": "isolated fixture"}],
            }
        )
    )
    failure = recording["root"] / "install-failure.yaml"
    failure.write_text("reason: sanitized operand failed to install\n")
    code, receipt, error = invoke(
        recording,
        capsys,
        extra=("--target-attestation", str(attestation), "--install-failure", str(failure)),
    )
    assert code == 0, error
    (row,) = receipt["findings"]
    assert row["decision_id"] is None
    assert row["soundness_flag"] == "environment_invalid"
    evidence = (
        load(recording["config"])
        .services()
        .validation.evidence(
            UUID(receipt["evidence_artifact_ids"][0]), finding_id=recording["finding_id"]
        )
    )
    assert evidence.bindings.install_failure == failure.read_text()
    assert evidence.bindings.target_attestation.attested is False


def test_different_target_and_run_do_not_collapse(recording, capsys):
    code, first, error = invoke(recording, capsys)
    assert code == 0, error
    report = copy.deepcopy(recording["report"])
    report["metadata"]["target_environment"] = "another-isolated-fixture"
    recording["provenance"]["run_id"] = str(uuid4())
    recording["provenance"]["occurred_at"] = "2026-10-23T13:00:00Z"
    code, second, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    assert first["findings"][0]["decision_id"] != second["findings"][0]["decision_id"]
    assert len(load(recording["config"]).services().findings.history(recording["finding_id"])) == 2


def test_actual_report_producer_hands_attestation_to_registered_record(recording, capsys):
    from adapters import StepResult
    from ingest import Finding, Normalized
    from report import build_validation_json, write
    from scope import ClusterScope, Scope

    source = recording["report"]["source_reports"][0]
    scope = Scope(environment="lab")
    scope.modes.add("explicit")
    scope.clusters["isolated-fixture"] = ClusterScope(
        context="isolated-fixture", namespaces=["fixture"]
    )
    normalized = Normalized(
        target_name="fixture",
        source_dir="opaque:source",
        source_reports=[source],
        findings=[
            Finding(
                id="package/f001",
                source_id="f001",
                source_report_path=source["path"],
                title="Bound original claim",
                severity="high",
            )
        ],
    )
    generated = build_validation_json(
        normalized,
        scope,
        [
            StepResult(
                step_id="step-001",
                adapter="k8s",
                verb="get",
                target={},
                classification="safe",
                verdict="confirmed",
                observed="success",
                finding_ref="package/f001",
            )
        ],
        [],
        [],
        audit_path="opaque:audit",
        audit_sha256="b" * 64,
        flags=[],
        approval={"mode": "interactive"},
        target_attestation={"attested": False, "checks": [{"name": "not-ready", "ok": False}]},
        finding_assessments={"package/f001": {"evidence_grade": "E1"}},
    )
    report, _ = write(generated, recording["root"] / "output", "fixture")
    bindings = recording["root"] / "bindings.json"
    bindings.write_text(json.dumps(recording["bindings"]))
    provenance = recording["root"] / "provenance.json"
    provenance.write_text(json.dumps(recording["provenance"]))
    assert (
        main(
            [
                "validation",
                "record",
                "--config-home",
                str(recording["config"]),
                "--report",
                str(report),
                "--bindings",
                str(bindings),
                "--provenance",
                str(provenance),
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["findings"][0]["soundness_flag"] == "environment_invalid"
    assert receipt["findings"][0]["decision_id"] is None
    assert receipt["findings"][0]["source_id"] == "f001"
    assert load(recording["config"]).services().findings.history(recording["finding_id"]) == []


@pytest.mark.parametrize("cross_repository", [False, True])
def test_multisource_original_labels_are_bound_without_path_aliases(
    recording, capsys, cross_repository
):
    core = load(recording["config"])
    services = core.services()
    publisher = core.artifact_publisher(PublishSpecs(PublishSpec(TriageArtifact)))
    first_binding = recording["bindings"]["sources"][0]
    source = json.loads(publisher.get(UUID(first_binding["artifact_id"])).payload)
    url = "https://github.com/example/second-validation-fixture"
    source["triage_context"]["repo"] = url
    source["findings"][0]["file"] = "second.c"
    doc = TriageArtifact.from_document(source)
    repo = services.portfolio.register_repository(HttpsRepoUrl.parse(url, ("github.com",)), False)
    ref = services.portfolio.register_ref(repo.id, GitSha.parse("b" * 40), None, None)
    doc, assessment, artifact, second_finding = record_source(
        core, repo, ref, doc, recording["root"] / "second-source-checkout"
    )
    report = copy.deepcopy(recording["report"])
    source_ref = "different://opaque/report-not-a-local-path"
    report["source_reports"].append(
        {
            "kind": "triage",
            "path": source_ref,
            "sha256": hashlib.sha256(doc.payload).hexdigest(),
        }
    )
    report["validated_findings"].append(
        {
            **report["validated_findings"][0],
            "source_report": source_ref,
        }
    )
    report["summary"]["by_verdict"]["confirmed"] = 2
    report["summary"]["by_technique"]["replay"] = 2
    bindings = copy.deepcopy(recording["bindings"])
    bindings["sources"].append(
        {
            "source_report": source_ref,
            "assessment_id": str(assessment.id),
            "artifact_id": str(artifact.id),
            "findings": [
                {
                    "source_id": "f001",
                    "finding_id": str(
                        recording["finding_id"] if cross_repository else second_finding
                    ),
                }
            ],
        }
    )
    code, receipt, error = invoke(recording, capsys, report=report, bindings=bindings)
    if cross_repository:
        assert code == 2
        assert receipt is None
        assert services.findings.history(recording["finding_id"]) == []
        assert services.findings.history(second_finding) == []
    else:
        assert code == 0, error
        assert {row["finding_id"] for row in receipt["findings"]} == {
            str(recording["finding_id"]),
            str(second_finding),
        }
        assert len(receipt["assessment_ids"]) == 2


def test_machine_severity_proposal_is_review_only(recording, capsys):
    report = copy.deepcopy(recording["report"])
    report["validated_findings"][0]["severity_validation"] = {
        "demonstrated": {},
        "proposal": {
            "severity": "critical",
            "rationale": "Sanitized observed impact warrants an explicit human severity review.",
        },
    }
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    (saved,) = load(recording["config"]).services().findings.history(recording["finding_id"])
    assert saved.severity is None
    assert receipt["findings"][0]["review_item_ids"]


def test_receipt_does_not_repeat_untrusted_observations(recording, capsys):
    report = copy.deepcopy(recording["report"])
    secret = "sensitive-test-only-value-not-a-real-secret"
    report["validated_findings"][0]["observed_impact"] = secret
    report["validated_findings"][0]["steps"][0]["observed"] = secret
    code, receipt, error = invoke(recording, capsys, report=report)
    assert code == 0, error
    assert secret not in json.dumps(receipt)
    assert "rationale" not in receipt["findings"][0]
    (saved,) = load(recording["config"]).services().findings.history(recording["finding_id"])
    assert secret in saved.rationale
