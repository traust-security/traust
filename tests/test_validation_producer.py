"""Real producer bytes respect the existing validation artifact contract."""

import json

import pytest
from adapters import StepResult
from ingest import Finding, Normalized
from report import build_validation_json, write
from scope import ClusterScope, Scope
from traust_core.v1.errors import DocumentError
from traust_core.v1.models.artifacts import ValidationArtifact


def produce(*, verdict="confirmed", reason="", controls=None):
    scope = Scope(environment="lab")
    scope.modes.add("explicit")
    scope.clusters["fixture"] = ClusterScope(context="fixture", namespaces=["fixture"])
    normalized = Normalized(
        target_name="fixture",
        source_dir="opaque:source",
        source_reports=[{"kind": "security-audit", "path": "opaque:source", "sha256": "a" * 64}],
        findings=[
            Finding(
                id="package/f001",
                source_id="f001",
                source_report_path="opaque:source",
                title="An original source claim",
                severity="high",
                surface="ci-build",
            )
        ],
    )
    return build_validation_json(
        normalized,
        scope,
        [
            StepResult(
                step_id="step-001",
                adapter="k8s",
                verb="noop" if reason else "get",
                target={},
                classification="safe",
                verdict=verdict,
                observed="an observation",
                scope_reason=reason,
                finding_ref="package/f001",
                controls=controls or [],
            )
        ],
        [],
        [],
        audit_path="opaque:audit",
        audit_sha256="b" * 64,
        flags=[],
        approval={"mode": "interactive"},
        target_attestation={"attested": True, "fingerprint": {"target": "fixture"}},
    )


def test_writer_gates_real_bytes_and_preserves_declared_and_auxiliary_meaning(tmp_path):
    doc = produce(verdict="not_attempted", reason="needs-credential:fixture-token")
    path, markdown = write(doc, tmp_path, "fixture")
    artifact = ValidationArtifact.parse(path.read_bytes())
    (finding,) = artifact.validated_findings
    assert finding.source_id == "f001"
    assert finding.source_report == "opaque:source"
    assert finding.not_attempted_reason == "needs-credential:fixture-token"
    assert finding.evidence_grade is None
    raw = json.loads(artifact.payload)
    assert raw["validated_findings"][0]["evidence_grade"] is None
    producer = raw["metadata"]["additional"]["validation_producer"]
    assert producer["needs_credential_count"] == 1
    assert producer["findings"][0]["planner_id"] == "package/f001"
    assert producer["findings"][0]["surface"] == "ci-build"
    assert raw["metadata"]["target_attestation"]["fingerprint"] == {"target": "fixture"}
    assert markdown.is_file()


def test_invalid_final_report_does_not_write_either_companion(tmp_path):
    doc = produce()
    doc["validated_findings"][0]["evidence_grade"] = "inferred-proof"
    with pytest.raises(DocumentError):
        write(doc, tmp_path, "fixture")
    assert not (tmp_path / "fixture-validation.json").exists()
    assert not (tmp_path / "fixture-validation.md").exists()


def test_control_observations_are_not_lost_by_step_serialization(tmp_path):
    controls = [
        {
            "name": "same client allowed action",
            "kind": "must_succeed",
            "ok": False,
            "observed": "assay failed",
        }
    ]
    path, _ = write(produce(verdict="refuted", controls=controls), tmp_path, "fixture")
    (finding,) = ValidationArtifact.parse(path.read_bytes()).validated_findings
    assert finding.verdict == "inconclusive"
    assert finding.soundness_flag == "failed-positive-control"
    assert finding.steps[0].controls[0].ok is False


def test_multisource_producer_keeps_original_labels_and_source_context(tmp_path):
    sources = [
        {"kind": "security-audit", "path": reference, "sha256": digest * 64}
        for reference, digest in (("opaque:first", "a"), ("opaque:second", "b"))
    ]
    findings = [
        Finding(
            id=f"{number}/f001",
            source_id="f001",
            source_report_path=source["path"],
            title="An original source claim",
            severity="high",
        )
        for number, source in enumerate(sources)
    ]
    normalized = Normalized(
        target_name="two-repos",
        source_dir="opaque:package",
        source_reports=sources,
        findings=findings,
    )
    doc = build_validation_json(
        normalized,
        Scope(),
        [],
        [],
        [],
        audit_path="opaque:audit",
        audit_sha256="c" * 64,
        flags=[],
        approval={},
    )
    path, _ = write(doc, tmp_path, "two-repos")
    rows = ValidationArtifact.parse(path.read_bytes()).validated_findings
    assert [(row.source_id, row.source_report) for row in rows] == [
        ("f001", "opaque:first"),
        ("f001", "opaque:second"),
    ]
    findings[0].source_report_path = None
    with pytest.raises(ValueError, match="source report context"):
        build_validation_json(
            normalized,
            Scope(),
            [],
            [],
            [],
            audit_path="opaque:audit",
            audit_sha256="c" * 64,
            flags=[],
            approval={},
        )
