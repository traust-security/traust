"""Phase 4 tests: idempotence gate and N-pass enforcement."""

import json
import os
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

yaml = pytest.importorskip("yaml")
pytest.importorskip("jsonschema")

# The calibration snapshot is a real deployment's IaC inventory, so it is
# deployment data: compliance/calibration/ in the operator's config home.
# Only the two idempotence tests need it; everything else here runs offline.
_OPERATOR_HOME = os.environ.get("TRAUST_OPERATOR_CONFIG_HOME")
_CALIBRATION_SNAPSHOT = (
    Path(_OPERATOR_HOME) / "compliance" / "calibration" / "iac-inventory-app-interface-mirror.json"
    if _OPERATOR_HOME
    else Path("/nonexistent")
)
_needs_snapshot = pytest.mark.skipif(
    not _CALIBRATION_SNAPSHOT.is_file(),
    reason="no calibration snapshot in the operator config home "
    "(compliance/calibration/iac-inventory-app-interface-mirror.json)",
)


def _load(name):
    import importlib

    pkg_paths = {
        "calibrate_compliance": "traust.ops.calibrate_compliance",
        "build_compliance_dashboard": "traust_engine.compliance.dashboard",
    }
    if name in pkg_paths:
        return importlib.import_module(pkg_paths[name])
    path = skill_dir("compliance-check") / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cal = _load("calibrate_compliance")
vca = _load("validate_compliance_assessment")


# ---------------- idempotence (offline, real calibration snapshot) ----


@_needs_snapshot
def test_idempotence_over_calibration_snapshot(tmp_path):
    snap = _CALIBRATION_SNAPSHOT
    assert snap.is_file(), "calibration snapshot missing"
    rc = cal.main(["--snapshot", str(snap), "--work-dir", str(tmp_path / "w")])
    assert rc == 0


@_needs_snapshot
def test_idempotence_gate_detects_divergence(tmp_path, monkeypatch):
    snap = _CALIBRATION_SNAPSHOT
    calls = {"n": 0}
    real = cal.run_once

    def flaky(out_dir, snapshot, khs, frameworks):
        doc = real(out_dir, snapshot, khs, frameworks)
        calls["n"] += 1
        if calls["n"] == 2 and doc["results"]:
            doc["results"][0]["verdict"] = "not_assessed"
            doc["results"][0].pop("evidence", None)
            doc["results"][0]["reason"] = "injected divergence"
        return doc

    monkeypatch.setattr(cal, "run_once", flaky)
    rc = cal.main(["--snapshot", str(snap), "--work-dir", str(tmp_path / "w")])
    assert rc == 1


# ---------------- N-pass agreement enforcement ----------------


def _er_result(**over):
    r = {
        "framework": "soc2-tsc",
        "control_id": "A1.2",
        "classification": "evidence_review",
        "verdict": "satisfied",
        "verdict_source": "agent",
        "evidence": [
            {
                "sha256": "a" * 64,
                "kind": "human_artifact",
                "locator": "artifact:backup-evidence.pdf",
            }
        ],
    }
    r.update(over)
    return {"results": [r]}


def test_agent_verdict_requires_n_pass_agreement():
    failures = vca.n_pass_failures(_er_result())
    assert failures and "n_pass_agreement" in failures[0]


def test_agreed_two_passes_ok():
    doc = _er_result(n_pass_agreement={"passes": 2, "agreed": True})
    assert vca.n_pass_failures(doc) == []


def test_disagreement_cannot_carry_verdict():
    doc = _er_result(n_pass_agreement={"passes": 2, "agreed": False})
    failures = vca.n_pass_failures(doc)
    assert failures and "disagreement" in failures[0]


def test_not_assessed_needs_no_agreement():
    doc = _er_result(verdict="not_assessed", verdict_source="check", evidence=None)
    doc["results"][0].pop("evidence")
    doc["results"][0]["reason"] = "awaiting artifact"
    assert vca.n_pass_failures(doc) == []


# ---------------- Phase 5: dashboard builder ----------------

dash = _load("build_compliance_dashboard")


def _mk_assessment_dir(tmp_path, target, generated_at, ns_count=1):
    d = tmp_path / "assessments" / target
    d.mkdir(parents=True)
    results = [
        {
            "framework": "nist-800-53-rev5",
            "control_id": "sc-28",
            "classification": "deterministic",
            "verdict": "not_satisfied",
            "verdict_source": "check",
            "check_id": "chk-encryption-at-rest",
            "evidence": [
                {"sha256": "a" * 64, "kind": "inventory_snapshot_excerpt", "locator": "x"}
            ],
        }
    ] * ns_count
    (d / "compliance-assessment.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "artifact": "compliance-assessment",
                    "harness_version": "t",
                    "registry_hash": "b" * 64,
                    "generated_at": generated_at,
                    "target": {"kind": "environment", "environment": target},
                    "frameworks": [{"id": "nist-800-53-rev5"}],
                    "skipped_frameworks": {"pci-dss-v4": "skipped: no CDE"},
                },
                "coverage": {
                    "nist-800-53-rev5": {
                        "total_in_scope": ns_count,
                        "deterministic": ns_count,
                        "evidence_review": 0,
                        "organizational": 0,
                        "satisfied": 0,
                        "not_satisfied": ns_count,
                        "not_applicable": 0,
                        "not_assessed": 0,
                    }
                },
                "results": results,
            }
        )
    )
    return d


def test_artifact_base_naming():
    rcc2 = _load("run_compliance_check")
    assert rcc2.artifact_base("env a/b", "all") == "env-a-b-all-compliance-assessment"
    assert rcc2.artifact_base("x", "soc2-tsc") == "x-soc2-tsc-compliance-assessment"
    assert (
        rcc2.artifact_base("x", "pci-dss-v4, soc2-tsc")
        == "x-pci-dss-v4+soc2-tsc-compliance-assessment"
    )
