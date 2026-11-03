"""`traust triage intake|prepare|record|render` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml

from traust.cli import triage
from traust.cli.__main__ import main
from traust.context import load
from traust.paths import skill_dir

CANARY = skill_dir("triage") / "fixtures" / "canary-target"
SHA = "a" * 40
SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "version": "2.20.0",
                    "rules": [
                        {
                            "id": "c/overflow",
                            "shortDescription": {"text": "Unbounded copy into a heap buffer"},
                            "properties": {"security-severity": "8.1"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "c/overflow",
                    "ruleIndex": 0,
                    "message": {"text": "memcpy of claimed bytes"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "entry.c"},
                                "region": {"startLine": 25},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A config home whose traust.yaml keeps the store in the test's directory."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    return rc, out.getvalue()


def intake(home: Path, tmp_path: Path) -> str:
    scan = tmp_path / "scan.sarif"
    scan.write_text(json.dumps(SARIF))
    rc, out = run(
        triage.intake,
        home,
        str(scan),
        "--format",
        "sarif",
        "--repo-url",
        "https://github.com/example/canary",
        "--sha",
        SHA,
    )
    assert rc == 0, out
    got = json.loads(out)
    assert (got["findings"], got["new"]) == (1, 1)
    return got["assessment_id"]


@pytest.mark.parametrize("include_suppressed", [False, True])
def test_suppressed_sarif_intake_requires_explicit_review_override(
    home: Path, tmp_path: Path, include_suppressed: bool
) -> None:
    doc = json.loads(json.dumps(SARIF))
    suppressed = json.loads(json.dumps(doc["runs"][0]["results"][0]))
    suppressed["suppressions"] = [{"kind": "external"}]
    suppressed["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "suppressed.c"
    doc["runs"][0]["results"].append(suppressed)
    scan = tmp_path / "suppressed.sarif"
    scan.write_text(json.dumps(doc))
    rc, output = run(
        triage.intake,
        home,
        str(scan),
        "--format",
        "sarif",
        "--repo-url",
        "https://github.com/example/canary",
        "--sha",
        SHA,
        *(["--include-suppressed"] if include_suppressed else []),
    )
    assert rc == 0, output
    receipt = json.loads(output)
    assert receipt["findings"] == (2 if include_suppressed else 1)
    rc, prepared = run(triage.prepare, home, receipt["assessment_id"])
    assert rc == 0, prepared
    paths = {item["locations"][0]["path"] for item in json.loads(prepared)["items"]}
    assert paths == ({"entry.c", "suppressed.c"} if include_suppressed else {"entry.c"})


def test_scanner_output_triaged_and_recorded(home: Path, tmp_path: Path) -> None:
    assessment = intake(home, tmp_path)

    rc, out = run(triage.prepare, home, assessment)
    assert rc == 0, out
    prepared = json.loads(out)
    assert prepared["subject"]["sha"] == SHA
    [item] = prepared["items"]
    assert item["occurrence"]["severity"] == "high"
    assert item["locations"][0]["path"] == "entry.c"

    finding = item["finding"]
    report = {
        "triage_completed": "2026-10-23",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant platform",
            "votes_per_finding": 3,
            "repo": str(CANARY),
            "harness_version": "0.34.2-abc1234",
        },
        "summary": {
            "input_count": 1,
            "true_positives": 1,
            "hardening": 0,
            "false_positives": 0,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            {
                "id": "f001",
                "title": finding["title"],
                "verdict": "true_positive",
                "severity": "high",
                "file": "entry.c",
                "line": 25,
                "rationale": "reachable from main at entry.c:53",
                "fingerprint": finding["fingerprint"],
                "fingerprint_algo": finding["fingerprint_algo"],
            }
        ],
    }
    path = tmp_path / "canary-triage.json"
    path.write_text(json.dumps(report))

    rc, out = run(triage.record, home, assessment, str(path), "--repo", str(CANARY))
    assert rc == 0, out
    receipt = json.loads(out)
    assert {
        key: receipt[key] for key in ("decisions", "awaiting_countersign", "auto_accepted")
    } == {
        "decisions": 1,
        "awaiting_countersign": 0,
        "auto_accepted": 0,
    }
    assert receipt["baseline_assessment_id"] == assessment
    (native,) = receipt["records"]
    (saved,) = load(home).services().findings.history(finding["id"])
    assert native == {
        "decision_id": str(saved.id),
        "assessment_id": str(saved.assessment_id),
        "artifact_id": str(saved.artifact_id),
        "finding_id": finding["id"],
    }

    validation = {
        "title": "Live validation report for the isolated CLI fixture",
        "metadata": {
            "date": "2026-10-23",
            "harness_version": "0.34.3",
            "scope_binding_mode": "explicit",
            "target_fingerprint": [],
            "target_environment": "isolated-fixture",
            "target_attestation": {"attested": True},
        },
        "source_reports": [
            {
                "kind": "triage",
                "path": "opaque:canary-triage",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
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
                "source_report": "opaque:canary-triage",
                "verdict": "confirmed",
                "technique": "replay",
                "evidence_grade": "E1",
                "observed_impact": "Authenticated fixture action succeeded.",
            }
        ],
        "attack_chains": [],
        "novel_findings": [],
        "execution_log_ref": "opaque:audit",
    }
    validation_path = tmp_path / "canary-validation.json"
    validation_path.write_text(json.dumps(validation))
    bindings_path = tmp_path / "bindings.json"
    bindings_path.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "source_report": "opaque:canary-triage",
                        "assessment_id": native["assessment_id"],
                        "artifact_id": native["artifact_id"],
                        "findings": [{"source_id": "f001", "finding_id": native["finding_id"]}],
                    }
                ]
            }
        )
    )
    provenance_path = tmp_path / "provenance.json"
    provenance_path.write_text(
        json.dumps(
            {
                "run_id": str(uuid4()),
                "source": "validation_report",
                "occurred_at": "2026-10-23T12:00:00Z",
            }
        )
    )
    rc, out = run(
        lambda argv: main(["validation", "record", *argv]),
        home,
        "--report",
        str(validation_path),
        "--bindings",
        str(bindings_path),
        "--provenance",
        str(provenance_path),
    )
    assert rc == 0, out
    (recorded,) = json.loads(out)["findings"]
    assert recorded["finding_id"] == native["finding_id"]
    assert recorded["decision_id"]
    assert recorded["assessment_id"] != native["assessment_id"]

    rc, out = run(triage.render, home, str(path))
    assert rc == 0 and "## Act on these" in out and "(f001)" in out
    assert not (Path.cwd() / "artifacts").exists(), "artifacts belong under the core home"


def test_a_triage_not_matching_the_assessment_is_refused(
    home: Path, tmp_path: Path, capsys: Any
) -> None:
    assessment = intake(home, tmp_path)
    report = json.loads((skill_dir("triage") / "fixtures" / "canary-findings.json").read_text())
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(report))
    rc, _ = run(triage.record, home, assessment, str(path), "--repo", str(CANARY))
    assert rc == 2
    assert "ERROR" in capsys.readouterr().err


def test_an_unknown_assessment_is_an_error(home: Path) -> None:
    rc, _ = run(triage.prepare, home, "00000000-0000-0000-0000-000000000000")
    assert rc == 2
