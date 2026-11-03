"""Recorded impact documents reach the grouped export and real verification scope."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import ImpactEvidence, ImpactExport
from traust_core.v1.models.vocabulary import SourceType

from tests.test_impact_doors import LODASH, home, run, sbom
from traust.cli import impact, remediation
from traust.cli.__main__ import main
from traust.context import load

__all__ = ["home"]

AFFECTED = "https://github.com/example-org/affected"
LIKELY = "https://github.com/example-org/likely"
SAFE = "https://github.com/example-org/safe"
UNRELATED = "https://github.com/example-org/unrelated"


def record_fleet(home: Path, tmp_path: Path) -> dict[str, dict]:
    documents = {}
    for index, (url, version) in enumerate(
        ((AFFECTED, "4.17.20"), (LIKELY, "4.17.20"), (SAFE, "4.17.21"))
    ):
        rc, text = run(
            impact.sbom,
            home,
            str(sbom(tmp_path, version)),
            "--repo-url",
            url,
            "--sha",
            str(index + 1) * 40,
        )
        assert rc == 0
        ref_id = uuid.UUID(json.loads(text)["repository_ref_id"])
        exposure = impact._core(home).services().exposure
        known = exposure.find_advisory(LODASH.identifier)
        assert known is not None and known.advisory_id is not None
        [prepared] = exposure.prepare(known.advisory_id, ref_id)
        if url == AFFECTED:
            prepared = prepared.model_copy(
                update={
                    "evidence": prepared.evidence.model_copy(update={"feature_pattern_matches": 1})
                }
            )
        doc = prepared.document("1.0.0", "Template evaluation with untrusted input")
        recorded = exposure.record(
            ref_id,
            doc,
            Provenance(
                run_id=uuid.uuid4(),
                source=SourceType.IMPACT_REPORT,
                occurred_at=datetime(2026, 11, 3, tzinfo=UTC),
            ),
        )
        documents[str(recorded.artifact_id)] = json.loads(doc.payload)
    assert (
        run(
            impact.sbom,
            home,
            str(sbom(tmp_path, "4.17.20")),
            "--repo-url",
            UNRELATED,
            "--sha",
            "4" * 40,
        )[0]
        == 0
    )
    return documents


def sweep(home: Path, *argv: str) -> dict:
    rc, text = run(remediation.verify_sweep, home, *argv)
    assert rc == 0
    return json.loads(text)


def repositories(worklist: dict) -> set[str]:
    return {row["repository"] for row in (*worklist["queued"], *worklist["skipped"])}


def test_grouped_export_keeps_native_evidence_and_scopes_real_verification(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    documents = record_fleet(home, tmp_path)
    target = tmp_path / "advisory-impact-analysis.json"
    assert (
        main(
            [
                "impact",
                "export",
                LODASH.identifier,
                "--config-home",
                str(home),
                "--out",
                str(target),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    exported = json.loads(target.read_text())
    assert (exported["commits"], exported["analyses"]) == (3, 3)
    assert {row["classification"] for row in exported["repos"]} == {
        "affected",
        "likely_affected",
        "version_not_in_range",
    }
    for row in exported["repos"]:
        assert row["document"] == documents[row["artifact_id"]]
        native_evidence = row["document"]["repos"][0]["evidence"]
        assert {key: row["evidence"][key] for key in native_evidence} == native_evidence
        assert (
            ImpactEvidence.model_validate(row["evidence"]).classification(row["ecosystem"])
            == row["classification"]
        )
    assert repositories(sweep(home)) == {AFFECTED, LIKELY, SAFE, UNRELATED}
    assert repositories(sweep(home, "--impact-filter", str(target))) == {AFFECTED, LIKELY}
    assert repositories(
        sweep(home, "--impact-filter", str(target), "--repo-url", LIKELY, "--repo-url", SAFE)
    ) == {LIKELY}


@pytest.mark.parametrize("branch_args", [(), ("--include-branches",)])
def test_an_empty_or_no_matching_impact_filter_never_becomes_the_whole_fleet(
    home: Path, tmp_path: Path, branch_args: tuple[str, ...]
) -> None:
    record_fleet(home, tmp_path)
    rc, text = run(impact.export, home, LODASH.identifier)
    assert rc == 0
    exported = ImpactExport.model_validate_json(text)
    target = tmp_path / "empty.json"
    target.write_text(exported.model_copy(update={"repos": ()}).model_dump_json())
    assert sweep(home, *branch_args, "--impact-filter", str(target)) == {
        "queued": [],
        "skipped": [],
    }
    target.write_text(text)
    assert sweep(home, *branch_args, "--impact-filter", str(target), "--repo-url", SAFE) == {
        "queued": [],
        "skipped": [],
    }


def test_export_without_a_live_provider_uses_kept_identity_and_preserves_stdout(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    documents = record_fleet(home, tmp_path)

    def no_lookup(*args: object, **kwargs: object) -> None:
        pytest.fail("Export must not configure live feeds")

    monkeypatch.setattr(impact, "_core", no_lookup)
    rc, text = run(impact.export, home, LODASH.identifier)
    assert rc == 0
    assert {row["artifact_id"]: row["document"] for row in json.loads(text)["repos"]} == documents
    target = tmp_path / "unknown.json"
    assert run(impact.export, home, "CVE-2099-9999", "--out", str(target))[0] == 2
    assert not target.exists()
    assert load(home).services().exposure.export_impacts(LODASH.identifier).analyses == 3
