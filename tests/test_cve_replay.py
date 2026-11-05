from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from traust.lib.pending_decisions import Decision, skip_reason

pytest.skip(skip_reason(Decision.CVE_REPLAY), allow_module_level=True)

from traust_core.v1.context import Config, Context
from traust_core.v1.models.cve_replay import (
    CveReplayCandidate,
    CveReplayState,
    CveReplayVerdict,
)
from traust_core.v1.models.vocabulary import ScannerSeverity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.objects.store import ObjectKey

from traust.cli import cve_replay
from traust.cli.__main__ import main as cli

NOW = datetime(2026, 11, 3, tzinfo=UTC)


def candidate(
    identifier: str, verdict: CveReplayVerdict, presence: bool | None
) -> CveReplayCandidate:
    return CveReplayCandidate(
        repository_id=UUID(int=1),
        repository_ref_id=UUID(int=2),
        repository="https://example.test/project",
        audited_commit="a" * 40,
        audit_id=UUID(int=3),
        report_artifact_id=UUID(int=4),
        audited_at=datetime(2026, 10, 1, tzinfo=UTC),
        advisory_id=identifier,
        published_at=datetime(2026, 11, 2, tzinfo=UTC),
        checked_at=NOW,
        severity=ScannerSeverity.CRITICAL,
        summary="Synthetic replay candidate",
        present_at_audit=presence,
        audit_verdict=verdict,
        reason="synthetic report evidence",
        source="fixture:osv",
    )


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Context:
    objects = InMemoryObjectStore()
    rows = (
        candidate("CVE-2026-99901", CveReplayVerdict.MISSED, True),
        candidate("CVE-2026-99902", CveReplayVerdict.UNCLEAR, None),
        candidate("CVE-2026-99903", CveReplayVerdict.NOT_APPLICABLE, False),
        candidate("CVE-2026-99904", CveReplayVerdict.DETECTED, True),
    )
    objects.put(
        ObjectKey("detection-quality/cve-replay/state.json"),
        CveReplayState(checks=rows).model_dump_json().encode(),
    )
    core = Context(Config(home=tmp_path / "core"), object_store=objects, clock=FixedClock(NOW))
    monkeypatch.setattr(cve_replay, "load", lambda config_home: core)
    return core


def test_grouped_candidate_export_uses_real_core_policy_and_stays_human_gated(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(["sweep", "cve-replay", "candidates"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert [r["advisory_id"] for r in output["candidates"]] == ["CVE-2026-99901", "CVE-2026-99902"]
    assert all(r["requires_human_review"] is True for r in output["candidates"])
    assert core.services().detection_quality.cve_replay_trends().rows[0].advisory_id == (
        "CVE-2026-99901"
    )


def test_grouped_trend_export_excludes_unknown_presence_and_area_only_checks(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(["sweep", "cve-replay", "trends"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["series"] == "fn_cve_replay_missed"
    assert [r["advisory_id"] for r in output["rows"]] == ["CVE-2026-99901"]
    assert len(core.services().detection_quality.cve_replay_candidates().candidates) == 2


def test_monitor_without_registered_osv_provider_fails_without_changing_candidates(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    before = core.services().detection_quality.cve_replay_candidates()
    assert cli(["sweep", "cve-replay", "monitor"]) == 2
    assert capsys.readouterr().out == ""
    assert core.services().detection_quality.cve_replay_candidates() == before


def test_oracle_invalid_assessment_identifier_is_rejected_before_loading_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_load(config_home: Path | None) -> Context:
        raise AssertionError("invalid input must not load Core")

    monkeypatch.setattr(cve_replay, "load", unexpected_load)
    with pytest.raises(SystemExit) as failure:
        cli(["sweep", "cve-replay", "oracle", "not-a-uuid", "CVE-2026-99901"])
    assert failure.value.code == 2
