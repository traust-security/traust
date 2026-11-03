from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from traust_core.v1.context import ArtifactsConfig, Config, Context
from traust_core.v1.models.critical_misses import CriticalMissReport
from traust_core.v1.providers.clock import FixedClock

from traust.cli import critical_misses
from traust.cli.__main__ import main as cli

NOW = datetime(2026, 10, 20, tzinfo=UTC)


def write_json(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Context]:
    context = Context(
        Config(
            home=tmp_path / "store",
            artifacts=ArtifactsConfig(path=tmp_path / "artifacts"),
        ),
        clock=FixedClock(NOW),
    )
    monkeypatch.setattr(critical_misses, "load", lambda _: context)
    monkeypatch.setattr(critical_misses, "harness_version", lambda: "h-1")
    yield context
    context.database.dispose()


def test_grouped_cli_exports_raw_candidates_without_intake_rows(
    core: Context,
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign"
    write_json(
        campaign / "b-lite/widget-delta.json",
        {
            "slug": "widget",
            "deltas": [
                {
                    "title": "Critical delta",
                    "severity": "critical",
                    "cwe": "CWE-78",
                }
            ],
        },
    )
    write_json(
        campaign / "matrix/widget-delta-wave2.json",
        {
            "slug": "widget",
            "deltas": [{"title": "Matrix critical", "severity": "critical"}],
        },
    )
    write_json(
        campaign / "cve-replay/candidates.json",
        {
            "rows": [
                {
                    "slug": "widget",
                    "cve": "CVE-2026-1234",
                    "severity": "critical",
                    "present_at_audit": True,
                    "audit_verdict": "missed",
                    "summary": "RCE",
                },
                {
                    "slug": "widget",
                    "cve": "CVE-2026-5678",
                    "severity": "critical",
                    "present_at_audit": None,
                    "audit_verdict": "unclear",
                    "summary": "Unknown",
                },
            ]
        },
    )
    out = tmp_path / "exports/CRITICAL-MISSES.md"
    assert (
        cli(
            [
                "sweep",
                "critical-misses",
                "--campaign-dir",
                str(campaign),
                "--out",
                str(out),
                "--start",
                "2026-10-01T00:00:00Z",
                "--end",
                "2026-11-01T00:00:00Z",
            ]
        )
        == 0
    )
    report = CriticalMissReport.model_validate_json(out.with_suffix(".json").read_bytes())
    assert (report.counts.delta_candidates, report.counts.cve_replay_missed) == (2, 1)
    assert report.counts.replay_unknown == 1
    assert report.recorded_misses == ()
    assert report.generated_at == NOW and report.harness_version == "h-1"
    assert {r.candidate.title for r in report.candidates} == {
        "Critical delta",
        "Matrix critical",
        "CVE-2026-1234: RCE",
    }
    assert {r.ingestion.value for r in report.candidates} == {"not_ingested"}
    assert {r.routing.value for r in report.candidates} == {"pending_triage", "measured_not_routed"}
    rendered = out.read_text(encoding="utf-8")
    assert "Critical delta" in rendered and "CVE-2026-1234" in rendered
    assert "CVE-2026-5678" not in rendered
    assert (
        core.services().detection_quality.critical_misses(
            critical_misses.TimeWindow(start=NOW, end=NOW.replace(day=21))
        )
        == []
    )


def test_cli_writes_json_to_an_explicit_independent_destination(
    core: Context,
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    out, json_out = tmp_path / "reports/CRITICAL-MISSES.md", tmp_path / "data/critical.json"
    assert (
        critical_misses.main(
            [
                "--campaign-dir",
                str(campaign),
                "--out",
                str(out),
                "--json-out",
                str(json_out),
            ]
        )
        == 0
    )
    report = CriticalMissReport.model_validate_json(json_out.read_bytes())
    assert report.counts.delta_candidates == 0 and report.recorded_misses == ()
    assert out.is_file()
    assert not out.with_suffix(".json").exists()


def test_provider_refusals_exit_two_without_publishing_a_partial_report(
    core: Context,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    campaign = tmp_path / "campaign"
    write_json(campaign / "b-lite/widget-delta.json", {"deltas": "not an array"})
    out = tmp_path / "CRITICAL-MISSES.md"
    assert (
        critical_misses.main(
            [
                "--campaign-dir",
                str(campaign),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert "widget-delta.json" in capsys.readouterr().err
    assert not out.exists() and not out.with_suffix(".json").exists()


@pytest.mark.parametrize(
    "window",
    [
        ["--start", "2026-10-01T00:00:00Z"],
        ["--start", "2026-10-01T00:00:00", "--end", "2026-11-01T00:00:00"],
        ["--start", "2026-11-01T00:00:00Z", "--end", "2026-10-01T00:00:00Z"],
    ],
)
def test_invalid_recorded_windows_are_refused_without_writes(
    core: Context,
    tmp_path: Path,
    window: list[str],
) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    out = tmp_path / "CRITICAL-MISSES.md"
    assert (
        critical_misses.main(
            [
                "--campaign-dir",
                str(campaign),
                "--out",
                str(out),
                *window,
            ]
        )
        == 2
    )
    assert not out.exists()
