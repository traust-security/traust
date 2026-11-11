"""`traust impact below-range`: one `BelowRangeService.prepare` call (stubbed), the packet files the
skill reads, exit codes, and the feeds.yaml hosts core ships and loads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from traust_core.v1.context.config import SHIPPED_FEEDS
from traust_core.v1.context.feeds import load_package_sources
from traust_core.v1.models.below_range import (
    AdvisoryExcerpt,
    BelowRangeInput,
    BelowRangeStatus,
    Candidate,
    CandidateKind,
    CoverageGap,
    FixAttempt,
    FixChoice,
    GapReason,
    InstalledSource,
    Packet,
)
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AffectedPackage,
    NoManifestSbomError,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.services.below_range import BelowRangeService

from tests.test_impact_doors import REPO, SHA, home, run
from traust.cli import impact
from traust.cli.__main__ import main
from traust.paths import HARNESS_ROOT

__all__ = ["home"]

SKILL = HARNESS_ROOT / "harnessing" / "3-audit" / "dependency-watch" / "SKILL.md"
FEEDS = SHIPPED_FEEDS
CANDIDATE = Candidate(
    ecosystem=Ecosystem.GO,
    package="example.com/lib",
    version=Version("v1.4.0"),
    advisory=AdvisoryIdentifier("GHSA-test-0001"),
    kind=CandidateKind.BELOW_RANGE,
    stated_start=Version("2.0.0"),
    major_distance=1,
)
PACKET = Packet(
    case=CANDIDATE.case,
    candidate=CANDIDATE,
    advisory=AdvisoryExcerpt(
        identifier=CANDIDATE.advisory,
        aliases=(),
        summary="flaw",
        details="",
        affected=AffectedPackage(ecosystem=Ecosystem.GO, name="example.com/lib"),
    ),
    fix=FixChoice(
        chosen=FixAttempt(url="https://github.com/ex/lib/commit/" + "4" * 40, rank=2),
        alternatives=(),
        fixed_releases=(),
    ),
    installed_source=InstalledSource(
        url="https://proxy.golang.org/x.zip", sha256="0" * 64, files=2, root="_sources/x"
    ),
    hunk_presence=(),
    patch="From 4444 the fix\n",
)


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"status": BelowRangeStatus.COMPLETE}

    def prepare(self: Any, ref_id: UUID, workdir: Path, **kw: Any) -> BelowRangeInput:
        if "raise" in seen:
            raise seen["raise"]
        seen.update(ref_id=ref_id, workdir=workdir, **kw)
        return BelowRangeInput(
            repository_ref_id=ref_id,
            installed_exact=3,
            skipped_installs={"version:maven": 1},
            candidates=2,
            packets=(PACKET,),
            coverage_gaps=(CoverageGap(reason=GapReason.SOURCE_UNAVAILABLE, case="other"),),
            status=seen["status"],
        )

    monkeypatch.setattr(BelowRangeService, "prepare", prepare)
    monkeypatch.setattr(impact, "osv_access", lambda: "api")
    return seen


def test_writes_the_packets_the_skill_reads_and_summarizes(
    home: Path, tmp_path: Path, prepared: dict[str, Any]
) -> None:
    out = tmp_path / "packets"
    argv = ["--repo-url", REPO, "--sha", SHA, "--out", str(out), "--ecosystems", "go,NPM"]
    rc, printed = run(impact.below_range, home, *argv, "--max-candidates", "7")
    assert rc == 0
    assert json.loads(printed) == {
        "out": str(out),
        "installed_exact": 3,
        "candidates": 2,
        "packets": 1,
        "coverage_gaps": {"source_unavailable": 1},
        "status": "complete",
    }
    assert prepared["workdir"] == out
    assert (prepared["ecosystems"], prepared["max_candidates"]) == (
        {Ecosystem.GO, Ecosystem.NPM},
        7,
    )
    case = out / PACKET.case
    assert (case / "fix.patch").read_text() == PACKET.patch
    packet = json.loads((case / "packet.json").read_text())
    assert "patch" not in packet and packet["candidate"]["kind"] == "below_range"
    index = json.loads((out / "below-range.json").read_text())
    assert index["packets"] == [{"case": PACKET.case, "kind": "below_range", "ecosystem": "go"}]
    assert index["coverage_gaps"][0]["reason"] == "source_unavailable"
    assert index["repository_ref_id"] == str(prepared["ref_id"])


def test_a_degraded_run_exits_3(home: Path, tmp_path: Path, prepared: dict[str, Any]) -> None:
    prepared["status"] = BelowRangeStatus.DEGRADED
    argv = ["--repo-url", REPO, "--sha", SHA, "--out", str(tmp_path / "o")]
    rc, printed = run(impact.below_range, home, *argv)
    assert rc == 3 and json.loads(printed)["status"] == "degraded"


def test_a_commit_without_a_recorded_sbom_is_refused(
    home: Path, tmp_path: Path, prepared: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    prepared["raise"] = NoManifestSbomError(UUID(int=1))
    rc, printed = run(impact.below_range, home, "--repo-url", REPO, "--sha", SHA)
    assert (rc, printed) == (2, "")
    assert "no manifest SBOM ingested" in capsys.readouterr().err


def test_air_gapped_osv_is_refused(
    home: Path,
    prepared: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(impact, "osv_access", lambda: "air-gapped")
    assert run(impact.below_range, home, "--repo-url", REPO, "--sha", SHA)[0] == 2
    assert "air-gapped" in capsys.readouterr().err
    assert "ref_id" not in prepared


def test_an_unknown_ecosystem_is_a_usage_error(home: Path) -> None:
    with pytest.raises(SystemExit) as exit_:
        run(impact.below_range, home, "--repo-url", REPO, "--sha", SHA, "--ecosystems", "Go,cobol")
    assert exit_.value.code == 2


def test_the_impact_group_routes_below_range(
    home: Path, tmp_path: Path, prepared: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["impact", "below-range", "--config-home", str(home), "--repo-url", REPO, "--sha", SHA]
    assert main([*argv, "--out", str(tmp_path / "o")]) == 0
    assert json.loads(capsys.readouterr().out)["packets"] == 1


def test_the_shipped_feeds_registry_names_every_host_the_lane_fetches_from() -> None:
    hosts = load_package_sources(FEEDS, http=HttpFetcher("test")).hosts
    assert hosts.forges == {"github.com", "gitlab.com"}
    assert {
        "proxy.golang.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "repo1.maven.org",
        "static.crates.io",
        "rubygems.org",
        "api.nuget.org",
        "github.com",
    } == hosts.registries
    assert hosts.redirects["proxy.golang.org"] == {"storage.googleapis.com"}
    assert hosts.redirects["github.com"] == {
        "patch-diff.githubusercontent.com",
        "codeload.github.com",
    }


def test_the_skill_may_run_the_commands_its_below_range_mode_names() -> None:
    text = SKILL.read_text()
    mode = text.split("## Below-range verification", 1)[1].split("## Constraints", 1)[0]
    assert "below-range --task <dir>" in text
    assert "staged in `<task>/input/` by the runner" in mode
    for slot in ("reviewer_a", "reviewer_b", "judge"):
        assert f"models.{slot}" in mode
    assert "Two blind reviews per packet" in mode and "Judge on a split" in mode
    assert "coverage gaps unchanged" in mode
