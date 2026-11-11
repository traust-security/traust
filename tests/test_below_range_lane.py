"""The below-range lane: the `below_range_packets` materializer (traust-core's `BelowRangeService`
stubbed) and the review doors, `traust impact below-range-review` (the recorded packets written
for review, sources refetched) and `traust impact below-range-record`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.below_range import (
    BelowRangeInput,
    BelowRangeOutcome,
    BelowRangeScan,
    BelowRangeStatus,
    CoverageGap,
    GapReason,
)
from traust_core.v1.models.dependencies import NoManifestSbomError
from traust_core.v1.models.operations import AssetRequest, JobResult
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.services.below_range import BelowRangeService

from tests.test_impact_below_range import PACKET
from tests.test_impact_doors import REPO, home, run
from traust.cli import impact
from traust.context import load
from traust.ops.materializers import BelowRangePacketsMaterializer

__all__ = ["home"]

HOSTS = ("github.com",)
GAP = CoverageGap(reason=GapReason.OSV_UNANSWERED, package="lib")


def _input(status: BelowRangeStatus = BelowRangeStatus.COMPLETE, **kw: Any) -> BelowRangeInput:
    values: dict[str, Any] = {
        "repository_ref_id": uuid4(),
        "installed_exact": 3,
        "skipped_installs": {},
        "candidates": 1,
        "packets": (PACKET,),
        "coverage_gaps": (),
        "status": status,
    }
    return BelowRangeInput(**{**values, **kw})


class BelowRange:
    def __init__(self, outcome: BelowRangeInput | Exception) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def scan(self, repository_id: UUID, workdir: Path, **kw: Any) -> BelowRangeScan:
        self.calls.append({"repository_id": repository_id, "workdir": workdir, **kw})
        assert workdir.is_dir()
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return BelowRangeScan(assessment_id=uuid4(), artifact_id=uuid4(), packets=self.outcome)


class Portfolio:
    def __init__(self, known: bool = True) -> None:
        self.known = known

    def find_repository(self, url: HttpsRepoUrl) -> Any:
        return type("Repo", (), {"id": UUID(int=7)}) if self.known else None


class Services:
    def __init__(self, below_range: BelowRange, known: bool = True) -> None:
        self.below_range = below_range
        self.portfolio = Portfolio(known)


ORDER = str(uuid4())


@pytest.mark.parametrize(
    ("outcome", "want"),
    [
        (_input(), JobResult.succeeded()),
        (
            _input(BelowRangeStatus.DEGRADED, coverage_gaps=(GAP, GAP)),
            JobResult.partly({"osv_unanswered": 2}),
        ),
        (NoManifestSbomError(UUID(int=1)), "refused"),
        (NotFoundError("no default-branch commit; observe it"), "refused"),
        (ConfigError("below-range needs the advisory lookup"), "failed"),
    ],
    ids=["complete", "degraded", "no SBOM", "no head", "not configured"],
)
def test_the_materializer_answers_each_scan_outcome(
    outcome: BelowRangeInput | Exception, want: JobResult | str
) -> None:
    service = BelowRange(outcome)
    materializer = BelowRangePacketsMaterializer(Services(service), HOSTS)  # type: ignore[arg-type]
    got = materializer.materialize(
        AssetRequest(asset="below_range_packets", run_id=ORDER, partition=REPO)
    )
    assert got == want if isinstance(want, JobResult) else got.outcome == want
    [call] = service.calls
    assert (call["repository_id"], call["run_order_id"]) == (UUID(int=7), UUID(ORDER))
    assert not call["workdir"].exists()  # source trees live only for the run


@pytest.mark.parametrize(
    ("request_", "known", "outcome"),
    [
        (
            AssetRequest(asset="below_range_packets", run_id="manual", partition=REPO),
            False,
            "refused",
        ),
        (
            AssetRequest(
                asset="below_range_packets", run_id="manual", partition="https://x.io/a/b"
            ),
            True,
            "failed",
        ),
        (
            AssetRequest(asset="below_range_packets", run_id="not-an-order", partition=REPO),
            True,
            "failed",
        ),
    ],
    ids=["outside the inventory", "unknown host", "bad run id"],
)
def test_the_materializer_refuses_what_it_cannot_scan(
    request_: AssetRequest, known: bool, outcome: str
) -> None:
    service = BelowRange(_input())
    materializer = BelowRangePacketsMaterializer(Services(service, known), HOSTS)  # type: ignore[arg-type]
    assert materializer.materialize(request_).outcome == outcome
    assert service.calls == []


def _register(home: Path) -> UUID:
    core = load(home)
    repo = core.services().portfolio.register_repository(HttpsRepoUrl.parse(REPO, HOSTS), False)
    assert repo.id is not None
    return repo.id


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"packets": _input(coverage_gaps=(GAP,))}
    packets_id = uuid4()

    def latest(self: Any, repository_id: UUID) -> BelowRangeScan:
        seen["repository_id"] = repository_id
        return BelowRangeScan(
            assessment_id=packets_id, artifact_id=uuid4(), packets=seen["packets"]
        )

    def fetch(self: Any, packets: BelowRangeInput, workdir: Path) -> None:
        if "raise" in seen:
            raise seen["raise"]
        seen["fetched_into"] = workdir

    monkeypatch.setattr(BelowRangeService, "latest", latest)
    monkeypatch.setattr(BelowRangeService, "fetch", fetch)
    monkeypatch.setattr(impact, "osv_access", lambda: "api")
    seen["packets_id"] = packets_id
    return seen


def test_review_writes_the_recorded_packets_with_their_assessment(
    home: Path, tmp_path: Path, recorded: dict[str, Any]
) -> None:
    repo_id = _register(home)
    out = tmp_path / "review"
    rc, printed = run(impact.below_range_review, home, "--repo", REPO, "--out", str(out))
    assert rc == 0 and recorded["repository_id"] == repo_id and recorded["fetched_into"] == out
    assert json.loads(printed)["packets_assessment_id"] == str(recorded["packets_id"])
    assert (out / PACKET.case / "fix.patch").read_text() == PACKET.patch
    index = json.loads((out / "below-range.json").read_text())
    assert index["packets_assessment_id"] == str(recorded["packets_id"])
    assert index["coverage_gaps"] == [GAP.model_dump(mode="json")]


@pytest.mark.parametrize(
    "error",
    [IntegrityError("bytes changed"), ValidationError("x")],
    ids=["changed source", "bad packets"],
)
def test_review_writes_nothing_when_a_source_cannot_be_restored(
    home: Path, tmp_path: Path, recorded: dict[str, Any], error: Exception
) -> None:
    _register(home)
    recorded["raise"] = error
    out = tmp_path / "review"
    assert run(impact.below_range_review, home, "--repo", REPO, "--out", str(out))[0] == 2
    assert not (out / "below-range.json").exists()


def test_review_of_a_repository_outside_the_inventory_is_refused(
    home: Path, tmp_path: Path, recorded: dict[str, Any]
) -> None:
    assert run(impact.below_range_review, home, "--repo", REPO, "--out", str(tmp_path))[0] == 2
    assert "repository_id" not in recorded


def test_scan_is_refused_when_osv_is_air_gapped(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(impact, "osv_access", lambda: "air-gapped")
    rc, printed = run(impact.below_range_scan, home, "--repo", REPO)
    assert (rc, json.loads(printed)["outcome"]) == (5, "refused")


def test_record_hands_the_document_to_core_and_prints_the_outcome(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packets_id = uuid4()
    doc = {
        "artifact": "below-range-verdicts",
        "packets_assessment_id": str(packets_id),
        "cases": [],
        "coverage_gaps": [],
    }
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps(doc))
    seen: dict[str, Any] = {}

    def record(self: Any, artifact: Any, provenance: Any) -> BelowRangeOutcome:
        seen["doc"] = json.loads(artifact.payload)
        return BelowRangeOutcome(
            assessment_id=uuid4(),
            artifact_id=uuid4(),
            packets_assessment_id=packets_id,
            findings={},
            not_applicable=(),
            undetermined=(),
            coverage_gaps=0,
        )

    monkeypatch.setattr(BelowRangeService, "record", record)
    rc, printed = run(impact.below_range_record, home, str(path))
    assert rc == 0 and seen["doc"] == doc
    assert json.loads(printed)["packets_assessment_id"] == str(packets_id)


def test_record_refuses_a_document_off_the_contract(home: Path, tmp_path: Path) -> None:
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps({"artifact": "below-range-verdicts", "cases": "all fine"}))
    assert run(impact.below_range_record, home, str(path))[0] == 2


def test_the_skill_may_run_the_lane_doors_it_names() -> None:
    from tests.test_impact_below_range import SKILL

    text = SKILL.read_text()
    for door in ("impact below-range-review", "impact below-range-record"):
        assert f"Bash(python3 *-m traust.cli {door}:*)" not in text
    mode = text.split("## Below-range verification", 1)[1].split("## Constraints", 1)[0]
    assert "the runner validates and records it" in mode
    assert "<task>/output/verdicts.json" in mode
    assert "traust session prepare" in mode and "traust session record" in mode
    assert "traust.cli" not in mode
