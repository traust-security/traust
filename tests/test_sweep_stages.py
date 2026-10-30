"""`traust sweep collect / draft / sweep / emit / rule-lane / benchmark`: the CLI layer only. Each is
one `DetectionQualityService` door (stubbed); the CLI prints its summary, writes the files a
reader takes (sweep-candidates, the lane's reports, the benchmark worklist) and keeps the exit
codes. The stages themselves are traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.detection_quality import RuleMining, RulePack
from traust_core.v1.models.rule_mining import (
    Attention,
    LaneDelta,
    LaneStage,
    RuleLane,
    RuleSweep,
    RuleSweepCandidate,
    StageStatus,
    SweepCandidates,
    SweepCollect,
    SweepDrafts,
    SweepEmit,
    SweepStats,
    TpCorpus,
)
from traust_core.v1.models.validation_benchmark import (
    BenchmarkScore,
    BenchmarkScorecard,
    BenchmarkTrigger,
    BenchmarkVariant,
    BenchmarkWorklist,
)

from traust.cli.groups import sweep
from traust.paths import skill_dir

NOW = datetime(2026, 10, 27, tzinfo=UTC)
RID = "traust-go-sweep-cwe-78"


class Door:
    def __init__(self, result: Any = None) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any, **kw: Any) -> Any:
        self.calls.append((*args, *kw.values()))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result(*args) if callable(self.result) else self.result


@pytest.fixture
def quality(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    stub = SimpleNamespace(loaded=[])
    locations = SimpleNamespace(
        analysis_results_dir=lambda: tmp_path / "ar",
        progress_tracker_dir=lambda: tmp_path / "pt",
        rule_drafts_dir=lambda: tmp_path / "drafts",
    )

    def load(home: Path | None, **kw: Any) -> SimpleNamespace:
        stub.loaded.append(kw)
        return SimpleNamespace(
            services=lambda: SimpleNamespace(detection_quality=stub),
            rule_drafts=SimpleNamespace(root=kw.get("rule_drafts") or tmp_path / "drafts"),
            config=SimpleNamespace(
                locations=locations,
                overrides=SimpleNamespace(rule_pack_allowlist=getattr(stub, "allowlist", None)),
            ),
        )

    monkeypatch.setattr(sweep, "load", load)
    return stub


def call(op: Any, **args: Any) -> tuple[int, str, str]:
    ns = SimpleNamespace(**{"config_home": None, "pack": None, "drafts_dir": None, **args})
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = op(ns)
    return rc, out.getvalue(), err.getvalue()


STATS = SweepStats(
    confirmed_findings=8, by_source={"ledger": 8}, rule_expressible=4, not_expressible=4, classes=3
)


@pytest.mark.parametrize(
    ("result", "printed"),
    [
        (
            SweepCollect(skipped=False, state="k/collect.json", stats=STATS),
            "collect: 8 confirmed finding(s) ({'ledger': 8}); 4 rule-expressible across 3 "
            "class(es); 4 not expressible (reasons recorded) -> k/collect.json",
        ),
        (
            SweepCollect(skipped=True, state="k/collect.json"),
            "collect: state exists, skipping (k/collect.json) — use --force to re-collect",
        ),
    ],
)
def test_collect_prints_its_stats_or_that_it_resumed(
    quality: SimpleNamespace, result: SweepCollect, printed: str
) -> None:
    quality.sweep_collect = Door(result)
    rc, out, _ = call(sweep.call_collect, force=True)
    assert (rc, out.strip()) == (0, printed)
    assert quality.sweep_collect.calls == [(True,)]


def test_the_rule_pack_and_drafts_flags_reach_core(
    quality: SimpleNamespace, tmp_path: Path
) -> None:
    quality.sweep_drafts = Door(
        SweepDrafts(generated=NOW, pack="traust 1", drafts_dir="d", emitted=("a", "b"))
    )
    rc, out, _ = call(sweep.call_draft, pack=tmp_path / "pack", drafts_dir=tmp_path / "d")
    assert rc == 0 and out.startswith("draft: 2 draft(s) staged (a, b); 0 class(es) skipped")
    assert quality.loaded[-1] == {"rule_pack": tmp_path / "pack", "rule_drafts": tmp_path / "d"}


def test_a_refusing_door_is_exit_2(quality: SimpleNamespace) -> None:
    quality.sweep_drafts = Door(NotFoundError("no sweep collection: run `sweep collect` first"))
    rc, _, err = call(sweep.call_draft)
    assert rc == 2 and "run `sweep collect` first" in err


def test_sweep_reads_the_repos_override(quality: SimpleNamespace, tmp_path: Path) -> None:
    repos = tmp_path / "repos.json"
    repos.write_text(json.dumps([{"slug": "a", "url": "dir:/x"}]))
    quality.sweep_rule = Door(
        RuleSweep(
            rule_id=RID,
            rule_path="r",
            repos=1,
            swept=1,
            skipped=0,
            repo_errors=0,
            hits=2,
            repo_results="k/repos",
        )
    )
    rc, out, _ = call(
        sweep.call_sweep,
        rule=RID,
        limit=5,
        repos=repos,
        work_dir=None,
        opengrep="og",
        timeout=9,
    )
    assert rc == 0
    assert out.strip() == (
        f"sweep [{RID}]: 1 repo(s) swept, 0 resumed/skipped, 0 errored, 2 raw hit(s) -> k/repos"
    )
    (request,) = quality.sweep_rule.calls[0]
    assert (request.rule, request.limit, request.binary, request.timeout) == (RID, 5, "og", 9)
    assert [r.url for r in request.repos] == ["dir:/x"]


def test_a_malformed_repos_file_is_exit_2(quality: SimpleNamespace, tmp_path: Path) -> None:
    repos = tmp_path / "repos.json"
    repos.write_text("[{]")
    rc, _, err = call(
        sweep.call_sweep, rule=RID, limit=5, repos=repos, work_dir=None, opengrep="og", timeout=9
    )
    assert rc == 2 and err.startswith("ERROR:")


CANDIDATES = SweepCandidates(
    generated=NOW,
    harness_version="1",
    rule_id=RID,
    rule_path="r",
    repos_swept=2,
    repos_with_hits=1,
    repo_errors=1,
    candidates=(
        RuleSweepCandidate(
            repo="a",
            url=None,
            file="m.go",
            line=3,
            end_line=3,
            location="m.go:3",
            excerpt="x",
            rule_id=RID,
            severity_hint="high",
            test_path=False,
            source_finding_provenance=("F-1",),
        ),
    ),
)


def test_emit_writes_the_triage_input_under_the_sweeps_root(
    quality: SimpleNamespace, tmp_path: Path
) -> None:
    quality.emit_sweep = Door(
        SweepEmit(rule_id=RID, skipped=False, out="k", candidates=CANDIDATES, summary="# s\n")
    )
    rc, out, _ = call(
        sweep.call_emit, rule=RID, force=False, sweeps_root=None, analysis_results=None
    )
    target = tmp_path / "ar" / "scan-testing" / "sweeps" / RID
    assert rc == 0 and f"-> {target / 'sweep-candidates.json'}" in out
    doc = json.loads((target / "sweep-candidates.json").read_text())
    assert doc["artifact"] == "sweep-candidates" and doc["candidates"][0]["location"] == "m.go:3"
    assert (target / "sweep-summary.md").read_text() == "# s\n"


def test_emit_resumes_without_writing(quality: SimpleNamespace, tmp_path: Path) -> None:
    quality.emit_sweep = Door(SweepEmit(rule_id=RID, skipped=True, out="k/c.json"))
    rc, out, _ = call(
        sweep.call_emit, rule=RID, force=False, sweeps_root=tmp_path / "s", analysis_results=None
    )
    assert (rc, out.strip()) == (
        0,
        "emit: candidates exist, skipping (k/c.json) — use --force to re-emit",
    )
    assert not (tmp_path / "s").exists()


def lane(attention: bool = False, failed: bool = False, delta: bool = True) -> RuleLane:
    stages = (
        LaneStage(stage="mine", status=StageStatus.OK, summary="mined"),
        LaneStage(
            stage="sweep-draft",
            status=StageStatus.FAILED if failed else StageStatus.OK,
            returncode=1 if failed else 0,
            summary="no drafts dir" if failed else "draft: 0 draft(s) staged",
        ),
    )
    lane_delta = LaneDelta(
        generated_at=NOW,
        baseline=False,
        tp_corpus=TpCorpus(confirmed_tps=3, ruleable_tps=2, growth=1),
        attention=Attention(needed=attention, reasons=("grew",) if attention else ()),
        stages=stages,
    )
    return RuleLane(
        stages=stages,
        mining=RuleMining(pack=RulePack(name="traust", version="1")) if delta else None,
        delta=lane_delta if delta else None,
        mining_report="# mining\n" if delta else None,
        delta_report="# delta\n" if delta else None,
    )


@pytest.mark.parametrize(
    ("result", "code"),
    [(lane(), 0), (lane(attention=True), 1), (lane(failed=True), 2), (lane(delta=False), 2)],
)
def test_the_lane_writes_its_reports_and_keeps_its_exit_codes(
    quality: SimpleNamespace, tmp_path: Path, result: RuleLane, code: int
) -> None:
    quality.rule_lane = Door(result)
    rc, out, err = call(sweep.call_rule_lane, out=None, draft_limit=6, skip_sweep=False)
    assert rc == code
    metrics = tmp_path / "pt" / "metrics" / "rule-mining"
    assert "[mine] mined" in out
    if result.delta is None:
        assert not metrics.exists()
        return
    assert (metrics / "lane-delta.md").read_text() == "# delta\n"
    assert json.loads((metrics / "lane-delta.json").read_text())["tp_corpus"]["growth"] == 1
    assert (metrics / "rule-mining.md").read_text() == "# mining\n"
    assert json.loads((metrics / "rule-mining.json").read_text())["pack"]["name"] == "traust"
    assert (metrics / "tp-corpus.jsonl").read_text() == ""
    assert "rule-mining lane: TPs 3 (+1);" in out and f"-> {metrics}/lane-delta.{{json,md}}" in out
    if result.failed:
        assert "[sweep-draft] FAILED (rc 1): no drafts dir" in err


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (None, None),
        ("packs:\n  argus:\n    rules: [go-tls-bypass]\n", frozenset({"go-tls-bypass"})),
        ("packs: {}\n", "yielded no rule ids"),
    ],
)
def test_the_lane_rechecks_the_config_homes_allowlist(
    quality: SimpleNamespace, tmp_path: Path, text: str | None, expected: Any
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    if text is not None:
        (home / "rule-pack-allowlist.yaml").write_text(text)
        quality.allowlist = home / "rule-pack-allowlist.yaml"
    quality.rule_lane = Door(lane())
    call(sweep.call_rule_lane, config_home=home, out=tmp_path / "o", draft_limit=0, skip_sweep=True)
    (request,) = quality.rule_lane.calls[0]
    assert (request.draft_limit, request.skip_sweep) == (0, True)
    if expected is None:
        assert request.allowlist is None
    elif isinstance(expected, frozenset):
        assert request.allowlist.rules == expected
    else:
        assert expected in request.allowlist.unreadable


def test_a_lane_core_refuses_is_exit_2(quality: SimpleNamespace, tmp_path: Path) -> None:
    quality.rule_lane = Door(ConfigError("no object store configured"))
    rc, _, err = call(sweep.call_rule_lane, out=tmp_path, draft_limit=6, skip_sweep=False)
    assert rc == 2 and "object store" in err


EXPECTED = {
    "namespace": "vb",
    "floors": {"confirm_recall": 0.9, "refute_precision": 0.9, "severity_within": 1.0},
    "fixtures": [
        {
            "id": "VB-1",
            "probe_class": "rbac",
            "controls_hint": "h",
            "vuln_manifest": "v.yaml",
            "claim": {
                "title": "t",
                "severity": "high",
                "cvss": 8.0,
                "cvss_vector": "CVSS:3.1/AV:N",
                "category": "authorization",
            },
            "expected": {"vuln": "confirmed", "safe": "refuted"},
        }
    ],
}


@pytest.fixture
def bench(tmp_path: Path) -> Path:
    d = tmp_path / "bench"
    d.mkdir()
    (d / "expected.json").write_text(json.dumps(EXPECTED))
    return d


def test_plan_writes_the_worklist_beside_the_benchmark(
    quality: SimpleNamespace, bench: Path
) -> None:
    quality.benchmark_worklist = Door(lambda b: BenchmarkWorklist.of(b, NOW))
    rc, out, _ = call(sweep.call_benchmark, benchmark_cmd="plan", benchmark_dir=bench)
    assert rc == 0 and "benchmark worklist: 1 claims" in out
    assert f"oc apply -f {bench}/fixtures/v.yaml" in out
    (claim,) = json.loads((bench / "benchmark-findings.json").read_text())["findings"]
    assert claim["id"] == "VB-1" and "validation_status" not in claim


def test_plan_reads_the_shipped_benchmark_and_writes_to_the_estate(
    quality: SimpleNamespace, tmp_path: Path
) -> None:
    quality.benchmark_worklist = Door(lambda b: BenchmarkWorklist.of(b, NOW))
    rc, out, _ = call(sweep.call_benchmark, benchmark_cmd="plan", benchmark_dir=None)
    shipped = skill_dir("validate-findings") / "benchmark"
    assert rc == 0 and f"oc apply -f {shipped}/fixtures/" in out
    assert (tmp_path / "ar" / sweep.VALIDATION_BENCHMARK_REL / "benchmark-findings.json").is_file()
    assert not (shipped / "benchmark-findings.json").exists()


@pytest.mark.parametrize(("value", "code"), [(1.0, 0), (0.5, 1)])
def test_score_exits_1_below_the_floor(
    quality: SimpleNamespace, bench: Path, value: float, code: int
) -> None:
    report = bench / "report.json"
    report.write_text(json.dumps({"validated_findings": []}))
    quality.score_benchmark = Door(
        BenchmarkScore(variant=BenchmarkVariant.VULN, confirm_recall=value, n=1)
    )
    rc, out, err = call(
        sweep.call_benchmark,
        benchmark_cmd="score",
        benchmark_dir=bench,
        report=str(report),
        variant="vuln",
    )
    assert rc == code and f"confirm_recall: {value} (floor 0.9)" in out
    assert ("BELOW FLOOR" in err) is (code == 1)


@pytest.mark.parametrize(("paths", "code"), [(("traust/harnessing/x",), 10), ((), 0)])
def test_check_trigger_exits_10_when_the_benchmark_is_required(
    quality: SimpleNamespace, tmp_path: Path, paths: tuple[str, ...], code: int
) -> None:
    quality.benchmark_trigger = Door(BenchmarkTrigger(since="v1", paths=paths))
    rc, out, _ = call(
        sweep.call_benchmark,
        benchmark_cmd="check-trigger",
        benchmark_dir=None,
        since="v1",
        repo_root=tmp_path,
    )
    assert rc == code
    (request, since) = quality.benchmark_trigger.calls[0]
    assert (request.workspace, since) == (tmp_path, "v1")
    assert ("benchmark REQUIRED" in out) is (code == 10)


def test_check_trigger_needs_a_checkout(quality: SimpleNamespace) -> None:
    with pytest.raises(SystemExit, match="--repo-root required"):
        call(
            sweep.call_benchmark,
            benchmark_cmd="check-trigger",
            benchmark_dir=None,
            since="v1",
            repo_root=None,
        )


def test_the_scorecard_lists_the_latest_runs(quality: SimpleNamespace) -> None:
    quality.benchmark_scorecard = Door(BenchmarkScorecard())
    _, out, _ = call(sweep.call_benchmark, benchmark_cmd="scorecard", benchmark_dir=None)
    assert out.startswith("no benchmark runs recorded yet")
    run = BenchmarkScore(variant=BenchmarkVariant.SAFE, refute_precision=1.0, n=4, scored_at=NOW)
    quality.benchmark_scorecard = Door(BenchmarkScorecard(runs=(run,)))
    _, out, _ = call(sweep.call_benchmark, benchmark_cmd="scorecard", benchmark_dir=None)
    assert out.strip() == "2026-10-27T00:00:00Z  safe  refute_precision=1.0  severity=None  n=4"
