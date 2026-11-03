"""`traust sweep score-benchmark`: the CLI layer only. A runs dir is read into one
`DetectionQualityService.score_reports` call (target id -> report, then rerun); without one, one
`scorecards` call. The match ladder and the scorecard are traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.detection_quality import (
    BenchmarkFilter,
    BenchmarkRun,
    Recall,
    Scorecard,
)

from tests.test_validate_report import _valid_report
from traust.cli import recall

KEY = "00000000-0000-0000-0000-000000000001"


def card(**kw: Any) -> Scorecard:
    return Scorecard(
        overall=Recall(detected=1, expected=2),
        near_misses=0,
        by_cwe={},
        by_severity={},
        by_provenance={},
        by_language={},
        by_split={},
        injection={"total": 0, "passed": 0, "reported": 0},
        targets_scored=1,
        targets_skipped=0,
        **kw,
    )


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    seen = SimpleNamespace(reports=[], filters=[], refusal=None)

    def score_reports(reports: Any, auditor_version: str, *, include_held_out: bool) -> Any:
        if seen.refusal is not None:
            raise seen.refusal
        seen.reports.append((reports, auditor_version, include_held_out))
        return BenchmarkRun(answer_key_id=KEY, manifest_version=3)  # type: ignore[arg-type]

    def scorecards(filter: BenchmarkFilter) -> Any:
        seen.filters.append(filter)
        return [card(auditor_versions=("h-1",))]

    quality = SimpleNamespace(score_reports=score_reports, scorecards=scorecards)
    services = SimpleNamespace(detection_quality=quality)
    monkeypatch.setattr(recall, "load", lambda home: SimpleNamespace(services=lambda: services))
    return seen


def call(*argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = recall.score(list(argv))
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def audit(run_dir: Path, name: str = "x-security-audit.json", **meta: str) -> None:
    body = _valid_report()
    body["metadata"].update(meta)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / name).write_text(json.dumps(body))


def test_a_runs_dir_is_each_target_report_then_its_rerun(
    wired: SimpleNamespace, tmp_path: Path
) -> None:
    runs = tmp_path / "runs"
    audit(runs / "bt-a", scope="The first audit pass")
    audit(runs / "bt-a__rerun", scope="The rerun audit pass")
    audit(runs / "bt-b")
    (runs / "bt-empty").mkdir()  # no report: no run, which core reports as skipped
    out_file = tmp_path / "bench" / "benchmark.json"
    rc, out = call(
        "--runs-dir", str(runs), "--auditor-version", "h-9", "--include-held-out",
        "--out", str(out_file),
    )  # fmt: skip
    assert rc == 0
    [(reports, auditor_version, held_out)] = wired.reports
    assert (auditor_version, held_out) == ("h-9", True)
    assert {t: [r.metadata.scope for r in rs] for t, rs in reports.items()} == {
        "bt-a": ["The first audit pass", "The rerun audit pass"],
        "bt-b": [_valid_report()["metadata"]["scope"]],
    }
    assert all(isinstance(r, ReportArtifact) for rs in reports.values() for r in rs)
    assert out["run"]["manifest_version"] == 3
    assert out["scorecard"]["overall"] == {"detected": 0, "expected": 0, "recall": None}
    assert json.loads(out_file.read_text()) == out
    markdown = out_file.with_suffix(".md").read_text(encoding="utf-8")
    assert markdown.startswith("# Detection-recall benchmark\n")
    assert "| Expected findings | 0 |" in markdown


def test_the_default_auditor_version_is_this_traust(wired: SimpleNamespace, tmp_path: Path) -> None:
    audit(tmp_path / "bt-a")
    assert call("--runs-dir", str(tmp_path))[0] == 0
    assert wired.reports[0][1] and wired.reports[0][2] is False


@pytest.mark.parametrize(
    ("layout", "error"),
    [
        ({"bt-a__rerun": 1}, "have no first run"),
        ({"bt-a": 2}, "2 reports"),
    ],
)
def test_an_ambiguous_runs_dir_is_refused_before_scoring(
    wired: SimpleNamespace, tmp_path: Path, layout: dict[str, int], error: str
) -> None:
    for d, n in layout.items():
        for i in range(n):
            audit(tmp_path / d, name=f"{i}-security-audit.json")
    rc, err = call("--runs-dir", str(tmp_path))
    assert rc == 2 and error in err
    assert wired.reports == []


def test_a_report_off_its_schema_is_refused(wired: SimpleNamespace, tmp_path: Path) -> None:
    (tmp_path / "bt-a").mkdir()
    (tmp_path / "bt-a" / "x-security-audit.json").write_text('{"title": "no"}')
    rc, _ = call("--runs-dir", str(tmp_path))
    assert rc == 2 and wired.reports == []


def test_a_missing_runs_dir_is_exit_2(wired: SimpleNamespace, tmp_path: Path) -> None:
    rc, err = call("--runs-dir", str(tmp_path / "nope"))
    assert rc == 2 and "no runs dir" in err


def test_a_refusal_is_exit_2(wired: SimpleNamespace, tmp_path: Path) -> None:
    audit(tmp_path / "bt-typo")
    wired.refusal = NotFoundError("no benchmark answer key recorded")
    rc, err = call("--runs-dir", str(tmp_path))
    assert rc == 2 and "no benchmark answer key" in err


def test_without_a_runs_dir_the_recorded_audits_are_scored(wired: SimpleNamespace) -> None:
    rc, out = call("--auditor-version", "h-1")
    assert rc == 0
    assert wired.filters == [BenchmarkFilter(auditor_version="h-1", include_held_out=False)]
    [scorecard] = out["scorecards"]
    assert scorecard["overall"]["recall"] == 0.5
    assert scorecard["auditor_versions"] == ["h-1"]


def test_recorded_scorecards_materialize_a_sibling_markdown_file(
    wired: SimpleNamespace, tmp_path: Path
) -> None:
    out_file = tmp_path / "nested" / "benchmark.json"
    rc, out = call("--out", str(out_file), "--auditor-version", "h-1")
    assert rc == 0 and json.loads(out_file.read_text()) == out
    markdown = out_file.with_suffix(".md").read_text(encoding="utf-8")
    assert markdown.startswith("# Detection-recall benchmark — recorded scorecards\n")
    assert "| Auditor versions | h-1 |" in markdown
    assert "| Strict recall | 50.0% |" in markdown


@pytest.mark.parametrize("runs_dir", [False, True])
@pytest.mark.parametrize("json_output", [False, True])
def test_explicit_markdown_is_reachable_in_both_scoring_modes(
    wired: SimpleNamespace, tmp_path: Path, runs_dir: bool, json_output: bool
) -> None:
    markdown_file = tmp_path / "review" / "score.md"
    out_file = tmp_path / "data" / "score.json"
    argv = ["--markdown", str(markdown_file)]
    if runs_dir:
        audit(tmp_path / "runs" / "bt-a")
        argv += ["--runs-dir", str(tmp_path / "runs")]
    if json_output:
        argv += ["--out", str(out_file)]
    rc, out = call(*argv)
    assert rc == 0
    assert markdown_file.read_text(encoding="utf-8").startswith("# Detection-recall benchmark")
    assert not out_file.with_suffix(".md").exists()
    if json_output:
        assert json.loads(out_file.read_text()) == out
    else:
        assert not out_file.exists()
