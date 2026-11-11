"""`traust dashboard refresh`'s views stage: the `dashboards` materializer. Core tests the views
and `InsightService.refresh`; here, its outcome mapping, the files it writes, and the door."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.insight import (
    FindingsRollup,
    FindingTally,
    RefreshResult,
    RenderedView,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason, Outcome

from traust.cli import refresh_dashboards
from traust.ops.materializers import DashboardsMaterializer, write_view

ROLLUP = RenderedView(
    view=ViewName.FINDINGS_ROLLUP,
    stem="findings-rollup",
    model=FindingsRollup(as_of=datetime(2026, 10, 1, tzinfo=UTC), total=FindingTally()),
    markdown="# Findings rollup\n",
    html="<!doctype html><title>Findings rollup</title>",
)


class Insight:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def refresh(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def materialize(insight: Insight, out: Path, partition: str | None = None) -> JobResult:
    services = SimpleNamespace(insight=insight)
    materializer = DashboardsMaterializer(services, out)  # type: ignore[arg-type]
    return materializer.materialize(
        AssetRequest(asset="dashboards", run_id="manual", partition=partition)
    )


def test_every_built_view_is_written_beside_its_model(tmp_path: Path) -> None:
    insight = Insight(RefreshResult(rendered={ViewName.FINDINGS_ROLLUP: ROLLUP}))
    result = materialize(insight, tmp_path)
    base = tmp_path / "findings-rollup" / "findings-rollup"
    paths = tuple(str(base.with_suffix(s)) for s in (".md", ".html", ".json"))
    assert result == JobResult.succeeded(paths)
    assert insight.calls == [(None, ViewFilter())]
    assert base.with_suffix(".md").read_text() == ROLLUP.markdown
    assert base.with_suffix(".html").read_text() == ROLLUP.html
    assert json.loads(base.with_suffix(".json").read_text())["as_of"].startswith("2026-10-01")


def test_a_partition_refreshes_that_view_only(tmp_path: Path) -> None:
    insight = Insight(RefreshResult())
    assert materialize(insight, tmp_path, "findings-rollup") == JobResult.succeeded()
    assert insight.calls == [([ViewName.FINDINGS_ROLLUP], ViewFilter())]


def test_a_view_that_fails_is_degraded_and_the_rest_are_written(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    failed = {ViewName.LOC: "ValidationError: no language facts"}
    insight = Insight(RefreshResult(rendered={ViewName.FINDINGS_ROLLUP: ROLLUP}, failed=failed))
    result = materialize(insight, tmp_path)
    assert result.outcome == Outcome.DEGRADED
    assert result.degraded == {"loc": 1}
    assert result.reason == OrderReason.SOURCE_UNAVAILABLE
    assert "loc: ValidationError: no language facts" in caplog.text
    assert len(result.written) == 3


@pytest.mark.parametrize(
    ("partition", "raised"),
    [
        ("not-a-view", None),
        ("findings-trend", ValidationError("view 'findings-trend' is not built")),
        (None, ConfigError("no rating config")),
    ],
)
def test_a_bad_request_fails_and_writes_nothing(
    tmp_path: Path, partition: str | None, raised: Exception | None
) -> None:
    result = materialize(Insight(raised or RefreshResult()), tmp_path, partition)
    assert result.outcome == Outcome.FAILED and result.reason == OrderReason.BAD_REQUEST
    assert not any(tmp_path.iterdir())


def test_write_view_writes_the_rendered_pair(tmp_path: Path) -> None:
    written = write_view(ROLLUP, tmp_path / "x" / "Executive-Summary-Alpha")
    assert [p.name for p in written] == [
        "Executive-Summary-Alpha.md",
        "Executive-Summary-Alpha.html",
    ]
    assert written[1].read_text() == ROLLUP.html


@pytest.fixture
def insight(monkeypatch: pytest.MonkeyPatch) -> Insight:
    stub = Insight(RefreshResult(rendered={ViewName.FINDINGS_ROLLUP: ROLLUP}))
    monkeypatch.setattr(Context, "services", lambda self: SimpleNamespace(insight=stub))
    return stub


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = refresh_dashboards.main(list(argv))
    return rc, out.getvalue()


def test_the_views_stage_is_one_refresh_and_its_job_result(
    insight: Insight, tmp_path: Path
) -> None:
    argv = ("--only", "views", "--results-root", str(tmp_path), "--out", str(tmp_path / "d"))
    rc, out = run(*argv, "--view", "findings-rollup")
    assert rc == 0
    assert insight.calls == [([ViewName.FINDINGS_ROLLUP], ViewFilter())]
    job = JobResult.model_validate_json(out.splitlines()[1])
    assert job.outcome == Outcome.SUCCEEDED and len(job.written) == 3
    assert (tmp_path / "d" / "findings-rollup" / "findings-rollup.html").is_file()


def test_a_degraded_refresh_exits_with_its_outcome(insight: Insight, tmp_path: Path) -> None:
    insight.result = RefreshResult(failed={ViewName.FINDINGS_ROLLUP: "ValidationError: x"})
    rc, _ = run("--only", "views", "--results-root", str(tmp_path), "--out", str(tmp_path))
    assert rc == 4


def test_a_runner_reads_the_job_result_as_the_last_stdout_line(
    insight: Insight, tmp_path: Path
) -> None:
    insight.result = RefreshResult(failed={ViewName.FINDINGS_ROLLUP: "ValidationError: x"})
    rc, out = run("--results-root", str(tmp_path), "--out", str(tmp_path / "d"))
    job = JobResult.model_validate_json(out.strip().splitlines()[-1])
    assert (rc, job.outcome) == (4, Outcome.DEGRADED)


def test_views_run_first_and_render_the_scoreboard() -> None:
    stages = refresh_dashboards.build_stages(Path("/w"), Path("/r"), False)
    assert stages[0][0] == "views" and "scoreboard" not in [name for name, _, _ in stages]


def test_the_views_stage_builds_the_sla_view_on_the_packs_default_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "config"
    shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
    seen: list[Any] = []
    stub = Insight(RefreshResult())

    def services(self: Context) -> SimpleNamespace:
        seen.append((self.sla_policy, self.default_sla_policy.policy_name))
        return SimpleNamespace(insight=stub)

    monkeypatch.setattr(Context, "services", services)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    rc, _ = run("--only", "views", "--results-root", str(tmp_path), "--out", str(tmp_path / "d"))
    assert rc == 0 and seen == [(None, "fedramp-rev5-ra-5")]
    names = [name for name, _, _ in refresh_dashboards.build_stages(tmp_path, tmp_path, False)]
    assert "sla" not in names
