"""`traust findings summary|timeline`: the CLI layer only. Arguments become one door call with the
right filter; the answer is printed as JSON; a typed error is exit 2. The rollups themselves are
traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.findings import (
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
)
from traust_core.v1.models.vocabulary import Severity, Validity

from traust.cli import findings

REPO = "https://github.com/example-org/app"
REPO_ID = uuid.uuid4()
AS_OF = datetime(2026, 10, 1, tzinfo=UTC)
ROLLUP = FindingRollup(
    key="critical",
    findings=3,
    open=2,
    hardening=0,
    accepted=0,
    resolved=1,
    false_positives=0,
    open_by_severity={Severity.CRITICAL: 2},
)
POINT = FindingSeriesPoint(
    bucket=AS_OF,
    open_by_severity={Severity.HIGH: 1},
    new=1,
    resolved=0,
    accepted=0,
    hardening=0,
    false_positives=0,
    regressions=0,
    risk_index=7.5,
)


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        summary=Door([ROLLUP]),
        timeline=Door([POINT]),
        find_repository=Door(SimpleNamespace(id=REPO_ID, url=REPO)),
    )
    services = SimpleNamespace(
        findings=SimpleNamespace(summary=stub.summary, timeline=stub.timeline),
        portfolio=SimpleNamespace(find_repository=stub.find_repository),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.mark.parametrize(
    ("argv", "wanted"),
    [
        ((), FindingFilter(repository_id=REPO_ID, as_of=AS_OF)),
        (("--open",), FindingFilter(repository_id=REPO_ID, open=True, as_of=AS_OF)),
        (("--closed",), FindingFilter(repository_id=REPO_ID, open=False, as_of=AS_OF)),
        (
            ("--validity", "confirmed"),
            FindingFilter(repository_id=REPO_ID, validity=Validity.CONFIRMED, as_of=AS_OF),
        ),
    ],
)
def test_summary_is_one_door_call_with_the_filter(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], wanted: FindingFilter
) -> None:
    rc, out = run(
        findings.summary,
        home,
        "--repo-url",
        REPO,
        "--group-by",
        "severity",
        "--as-of",
        AS_OF.isoformat(),
        *argv,
    )
    assert (rc, out) == (0, [ROLLUP.model_dump(mode="json")])
    assert doors.summary.calls == [(wanted, FindingDimension.SEVERITY)]


def test_timeline_defaults_to_weekly_buckets_through_now(
    doors: SimpleNamespace, home: Path
) -> None:
    before = datetime.now(UTC)
    rc, out = run(findings.timeline, home, "--repo-url", REPO)
    assert (rc, out) == (0, [POINT.model_dump(mode="json")])
    [(wanted, bucket)] = doors.timeline.calls
    assert bucket is TimeBucket.WEEK
    assert wanted.repository_id == REPO_ID
    assert wanted.as_of is not None and wanted.as_of >= before


def test_timeline_takes_a_bucket(doors: SimpleNamespace, home: Path) -> None:
    rc, _ = run(findings.timeline, home, "--repo-url", REPO, "--bucket", "month")
    assert rc == 0
    assert doors.timeline.calls[0][1] is TimeBucket.MONTH


def test_an_unregistered_repository_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.find_repository.result = None
    rc, err = run(findings.summary, home, "--repo-url", REPO, "--group-by", "cwe")
    assert rc == 2 and "not registered" in err
    assert doors.summary.calls == []


def test_a_time_without_a_zone_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(findings.timeline, home, "--repo-url", REPO, "--as-of", "2026-10-01T00:00:00")
    assert rc == 2 and "time zone" in err
    assert doors.timeline.calls == []


def test_a_door_refusal_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.summary.result = NotFoundError("no such repository")
    rc, err = run(findings.summary, home, "--repo-url", REPO, "--group-by", "label")
    assert rc == 2 and "no such repository" in err


def test_open_and_closed_are_exclusive(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit):
        run(findings.summary, home, "--repo-url", REPO, "--group-by", "cwe", "--open", "--closed")
