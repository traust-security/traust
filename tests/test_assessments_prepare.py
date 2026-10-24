"""`traust assessments prepare|record|coverage`: the CLI layer only. URL and commit become a ref, then one
`AssessmentService.prepare`; a refused diff is exit 3 with the verdict. The door's behaviour
(baseline, anchor, clusters, hunks, callers, refusals) is traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import (
    AssessmentFilter,
    AssessmentKind,
    Coverage,
    CoverageGap,
    DiffRefused,
    DiffRequest,
    GapSignal,
)
from traust_core.v1.models.common import ArtifactRef, Page
from traust_core.v1.models.vocabulary import RefKind

from traust.cli import assessments

URL = "https://github.com/example/widget"
SHA = "a" * 40
REPO = SimpleNamespace(id=uuid.uuid4())
REF = SimpleNamespace(id=uuid.uuid4())


class Prepared:
    def model_dump_json(self, indent: int | None = None) -> str:
        return json.dumps({"kind": "vuln-scan", "diff": None}, indent=indent)


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
        prepare=Door(Prepared()),
        register_ref=Door(REF),
        find_repository=Door(REPO),
    )
    services = SimpleNamespace(
        assessment=SimpleNamespace(prepare=stub.prepare),
        portfolio=SimpleNamespace(
            find_repository=stub.find_repository, register_ref=stub.register_ref
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    stub.services = services
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = assessments.prepare(
            ["--config-home", str(home), "--repo-url", URL, "--sha", SHA, *argv]
        )
    return rc, out.getvalue().strip(), err.getvalue()


def test_whole_target_is_one_prepare_of_the_commit(doors: SimpleNamespace, home: Path) -> None:
    rc, out, _ = run(home, "--kind", "vuln-scan")
    assert rc == 0
    assert json.loads(out) == {"kind": "vuln-scan", "diff": None}
    assert doors.register_ref.calls[0][0] == REPO.id
    assert str(doors.register_ref.calls[0][1]) == SHA
    assert doors.prepare.calls == [(REF.id, AssessmentKind.VULN_SCAN, None)]


def test_diff_overrides_reach_the_door(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    baseline = uuid.uuid4()
    rc, _, _ = run(
        home,
        "--kind",
        "vuln-scan",
        "--diff",
        str(tmp_path),
        "--since",
        "abc1234",
        "--baseline-assessment",
        str(baseline),
    )
    assert rc == 0
    request = doors.prepare.calls[0][2]
    assert request == DiffRequest(
        checkout=tmp_path, baseline_assessment_id=baseline, since="abc1234"
    )


def test_out_writes_the_input(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    target = tmp_path / "scope.json"
    rc, out, _ = run(home, "--kind", "vuln-scan", "-o", str(target))
    assert (rc, out) == (0, "")
    assert json.loads(target.read_text())["kind"] == "vuln-scan"


def test_refused_diff_is_the_verdict_and_exit_3(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doors.prepare.result = DiffRefused("41% of first-party files changed")
    rc, out, _ = run(home, "--kind", "vuln-scan", "--diff", str(tmp_path))
    assert rc == 3
    assert json.loads(out) == {
        "refuse": True,
        "recommend": "full-audit",
        "reason": "41% of first-party files changed",
    }


def test_unregistered_repository_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.find_repository.result = None
    rc, _, err = run(home, "--kind", "vuln-scan")
    assert rc == 2
    assert "not registered" in err
    assert doors.prepare.calls == []


@pytest.mark.parametrize(
    "flag", [["--since", "abc1234"], ["--baseline-assessment", str(uuid.uuid4())]]
)
def test_overrides_without_diff_are_exit_2(
    doors: SimpleNamespace, home: Path, flag: list[str]
) -> None:
    rc, _, err = run(home, "--kind", "vuln-scan", *flag)
    assert rc == 2
    assert "need --diff" in err
    assert doors.prepare.calls == []


def test_bad_since_is_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    rc, _, err = run(home, "--kind", "vuln-scan", "--diff", str(tmp_path), "--since", "HEAD~1")
    assert rc == 2
    assert "7-40 hex" in err
    assert doors.prepare.calls == []


def test_coverage_is_one_door_call_over_every_repository(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    other = uuid.uuid4()
    found = Coverage(
        examined=1,
        total=2,
        gaps=(
            CoverageGap(
                tool="route-guards",
                system="fastapi",
                repositories=1,
                signals={GapSignal.STRUCTURED: 1},
                example_repository_ids=(REPO.id,),
            ),
        ),
    )
    coverage_door = Door(found)
    services = SimpleNamespace(
        assessment=SimpleNamespace(coverage=coverage_door),
        portfolio=SimpleNamespace(
            list_repositories=lambda _filter, _page: Page(
                items=[SimpleNamespace(id=REPO.id, url=URL), SimpleNamespace(id=other, url="u2")]
            )
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = assessments.coverage(["--config-home", str(home)])
    assert rc == 0
    assert coverage_door.calls == [(AssessmentFilter(), [REPO.id, other])]
    body = json.loads(out.getvalue())
    assert (body["examined"], body["total"], body["ratio"]) == (1, 2, 0.5)
    assert body["gaps"][0]["examples"] == [URL]
    assert body["gaps"][0]["tool"] == "route-guards"


MODEL = {
    "system": "widget",
    "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": URL},
    "threats": [],
}


class Publisher:
    def __init__(self) -> None:
        self.published: list[Any] = []

    def publish_ref(self, doc: Any) -> ArtifactRef:
        self.published.append(doc)
        return ArtifactRef(id=uuid.uuid4(), name=doc.name, digest="0" * 64)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch, doors: SimpleNamespace) -> SimpleNamespace:
    publisher = Publisher()
    record_door = Door(SimpleNamespace(id=uuid.uuid4()))
    doors.services.assessment.record = record_door
    monkeypatch.setattr(Context, "artifact_publisher", lambda self, specs: publisher)
    return SimpleNamespace(publisher=publisher, record=record_door, doors=doors)


def record(home: Path, document: Path, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = assessments.record(
            ["--config-home", str(home), str(document), "--repo-url", URL, "--sha", SHA, *argv]
        )
    return rc, out.getvalue().strip(), err.getvalue()


def test_record_publishes_then_records_one_assessment(
    recorder: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doc = tmp_path / "widget-threat-model.json"
    doc.write_text(json.dumps(MODEL))
    rc, out, _ = record(home, doc, "--kind", "threat-model", "--branch", "main")
    assert rc == 0
    assert recorder.doors.register_ref.calls[0][2:] == ("main", RefKind.BRANCH)
    (published,) = recorder.publisher.published
    (call,) = recorder.record.calls
    doc_arg, ref_id, kind, assessor, _version, provenance = call
    assert doc_arg is published
    assert (ref_id, kind, assessor) == (REF.id, AssessmentKind.THREAT_MODEL, "skill:threat-model")
    assert provenance.artifact is not None
    assert json.loads(out)["assessment_id"] == str(recorder.record.result.id)


def test_record_refuses_an_invalid_document(
    recorder: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doc = tmp_path / "bad.json"
    doc.write_text("{}")
    rc, _, err = record(home, doc, "--kind", "threat-model")
    assert rc == 2
    assert "system" in err
    assert recorder.publisher.published == []
    assert recorder.record.calls == []
