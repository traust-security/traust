"""`traust remediation open|work-items|fork|progress|mutation-evidence|assemble|record|candidates`:
the CLI layer
only. Arguments become one door call; the answer is printed as JSON; a typed error is exit 2.
The doors and the evidence rules are traust-core's tests."""

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
from traust_core.v1.errors import ConflictError, ValidationError
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.common import Page
from traust_core.v1.models.remediation import (
    Fork,
    RemediationDraft,
    RepositoryCandidates,
    WorkItem,
    WorkItemFilter,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import RemediationStatus

from traust.cli import remediation

FIXTURES = Path(__file__).parent / "fixtures" / "remediation"
REPO = "https://github.com/example-org/example-service"
SHA = "0123456789abcdef0123456789abcdef01234567"
REPO_ID, REF_ID, ITEM_ID, FINDING_ID = (uuid.uuid4() for _ in range(4))
ITEM = WorkItem(
    work_item_id=ITEM_ID,
    repository_ref_id=REF_ID,
    finding_ids=(FINDING_ID,),
    status="candidate",
    opened_at=datetime(2026, 10, 24, tzinfo=UTC),
)
FORK = Fork(
    host="github",
    owner="example-mirrors",
    url=HttpsRepoUrl.parse(
        "https://github.com/example-mirrors/example-service", {"github.com": "github"}
    ),
    visibility="private",
)

REPORT = (FIXTURES / "remediation-report.json").read_text().replace("FINDING_ID", str(FINDING_ID))
_DRAFTED = json.loads(REPORT)
_DRAFTED["patch"]["diff_path"] = f"{ITEM_ID}-patch.diff"
DRAFT = RemediationDraft(report=RemediationArtifact.from_document(_DRAFTED), diff=b"+fix\n")
PRODUCT_ID = uuid.uuid4()
CANDIDATES = RepositoryCandidates(
    repository_id=REPO_ID, url=REPO, repository_ref_ids=(REF_ID,), findings=()
)


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.keywords: list[dict[str, Any]] = []
        self.result = result

    def __call__(self, *args: Any, **keywords: Any) -> Any:
        self.calls.append(args)
        self.keywords.append(keywords)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        open=Door(ITEM),
        list=Door(Page(items=(ITEM,))),
        resolve_fork=Door(FORK),
        record_progress=Door(ITEM),
        record=Door(ITEM),
        register_ref=Door(SimpleNamespace(id=REF_ID)),
        assemble=Door(DRAFT),
        candidates=Door([CANDIDATES]),
    )
    services = SimpleNamespace(
        remediation=SimpleNamespace(
            open=stub.open,
            list=stub.list,
            resolve_fork=stub.resolve_fork,
            record_progress=stub.record_progress,
            record=stub.record,
            assemble=stub.assemble,
            candidates=stub.candidates,
        ),
        portfolio=SimpleNamespace(
            find_product=lambda slug: (
                SimpleNamespace(id=PRODUCT_ID) if str(slug) == "prod" else None
            ),
            find_repository=lambda url: SimpleNamespace(id=REPO_ID) if str(url) == REPO else None,
            register_ref=stub.register_ref,
        ),
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


def test_open_registers_the_commit_and_opens_one_item(doors: SimpleNamespace, home: Path) -> None:
    other = uuid.uuid4()
    rc, out = run(
        remediation.open_,
        home,
        *("--repo-url", REPO, "--sha", SHA, "--finding", str(FINDING_ID), "--finding", str(other)),
    )
    assert (rc, out) == (0, ITEM.model_dump(mode="json"))
    [(repository_id, sha, None_, _)] = doors.register_ref.calls
    assert (repository_id, str(sha), None_) == (REPO_ID, SHA, None)
    assert doors.open.calls == [([FINDING_ID, other], REF_ID)]


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--repo-url", "https://github.com/example-org/unknown", "--sha", SHA), "not registered"),
        (("--repo-url", REPO, "--sha", "nope"), "sha"),
    ],
)
def test_open_refuses_before_the_door(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], reason: str
) -> None:
    rc, err = run(remediation.open_, home, *argv, "--finding", str(FINDING_ID))
    assert rc == 2 and reason in err.lower()
    assert doors.open.calls == []


@pytest.mark.parametrize(
    "error", [ValidationError("finding is not confirmed"), ConflictError("already covers")]
)
def test_open_door_refusals_are_exit_2(
    doors: SimpleNamespace, home: Path, error: Exception
) -> None:
    doors.open.result = error
    rc, err = run(
        remediation.open_, home, "--repo-url", REPO, "--sha", SHA, "--finding", str(FINDING_ID)
    )
    assert rc == 2 and str(error) in err


def test_open_needs_a_finding(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit):
        run(remediation.open_, home, "--repo-url", REPO, "--sha", SHA)


@pytest.mark.parametrize(("argv", "status"), [((), None), (("--status", "forked"), "forked")])
def test_work_items_lists_with_the_filter(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], status: str | None
) -> None:
    rc, out = run(remediation.work_items, home, "--repo-url", REPO, *argv)
    assert (rc, out) == (0, [ITEM.model_dump(mode="json")])
    [(wanted, _)] = doors.list.calls
    assert wanted == WorkItemFilter(repository_id=REPO_ID, status=status)


def test_fork_is_one_door_call(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.fork, home, "--repo-url", REPO)
    assert (rc, out["url"], out["visibility"]) == (0, str(FORK.url), "private")
    assert doors.resolve_fork.calls == [(REPO_ID,)]


def test_progress_moves_the_item(doors: SimpleNamespace, home: Path) -> None:
    rc, _ = run(remediation.progress, home, str(ITEM_ID), "forked")
    assert rc == 0
    assert doors.record_progress.calls == [(ITEM_ID, RemediationStatus("forked"))]


def test_progress_backwards_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.record_progress.result = ConflictError("patched can't move to forked")
    rc, err = run(remediation.progress, home, str(ITEM_ID), "forked")
    assert rc == 2 and "can't move" in err


def test_progress_refuses_an_unknown_status(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit):
        run(remediation.progress, home, str(ITEM_ID), "patching")


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        ("mewt-status-all-caught.json", "proves"),
        ("mewt-status-uncaught.json", "fails_to_prove"),
        ("missing.json", "not_attempted"),
    ],
)
def test_mutation_evidence_reads_the_status_json(home: Path, status: str, outcome: str) -> None:
    rc, out = run(
        remediation.mutation_evidence_,
        home,
        *("--target", "pkg", "--rc", "0", "--log", "campaign.log"),
        *("--status-json", str(FIXTURES / status)),
    )
    assert rc == 0
    assert out["kind"] == "mutation" and out["outcome"].startswith(outcome)


def test_record_parses_the_report_and_records_it(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    report = tmp_path / "r.json"
    report.write_text(
        (FIXTURES / "remediation-report.json").read_text().replace("FINDING_ID", str(FINDING_ID))
    )
    rc, out = run(remediation.record, home, str(report))
    assert (rc, out) == (0, ITEM.model_dump(mode="json"))
    [(doc, _)] = doors.record.calls
    assert isinstance(doc, RemediationArtifact)


def test_record_names_the_work_item_the_run_prepared(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    report = tmp_path / "r.json"
    report.write_text(
        (FIXTURES / "remediation-report.json").read_text().replace("FINDING_ID", str(FINDING_ID))
    )
    assert run(remediation.record, home, str(report))[0] == 0
    rc, _ = run(remediation.record, home, str(report), "--work-item", str(ITEM.work_item_id))
    assert rc == 0
    assert doors.record.keywords == [{"work_item_id": None}, {"work_item_id": ITEM.work_item_id}]


def test_record_refusals_are_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    assert run(remediation.record, home, str(report))[0] == 2
    assert doors.record.calls == []
    report.write_text(
        (FIXTURES / "remediation-report.json").read_text().replace("FINDING_ID", str(FINDING_ID))
    )
    doors.record.result = ValidationError("remediation report pushes to a public fork")
    rc, err = run(remediation.record, home, str(report))
    assert rc == 2 and "public fork" in err


def _assemble_args(tmp_path: Path, *extra: str) -> tuple[str, ...]:
    (tmp_path / "checks.json").write_text(
        json.dumps([{"name": "go test", "command": "go test ./...", "outcome": "pass"}])
    )
    (tmp_path / "ev.json").write_text(
        json.dumps({"kind": "mutation", "outcome": "not_attempted: no mewt"})
    )
    return (
        str(ITEM_ID),
        *("--worktree", str(tmp_path), "--product", "prod"),
        *("--out", str(tmp_path / "out" / "r.json"), "--checks", str(tmp_path / "checks.json")),
        *("--rationale", "x" * 60, "--tests-added", "a_test.go:TestA, ,b_test.go:TestB"),
        *("--evidence", str(tmp_path / "ev.json"), "--strategy", "bound-resource"),
        *extra,
    )


def test_assemble_drafts_the_report_and_writes_it_and_its_diff(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    rc, out = run(remediation.assemble, home, *_assemble_args(tmp_path, "--status", "abandoned"))
    diff = tmp_path / "out" / DRAFT.report.patch.diff_path
    assert (rc, out) == (
        0,
        {"report": str(tmp_path / "out" / "r.json"), "diff": str(diff), "status": "checks_passed"},
    )
    assert (tmp_path / "out" / "r.json").read_bytes() == DRAFT.report.payload
    assert diff.read_bytes() == b"+fix\n"
    [(item, worktree, narrative, checks)] = doors.assemble.calls
    assert (item, worktree) == (ITEM_ID, tmp_path)
    assert (narrative.logical_product, narrative.strategy, narrative.status) == (
        "prod",
        "bound-resource",
        "abandoned",
    )
    assert narrative.tests_added == ("a_test.go:TestA", "b_test.go:TestB")
    assert [e.outcome for e in narrative.evidence] == ["not_attempted: no mewt"]
    assert [c.outcome for c in checks] == ["pass"]


@pytest.mark.parametrize(
    ("break_it", "reason"),
    [
        (lambda p: (p / "checks.json").write_text('[{"name": "x"}]'), "validation error"),
        (lambda p: (p / "ev.json").write_text('{"kind": "nope"}'), "validation error"),
    ],
)
def test_assemble_refuses_malformed_checks_or_evidence(
    doors: SimpleNamespace, home: Path, tmp_path: Path, break_it: Any, reason: str
) -> None:
    args = _assemble_args(tmp_path)
    break_it(tmp_path)
    rc, err = run(remediation.assemble, home, *args)
    assert rc == 2 and reason in err and doors.assemble.calls == []


def test_assemble_door_refusals_are_exit_2_and_write_nothing(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doors.assemble.result = ValidationError("nothing committed since abc")
    rc, err = run(remediation.assemble, home, *_assemble_args(tmp_path))
    assert rc == 2 and "nothing committed" in err
    assert not (tmp_path / "out").exists()


def test_candidates_lists_a_products_repositories(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.candidates, home, "--product", "prod")
    assert (rc, out) == (0, [CANDIDATES.model_dump(mode="json")])
    assert doors.candidates.calls == [(PRODUCT_ID,)]


def test_candidates_of_an_unknown_product_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(remediation.candidates, home, "--product", "nope")
    assert rc == 2 and "not registered" in err and doors.candidates.calls == []
