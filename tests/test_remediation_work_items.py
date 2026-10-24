"""`traust remediation open|work-items|fork|progress|mutation-evidence|record`: the CLI layer
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
from traust_core.v1.models.remediation import Fork, WorkItem, WorkItemFilter
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
        open=Door(ITEM),
        list=Door(Page(items=(ITEM,))),
        resolve_fork=Door(FORK),
        record_progress=Door(ITEM),
        record=Door(ITEM),
        register_ref=Door(SimpleNamespace(id=REF_ID)),
    )
    services = SimpleNamespace(
        remediation=SimpleNamespace(
            open=stub.open,
            list=stub.list,
            resolve_fork=stub.resolve_fork,
            record_progress=stub.record_progress,
            record=stub.record,
        ),
        portfolio=SimpleNamespace(
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
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
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
