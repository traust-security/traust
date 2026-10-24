"""`traust remediation next|prepare`: the CLI layer only. Arguments become one door call; the
answer is printed as JSON; a typed error is exit 2. The doors are traust-core's tests."""

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
from traust_core.v1.models.remediation import WorkItem, WorkItemFilter

from traust.cli import remediation

REPO = "https://github.com/example-org/example-service"
REPO_ID, ITEM_ID = uuid.uuid4(), uuid.uuid4()
ITEM = WorkItem(
    work_item_id=ITEM_ID,
    repository_ref_id=uuid.uuid4(),
    finding_ids=(uuid.uuid4(),),
    status="candidate",
    opened_at=datetime(2026, 10, 24, tzinfo=UTC),
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
        next_pending=Door(ITEM),
        prepare=Door(SimpleNamespace(model_dump_json=lambda indent: '{"fix_branch": "b"}')),
    )
    services = SimpleNamespace(
        remediation=SimpleNamespace(next_pending=stub.next_pending, prepare=stub.prepare),
        portfolio=SimpleNamespace(
            find_repository=lambda url: SimpleNamespace(id=REPO_ID) if str(url) == REPO else None
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


def test_next_is_one_door_call_for_the_repository(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.next_, home, "--repo-url", REPO)
    assert (rc, out) == (0, ITEM.model_dump(mode="json"))
    assert doors.next_pending.calls == [(WorkItemFilter(repository_id=REPO_ID),)]


def test_next_with_nothing_pending_prints_null(doors: SimpleNamespace, home: Path) -> None:
    doors.next_pending.result = None
    assert run(remediation.next_, home, "--repo-url", REPO) == (0, None)


def test_next_of_an_unregistered_repository_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(remediation.next_, home, "--repo-url", "https://github.com/example-org/unknown")
    assert rc == 2 and "not registered" in err
    assert doors.next_pending.calls == []


def test_prepare_is_one_door_call(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    assert run(remediation.prepare, home, str(ITEM_ID)) == (0, {"fix_branch": "b"})
    assert doors.prepare.calls == [(ITEM_ID,)]
    out = tmp_path / "in.json"
    assert run(remediation.prepare, home, str(ITEM_ID), "-o", str(out)) == (0, "")
    assert json.loads(out.read_text()) == {"fix_branch": "b"}


def test_prepare_of_an_unknown_work_item_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.prepare.result = NotFoundError(f"work item {ITEM_ID}")
    rc, err = run(remediation.prepare, home, str(ITEM_ID))
    assert rc == 2 and str(ITEM_ID) in err


def test_prepare_needs_a_work_item_id(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit):
        run(remediation.prepare, home, "not-a-uuid")
