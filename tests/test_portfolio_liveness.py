"""`traust portfolio liveness`: the CLI layer only. Every page of `liveness` becomes one
repo-liveness document keyed by URL, with the artifact's status words and their counts; a typed
error is exit 2 with its reason. What liveness reads is traust-core's tests."""

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
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import Cursor, Page
from traust_core.v1.models.inventory import Liveness, RepositoryFilter
from traust_core.v1.models.vocabulary import LivenessStatus

from traust.cli import portfolio_liveness

WHEN = datetime(2026, 10, 1, tzinfo=UTC)
ACTIVE = Liveness(
    repository_id=uuid.uuid4(),
    url="https://github.com/example-org/active",
    status=LivenessStatus.ACTIVE,
    observed_at=WHEN,
    status_since=WHEN,
    archived=False,
    pushed_at="2026-09-30T12:00:00Z",
    dormant=False,
)
ARCHIVED = Liveness(
    repository_id=uuid.uuid4(),
    url="https://github.com/example-org/archived",
    status=LivenessStatus.ARCHIVED,
    observed_at=WHEN,
    status_since=WHEN,
    archived=True,
    pushed_at="2024-01-02T00:00:00Z",
    dormant=True,
)
NEVER = Liveness(
    repository_id=uuid.uuid4(),
    url="https://gitlab.com/example-org/never",
    unobserved="unsupported-host",
    reason="no forge observes this host",
)


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    pages = [(ARCHIVED, NEVER), (ACTIVE,)]
    stub = SimpleNamespace(calls=[], result=None)

    def liveness(filter: Any, page: Any) -> Page[Liveness]:
        stub.calls.append((filter, page.cursor))
        if isinstance(stub.result, Exception):
            raise stub.result
        index = 0 if page.cursor is None else int(page.cursor)
        last = index == len(pages) - 1
        return Page(items=pages[index], next=None if last else Cursor(str(index + 1)))

    services = SimpleNamespace(portfolio=SimpleNamespace(liveness=liveness))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = portfolio_liveness.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_liveness_of_every_registered_repository_keyed_by_url(doors, home):
    rc, out = run(home)

    assert rc == 0
    assert out == {
        "counts": {"active": 1, "archived": 1, "unknown": 1},
        "repos": {
            ACTIVE.url: {
                "status": "active",
                "observed_at": WHEN.isoformat().replace("+00:00", "Z"),
                "status_since": WHEN.isoformat().replace("+00:00", "Z"),
                "archived": False,
                "pushed_at": "2026-09-30T12:00:00Z",
                "dormant": False,
            },
            ARCHIVED.url: {
                "status": "archived",
                "observed_at": WHEN.isoformat().replace("+00:00", "Z"),
                "status_since": WHEN.isoformat().replace("+00:00", "Z"),
                "archived": True,
                "pushed_at": "2024-01-02T00:00:00Z",
                "dormant": True,
            },
            NEVER.url: {
                "status": "unknown",
                "unobserved": "unsupported-host",
                "reason": "no forge observes this host",
            },
        },
    }
    assert doors.calls == [(RepositoryFilter(), None), (RepositoryFilter(), "1")]


def test_liveness_refusal_exits_2_with_the_reason(doors, home):
    doors.result = ConfigError("liveness reads observations through AssessmentService")

    rc, err = run(home)

    assert rc == 2
    assert "liveness reads observations through AssessmentService" in err


def test_liveness_serializes_moved_missing_disabled_and_unknown_without_rederiving_status(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    statuses = (
        LivenessStatus.MOVED,
        LivenessStatus.MISSING,
        LivenessStatus.DISABLED,
        LivenessStatus.UNKNOWN,
    )
    rows = tuple(
        Liveness(
            repository_id=uuid.uuid4(),
            url=f"https://github.com/example-org/{status}",
            status=status,
            observed_at=WHEN,
            status_since=WHEN,
            canonical_url="https://github.com/example-org/new-name"
            if status == LivenessStatus.MOVED
            else None,
            archived=False if status == LivenessStatus.MOVED else None,
            unobserved="no-credentials" if status == LivenessStatus.UNKNOWN else None,
        )
        for status in statuses
    )
    service = SimpleNamespace(liveness=lambda filter, page: Page(items=rows))
    monkeypatch.setattr(Context, "services", lambda self: SimpleNamespace(portfolio=service))
    rc, out = run(home)
    assert rc == 0
    assert out["counts"] == {"disabled": 1, "missing": 1, "moved": 1, "unknown": 1}
    assert len(out["repos"]) == 4
    for row in rows:
        exported = out["repos"][row.url]
        assert exported["status"] == row.status.value
        assert exported["status_since"] == WHEN.isoformat().replace("+00:00", "Z")
        assert exported["observed_at"] == WHEN.isoformat().replace("+00:00", "Z")
        assert "repository_id" not in exported
    moved = out["repos"][rows[0].url]
    assert moved["canonical_url"] == "https://github.com/example-org/new-name"
    assert moved["archived"] is False
    assert out["repos"][rows[-1].url]["unobserved"] == "no-credentials"
