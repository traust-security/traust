"""`traust portfolio population`: the CLI layer only. The registered repositories and the arguments
become one `population` call; the answer is printed as JSON with repository URLs; a typed error is
exit 2 with its reason. Counting itself is traust-core's tests."""

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
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    Population,
    PopulationRow,
)
from traust_core.v1.models.common import Cursor, Page
from traust_core.v1.models.inventory import Repository

from traust.cli import portfolio_population

AUDITED = Repository(id=uuid.uuid4(), url="https://github.com/example-org/audited", public=True)
NEVER = Repository(id=uuid.uuid4(), url="https://github.com/example-org/never", public=True)
WHEN = datetime(2026, 10, 1, tzinfo=UTC)
LATEST = Assessment(
    id=uuid.uuid4(),
    repository_ref_id=uuid.uuid4(),
    kind="secure-code",
    status="completed",
    assessor="secure-code-audit",
    assessor_version="1",
    occurred_at=WHEN,
)


class Door:
    """Records each call; answers with `result`, or raises it when it is an exception."""

    def __init__(self, result: Any = None) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _pages(*pages: tuple[Repository, ...]) -> Any:
    """`list_repositories` answering page after page, following the cursor."""

    def door(_filter: Any, page: Any) -> Page[Repository]:
        index = 0 if page.cursor is None else int(page.cursor)
        last = index == len(pages) - 1
        return Page(items=pages[index], next=None if last else Cursor(str(index + 1)))

    return door


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        list_repositories=_pages((AUDITED,), (NEVER,)),
        population=Door(
            Population(
                as_of=WHEN,
                rows=(
                    PopulationRow(
                        repository_id=AUDITED.id,
                        kind="secure-code",
                        latest=LATEST,
                        default_line=2,
                        branches=1,
                    ),
                ),
                never_assessed_repository_ids=(NEVER.id,),
            )
        ),
    )
    services = SimpleNamespace(
        portfolio=SimpleNamespace(list_repositories=lambda f, p: stub.list_repositories(f, p)),
        assessment=SimpleNamespace(population=stub.population),
    )
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
        rc = portfolio_population.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_population_over_every_registered_repository(doors, home):
    rc, out = run(home, "--kind", "secure-code", "--as-of", "2026-10-01T00:00:00+00:00")

    assert rc == 0
    assert out == {
        "as_of": WHEN.isoformat(),
        "repositories": 2,
        "rows": [
            {
                "repository": AUDITED.url,
                "kind": "secure-code",
                "latest": {
                    "assessment_id": str(LATEST.id),
                    "status": "completed",
                    "occurred_at": WHEN.isoformat(),
                },
                "default_line": 2,
                "branches": 1,
            }
        ],
        "never_assessed": [NEVER.url],
    }
    [(as_of, filter, ids)] = doors.population.calls
    assert as_of == WHEN
    assert filter == AssessmentFilter(kind=AssessmentKind.SECURE_CODE)
    assert ids == [AUDITED.id, NEVER.id]


def test_population_defaults_to_now_any_kind_and_reads_naive_as_utc(doors, home):
    run(home)
    run(home, "--as-of", "2026-10-01T00:00:00", "--status", "completed")

    (now, any_kind, _), (naive, completed, _) = doors.population.calls
    assert now.tzinfo is not None and any_kind == AssessmentFilter()
    assert naive == WHEN and completed == AssessmentFilter(status="completed")


def test_population_of_an_empty_inventory(doors, home):
    doors.list_repositories = _pages(())
    doors.population.result = Population(as_of=WHEN)

    rc, out = run(home)

    assert rc == 0
    assert out["repositories"] == 0 and out["rows"] == [] and out["never_assessed"] == []
    assert doors.population.calls[0][2] == []


def test_population_refusal_exits_2_with_the_reason(doors, home):
    doors.population.result = ValidationError("as_of must be timezone-aware")

    rc, err = run(home)

    assert rc == 2
    assert "as_of must be timezone-aware" in err


@pytest.mark.parametrize("argv", [("--kind", "bogus"), ("--as-of", "yesterday")])
def test_population_refuses_bad_arguments_before_any_door(doors, home, argv):
    with pytest.raises(SystemExit) as exc:
        run(home, *argv)

    assert exc.value.code == 2
    assert doors.population.calls == []
