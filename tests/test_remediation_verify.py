"""`traust remediation verify-*`: the CLI layer only. Arguments become one door call; the answer
is printed as JSON; a typed error is exit 2. The doors themselves are traust-core's tests."""

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
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.common import ArtifactRef, Page
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.remediation import (
    EvidenceItem,
    SweepEntry,
    Verification,
    VerificationFilter,
    VerifySweep,
)
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import SourceType

from traust.cli import remediation

FIXTURE = Path(__file__).parent / "fixtures" / "remediation" / "verification-report.json"
REPO = "https://github.com/example-org/example-service"
OTHER = "https://github.com/example-org/other-service"
REPO_ID, OTHER_ID, REF_ID, ITEM_ID = (uuid.uuid4() for _ in range(4))
SHA = "89abcdef0123456789abcdef0123456789abcdef"
SWEEP = VerifySweep.of(
    [
        SweepEntry(repository_id=REPO_ID, head_sha=SHA, open_findings=1, criticals=1),
        SweepEntry(repository_id=OTHER_ID),
    ]
)
EVIDENCE = EvidenceItem(
    kind="scanner_differential", outcome="not_attempted: no scanner backed these findings"
)
VERIFICATION = Verification(
    verification_id=uuid.uuid4(),
    repository_ref_id=REF_ID,
    verified_at=datetime(2026, 10, 24, tzinfo=UTC),
    verdicts=(),
    artifact=ArtifactRef(id=uuid.uuid4(), name="remediation-verification", digest="0" * 64),
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


def _repo(id: uuid.UUID, url: str) -> SimpleNamespace:
    return SimpleNamespace(id=id, url=url)


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repos = {REPO: _repo(REPO_ID, REPO), OTHER: _repo(OTHER_ID, OTHER)}
    stub = SimpleNamespace(
        sweep=Door(SWEEP),
        prepare=Door(SimpleNamespace(model_dump_json=lambda indent: '{"work_item": "w"}')),
        differential=Door(EVIDENCE),
        record=Door(VERIFICATION),
        list=Door(Page(items=(VERIFICATION,))),
        list_repositories=Door(Page(items=tuple(repos.values()))),
        find_product=Door(SimpleNamespace(id=uuid.uuid4())),
        list_product_refs=Door([SimpleNamespace(repository_id=OTHER_ID)]),
        get_repository=Door(repos[OTHER]),
        register_ref=Door(SimpleNamespace(id=REF_ID)),
    )
    stub.find_repository = lambda url: stub.find_repository_calls.append(url) or repos.get(str(url))
    stub.find_repository_calls = []
    services = SimpleNamespace(
        verification=SimpleNamespace(
            sweep=stub.sweep,
            prepare=stub.prepare,
            differential=stub.differential,
            record=stub.record,
            list=stub.list,
        ),
        portfolio=SimpleNamespace(
            find_repository=lambda url: repos.get(str(url)),
            list_repositories=stub.list_repositories,
            find_product=stub.find_product,
            list_product_refs=stub.list_product_refs,
            get_repository=stub.get_repository,
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


def test_sweep_defaults_to_every_registered_repository(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.verify_sweep, home)
    assert rc == 0
    assert doors.sweep.calls == [([REPO_ID, OTHER_ID],)]
    [(filter, _)] = doors.list_repositories.calls
    assert filter == RepositoryFilter()
    assert [(e["tier"], e["repository"]) for e in out["queued"]] == [("T2", REPO)]
    assert [(e["skip"], e["repository"]) for e in out["skipped"]] == [("unobserved", OTHER)]


def test_sweep_scopes_to_named_repositories_and_products(
    doors: SimpleNamespace, home: Path
) -> None:
    rc, _ = run(remediation.verify_sweep, home, "--repo-url", REPO, "--product", "example-product")
    assert rc == 0
    assert doors.sweep.calls == [([REPO_ID, OTHER_ID],)]
    assert doors.find_product.calls == [(ProductSlug("example-product"),)]
    assert doors.list_repositories.calls == []


def test_sweep_writes_out(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    doors.sweep.result = VerifySweep(queued=SWEEP.queued, skipped=())
    out = tmp_path / "sweep.json"
    rc, printed = run(remediation.verify_sweep, home, "--repo-url", REPO, "-o", str(out))
    assert (rc, printed) == (0, "")
    assert json.loads(out.read_text())["queued"][0]["repository"] == REPO


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--repo-url", "https://github.com/example-org/unknown"), "not registered"),
        (("--product", "unknown-product"), "not registered"),
    ],
)
def test_sweep_refuses_what_is_not_registered(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], reason: str
) -> None:
    doors.find_product.result = None
    rc, err = run(remediation.verify_sweep, home, *argv)
    assert rc == 2 and reason in err
    assert doors.sweep.calls == []


def test_prepare_is_one_door_call(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    rc, out = run(remediation.verify_prepare, home, str(ITEM_ID))
    assert (rc, out) == (0, {"work_item": "w"})
    assert doors.prepare.calls == [(ITEM_ID,)]
    target = tmp_path / "in.json"
    assert run(remediation.verify_prepare, home, str(ITEM_ID), "-o", str(target))[0] == 0
    assert json.loads(target.read_text()) == {"work_item": "w"}


def test_prepare_of_an_unknown_work_item_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.prepare.result = NotFoundError("work item not found")
    rc, err = run(remediation.verify_prepare, home, str(ITEM_ID))
    assert rc == 2 and "work item not found" in err


def test_differential_registers_the_patched_commit_and_compares(
    doors: SimpleNamespace, home: Path
) -> None:
    rc, out = run(
        remediation.verify_differential, home, str(ITEM_ID), "--repo-url", REPO, "--sha", SHA
    )
    assert (rc, out) == (0, EVIDENCE.model_dump(mode="json"))
    [(repository_id, sha, name, kind)] = doors.register_ref.calls
    assert (repository_id, str(sha), name, kind) == (REPO_ID, SHA, None, None)
    assert doors.differential.calls == [(ITEM_ID, REF_ID)]


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--repo-url", "https://github.com/example-org/unknown", "--sha", SHA), "not registered"),
        (("--repo-url", REPO, "--sha", "not-a-sha"), "sha"),
    ],
)
def test_differential_refuses_before_the_door(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], reason: str
) -> None:
    rc, err = run(remediation.verify_differential, home, str(ITEM_ID), *argv)
    assert rc == 2 and reason in err.lower()
    assert doors.differential.calls == []


def test_differential_refusal_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.differential.result = ValidationError("is the work item's own commit")
    rc, err = run(
        remediation.verify_differential, home, str(ITEM_ID), "--repo-url", REPO, "--sha", SHA
    )
    assert rc == 2 and "own commit" in err


def test_record_parses_the_report_and_records_it(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    report = tmp_path / "v.json"
    report.write_text(FIXTURE.read_text().replace("FINDING_ID", str(uuid.uuid4())))
    rc, out = run(remediation.verify_record, home, str(report))
    assert (rc, out) == (0, VERIFICATION.model_dump(mode="json"))
    [(doc, provenance)] = doors.record.calls
    assert isinstance(doc, VerificationArtifact)
    assert provenance.source is SourceType.VERIFICATION_REPORT


def test_record_refusals_are_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    report = tmp_path / "v.json"
    report.write_text("{}")
    rc, _ = run(remediation.verify_record, home, str(report))
    assert rc == 2 and doors.record.calls == []
    report.write_text(FIXTURE.read_text().replace("FINDING_ID", str(uuid.uuid4())))
    doors.record.result = ValidationError("covers findings of several repositories")
    rc, err = run(remediation.verify_record, home, str(report))
    assert rc == 2 and "several repositories" in err
    assert run(remediation.verify_record, home, str(tmp_path / "missing.json"))[0] == 2


def test_verifications_lists_one_repository(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.verifications, home, "--repo-url", REPO, "--work-item", str(ITEM_ID))
    assert (rc, out) == (0, [VERIFICATION.model_dump(mode="json")])
    [(wanted, _)] = doors.list.calls
    assert wanted == VerificationFilter(repository_id=REPO_ID, work_item_id=ITEM_ID)
