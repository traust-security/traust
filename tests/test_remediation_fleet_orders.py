"""`traust remediation fleet-submit|fleet-approve|fleet-claim`: the CLI layer only. Each is one
door call on a Context carrying traust-engine's applier; the caller is the stored login. The
doors, the approval gate and the order lifecycle are traust-core's tests, the applier
traust-engine's."""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import (
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
)
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.operations import OrderState, RunOrder
from traust_core.v1.models.remediation import FleetFixRun, PatchResult
from traust_core.v1.models.vocabulary import ActorKind

from tests.test_remediation_fleet import REPO, REPO_ID, Door, run
from traust.cli import remediation

FIX_ID, ORDER_ID, REF_ID, ASSESSMENT_ID = (uuid.uuid4() for _ in range(4))
CALLER = Principal(
    identity="lead@example.com",
    kind=ActorKind.HUMAN,
    display="lead",
    verified_by=IdentitySource.OIDC,
)
WHEN = datetime(2026, 10, 26, 9, tzinfo=UTC)
ORDER = RunOrder(
    id=ORDER_ID,
    asset="fleet-fix",
    repository_id=REPO_ID,
    state=OrderState.AWAITING_APPROVAL,
    priority=0,
    requested_by=CALLER.ref,
    created_at=WHEN,
    updated_at=WHEN,
)
RUN = FleetFixRun(
    order=ORDER.model_copy(update={"state": OrderState.SUCCEEDED}),
    patch=PatchResult(
        files_changed=(".tekton/push.yaml",),
        diff="--- a/.tekton/push.yaml\n+++ b/.tekton/push.yaml\n",
        fleet_fix_id=FIX_ID,
        repository_ref_id=REF_ID,
        assessment_id=ASSESSMENT_ID,
    ),
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", config)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        submit=Door([ORDER]),
        approve=Door(ORDER.model_copy(update={"state": OrderState.QUEUED})),
        claim=Door(RUN),
        callers=[],
        wired=[],
    )
    services = SimpleNamespace(
        remediation=SimpleNamespace(
            submit_fleet_fix=stub.submit,
            approve_fleet_fix=stub.approve,
            claim_fleet_fix=stub.claim,
        ),
        portfolio=SimpleNamespace(
            find_repository=lambda url: SimpleNamespace(id=REPO_ID) if str(url) == REPO else None
        ),
    )

    def wired(self: Context) -> SimpleNamespace:
        stub.wired.append(self.fleet_fix_applier is not None)
        return services

    def caller(core: Context) -> Principal:
        stub.callers.append(core)
        if isinstance(stub.caller, Exception):
            raise stub.caller
        return stub.caller

    stub.caller = CALLER
    monkeypatch.setattr(Context, "services", wired)
    monkeypatch.setattr(remediation, "load_caller", caller)
    return stub


def test_submit_names_the_targets_and_the_caller(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.fleet_submit, home, str(FIX_ID), "--repo-url", REPO)
    assert (rc, out) == (0, [ORDER.model_dump(mode="json")])
    assert doors.submit.calls == [(FIX_ID, [REPO_ID], CALLER)]


def test_submit_reads_fleet_targets_json(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    fleet = tmp_path / "fleet.json"
    fleet.write_text(json.dumps([{"repository_id": str(REPO_ID), "url": REPO}]))
    assert run(remediation.fleet_submit, home, str(FIX_ID), "--fleet", str(fleet))[0] == 0
    assert doors.submit.calls == [(FIX_ID, [REPO_ID], CALLER)]


@pytest.mark.parametrize(
    "argv",
    [(), ("--repo-url", REPO, "--fleet", "fleet.json")],
    ids=["no-targets", "both"],
)
def test_submit_needs_one_kind_of_target(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...]
) -> None:
    with pytest.raises(SystemExit):
        run(remediation.fleet_submit, home, str(FIX_ID), *argv)
    assert doors.submit.calls == []


@pytest.mark.parametrize("body", ["not json", '[{"url": "x"}]', '{"repository_id": 1}'])
def test_submit_refuses_a_fleet_file_that_is_not_fleet_targets(
    doors: SimpleNamespace, home: Path, tmp_path: Path, body: str
) -> None:
    fleet = tmp_path / "fleet.json"
    fleet.write_text(body)
    rc, err = run(remediation.fleet_submit, home, str(FIX_ID), "--fleet", str(fleet))
    assert rc == 2 and "not fleet-targets JSON" in err
    assert doors.submit.calls == []


def test_submit_refusals_are_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(
        remediation.fleet_submit, home, str(FIX_ID), "--repo-url", "https://github.com/x/unknown"
    )
    assert rc == 2 and "not registered" in err
    doors.submit.result = ConflictError("has open fleet-fix order for another fix")
    rc, err = run(remediation.fleet_submit, home, str(FIX_ID), "--repo-url", REPO)
    assert rc == 2 and "for another fix" in err


def test_approve_is_the_caller_s_door_call_per_order(doors: SimpleNamespace, home: Path) -> None:
    second = uuid.uuid4()
    rc, out = run(remediation.fleet_approve, home, str(ORDER_ID), str(second))
    assert rc == 0 and [o["state"] for o in out] == ["queued", "queued"]
    assert doors.approve.calls == [(ORDER_ID, CALLER), (second, CALLER)]
    assert len(doors.callers) == 1


@pytest.mark.parametrize(
    "refusal",
    [
        AuthenticationError("not logged in: run `traust auth login` or `traust auth local`"),
        ForbiddenError(f"order {ORDER_ID}: approval needs a verified human, not machine:engine"),
    ],
    ids=["not-logged-in", "not-a-verified-human"],
)
def test_approve_refusals_are_exit_2(
    doors: SimpleNamespace, home: Path, refusal: Exception
) -> None:
    if isinstance(refusal, AuthenticationError):
        doors.caller = refusal
    else:
        doors.approve.result = refusal
    rc, err = run(remediation.fleet_approve, home, str(ORDER_ID))
    assert rc == 2 and str(refusal) in err
    if isinstance(refusal, AuthenticationError):
        assert doors.approve.calls == []


def test_approve_needs_an_order(doors: SimpleNamespace, home: Path) -> None:
    for argv in ((), ("not-a-uuid",)):
        with pytest.raises(SystemExit):
            run(remediation.fleet_approve, home, *argv)
    assert doors.approve.calls == []


def test_claim_is_one_door_call_through_the_engine_applier(
    doors: SimpleNamespace, home: Path
) -> None:
    rc, out = run(remediation.fleet_claim, home, "--worker", "w1", "--lease-minutes", "10")
    assert (rc, out) == (0, RUN.model_dump(mode="json"))
    assert doors.claim.calls == [("w1", timedelta(minutes=10))]
    assert doors.wired and all(doors.wired)
    assert doors.callers == []


def test_claim_with_nothing_approved_says_so(doors: SimpleNamespace, home: Path) -> None:
    doors.claim.result = None
    assert run(remediation.fleet_claim, home) == (0, {"claimed": None})
    [(worker, lease)] = doors.claim.calls
    assert ":" in worker and lease == timedelta(minutes=30)


def test_claim_writes_out(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    out = tmp_path / "run.json"
    assert run(remediation.fleet_claim, home, "-o", str(out)) == (0, "")
    assert json.loads(out.read_text())["patch"]["files_changed"] == [".tekton/push.yaml"]


@pytest.mark.parametrize(
    "refusal",
    [
        ForbiddenError(f"run order {ORDER_ID} has no human approval"),
        IntegrityError("fleet fix konflux changed files outside its file_glob: ['README.md']"),
        NotFoundError(f"repository {REPO_ID} has no default-branch commit recorded"),
    ],
)
def test_claim_refusals_are_exit_2(doors: SimpleNamespace, home: Path, refusal: Exception) -> None:
    doors.claim.result = refusal
    rc, err = run(remediation.fleet_claim, home)
    assert rc == 2 and str(refusal) in err
