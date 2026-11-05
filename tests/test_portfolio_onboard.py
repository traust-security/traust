"""`traust portfolio plan|onboard|owner-hints|import-owners`: the CLI layer only. Arguments become
one door call with the right request; the answer is printed as JSON; a typed error is exit 2 with
its reason. The doors themselves (forge parsing, dedupe, mirroring) are traust-core's tests."""

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
from traust_core.v1.errors import AuthenticationError, NotFoundError, ValidationError
from traust_core.v1.models.inventory import OwnerAssignment, OwnershipSource, SyncReport
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.onboarding import (
    Gap,
    OnboardingPlan,
    OnboardingRequest,
    OnboardingResult,
    RepositorySpec,
)
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug
from traust_core.v1.providers.sources import OwnerHint, OwnerOrigin, SourceError

from traust.cli import portfolio_onboard

REPO = "https://github.com/example-org/app"
URL = HttpsRepoUrl("github.com", "example-org/app")
CALLER = object()
PRODUCT_ID, REPO_ID = uuid.uuid4(), uuid.uuid4()


class Door:
    """Records each call; answers with `result`, or raises it when it is an exception."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result: Any = None

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(plan=Door(), onboard=Door(), owner_hints=Door(), import_owners=Door())
    services = SimpleNamespace(
        onboarding=SimpleNamespace(plan=stub.plan, onboard=stub.onboard),
        sync=SimpleNamespace(owner_hints=stub.owner_hints, import_owners=stub.import_owners),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    monkeypatch.setattr(portfolio_onboard, "load_caller", lambda core: CALLER)
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


def request(**fields: Any) -> OnboardingRequest:
    return OnboardingRequest(product=ProductSlug.parse("example"), **fields)


@pytest.mark.parametrize(
    "argv,expected",
    [
        (
            ("--repo", REPO),
            request(repositories=(RepositorySpec(url=URL),)),
        ),
        (
            ("--repo", REPO + ".git/", "--label", "Example"),
            request(label="Example", repositories=(RepositorySpec(url=URL),)),
        ),
        (("--org", "example-org"), request(org="example-org")),
        (
            ("--org", "grp/sub", "--host", "gitlab.com", "--repo", REPO),
            request(repositories=(RepositorySpec(url=URL),), org="grp/sub", host="gitlab.com"),
        ),
    ],
)
@pytest.mark.parametrize("command", ["plan", "onboard"])
def test_arguments_become_one_onboarding_request(
    home: Path, doors: SimpleNamespace, command: str, argv: tuple[str, ...], expected: Any
) -> None:
    door = getattr(doors, command)
    door.result = OnboardingPlan() if command == "plan" else OnboardingResult(product_id=PRODUCT_ID)
    rc, _ = run(getattr(portfolio_onboard, command), home, "--product", "example", *argv)
    assert rc == 0
    assert door.calls == [(expected,) if command == "plan" else (expected, CALLER)]


def test_plan_prints_urls_ids_and_gaps(home: Path, doors: SimpleNamespace) -> None:
    doors.plan.result = OnboardingPlan(
        new=(RepositorySpec(url=URL),),
        existing_repository_ids=(REPO_ID,),
        gaps=(Gap(subject="example", reason="product is not registered"),),
    )
    rc, out = run(portfolio_onboard.plan, home, "--product", "example", "--repo", REPO)
    assert (rc, out) == (
        0,
        {
            "new": [{"url": REPO, "refs": [], "team": None}],
            "existing_repository_ids": [str(REPO_ID)],
            "gaps": [{"subject": "example", "reason": "product is not registered"}],
            "orders": [],
        },
    )


def test_onboard_prints_the_result(home: Path, doors: SimpleNamespace) -> None:
    doors.onboard.result = OnboardingResult(product_id=PRODUCT_ID, repository_ids=(REPO_ID,))
    rc, out = run(portfolio_onboard.onboard, home, "--product", "example", "--repo", REPO)
    assert (rc, out) == (
        0,
        {"product_id": str(PRODUCT_ID), "repository_ids": [str(REPO_ID)], "order_ids": []},
    )


@pytest.mark.parametrize(
    "argv,reason",
    [
        (("--product", "example"), "--repo or --org"),
        (("--product", "example", "--repo", "https://example.com/a/b"), "host not allowed"),
        (("--product", "example", "--repo", "http://github.com/a/b"), "must be https"),
        (("--product", "not a slug", "--repo", REPO), "slug"),
    ],
)
@pytest.mark.parametrize("command", ["plan", "onboard"])
def test_bad_input_is_refused_before_any_door_call(
    home: Path, doors: SimpleNamespace, command: str, argv: tuple[str, ...], reason: str
) -> None:
    rc, err = run(getattr(portfolio_onboard, command), home, *argv)
    assert rc == 2 and reason in err, err
    assert doors.plan.calls == doors.onboard.calls == []


@pytest.mark.parametrize(
    "command,error",
    [
        ("plan", SourceError("HTTP 401: Bad credentials", ComparisonStatus.NO_CREDENTIALS)),
        ("plan", ValidationError("cannot list 'bad org' on 'github.com'")),
        ("onboard", ValidationError("example: product is not registered")),
        ("onboard", SourceError("HTTP 401: Bad credentials", ComparisonStatus.NO_CREDENTIALS)),
    ],
)
def test_a_door_refusal_is_exit_2_with_its_reason(
    home: Path, doors: SimpleNamespace, command: str, error: Exception
) -> None:
    getattr(doors, command).result = error
    rc, err = run(getattr(portfolio_onboard, command), home, "--product", "example", "--org", "o")
    assert rc == 2 and str(error) in err


def test_onboard_needs_a_login(
    home: Path, doors: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(core: Any) -> Any:
        raise AuthenticationError("not logged in: run `traust auth login` or `traust auth local`")

    monkeypatch.setattr(portfolio_onboard, "load_caller", refuse)
    rc, err = run(portfolio_onboard.onboard, home, "--product", "example", "--repo", REPO)
    assert rc == 2 and "traust auth" in err
    assert doors.onboard.calls == []


def test_owner_hints_asks_for_one_repository_and_prints_the_hints(
    home: Path, doors: SimpleNamespace
) -> None:
    doors.owner_hints.result = [
        OwnerHint(handle="alice", origin=OwnerOrigin.OWNERS_FILE, file="OWNERS"),
        OwnerHint(handle="bob", origin=OwnerOrigin.CONTRIBUTOR),
    ]
    rc, out = run(portfolio_onboard.owner_hints, home, "--repo", REPO)
    assert doors.owner_hints.calls == [(URL,)]
    assert (rc, out) == (
        0,
        [
            {"handle": "alice", "origin": "owners-file", "file": "OWNERS"},
            {"handle": "bob", "origin": "contributor", "file": None},
        ],
    )


@pytest.mark.parametrize(
    "repo,error,reason",
    [
        ("https://example.com/a/b", None, "host not allowed"),
        (
            REPO,
            SourceError("HTTP 401: Bad credentials", ComparisonStatus.NO_CREDENTIALS),
            "Bad credentials",
        ),
        (REPO, NotFoundError("no such repository"), "no such repository"),
    ],
)
def test_owner_hints_refusals_are_exit_2(
    home: Path, doors: SimpleNamespace, repo: str, error: Exception | None, reason: str
) -> None:
    doors.owner_hints.result = error
    rc, err = run(portfolio_onboard.owner_hints, home, "--repo", repo)
    assert rc == 2 and reason in err


def source(tmp_path: Path, doc: Any) -> str:
    path = tmp_path / "owners.yaml"
    path.write_text(yaml.safe_dump(doc))
    return str(path)


@pytest.mark.parametrize(
    "doc,expected",
    [
        ({}, OwnershipSource()),
        (
            {"segments": {"svc": {"kind": "services"}}, "org_teams": {"example-org": "Platform"}},
            OwnershipSource(org_teams={"example-org": "Platform"}),
        ),
        (
            {"assignments": [{"repo": REPO, "teams": ["Tools", "Platform"]}]},
            OwnershipSource(assignments=(OwnerAssignment(repo=URL, teams=("Tools", "Platform")),)),
        ),
    ],
)
def test_import_owners_reads_the_source_into_one_call(
    home: Path, tmp_path: Path, doors: SimpleNamespace, doc: Any, expected: OwnershipSource
) -> None:
    doors.import_owners.result = SyncReport(added=(REPO_ID,), skipped=("https://x/y/z",))
    rc, out = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, doc))
    assert doors.import_owners.calls == [(expected,)]
    assert (rc, out) == (
        0,
        {"added": [str(REPO_ID)], "unchanged": [], "removed": [], "skipped": ["https://x/y/z"]},
    )


@pytest.mark.parametrize(
    "doc,reason",
    [
        ({"assignments": [{"repo": REPO}]}, "not an ownership source"),
        ({"assignments": [{"repo": "https://example.com/a/b", "teams": ["T"]}]}, "host"),
        (["not", "a", "mapping"], "not an ownership source"),
        ("org_teams: {unclosed\n", "not an ownership source"),
        (None, "missing.yaml"),
    ],
)
def test_import_owners_refuses_a_bad_source_before_any_door_call(
    home: Path, tmp_path: Path, doors: SimpleNamespace, doc: Any, reason: str
) -> None:
    if doc is None:
        path = str(tmp_path / "missing.yaml")
    elif isinstance(doc, str):
        path = str(tmp_path / "broken.yaml")
        Path(path).write_text(doc)
    else:
        path = source(tmp_path, doc)
    rc, err = run(portfolio_onboard.import_owners, home, "--source", path)
    assert rc == 2 and reason in err, err
    assert doors.import_owners.calls == []


def test_import_owners_door_refusal_is_exit_2(
    home: Path, tmp_path: Path, doors: SimpleNamespace
) -> None:
    doors.import_owners.result = ValidationError("team.name must not be blank")
    rc, err = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, {}))
    assert rc == 2 and "team.name must not be blank" in err
