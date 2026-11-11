"""`traust portfolio dependencies|dependents`: the CLI layer only. Arguments become the door call;
the answer is printed as JSON; a typed error is exit 2 with its reason. The SBOM walk itself is
traust-core's tests."""

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
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.dependencies import (
    Dependency,
    NoManifestSbomError,
    Package,
    RefDependency,
)
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli import portfolio_dependencies

REPO_URL = "https://github.com/example-org/app"
SHA = "a" * 40
REPO = Repository(id=uuid.uuid4(), url=REPO_URL, public=True)
REF = RepositoryRef(id=uuid.uuid4(), repository_id=REPO.id, sha=SHA)
PACKAGE = Package(id=uuid.uuid4(), ecosystem="golang", name="golang.org/x/net")


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


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        find_repository=Door(REPO),
        find_ref=Door(REF),
        resolve=Door((REF, REPO)),
        dependencies=Door([]),
        dependents=Door([]),
    )
    services = SimpleNamespace(
        portfolio=SimpleNamespace(
            find_repository=stub.find_repository,
            inventory=SimpleNamespace(find_ref=stub.find_ref, resolve=stub.resolve),
        ),
        exposure=SimpleNamespace(dependencies=stub.dependencies, dependents=stub.dependents),
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


def deps(home: Path, *argv: str) -> tuple[int, Any]:
    return run(portfolio_dependencies.dependencies, home, *argv)


def dependents(home: Path, *argv: str) -> tuple[int, Any]:
    return run(portfolio_dependencies.dependents, home, *argv)


def test_dependencies_reads_the_commits_manifest_sbom(doors, home):
    dependency = Dependency(
        sbom_id=uuid.uuid4(), package_id=PACKAGE.id, version="v0.1.0", direct=True
    )
    doors.dependencies.result = [RefDependency(dependency=dependency, package=PACKAGE)]

    rc, out = deps(home, "--repo-url", REPO_URL + ".git", "--sha", SHA)

    assert rc == 0
    assert out == [
        {
            "package_id": str(PACKAGE.id),
            "ecosystem": "golang",
            "name": "golang.org/x/net",
            "version": "v0.1.0",
            "direct": True,
        }
    ]
    assert str(doors.find_repository.calls[0][0]) == REPO_URL
    assert doors.find_ref.calls == [(REPO.id, SHA)]
    assert doors.dependencies.calls == [(REF.id,)]


def test_dependencies_of_a_commit_with_no_packages_is_empty(doors, home):
    assert deps(home, "--repo-url", REPO_URL, "--sha", SHA) == (0, [])


def test_dependencies_of_an_unregistered_repository_is_refused(doors, home):
    doors.find_repository.result = None

    rc, err = deps(home, "--repo-url", REPO_URL, "--sha", SHA)

    assert rc == 2
    assert "not a registered repository" in err
    assert doors.find_ref.calls == doors.dependencies.calls == []


def test_dependencies_refuses_a_host_that_is_not_allowed(doors, home):
    rc, err = deps(home, "--repo-url", "https://evil.example/org/app", "--sha", SHA)

    assert rc == 2
    assert "ERROR" in err
    assert doors.find_repository.calls == []


@pytest.mark.parametrize(
    ("door", "error"),
    [
        ("find_ref", ValidationError(f"commit {SHA} has 0 registered refs")),
        ("dependencies", NoManifestSbomError(REF.id)),
    ],
)
def test_dependencies_door_refusals_exit_2_with_the_reason(doors, home, door, error):
    getattr(doors, door).result = error

    rc, err = deps(home, "--repo-url", REPO_URL, "--sha", SHA)

    assert rc == 2
    assert str(error) in err


def test_dependents_lists_each_commit_the_package_reaches(doors, home):
    doors.dependents.result = [REF.id]

    rc, out = dependents(home, "--package-id", str(PACKAGE.id))

    assert rc == 0
    assert out == [{"repository_ref_id": str(REF.id), "repository": REPO_URL, "sha": SHA}]
    assert doors.dependents.calls == [(PACKAGE.id,)]
    assert doors.resolve.calls == [(REF.id,)]


def test_dependents_of_a_package_nothing_holds_is_empty(doors, home):
    assert dependents(home, "--package-id", str(PACKAGE.id)) == (0, [])
    assert doors.resolve.calls == []


def test_dependents_of_an_unknown_package_exits_2(doors, home):
    doors.dependents.result = NotFoundError(f"package {PACKAGE.id} not found")

    rc, err = dependents(home, "--package-id", str(PACKAGE.id))

    assert rc == 2
    assert "not found" in err


def test_dependents_needs_a_package_uuid(doors, home):
    with pytest.raises(SystemExit) as exc:
        dependents(home, "--package-id", "golang.org/x/net")

    assert exc.value.code == 2
    assert doors.dependents.calls == []


@pytest.fixture
def find_package(doors: SimpleNamespace) -> Door:
    door = Door(PACKAGE)
    Context.services(None).exposure.find_package = door  # type: ignore[arg-type]
    return door


def test_dependents_by_name_finds_the_package_then_walks_from_it(doors, home, find_package):
    doors.dependents.result = [REF.id]

    rc, out = dependents(home, "--name", "golang.org/x/net")

    assert rc == 0
    assert out == [{"repository_ref_id": str(REF.id), "repository": REPO_URL, "sha": SHA}]
    assert find_package.calls == [(Ecosystem.GO, "golang.org/x/net")]
    assert doors.dependents.calls == [(PACKAGE.id,)]


def test_dependents_ecosystem_and_version_go_to_the_doors(doors, home, find_package):
    argv = ("--name", "Left-Pad", "--ecosystem", "npm", "--version", "1.3.0")

    assert dependents(home, *argv) == (0, [])
    assert find_package.calls == [(Ecosystem.NPM, "Left-Pad")]
    assert doors.dependents.calls == [(PACKAGE.id, "1.3.0")]


def test_dependents_of_an_unknown_name_exits_2_and_walks_nothing(doors, home, find_package):
    find_package.result = None

    rc, err = dependents(home, "--name", "left-pad", "--ecosystem", "npm")

    assert rc == 2
    assert "no npm package named left-pad" in err
    assert doors.dependents.calls == []


@pytest.mark.parametrize(
    "argv",
    [
        (),
        ("--name", "x", "--package-id", str(PACKAGE.id)),
        ("--name", "x", "--ecosystem", "golang"),
    ],
)
def test_dependents_needs_one_package_and_a_known_ecosystem(doors, home, find_package, argv):
    with pytest.raises(SystemExit) as exc, contextlib.redirect_stderr(io.StringIO()):
        dependents(home, *argv)

    assert exc.value.code == 2
    assert find_package.calls == doors.dependents.calls == []
