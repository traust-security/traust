"""`--branch` on every door that records a scanned commit: the CLI layer. A named branch is
registered as that branch, no branch as the bare commit (never guessed from the sha); core puts
a branch named like the forge-observed default branch on the default line."""

from __future__ import annotations

import contextlib
import io
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import TraustError
from traust_core.v1.models.assessment import AssessmentFilter
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_assessment_record import PRIV_PROFILE, document
from tests.test_cloud_config_doors import a_report
from tests.test_products_doors import _postgres
from traust.cli import (
    assessment_record,
    check_fix_propagation,
    cloud_config,
    crypto,
    image,
    impact,
    triage,
)

SHA, HEAD = "a" * 40, "b" * 40
URL = "https://github.com/example/widget-operator"
DIGEST = "quay.io/example/widget@sha256:" + "c" * 64


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


def run(door: Any, home: Path, *argv: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = door(["--config-home", str(home), *argv])
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue() + err.getvalue()


def observed_default(home: Path, branch: str) -> None:
    """Setup: what `traust portfolio observe` keeps, the forge's default branch at its head."""
    core = Context.from_file(home / "traust.yaml")
    url = HttpsRepoUrl.parse(URL, core.config.forge_hosts)
    repo = core.services().portfolio.register_repository(url, False)
    with SqlTraustUnitOfWork(core.database) as uow:
        uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id, name=branch, kind="branch", is_default=True, sha=HEAD
            )
        )
        uow.commit()


@pytest.mark.parametrize(
    ("branch", "ref", "default_line"),
    [
        (["--branch", "main"], ("main", "branch"), True),
        (["--branch", "feature"], ("feature", "branch"), False),
        ([], (None, None), False),
    ],
    ids=["default-branch", "other-branch", "no-branch-bare"],
)
def test_on_core_the_named_branch_decides_the_default_line(
    home: Path,
    tmp_path: Path,
    branch: list[str],
    ref: tuple[str | None, str | None],
    default_line: bool,
) -> None:
    observed_default(home, "main")
    path = str(document(tmp_path, PRIV_PROFILE))
    argv = ("--kind", "priv_profile", "--repo-url", URL, "--sha", SHA, *branch)
    rc, out = run(assessment_record.main, home, path, *argv)
    assert rc == 0, out
    services = Context.from_file(home / "traust.yaml").services()
    repo = services.portfolio.find_repository(HttpsRepoUrl.parse(URL, ("github.com",)))
    [recorded] = [r for r in services.portfolio.inventory.list_refs(repo.id) if r.sha == SHA]
    assert (recorded.name, recorded.kind, recorded.is_default) == (*ref, False)
    seen = services.assessment.privileges(AssessmentFilter(), [repo.id])
    assert [p.repository_id for p in seen] == ([repo.id] if default_line else [])


class Refused(TraustError):
    pass


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str | None]]:
    """Each door's register_commit call (sha, branch); the door stops there."""
    calls: list[tuple[str, str | None]] = []

    def register_commit(services: Any, repository_id: Any, sha: str, branch: str | None) -> Any:
        calls.append((sha, branch))
        raise Refused("stop")

    for door in (
        assessment_record,
        check_fix_propagation,
        cloud_config,
        crypto,
        image,
        impact,
        triage,
    ):
        monkeypatch.setattr(door, "register_commit", register_commit)
    advisory = SimpleNamespace(advisory_id="GHSA-xxxx-xxxx-xxxx")
    monkeypatch.setattr(impact, "_advisory", lambda services, identifier: advisory)
    return calls


def doors(tmp_path: Path) -> list[tuple[Any, list[str]]]:
    commit = ["--repo-url", URL, "--sha", SHA]
    return [
        (
            assessment_record.main,
            [str(document(tmp_path, PRIV_PROFILE)), "--kind", "priv_profile", *commit],
        ),
        (
            check_fix_propagation.main,
            [*commit, "--ecosystem", "go", "--module", "golang.org/x/net", "--fixed-version", "v1"],
        ),
        (cloud_config.record, [str(a_report(tmp_path)), *commit]),
        (crypto.source, [str(tmp_path), *commit]),
        (image.sbom, [DIGEST, "--sbom", str(tmp_path / "image.cdx.json"), *commit]),
        (impact.sbom, [str(tmp_path / "app.cdx.json"), *commit]),
        (impact.analyze, ["GHSA-xxxx-xxxx-xxxx", *commit]),
        (
            triage.intake,
            [str(tmp_path / "scan.sarif"), "--format", "sarif", *commit],
        ),
    ]


@pytest.mark.parametrize("branch", ["main", None], ids=["branch", "no-branch"])
def test_every_recording_door_passes_its_branch_or_none(
    spy: list[tuple[str, str | None]], tmp_path: Path, branch: str | None
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    named = ["--branch", branch] if branch else []
    for door, argv in doors(tmp_path):
        rc, out = run(door, home, *argv, *named)
        assert (rc, out.strip()) == (2, "ERROR: stop"), door
    assert spy == [(SHA, branch)] * 8


@pytest.mark.parametrize(
    ("door", "argv"),
    [
        (image.sbom, [DIGEST, "--sbom", "image.cdx.json"]),
        (impact.analyze, ["GHSA-xxxx-xxxx-xxxx"]),
    ],
)
def test_a_branch_without_the_commit_is_a_usage_error(
    spy: list[tuple[str, str | None]], tmp_path: Path, door: Any, argv: list[str]
) -> None:
    rc, out = run(door, tmp_path, *argv, "--branch", "main")
    assert rc == 2 and "--branch" in out
    assert spy == []
