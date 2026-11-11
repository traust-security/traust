"""The git mirror cache's pack assets: `repo_checkout_refresh`'s and `mirror_evict`'s
materializers' answer to each door outcome, and both CLIs end to end on traust-core (SQLite)
with the forge stubbed and a local bare repository standing in for the remote — the disk-space
rule: never a real remote."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from traust_core.v1.context import observation
from traust_core.v1.errors import NotFoundError, ServiceError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers import mirror as core_mirror
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.observation import GITLEAKS

from traust.cli import portfolio_checkout, portfolio_observe
from traust.context import load
from traust.ops.materializers import (
    EVICT_IDLE_DAYS,
    MirrorEvictMaterializer,
    RepoCheckoutRefreshMaterializer,
)

REPO = "https://github.com/org/app"
HOSTS = ("github.com",)
SHA = "b" * 40
AUDITED = "a" * 40


class CleanGitleaks:
    """The scanner the observation requires over a changed repo's patch, finding nothing."""

    name = GITLEAKS

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def acquire(self, request: object) -> Result[AdapterResultArtifact]:
        return Result(
            AdapterResultArtifact.from_document(
                {
                    "target": "change",
                    "scanned_at": "2026-10-23T00:00:00Z",
                    "metadata": {"tool": GITLEAKS, "scanner_version": "8.30.0"},
                    "findings": [],
                }
            ),
            Acquisition(provider=self.name, acquired_at=datetime(2026, 10, 23, tzinfo=UTC)),
        )


class Checkouts:
    def __init__(self, outcome: Exception | None = None) -> None:
        self.outcome, self.refreshed, self.evicted = outcome, [], []

    def refresh(self, repo: HttpsRepoUrl, head: Any) -> None:
        self.refreshed.append((str(repo), str(head)))
        if self.outcome is not None:
            raise self.outcome

    def evict(self, idle_days: int) -> list[HttpsRepoUrl]:
        self.evicted.append(idle_days)
        if self.outcome is not None:
            raise self.outcome
        return [HttpsRepoUrl.parse(REPO, HOSTS)]


class States:
    """The Context's repo_state query: one repository's routing state, or no observation."""

    def __init__(self, push_changed: bool | None, observed: bool = True) -> None:
        self.push_changed, self.observed = push_changed, observed

    def repo_state(self, *, repository_id: UUID | None = None, repo_url: str | None = None) -> Any:
        if not self.observed:
            raise NotFoundError(f"no forge observation for {repo_url}; observe it first")
        return SimpleNamespace(repository_id=UUID(int=7), push_changed=self.push_changed)


class Portfolio:
    def __init__(self, head: str | None = SHA) -> None:
        self.head = head

    def default_ref(self, repository_id: UUID) -> Any:
        return None if self.head is None else SimpleNamespace(sha=self.head)


class Services:
    def __init__(self, checkouts: Checkouts, portfolio: Portfolio) -> None:
        self.checkouts, self.portfolio = checkouts, portfolio


def materialize(services: Services, states: States, partition: str = REPO) -> JobResult:
    materializer = RepoCheckoutRefreshMaterializer(services, states, HOSTS)  # type: ignore[arg-type]
    return materializer.materialize(
        AssetRequest(asset="repo_checkout_refresh", run_id=str(uuid4()), partition=partition)
    )


@pytest.mark.parametrize(
    ("push_changed", "want", "refreshed"),
    [
        (True, JobResult.succeeded(written=(SHA,)), [(REPO, SHA)]),
        (False, JobResult.succeeded(), []),
        (None, JobResult.succeeded(), []),
    ],
    ids=["moved head", "head unmoved since the audit", "no audit to compare against"],
)
def test_refresh_happens_only_on_a_moved_head(
    push_changed: bool | None, want: JobResult, refreshed: list[tuple[str, str]]
) -> None:
    checkouts = Checkouts()
    assert materialize(Services(checkouts, Portfolio()), States(push_changed)) == want
    assert checkouts.refreshed == refreshed


@pytest.mark.parametrize(
    ("states", "portfolio", "want"),
    [
        (States(True, observed=False), Portfolio(), JobResult.refused(OrderReason.NOT_FOUND)),
        (States(True), Portfolio(head=None), JobResult.refused(OrderReason.NOT_FOUND)),
    ],
    ids=["never observed", "no observed default head"],
)
def test_the_materializer_refuses_before_fetching(
    states: States, portfolio: Portfolio, want: JobResult
) -> None:
    checkouts = Checkouts()
    assert materialize(Services(checkouts, portfolio), states) == want
    assert checkouts.refreshed == []


@pytest.mark.parametrize(
    ("outcome", "want"),
    [
        (
            NotFoundError("commit e is not in the repo after refresh"),
            JobResult.refused(OrderReason.NOT_FOUND),
        ),
        (
            ServiceError("git exited 128: authentication failed"),
            JobResult.failed(OrderReason.SOURCE_UNAVAILABLE),
        ),
    ],
    ids=["head the forge no longer serves", "the fetch failed"],
)
def test_the_materializer_answers_each_refresh_outcome(outcome: Exception, want: JobResult) -> None:
    assert materialize(Services(Checkouts(outcome), Portfolio()), States(True)) == want


@pytest.mark.parametrize("push_changed", [False, None], ids=["head unmoved", "no audit"])
def test_a_headless_repository_at_rest_needs_no_fetch(push_changed: bool | None) -> None:
    checkouts = Checkouts()
    assert materialize(Services(checkouts, Portfolio(head=None)), States(push_changed)) == (
        JobResult.succeeded()
    )
    assert checkouts.refreshed == []


def test_an_unknown_host_is_a_bad_request() -> None:
    checkouts = Checkouts()
    result = materialize(Services(checkouts, Portfolio()), States(True), "https://x.io/a/b")
    assert result == JobResult.failed(OrderReason.BAD_REQUEST)
    assert checkouts.refreshed == []


def test_eviction_drops_idle_mirrors_and_records_them() -> None:
    checkouts = Checkouts()
    result = MirrorEvictMaterializer(Services(checkouts, Portfolio())).materialize(  # type: ignore[arg-type]
        AssetRequest(asset="mirror_evict", run_id=str(uuid4()))
    )
    assert result == JobResult.succeeded(written=(REPO,))
    assert checkouts.evicted == [EVICT_IDLE_DAYS]


def test_the_materializer_answers_an_eviction_failure() -> None:
    result = MirrorEvictMaterializer(
        Services(Checkouts(ServiceError("git exited 128")), Portfolio())  # type: ignore[arg-type]
    ).materialize(AssetRequest(asset="mirror_evict", run_id=str(uuid4())))
    assert result == JobResult.failed(OrderReason.SOURCE_UNAVAILABLE)


def git(repo: Path, *args: str) -> str:
    """Run git in a test repository; the identity is fixed so commits need no global config."""
    done = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


class Forge:
    """A local bare repository standing in for the forge at REPO, with a working clone."""

    def __init__(self, root: Path) -> None:
        self.bare = root / "forge" / "org" / "app.git"
        self.bare.mkdir(parents=True)
        git(self.bare, "init", "--bare", "-q")
        self.work = root / "work"
        self.work.mkdir()
        git(self.work, "init", "-q")

    def commit(self, name: str, content: bytes) -> str:
        (self.work / name).write_bytes(content)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "-m", name)
        sha = git(self.work, "rev-parse", "HEAD")
        git(self.work, "push", "-q", str(self.bare), "HEAD:refs/heads/main")
        return sha


@pytest.fixture
def lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A config home whose core answers the forge from `facts`, and whose git rewrites REPO to
    the local bare forge (`url.insteadOf` in the test HOME — only a test configures it). The
    fetch's https-only protocol guard is dropped for the same reason: git's file transport
    carries the local forge standing in for the https repository."""
    config = tmp_path / "config"
    config.mkdir()
    # the mirror's fetches run under the process policy, so the deployment allows git
    (config / "traust.yaml").write_text(
        yaml.safe_dump({"home": str(tmp_path / "store"), "process": {"allowed_binaries": ["git"]}})
    )
    forge = Forge(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".gitconfig").write_text(f'[url "{forge.bare}"]\n\tinsteadOf = {REPO}\n')
    monkeypatch.setattr(core_mirror, "_FETCH_ENV", {"GIT_TERMINAL_PROMPT": "0"})
    facts: dict[str, Any] = {
        "repos/org/app": {
            "pushed_at": "2026-10-01T00:00:00Z",
            "archived": False,
            "default_branch": "main",
            "visibility": "private",
            "fork": False,
        },
        "rate_limit": {"resources": {"core": {"remaining": 4000}}},
    }

    def get(host: str, endpoint: str, headers: Any = None) -> Any:
        return facts[endpoint]

    def stream(host: str, endpoint: str, consume: Any, headers: Any = None) -> Any:
        return consume(io.BytesIO(b"+++ b/x.py\n+x = 1\n"))

    wire = observation.command_source
    api = SimpleNamespace(get=get, stream=stream)
    monkeypatch.setattr(
        "traust_core.v1.context.context.command_source",
        lambda hosts, **kw: wire(hosts, **{**kw, "api": api}),
    )
    # A changed repository's observation scans its patch for secrets (gitleaks required,
    # core's fail-loud rule); the runner image's scanner is not this test's subject.
    real_load = portfolio_observe.load

    def load_with_scanner(config_home: Path | None) -> Any:
        core = real_load(config_home)
        core.tools = ProviderRegistry("tool")
        core.tools.register(CleanGitleaks.name, CleanGitleaks)
        return core

    monkeypatch.setattr(portfolio_observe, "load", load_with_scanner)
    return SimpleNamespace(config=config, forge=forge, facts=facts, store=tmp_path / "store")


def run(op: Any, config: Path, *args: str) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = op(["--config-home", str(config), *args])
    return rc, json.loads(out.getvalue())


def observe(
    lane: Any, head: str, files: list[dict[str, Any]], pushed: str, baseline: str = AUDITED
) -> None:
    lane.facts["repos/org/app"]["pushed_at"] = pushed
    lane.facts["repos/org/app/branches/main"] = {"commit": {"sha": head}}
    lane.facts[f"repos/org/app/compare/{baseline}...HEAD"] = {
        "ahead_by": len(files),
        "status": "ahead",
        "files": files,
    }
    rc, result = run(portfolio_observe.main, lane.config, "--repo", REPO)
    assert (rc, result["outcome"]) == (0, "succeeded")


def register(lane: Any) -> None:
    """The repository, in the inventory with a September audit to move away from."""
    core = load(lane.config)
    repo = core.services().portfolio.register_repository(HttpsRepoUrl.parse(REPO, HOSTS), False)
    with SqlTraustUnitOfWork(core.database) as uow:
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repo.id, sha=AUDITED))
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.SECURE_CODE,
                status="completed",
                assessor="skill:secure-code-audit",
                assessor_version="1",
                occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
            )
        )
        uow.commit()


def mirror(lane: Any) -> Path:
    return lane.store / "mirrors" / "github.com" / "org" / "app.git"


def test_a_moved_head_is_fetched_into_the_mirror_and_a_head_at_rest_is_not(lane: Any) -> None:
    register(lane)
    head = lane.forge.commit("a.txt", b"one\n")
    observe(lane, head, [{"filename": "a.txt", "changes": 1}], "2026-10-01T00:00:00Z")
    rc, result = run(portfolio_checkout.refresh, lane.config, "--repo", REPO)
    assert rc == 0
    assert result == JobResult.succeeded(written=(head,)).model_dump(mode="json")
    assert git(mirror(lane), "cat-file", "-t", head) == "commit"

    moved = lane.forge.commit("b.txt", b"two\n")
    observe(
        lane,
        moved,
        [{"filename": "a.txt", "changes": 1}, {"filename": "b.txt", "changes": 1}],
        "2026-10-02T00:00:00Z",
    )
    rc, result = run(portfolio_checkout.refresh, lane.config, "--repo", REPO)
    assert rc == 0
    assert result == JobResult.succeeded(written=(moved,)).model_dump(mode="json")
    assert git(mirror(lane), "cat-file", "-t", moved) == "commit"

    # an audit after the push: repo_state no longer says the head moved, so nothing is fetched
    core = load(lane.config)
    repository = core.services().portfolio.find_repository(HttpsRepoUrl.parse(REPO, HOSTS))
    with SqlTraustUnitOfWork(core.database) as uow:
        head_ref = uow.repository_refs.find(repository.id, "main", moved)
        assert head_ref is not None
        uow.assessments.add(
            Assessment(
                repository_ref_id=head_ref.id,
                kind=AssessmentKind.SECURE_CODE,
                status="completed",
                assessor="skill:secure-code-audit",
                assessor_version="1",
                occurred_at=datetime(2026, 10, 15, tzinfo=UTC),
            )
        )
        uow.commit()
    observe(lane, moved, [], "2026-10-02T00:00:00Z", baseline=moved)
    rc, result = run(portfolio_checkout.refresh, lane.config, "--repo", REPO)
    assert rc == 0
    assert result == JobResult.succeeded().model_dump(mode="json")


def test_an_idle_mirror_is_evicted_and_a_used_one_kept(lane: Any) -> None:
    register(lane)
    head = lane.forge.commit("a.txt", b"one\n")
    observe(lane, head, [{"filename": "a.txt", "changes": 1}], "2026-10-01T00:00:00Z")
    assert run(portfolio_checkout.refresh, lane.config, "--repo", REPO)[0] == 0
    rc, result = run(portfolio_checkout.evict, lane.config)
    assert rc == 0
    assert result == JobResult.succeeded().model_dump(mode="json")  # seeded today: kept
    assert mirror(lane).is_dir()

    idle = time.time() - (EVICT_IDLE_DAYS + 10) * 86400
    os.utime(mirror(lane) / "traust-last-checkout", (idle, idle))
    rc, result = run(portfolio_checkout.evict, lane.config)
    assert rc == 0
    assert result == JobResult.succeeded(written=(REPO,)).model_dump(mode="json")
    assert not mirror(lane).exists()
