"""`traust portfolio observe`: the repo_state materializer end to end on traust-core, SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import observation
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.observation import GITLEAKS

from traust.cli import portfolio_observe
from traust.context import load
from traust.ops.materializers import RepoStateMaterializer
from traust.ops.router import SecurityRouter

REPO = "https://github.com/org/app"
HOSTS = ("github.com",)
FORGE = {
    "repos/org/app": {
        "pushed_at": "2026-10-01T00:00:00Z",
        "archived": False,
        "default_branch": "main",
        "visibility": "private",
        "fork": True,
        "parent": {"full_name": "org/upstream"},
    },
    "repos/org/app/branches/main": {"commit": {"sha": "b" * 40}},
    "rate_limit": {"resources": {"core": {"remaining": 4000}}},
    "repos/org/app/compare/" + "a" * 40 + "...HEAD": {
        "ahead_by": 1,
        "status": "ahead",
        "files": [{"filename": "src/app.py", "changes": 12}],
    },
}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))

    forge_api(monkeypatch, lambda host, endpoint, headers=None: FORGE[endpoint])
    # A changed repository's observation scans its patch for secrets (gitleaks required,
    # core's fail-loud rule); the runner image's scanner is not this test's subject.
    clean_scanner(monkeypatch)
    return config


def forge_api(monkeypatch: pytest.MonkeyPatch, get: Any) -> None:
    """Core's forge reads GitHub over its ForgeApi; answer them from `get` (and the compare
    patch from `stream`)."""
    wire = observation.command_source
    api = SimpleNamespace(
        get=get,
        stream=lambda host, endpoint, consume, headers=None: consume(
            io.BytesIO(b"+++ b/x.py\n+x = 1\n")
        ),
    )
    monkeypatch.setattr(
        "traust_core.v1.context.context.command_source",
        lambda hosts, **kw: wire(hosts, **{**kw, "api": api}),
    )


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


def clean_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    real_load = portfolio_observe.load

    def load_with_scanner(config_home: Path | None) -> Any:
        core = real_load(config_home)
        core.tools = ProviderRegistry("tool")
        core.tools.register(CleanGitleaks.name, CleanGitleaks)
        return core

    monkeypatch.setattr(portfolio_observe, "load", load_with_scanner)


def observe(home: Path, repo: str) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = portfolio_observe.main(["--config-home", str(home), "--repo", repo])
    return rc, json.loads(out.getvalue())


def register(home: Path, *, audited: bool) -> None:
    core = load(home)
    repo = core.services().portfolio.register_repository(HttpsRepoUrl.parse(REPO, HOSTS), False)
    if not audited:
        return
    with SqlTraustUnitOfWork(core.database) as uow:
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repo.id, sha="a" * 40))
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


def test_an_audited_fork_is_observed_kept_and_its_upstream_inventoried(home: Path) -> None:
    register(home, audited=True)
    assert observe(home, REPO) == (0, JobResult.succeeded().model_dump(mode="json"))
    core = load(home)
    with core.repository_observation() as observation:
        state = observation.query.repo_state(repo_url=REPO)
    assert (state.status, state.ahead_by, state.exposure) == ("ok", 1, "public-internal")
    with SqlTraustUnitOfWork(core.database) as uow:
        upstream = uow.repositories.find_by_url("https://github.com/org/upstream")
        assert upstream is not None
        assert uow.repositories.find_by_url(REPO).upstream_id == upstream.id


def test_a_never_audited_repository_keeps_its_head_with_no_comparison(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(home, audited=False)
    asked: list[str] = []

    def get(host: str, endpoint: str, headers: Any = None) -> Any:
        asked.append(endpoint)
        return FORGE[endpoint]

    forge_api(monkeypatch, get)
    assert observe(home, REPO)[0] == 0
    assert asked == ["repos/org/app", "repos/org/app/branches/main"]
    core = load(home)
    repo = core.services().portfolio.find_repository(HttpsRepoUrl.parse(REPO, HOSTS))
    assert repo is not None and repo.id is not None
    head = core.services().portfolio.default_ref(repo.id)
    assert head is not None and head.sha == "b" * 40
    with core.repository_observation() as observation:
        assert observation.query.repo_state(repo_url=REPO).status == "never-audited"


def test_a_repository_outside_the_inventory_is_refused(home: Path) -> None:
    rc, result = observe(home, REPO)
    assert (rc, result["outcome"]) == (5, "refused")


def test_an_audited_unknown_host_still_reaches_age_ceiling_routing(home: Path) -> None:
    unknown = "https://example.com/org/app"
    core = load(home)
    repo = core.services().portfolio.register_repository(
        HttpsRepoUrl.parse(unknown, ("example.com",)), False
    )
    with SqlTraustUnitOfWork(core.database) as uow:
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repo.id, sha="a" * 40))
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.SECURE_CODE,
                status="completed",
                assessor="skill:secure-code-audit",
                assessor_version="1",
                occurred_at=datetime(2000, 1, 1, tzinfo=UTC),
            )
        )
        uow.commit()
    assert observe(home, unknown) == (
        4,
        JobResult.partly({"unsupported-host": 1}).model_dump(mode="json"),
    )
    with core.repository_observation() as observation:
        state = observation.query.repo_state(repo_url=unknown)
    route = SecurityRouter().route(state, (), ())[0]
    assert (state.status, route.lane, route.reason) == (
        "unsupported-host",
        "full-audit",
        "rule-4",
    )


class Services:
    def __init__(self, portfolio: Portfolio) -> None:
        self.portfolio = portfolio


class Portfolio:
    def __init__(self, outcome: ComparisonStatus | Exception) -> None:
        self.outcome = outcome

    def record_forge_facts(self, *, repo_url: str) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return type("Facts", (), {"status": self.outcome})


@pytest.mark.parametrize("status", list(ComparisonStatus))
def test_every_status_is_succeeded_or_a_named_gap(status: ComparisonStatus) -> None:
    result = RepoStateMaterializer(Services(Portfolio(status)), HOSTS).materialize(  # type: ignore[arg-type]
        AssetRequest(asset="repo_state", run_id="t", partition=REPO)
    )
    answered = status in ("ok", "no-pinned-sha", "never-audited")
    assert result == (JobResult.succeeded() if answered else JobResult.partly({status: 1}))


def test_a_repository_core_doesnt_know_is_refused_with_its_reason() -> None:
    portfolio = Portfolio(NotFoundError("repository not in inventory: x"))
    result = RepoStateMaterializer(Services(portfolio), HOSTS).materialize(  # type: ignore[arg-type]
        AssetRequest(asset="repo_state", run_id="t", partition=REPO)
    )
    assert result == JobResult.refused(OrderReason.NOT_FOUND)
