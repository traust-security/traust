"""The `manifest_sbom` asset: its materializer's answer to each door outcome, and the CLI end to
end on traust-core (SQLite) with the forge archive and syft stubbed."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.forge_archive import ArchiveCheckout
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.providers.syft import SyftSbom
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_impact_doors import REPO, SHA, home, run, sbom
from traust.cli import impact
from traust.context import load
from traust.ops.materializers import ManifestSbomMaterializer

__all__ = ["home"]

HOSTS = ("github.com",)
SBOM_ID = UUID(int=9)


class Exposure:
    def __init__(self, outcome: Exception | None = None) -> None:
        self.outcome, self.asked = outcome, []

    def record_manifest_sbom(self, repository_ref_id: UUID) -> Any:
        self.asked.append(repository_ref_id)
        if self.outcome is not None:
            raise self.outcome
        return type("Sbom", (), {"id": SBOM_ID})


class Portfolio:
    def __init__(self, known: bool = True, observed: bool = True) -> None:
        self.known, self.observed = known, observed

    def find_repository(self, url: HttpsRepoUrl) -> Any:
        return type("Repo", (), {"id": UUID(int=7)}) if self.known else None

    def tracked_refs_of(self, repository_id: UUID) -> list[Any]:
        return (
            [type("Head", (), {"id": UUID(int=8), "manifest_sbom_id": None})]
            if self.observed
            else []
        )


class Services:
    def __init__(self, exposure: Exposure, **portfolio: bool) -> None:
        self.exposure, self.portfolio = exposure, Portfolio(**portfolio)


def materialize(services: Services, partition: str = REPO) -> JobResult:
    materializer = ManifestSbomMaterializer(services, HOSTS)  # type: ignore[arg-type]
    return materializer.materialize(
        AssetRequest(asset="manifest_sbom", run_id=str(uuid4()), partition=partition)
    )


@pytest.mark.parametrize(
    ("outcome", "want"),
    [
        (None, JobResult.succeeded(written=(str(SBOM_ID),))),
        (ServiceError("archive: HTTP 404", status=404), JobResult.partly({"unreachable": 1})),
        (
            ServiceError("archive: HTTP 401", status=401),
            JobResult.failed(OrderReason.SOURCE_UNAVAILABLE),
        ),
        (
            ServiceError("the kept files exceed the workspace cap"),
            JobResult.failed(OrderReason.SOURCE_UNAVAILABLE),
        ),
        (
            ConfigError("forge_tokens.github.com names unset variable"),
            JobResult.failed(OrderReason.BAD_REQUEST),
        ),
        (
            ValidationError("unsafe archive member '/etc/x'"),
            JobResult.failed(OrderReason.BAD_REQUEST),
        ),
    ],
    ids=["recorded", "head gone", "no access", "over cap", "not configured", "unsafe archive"],
)
def test_the_materializer_answers_each_door_outcome(
    outcome: Exception | None, want: JobResult
) -> None:
    exposure = Exposure(outcome)
    assert materialize(Services(exposure)) == want
    assert exposure.asked == [UUID(int=8)]


@pytest.mark.parametrize(
    ("partition", "portfolio", "want"),
    [
        (REPO, {"known": False}, JobResult.refused(OrderReason.NOT_FOUND)),
        (REPO, {"observed": False}, JobResult.refused(OrderReason.NOT_FOUND)),
        ("https://x.io/a/b", {}, JobResult.failed(OrderReason.BAD_REQUEST)),
    ],
    ids=["outside the inventory", "head never observed", "unknown host"],
)
def test_the_materializer_refuses_before_fetching(
    partition: str, portfolio: dict[str, bool], want: JobResult
) -> None:
    exposure = Exposure()
    assert materialize(Services(exposure, **portfolio), partition) == want
    assert exposure.asked == []


def test_the_cli_records_the_observed_heads_sbom_once(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = load(home)
    services = core.services()
    repo = services.portfolio.register_repository(HttpsRepoUrl.parse(REPO, HOSTS), False)
    assert repo.id is not None
    with SqlTraustUnitOfWork(core.database) as uow:
        head = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id, name="main", kind="branch", is_default=True, sha=SHA
            )
        )
        assert head.id is not None
        uow.assessments.add(  # its observation: what makes it the observed head
            Assessment(
                repository_ref_id=head.id,
                kind=AssessmentKind.REPO_STATE,
                status="completed",
                assessor="test",
                assessor_version="1",
                occurred_at=datetime.now(UTC),
            )
        )
        uow.commit()
    fetched: list[CheckoutRequest] = []

    def checkout(self: Any, request: CheckoutRequest) -> Result[Workspace]:
        fetched.append(request)
        workspace = Workspace(repo=request.repo, sha=request.ref, path=tmp_path, provider=self.name)
        return Result(
            workspace, Acquisition(provider="forge-archive", acquired_at=datetime.now(UTC))
        )

    def acquire(self: Any, request: Any) -> Result[bytes]:
        raw = sbom(tmp_path, "4.17.20").read_bytes()
        return Result(
            raw, Acquisition(provider="syft", acquired_at=datetime.now(UTC), version="1.0.0")
        )

    monkeypatch.setattr(SyftSbom, "check", lambda self: Readiness(ready=True))
    monkeypatch.setattr(SyftSbom, "acquire", acquire)
    monkeypatch.setattr(ArchiveCheckout, "checkout", checkout)
    monkeypatch.setattr(ArchiveCheckout, "release", lambda self, workspace: None)
    first = run(impact.manifest_sbom, home, "--repo", REPO)
    again = run(impact.manifest_sbom, home, "--repo", REPO)
    assert first[0] == again[0] == 0
    assert json.loads(first[1])["outcome"] == "succeeded"
    assert len(fetched) == 1  # the head has its SBOM: the second run is a lookup
    with SqlTraustUnitOfWork(core.database) as uow:
        assert uow.repository_refs.get(head.id).manifest_sbom_id is not None  # type: ignore[arg-type]


def test_the_cli_records_every_tracked_heads_sbom(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = load(home)
    services = core.services()
    repo = services.portfolio.register_repository(HttpsRepoUrl.parse(REPO, HOSTS), False)
    assert repo.id is not None
    with SqlTraustUnitOfWork(core.database) as uow:
        for name in ("main", "release-4.16"):
            uow.repository_refs.add(
                RepositoryRef(
                    repository_id=repo.id,
                    name=name,
                    kind="branch",
                    is_default=name == "main",
                    sha=SHA,
                )
            )
        uow.commit()
    fetched: list[CheckoutRequest] = []

    def checkout(self: Any, request: CheckoutRequest) -> Result[Workspace]:
        fetched.append(request)
        workspace = Workspace(repo=request.repo, sha=request.ref, path=tmp_path, provider=self.name)
        return Result(
            workspace, Acquisition(provider="forge-archive", acquired_at=datetime.now(UTC))
        )

    def acquire(self: Any, request: Any) -> Result[bytes]:
        raw = sbom(tmp_path, "4.17.20").read_bytes()
        return Result(
            raw, Acquisition(provider="syft", acquired_at=datetime.now(UTC), version="1.0.0")
        )

    monkeypatch.setattr(SyftSbom, "check", lambda self: Readiness(ready=True))
    monkeypatch.setattr(SyftSbom, "acquire", acquire)
    monkeypatch.setattr(ArchiveCheckout, "checkout", checkout)
    monkeypatch.setattr(ArchiveCheckout, "release", lambda self, workspace: None)
    first = run(impact.manifest_sbom, home, "--repo", REPO)
    again = run(impact.manifest_sbom, home, "--repo", REPO)
    assert first[0] == again[0] == 0
    assert json.loads(first[1])["outcome"] == "succeeded"
    assert len(fetched) == 2  # one archive per tracked line; re-runs are lookups
    with SqlTraustUnitOfWork(core.database) as uow:
        heads = uow.repository_refs.list_lines(repo.id)
    assert all(head.manifest_sbom_id is not None for head in heads)
