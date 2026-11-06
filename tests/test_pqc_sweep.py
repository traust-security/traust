from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from traust_core.v1.context import Config, Context, Services
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import Provenance, ToolRequest
from traust_core.v1.models.findings import CandidateFormat
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetName, JobResult, OrderRequest, WorkerId
from traust_core.v1.models.pqc import (
    PqcFilter,
    PqcScan,
    PqcScanFinding,
    PqcStamps,
    PqcWorklistRoute,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.providers.base import Acquisition, Readiness, Result

from traust.lib.pending_decisions import Decision, skip_reason
from traust.ops.pqc import PqcSweep

AT = datetime(2026, 10, 24, tzinfo=UTC)
SHA = "a" * 40
STAMPS = PqcStamps(adapter_version="1.4.0", pqc_scan_commit="be5c760", rules_sha256="ab" * 32)


class Scanner:
    name = "pqc-scan"

    def __init__(self) -> None:
        self.pack = STAMPS
        self.calls = 0

    def stamps(self) -> PqcStamps:
        return self.pack

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def scan(self, request: object) -> Result[PqcScan]:
        self.calls += 1
        return Result(
            PqcScan(
                findings=(
                    PqcScanFinding(rule_id="API_GO_CRYPTO_RSA_GENKEY", file="keys.go", line=1),
                ),
                scanned_files=1,
                skipped_files=0,
                rules_in_pack=1,
                stamps=self.pack,
            ),
            Acquisition(provider=self.name, acquired_at=AT),
        )


class Checkouts:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.released = []
        self.calls = []

    def checkout(self, request: object) -> object:
        self.calls.append(request)
        return SimpleNamespace(data=SimpleNamespace(path=self.root))

    def release(self, workspace: object) -> None:
        self.released.append(workspace)


def registry(tmp_path: Path) -> tuple[Context, Scanner, Checkouts]:
    core = Context(Config(home=tmp_path / "home"))
    scanner = Scanner()
    core.pqc_scanner = scanner
    source = tmp_path / "source"
    source.mkdir()
    return core, scanner, Checkouts(source)


def ref(core: Context, name: str, *, sbom: bool = True) -> object:
    services = core.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse(f"https://github.com/example/{name}", ["github.com"]),
        True,
    )
    made = services.portfolio.register_ref(repository.id, GitSha.parse(SHA), None, None)
    if sbom:
        services.exposure.ingest_sbom(b'{"bomFormat":"CycloneDX","components":[]}', made.id)
    return made


def observation(services: Services, repository_id: UUID, result: JobResult) -> UUID:
    principal = Principal(
        identity="operator@example.com",
        display="operator",
        kind=ActorKind.HUMAN,
        verified_by=IdentitySource.OIDC,
    )
    worker = WorkerId("pqc-fixture")
    order = services.ops.start(
        OrderRequest(asset=AssetName("repo_state"), priority=20, repository_id=repository_id),
        principal,
        worker,
        timedelta(minutes=5),
    )
    services.ops.complete(order.id, worker, result)
    return order.id


@pytest.mark.skip(reason=skip_reason(Decision.LIVENESS_STATUS))
def test_ranked_worklist_deduplicates_repositories_and_routes_evidenced_residuals(
    tmp_path: Path,
) -> None:
    core, _, _ = registry(tmp_path)
    choke = ref(core, "oauth-gateway")
    crypto = ref(core, "transport")
    tail = ref(core, "widget")
    denied = ref(core, "private-repo")
    unreachable = ref(core, "offline-repo")
    services = core.services()
    services.portfolio.register_ref(choke.repository_id, GitSha.parse("b" * 40), None, None)
    provenance = Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=AT)
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fixture",
                        "rules": [
                            {
                                "id": "crypto-rule",
                                "properties": {"tags": ["external/cwe/cwe-327"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "crypto-rule",
                        "message": {"text": "Weak algorithm"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "keys.go"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    services.assessment.record_scan(
        crypto.id, json.dumps(sarif).encode(), CandidateFormat.SARIF, provenance
    )
    denied_order = observation(
        services, denied.repository_id, JobResult.partly({ComparisonStatus.NO_CREDENTIALS: 1})
    )
    unreachable_order = observation(
        services, unreachable.repository_id, JobResult.partly({ComparisonStatus.UNREACHABLE: 1})
    )
    entries = services.pqc.worklist(PqcFilter(), chokepoints=("oauth-gateway",))
    assert len(entries) == 5
    assert [e.priority_tier for e in entries] == [
        "chokepoint",
        "crypto-cwe",
        "tail",
        "tail",
        "tail",
    ]
    by_repo = {e.repository_id: e for e in entries}
    assert by_repo[crypto.repository_id].route == PqcWorklistRoute.SOURCE
    assert by_repo[tail.repository_id].route == PqcWorklistRoute.SOURCE
    assert by_repo[denied.repository_id].route == PqcWorklistRoute.ACCESS_REQUEST
    assert by_repo[unreachable.repository_id].route == PqcWorklistRoute.SBOM_ONLY
    assert by_repo[denied.repository_id].access.unobserved == ComparisonStatus.NO_CREDENTIALS
    assert by_repo[unreachable.repository_id].access.unobserved == ComparisonStatus.UNREACHABLE
    assert by_repo[denied.repository_id].access.observed_at is not None
    assert services.ops.manifest(denied_order).degraded == {"no-credentials": 1}
    assert services.ops.manifest(unreachable_order).degraded == {"unreachable": 1}
    routes = [e.route for e in entries]
    progress = (
        routes.count(PqcWorklistRoute.ACCESS_REQUEST),
        routes.count(PqcWorklistRoute.SBOM_ONLY),
        len(services.pqc.list_readiness(PqcFilter())),
    )
    assert progress == (1, 1, 0)
    assert len(services.pqc.worklist(PqcFilter(repository_ref_ids=(tail.id,)))) == 1
    assert services.pqc.worklist(PqcFilter(repository_ref_ids=())) == ()


def test_bounded_refresh_resumes_from_recorded_pack_stamps_and_releases_checkouts(
    tmp_path: Path,
) -> None:
    core, scanner, checkouts = registry(tmp_path)
    first, second = ref(core, "a"), ref(core, "b")
    services = replace(core.services(), checkouts=checkouts)
    sweep = PqcSweep(services, ("github.com",), scanner=core.pqc_scanner)
    batch = sweep.refresh(PqcFilter(), limit=1, refresh=True)
    assert (len(batch.results), batch.remaining) == (1, 1)
    assert batch.results[0].entry.repository_ref_id == first.id
    assert batch.results[0].status == "scanned"
    assert batch.next_cursor is not None
    resumed = sweep.refresh(PqcFilter(), limit=1, after=batch.next_cursor, refresh=True)
    assert resumed.results[0].entry.repository_ref_id == second.id
    assert resumed.next_cursor is None
    assert scanner.calls == 2 and len(checkouts.released) == 2
    assert sweep.refresh(PqcFilter(), refresh=True).results == ()
    scanner.pack = scanner.pack.model_copy(update={"rules_sha256": "cd" * 32})
    refreshed = sweep.refresh(PqcFilter(), refresh=True)
    assert [r.status for r in refreshed.results] == ["scanned", "scanned"]
    assert scanner.calls == 4 and len(checkouts.released) == 4
    assert services.pqc.list_readiness(PqcFilter()) == []


@pytest.mark.skip(reason=skip_reason(Decision.LIVENESS_STATUS))
def test_missing_sbom_is_a_reported_failure_not_clean_readiness(
    tmp_path: Path,
) -> None:
    core, scanner, checkouts = registry(tmp_path)
    target = ref(core, "offline", sbom=False)
    services = replace(core.services(), checkouts=checkouts)
    observation(services, target.repository_id, JobResult.partly({"unreachable": 1}))
    batch = PqcSweep(services, ("github.com",), scanner=core.pqc_scanner).refresh(
        PqcFilter(), refresh=True
    )
    assert [r.status for r in batch.results] == ["failed"]
    assert batch.results[0].assessment_id is None
    assert scanner.calls == 0 and checkouts.calls == []
    assert services.pqc.find(target.id) is None


@pytest.mark.skip(reason=skip_reason(Decision.LIVENESS_STATUS))
def test_success_without_availability_does_not_clear_access_failure(
    tmp_path: Path,
) -> None:
    core, _, _ = registry(tmp_path)
    target = ref(core, "widget")
    services = core.services()
    observation(services, target.repository_id, JobResult.partly({"no-credentials": 1}))
    [entry] = services.pqc.worklist(PqcFilter())
    assert entry.access.unobserved == ComparisonStatus.NO_CREDENTIALS
    observation(services, target.repository_id, JobResult.succeeded())
    [current] = services.pqc.worklist(PqcFilter())
    assert current.access.unobserved == ComparisonStatus.NO_CREDENTIALS
    [entry] = services.pqc.worklist(PqcFilter())
    assert entry.route == PqcWorklistRoute.ACCESS_REQUEST
    assert services.pqc.find(target.id) is None


def test_a_batch_without_a_scanner_fails_before_dependency_or_scan_recording(
    tmp_path: Path,
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    target = ref(core, "widget", sbom=False)
    services = core.services()
    sweep = PqcSweep(services, ("github.com",))
    with pytest.raises(ConfigError):
        sweep.refresh(PqcFilter())
    assert services.portfolio.inventory.get_ref(target.id).manifest_sbom_id is None
    [state] = services.pqc.scan_states(PqcFilter())
    assert state.assessment_id is None
    assert services.pqc.list_readiness(PqcFilter()) == []


def test_recorded_scans_resume_without_a_scanner_but_refresh_requires_measured_currency(
    tmp_path: Path,
) -> None:
    core, _, checkouts = registry(tmp_path)
    target = ref(core, "widget")
    recorded = core.services().pqc.prescan(target.id, ToolRequest(workspace=checkouts.root))
    core.pqc_scanner = None
    services = core.services()
    sweep = PqcSweep(services, ("github.com",))
    resumed = sweep.refresh(PqcFilter())
    assert resumed.results == () and resumed.remaining == 0
    with pytest.raises(ConfigError):
        sweep.refresh(PqcFilter(), refresh=True)
    [state] = services.pqc.scan_states(PqcFilter())
    assert state.assessment_id == recorded.assessment_id
    assert services.pqc.prepare(target.id).facts == recorded.facts
    assert services.pqc.list_readiness(PqcFilter()) == []
