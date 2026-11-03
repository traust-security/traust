from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.context import CheckoutRequest, Services
from traust_core.v1.errors import ConfigError, TraustError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ToolRequest, every_item
from traust_core.v1.models.findings import FindingFilter
from traust_core.v1.models.inventory import Liveness, RepositoryFilter, RepositoryRef
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.pqc import PqcFilter, PqcScanState
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

CRYPTO_CWES = frozenset(
    {
        "CWE-256",
        "CWE-259",
        "CWE-261",
        "CWE-295",
        "CWE-296",
        "CWE-297",
        "CWE-310",
        "CWE-311",
        "CWE-312",
        "CWE-319",
        "CWE-321",
        "CWE-322",
        "CWE-323",
        "CWE-324",
        "CWE-325",
        "CWE-326",
        "CWE-327",
        "CWE-328",
        "CWE-329",
        "CWE-330",
        "CWE-331",
        "CWE-335",
        "CWE-338",
        "CWE-347",
        "CWE-522",
        "CWE-540",
        "CWE-547",
        "CWE-757",
        "CWE-798",
        "CWE-916",
        "CWE-1240",
    }
)
CHOKEPOINT = re.compile(
    r"oauth-proxy|kube-rbac-proxy|keycloak|authorino|cert-manager|service-ca|"
    r"cluster-ingress|certman|ingress-operator|router|haproxy|sigstore|cosign|chains|"
    r"recert|openssl|crypto|vault|pki|ca-operator|sso|dex|oauth",
    re.I,
)


class SweepRoute(StrEnum):
    SOURCE = "source"
    SBOM_ONLY = "sbom-only"
    ACCESS_REQUEST = "access-request"


class SweepEntry(Model):
    repository_id: UUID
    repository: str
    repository_ref_id: UUID | None
    sha: str | None
    priority_tier: str
    route: SweepRoute
    access: Liveness
    reason: str | None = None
    scan: PqcScanState | None = None
    cursor: str


class SweepResult(Model):
    entry: SweepEntry
    status: str
    assessment_id: UUID | None = None
    error: str | None = None


class SweepBatch(Model):
    results: tuple[SweepResult, ...]
    next_cursor: str | None
    remaining: int


class PqcSweep:
    def __init__(self, services: Services, hosts: tuple[str, ...]) -> None:
        self._services, self._hosts = services, hosts

    def worklist(self, filter: PqcFilter) -> tuple[SweepEntry, ...]:
        services = self._services
        refs: dict[UUID, list[RepositoryRef]] = defaultdict(list)
        for ref in services.pqc.scoped_refs(filter):
            refs[ref.repository_id].append(ref)
        states = {
            state.repository_ref_id: state
            for state in services.pqc.scan_states(
                PqcFilter(
                    repository_ref_ids=tuple(r.id for rows in refs.values() for r in rows if r.id)
                )
            )
        }
        availability = {
            live.repository_id: live
            for live in every_item(
                lambda page: services.portfolio.liveness(RepositoryFilter(), page)
            )
        }
        if filter.repository_ref_ids is None and filter.product_id is None:
            repositories = every_item(
                lambda page: services.portfolio.list_repositories(RepositoryFilter(), page)
            )
        else:
            repositories = services.portfolio.inventory.list_repositories(list(refs))
        entries = []
        for repository in repositories:
            assert repository.id is not None
            ref = max(
                refs[repository.id],
                key=lambda r: (
                    r.is_default,
                    r.created_at or datetime.min.replace(tzinfo=UTC),
                    str(r.id),
                ),
                default=None,
            )
            findings = services.findings.all(FindingFilter(repository_id=repository.id))
            crypto = any(
                cwe.upper().split(":")[0].strip() in CRYPTO_CWES
                for finding in findings
                for cwe in finding.cwes
            )
            tier = 0 if CHOKEPOINT.search(repository.url) else 1 if crypto else 2
            access = availability[repository.id]
            route, reason = SweepRoute.SOURCE, access.reason
            if ref is None:
                route, reason = SweepRoute.ACCESS_REQUEST, "no-registered-commit"
            elif access.unobserved == ComparisonStatus.NO_CREDENTIALS:
                route, reason = SweepRoute.ACCESS_REQUEST, access.unobserved.value
            elif access.unobserved == ComparisonStatus.UNREACHABLE:
                route, reason = SweepRoute.SBOM_ONLY, access.unobserved.value
            entries.append(
                SweepEntry(
                    repository_id=repository.id,
                    repository=repository.url,
                    repository_ref_id=ref.id if ref else None,
                    sha=ref.sha if ref else None,
                    priority_tier=("chokepoint", "crypto-cwe", "tail")[tier],
                    route=route,
                    access=access,
                    reason=reason,
                    scan=states.get(ref.id) if ref else None,
                    cursor=f"{tier}|{repository.url}",
                )
            )
        return tuple(sorted(entries, key=lambda e: e.cursor))

    def refresh(
        self,
        filter: PqcFilter,
        *,
        limit: int = 20,
        after: str | None = None,
        refresh: bool = False,
    ) -> SweepBatch:
        if limit < 1:
            raise ValidationError("pqc sweep limit must be positive")
        worklist = [e for e in self.worklist(filter) if after is None or e.cursor > after]
        pending = []
        for entry in worklist:
            scan = entry.scan
            basis = "sbom-only" if entry.route == SweepRoute.SBOM_ONLY else "source"
            if scan and scan.assessment_id and scan.basis == basis:
                if not refresh:
                    continue
                if scan.current is None:
                    raise ConfigError(
                        "PQC refresh needs a registered scanner pack to compare stamps"
                    )
                if scan.current:
                    continue
            pending.append(entry)
        results = []
        for entry in pending[:limit]:
            if entry.route == SweepRoute.ACCESS_REQUEST:
                results.append(SweepResult(entry=entry, status="access-request"))
                continue
            assert entry.repository_ref_id is not None and entry.sha is not None
            workspace = None
            try:
                request = None
                if entry.route == SweepRoute.SOURCE:
                    workspace = self._services.checkouts.checkout(
                        CheckoutRequest(
                            repo=HttpsRepoUrl.parse(entry.repository, self._hosts),
                            ref=GitSha.parse(entry.sha),
                        )
                    ).data
                    request = ToolRequest(workspace=workspace.path)
                    ref = self._services.portfolio.inventory.get_ref(entry.repository_ref_id)
                    if ref.manifest_sbom_id is None:
                        self._services.exposure.ingest_dependencies(
                            entry.repository_ref_id, workspace.path
                        )
                done = self._services.pqc.prescan(entry.repository_ref_id, request)
                results.append(
                    SweepResult(
                        entry=entry,
                        status="scanned" if done.scanned else "current",
                        assessment_id=done.assessment_id,
                    )
                )
            except TraustError as exc:
                results.append(SweepResult(entry=entry, status="failed", error=str(exc)))
            finally:
                if workspace is not None:
                    self._services.checkouts.release(workspace)
        remaining = max(0, len(pending) - limit)
        return SweepBatch(
            results=tuple(results),
            remaining=remaining,
            next_cursor=results[-1].entry.cursor if results and remaining else None,
        )
