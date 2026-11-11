from __future__ import annotations

from uuid import UUID

from traust_core.v1.context import CheckoutRequest, Services
from traust_core.v1.errors import ConfigError, TraustError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.pqc import PqcFilter, PqcWorklistEntry, PqcWorklistRoute
from traust_core.v1.models.values import GitSha, HttpsRepoUrl


class SweepResult(Model):
    entry: PqcWorklistEntry
    status: str
    assessment_id: UUID | None = None
    error: str | None = None


class SweepBatch(Model):
    results: tuple[SweepResult, ...]
    next_cursor: str | None
    remaining: int


class PqcSweep:
    """Bounded prescan batches over Core's ranked PQC worklist.

    ``chokepoints`` are the caller's priority repository URL fragments. ``scanner`` is the
    Context's registered ``pqc_scanner``; a batch that needs an absent provider or cannot
    measure refresh currency fails closed.
    """

    def __init__(
        self,
        services: Services,
        hosts: tuple[str, ...],
        chokepoints: tuple[str, ...] = (),
        scanner: object | None = None,
    ) -> None:
        self._services, self._hosts = services, hosts
        self._chokepoints = chokepoints
        self._scanner = scanner

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
        worklist = [
            entry
            for entry in self._services.pqc.worklist(filter, chokepoints=self._chokepoints)
            if after is None or entry.cursor > after
        ]
        pending = []
        for entry in worklist:
            scan = entry.scan
            basis = "sbom-only" if entry.route == PqcWorklistRoute.SBOM_ONLY else "source"
            if scan and scan.assessment_id and scan.basis == basis:
                if not refresh:
                    continue
                if scan.current is None:
                    raise ConfigError(
                        "pqc sweep refresh cannot compare recorded scans without the "
                        "pqc-scan provider (Context.register_pqc_scanner)"
                    )
                if scan.current:
                    continue
            pending.append(entry)
        batch = pending[:limit]
        if self._scanner is None and any(
            entry.route != PqcWorklistRoute.ACCESS_REQUEST for entry in batch
        ):
            raise ConfigError(
                "pqc sweep needs the pqc-scan provider (Context.register_pqc_scanner)"
            )
        results = []
        for entry in batch:
            if entry.route == PqcWorklistRoute.ACCESS_REQUEST:
                results.append(SweepResult(entry=entry, status="access-request"))
                continue
            assert entry.repository_ref_id is not None and entry.sha is not None
            workspace = None
            try:
                request = None
                if entry.route == PqcWorklistRoute.SOURCE:
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
