"""Materializers: one pack asset, one traust-core service call, its outcome as a JobResult."""

from __future__ import annotations

import logging
import tempfile
from collections import Counter
from collections.abc import Iterable
from http import HTTPStatus
from pathlib import Path
from typing import Any
from uuid import UUID

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.below_range import BelowRangeStatus
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.insight import RenderedView, ViewFilter, ViewName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetRequest, DegradedKey, JobResult, OrderReason
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

log = logging.getLogger(__name__)

# The forge answered, or there was nothing to ask; any other status is a gap, never green.
ANSWERED = frozenset(
    {ComparisonStatus.OK, ComparisonStatus.NO_PINNED_SHA, ComparisonStatus.NEVER_AUDITED}
)


class RepoStateMaterializer:
    """`repo_state`: observe one inventory repository at its forge and keep what it answered."""

    asset = "repo_state"

    def __init__(self, services: Services, hosts: Iterable[str]) -> None:
        self._portfolio = services.portfolio
        self._hosts = tuple(hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            url = HttpsRepoUrl.parse(request.partition or "", self._hosts)
        except ValidationError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        try:
            facts = self._portfolio.record_forge_facts(repo_url=str(url))
        except NotFoundError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.NOT_FOUND, e)
            return JobResult.refused(OrderReason.NOT_FOUND)
        if facts.status in ANSWERED:
            return JobResult.succeeded()
        return JobResult.partly({facts.status.value: 1})


class ManifestSbomMaterializer:
    """`manifest_sbom`: the dependency SBOM of one inventory repository's observed default head,
    from its manifests on the forge. A head that has one is a no-op; no observed head is refused."""

    asset = "manifest_sbom"

    def __init__(self, services: Services, hosts: Iterable[str]) -> None:
        self._portfolio = services.portfolio
        self._exposure = services.exposure
        self._hosts = tuple(hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            url = HttpsRepoUrl.parse(request.partition or "", self._hosts)
        except ValidationError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        repo = self._portfolio.find_repository(url)
        head = self._portfolio.default_ref(repo.id) if repo and repo.id else None
        if head is None or head.id is None:
            log.warning(
                "run %s: %s: no observed default head for %s",
                request.run_id,
                OrderReason.NOT_FOUND,
                url,
            )
            return JobResult.refused(OrderReason.NOT_FOUND)
        try:
            sbom = self._exposure.record_manifest_sbom(head.id)
        except (ConfigError, ValidationError) as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        except ServiceError as e:
            gone = e.status == HTTPStatus.NOT_FOUND
            reason = OrderReason.NOT_FOUND if gone else OrderReason.SOURCE_UNAVAILABLE
            log.warning("run %s: %s: %s", request.run_id, reason, e)
            return JobResult.refused(reason) if gone else JobResult.failed(reason)
        return JobResult.succeeded(written=(str(sbom.id),))


class RepoCheckoutRefreshMaterializer:
    """`repo_checkout_refresh`: fetch one inventory repository's git mirror to its observed
    default head, but only when repo_state says the head moved (pushed since its last audit) —
    a pre-warm for the lanes' checkouts, so a mirror is never seeded for a repository at rest
    (a headless one included: no work, no head needed)."""

    asset = "repo_checkout_refresh"

    def __init__(self, services: Services, states: Any, hosts: Iterable[str]) -> None:
        self._portfolio = services.portfolio
        self._checkouts = services.checkouts
        self._states = states  # the Context's repo_state query (core's `RepoStateQuery`)
        self._hosts = tuple(hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            url = HttpsRepoUrl.parse(request.partition or "", self._hosts)
        except ValidationError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        try:
            state = self._states.repo_state(repo_url=str(url))
        except NotFoundError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.NOT_FOUND, e)
            return JobResult.refused(OrderReason.NOT_FOUND)
        if not state.push_changed:
            return JobResult.succeeded()
        head = self._portfolio.default_ref(state.repository_id)
        if head is None:
            log.warning(
                "run %s: %s: no observed default head for %s",
                request.run_id,
                OrderReason.NOT_FOUND,
                url,
            )
            return JobResult.refused(OrderReason.NOT_FOUND)
        try:
            self._checkouts.refresh(url, GitSha.parse(head.sha))
        except NotFoundError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.NOT_FOUND, e)
            return JobResult.refused(OrderReason.NOT_FOUND)
        except ServiceError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.SOURCE_UNAVAILABLE, e)
            return JobResult.failed(OrderReason.SOURCE_UNAVAILABLE)
        return JobResult.succeeded(written=(head.sha,))


# A mirror no checkout has touched in this many days is dropped; only a checkout (or the seed)
# touches its last-use marker, so a mirror refreshed but never used is reclaim, not cache.
EVICT_IDLE_DAYS = 30


class MirrorEvictMaterializer:
    """`mirror_evict`: drop every git mirror no checkout has touched in the eviction window;
    the repos dropped are the run's record."""

    asset = "mirror_evict"

    def __init__(self, services: Services) -> None:
        self._checkouts = services.checkouts

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            dropped = self._checkouts.evict(EVICT_IDLE_DAYS)
        except ServiceError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.SOURCE_UNAVAILABLE, e)
            return JobResult.failed(OrderReason.SOURCE_UNAVAILABLE)
        return JobResult.succeeded(written=tuple(map(str, dropped)))


# A run by hand, not for an engine order.
MANUAL = "manual"


def _order_id(run_id: str) -> UUID | None:
    return None if run_id == MANUAL else UUID(run_id)


class FeedsCacheMaterializer:
    """`feeds_cache`: snapshot every security feed (or the one in ``partition``)."""

    asset = "feeds_cache"

    def __init__(self, services: Services) -> None:
        self._exposure = services.exposure

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            order = _order_id(request.run_id)
        except ValueError:
            log.warning(
                "run %s: %s: run id is not an order id", request.run_id, OrderReason.BAD_REQUEST
            )
            return JobResult.failed(OrderReason.BAD_REQUEST)
        feeds = None if request.partition is None else [FeedName(request.partition)]
        try:
            statuses = self._exposure.refresh_feeds(feeds, order)
        except ConfigError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        failed = [s for s in statuses if s.last_error]
        for status in failed:
            log.warning("run %s feed %s: %s", request.run_id, status.name, status.last_error)
        if any(s.fetched_at is None for s in failed):
            return JobResult.failed(OrderReason.SNAPSHOT_UNAVAILABLE)
        return JobResult.partly({s.name: 1 for s in failed}).model_copy(
            update={"reason": OrderReason.SOURCE_UNAVAILABLE if failed else None}
        )


class LedgerAuditMaterializer:
    """`ledger_audit`: verify every ledger layer. A layer that fails is `failed`; one signed but
    unverifiable here (no public key, no backend) is `unverified`; neither is ever green."""

    asset = "ledger_audit"

    def __init__(self, services: Services) -> None:
        self._ledger = services.ledger

    def materialize(self, request: AssetRequest) -> JobResult:
        if self._ledger is None:
            log.warning("run %s: no ledger configured; nothing to audit", request.run_id)
            return JobResult.refused(OrderReason.LEDGER_UNCONFIGURED)
        results = self._ledger.audit()
        failed = sum(1 for r in results if r.errors)
        unverified = sum(1 for r in results if r.warnings and not r.errors)
        return JobResult.partly(
            {
                key.value: count
                for key, count in (
                    (DegradedKey.FAILED, failed),
                    (DegradedKey.UNVERIFIED, unverified),
                )
                if count
            }
        )


def write_view(view: RenderedView, base: Path, model: bool = False) -> tuple[Path, ...]:
    """The rendered pair, `<base>.md` and `<base>.html` (its model as `<base>.json`, and its
    export table as `<base>.csv` when the view has one); core stores no view."""
    base.parent.mkdir(parents=True, exist_ok=True)
    out = {base.with_suffix(".md"): view.markdown, base.with_suffix(".html"): view.html}
    if model:
        out[base.with_suffix(".json")] = view.model.model_dump_json(indent=2)
    if view.csv is not None:
        out[base.with_suffix(".csv")] = view.csv
    for path, text in out.items():
        path.write_text(text, encoding="utf-8")
    return tuple(out)


class DashboardsMaterializer:
    """`dashboards`: render every built insight view (or the one in ``partition``) to
    ``<out>/<view>/<stem>.{md,html,json}``. A view that fails is degraded; the rest are written."""

    asset = "dashboards"

    def __init__(self, services: Services, out: Path) -> None:
        self._insight = services.insight
        self._out = out

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            views = None if request.partition is None else [ViewName(request.partition)]
            result = self._insight.refresh(views, ViewFilter())
        except (ValueError, ConfigError) as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        written: list[Path] = []
        for view in result.rendered.values():
            written += write_view(view, self._out / view.view / view.stem, model=True)
        for name, why in result.failed.items():
            log.warning("run %s view %s: %s", request.run_id, name, why)
        degraded = {name.value: 1 for name in result.failed}
        return JobResult.partly(degraded, tuple(map(str, written))).model_copy(
            update={"reason": OrderReason.SOURCE_UNAVAILABLE if result.failed else None}
        )


class BelowRangePacketsMaterializer:
    """`below_range_packets`: below-range packets for one inventory repository's default-branch
    head, recorded for review (source trees live only for the run). A commit with no head or
    no manifest SBOM is refused; a degraded scan is degraded by gap reason."""

    asset = "below_range_packets"

    def __init__(self, services: Services, hosts: Iterable[str]) -> None:
        self._portfolio = services.portfolio
        self._below_range = services.below_range
        self._hosts = tuple(hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            url = HttpsRepoUrl.parse(request.partition or "", self._hosts)
            order = _order_id(request.run_id)
        except (ValidationError, ValueError) as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        repo = self._portfolio.find_repository(url)
        if repo is None or repo.id is None:
            log.warning(
                "run %s: %s: %s is not in the inventory", request.run_id, OrderReason.NOT_FOUND, url
            )
            return JobResult.refused(OrderReason.NOT_FOUND)
        with tempfile.TemporaryDirectory(prefix="below-range-") as workdir:
            try:
                scan = self._below_range.scan(repo.id, Path(workdir), run_order_id=order)
            except NotFoundError as e:
                log.warning("run %s: %s: %s", request.run_id, OrderReason.NOT_FOUND, e)
                return JobResult.refused(OrderReason.NOT_FOUND)
            except ConfigError as e:
                log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
                return JobResult.failed(OrderReason.BAD_REQUEST)
        if scan.packets.status == BelowRangeStatus.COMPLETE:
            return JobResult.succeeded()
        return JobResult.partly(Counter(g.reason.value for g in scan.packets.coverage_gaps))
