from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.input_segments import InputSegmentInventory
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.operations import (
    AssetRequest,
    DegradedKey,
    JobResult,
    OrderReason,
    OrderRequest,
    RescanEventSource,
)
from traust_core.v1.models.vocabulary import ComparisonStatus

from traust.ops.materializers import _repo_url
from traust.ops.router import SecurityRouter, event_route

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RescanEvent:
    source: RescanEventSource
    repo: str


def _rescan_events(path: Path) -> tuple[RescanEvent, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ()
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"reading rescan events {path}: {error}") from error
    events = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("row must be an object")
            consumed = row.get("consumed", False)
            if not isinstance(consumed, bool):
                raise ValueError("consumed must be a boolean")
            if consumed:
                continue
            source = RescanEventSource(row.get("source"))
            if source is RescanEventSource.RELEASE:
                raise ValueError("release events use the native release-discovery feed")
            repo = str(_repo_url(row.get("repo")))
        except (TypeError, ValueError, ValidationError) as error:
            raise ConfigError(f"{path}:{line_number}: invalid rescan event: {error}") from error
        events.append(RescanEvent(source, repo))
    return tuple(events)


class InventoryDiscoveryMaterializer:
    """Register configured input repositories and plan their first observation and audit."""

    asset = "inventory_discovery"

    def __init__(
        self,
        services: Services,
        states: Any,
        inventory: InputSegmentInventory,
        principal: Principal,
    ) -> None:
        self._portfolio, self._ops = services.portfolio, services.ops
        self._states, self._inventory, self._principal = states, inventory, principal

    def materialize(self, request: AssetRequest) -> JobResult:
        written: list[str] = []
        try:
            urls = sorted(
                {url for segment in self._inventory.segments for url in segment.repository_urls}
            )
            for raw in urls:
                url = _repo_url(raw)
                repository = self._portfolio.find_repository(url)
                if repository is None:
                    repository = self._portfolio.register_repository(url, public=False)
                assert repository.id is not None
                observation = self._ops.plan(
                    OrderRequest(asset="repo_state", priority=20, repository_id=repository.id),
                    self._principal,
                )
                written.append(str(observation.id))
                [state] = self._states.list(
                    RepositoryFilter(url=str(url)), PageRequest(limit=1)
                ).items
                if state.status is ComparisonStatus.NEVER_AUDITED:
                    route = SecurityRouter().route(state, (), ())[0]
                    bootstrap = self._ops.plan(
                        OrderRequest(
                            asset="full_audit",
                            priority=route.priority,
                            repository_id=repository.id,
                            lane=route.lane,
                            rule=route.reason,
                        ),
                        self._principal,
                    )
                    written.append(str(bootstrap.id))
        except (ConfigError, ValidationError, ValueError) as error:
            log.warning("run %s: inventory discovery refused: %s", request.run_id, error)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        return JobResult.succeeded(written=tuple(dict.fromkeys(written)))


class RescanEventIntakeMaterializer:
    """Turn each unconsumed external-report, methodology or CVE record into an engine order."""

    asset = "rescan_event_intake"
    _assets: ClassVar[dict[RescanEventSource, str]] = {
        RescanEventSource.EXTERNAL_REPORT: "external_report_audit",
        RescanEventSource.METHODOLOGY: "methodology_audit",
        RescanEventSource.CVE: "cve_impact",
    }

    def __init__(self, services: Services, states: Any, principal: Principal, events: Path) -> None:
        self._portfolio, self._ops = services.portfolio, services.ops
        self._states, self._principal, self._events = states, principal, events

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            events = _rescan_events(self._events)
        except ConfigError as error:
            log.warning("run %s: event intake refused: %s", request.run_id, error)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        routed = []
        unavailable = 0
        for event in events:
            repository = self._portfolio.find_repository(event.repo)
            if repository is None or repository.id is None:
                log.warning(
                    "run %s: event repository is not registered: %s", request.run_id, event.repo
                )
                unavailable += 1
                continue
            [state] = self._states.list(
                RepositoryFilter(url=event.repo), PageRequest(limit=1)
            ).items
            route = event_route(state, event.source)
            if route is None:
                log.info(
                    "run %s: %s event honored without a route for %s",
                    request.run_id,
                    event.source,
                    event.repo,
                )
                continue
            routed.append((event, repository.id, route))
        written = []
        for event, repository_id, route in routed:
            order = self._ops.plan(
                OrderRequest(
                    asset=self._assets[event.source],
                    priority=route.priority,
                    repository_id=repository_id,
                    lane=route.lane,
                    event_source=event.source,
                ),
                self._principal,
            )
            written.append(str(order.id))
        if unavailable:
            return JobResult.partly(
                {DegradedKey.ERROR: unavailable}, written=tuple(dict.fromkeys(written))
            )
        return JobResult.succeeded(written=tuple(dict.fromkeys(written)))
