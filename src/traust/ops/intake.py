from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.common import PageRequest, every_item
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.input_segments import InputSegmentInventory
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetRequest,
    ConfigDigest,
    DegradedKey,
    JobResult,
    OrderFilter,
    OrderManifest,
    OrderReason,
    OrderRequest,
    RescanEventSource,
)
from traust_core.v1.models.vocabulary import ComparisonStatus

from traust.ops.materializers import _repo_url
from traust.ops.router import SecurityRouter, event_route

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExternalValidationInput:
    report: str
    targets: str


@dataclass(frozen=True, slots=True)
class RescanEvent:
    source: RescanEventSource
    repo: str
    identity: str
    validation: ExternalValidationInput | None = None


_EVENT_CONFIG = "rescan-event:"
_VALIDATION_CONFIG = "external-validation:"


def _event_config(event: RescanEvent) -> tuple[ConfigDigest, ...]:
    identity = ConfigDigest(name=_EVENT_CONFIG + event.identity, digest=event.identity)
    return (identity, *_external_validation_config(event))


def _has_event_identity(manifest: OrderManifest, event: RescanEvent) -> bool:
    return any(
        entry.name == _EVENT_CONFIG + event.identity and entry.digest == event.identity
        for entry in manifest.config
    )


def _required(row: dict[str, object], field: str) -> str:
    value = row.get(field)
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{field} must be one nonblank whitespace-free reference")
    return value


def _external_validation_config(event: RescanEvent) -> tuple[ConfigDigest, ...]:
    if event.validation is None:
        return ()
    payload = json.dumps(
        {"report": event.validation.report, "targets": event.validation.targets},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    encoded = payload.hex()
    return (ConfigDigest(name=_VALIDATION_CONFIG + encoded, digest=sha256_hex(payload)),)


def external_validation_input(manifest: OrderManifest) -> ExternalValidationInput:
    matches = tuple(row for row in manifest.config if row.name.startswith(_VALIDATION_CONFIG))
    if len(matches) != 1:
        raise ValidationError("external validation order has no single bound input")
    [entry] = matches
    encoded = entry.name.removeprefix(_VALIDATION_CONFIG)
    try:
        payload = bytes.fromhex(encoded)
        document = json.loads(payload)
        if not isinstance(document, dict) or sha256_hex(payload) != entry.digest:
            raise ValueError("invalid external validation input digest")
        return ExternalValidationInput(
            report=_required(document, "report"), targets=_required(document, "targets")
        )
    except (ValueError, UnicodeError) as error:
        raise ValidationError("invalid external validation input") from error


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
            validation = (
                ExternalValidationInput(_required(row, "report"), _required(row, "targets"))
                if source is RescanEventSource.EXTERNAL_REPORT
                else None
            )
            canonical = {**row, "repo": repo, "source": source.value}
            canonical.pop("consumed", None)
            identity = sha256_hex(
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise ConfigError(f"{path}:{line_number}: invalid rescan event: {error}") from error
        events.append(RescanEvent(source, repo, identity, validation))
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
        except ConfigError as error:
            log.warning("run %s: inventory discovery refused: %s", request.run_id, error)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        failures = 0
        for raw in urls:
            try:
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
                failures += 1
                log.warning(
                    "run %s: inventory URL %r refused (%s): %s",
                    request.run_id,
                    raw,
                    type(error).__name__,
                    error,
                )
        unique = tuple(dict.fromkeys(written))
        if failures:
            return JobResult.partly({DegradedKey.ERROR: failures}, written=unique)
        return JobResult.succeeded(written=unique)


class RescanEventIntakeMaterializer:
    """Turn each unconsumed external-report, methodology or CVE record into an engine order."""

    asset = "rescan_event_intake"
    _assets: ClassVar[dict[RescanEventSource, tuple[str, ...]]] = {
        RescanEventSource.EXTERNAL_REPORT: (
            "external_report_audit",
            "external_report_validation",
        ),
        RescanEventSource.METHODOLOGY: ("methodology_audit",),
        RescanEventSource.CVE: ("cve_impact",),
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
        blocked = 0
        for event, repository_id, route in routed:
            for offset, asset in enumerate(self._assets[event.source]):
                history = tuple(
                    every_item(
                        lambda page, asset=asset, repository_id=repository_id: self._ops.list(
                            OrderFilter(asset=asset, repository_id=repository_id), page
                        )
                    )
                )
                if any(
                    _has_event_identity(self._ops.manifest(order.id), event) for order in history
                ):
                    continue
                if any(order.state in OPEN_ORDER_STATES for order in history):
                    blocked += 1
                    continue
                order = self._ops.plan(
                    OrderRequest(
                        asset=asset,
                        priority=route.priority + offset,
                        repository_id=repository_id,
                        lane=route.lane,
                        event_source=event.source,
                    ),
                    self._principal,
                    config=_event_config(event),
                )
                if not _has_event_identity(self._ops.manifest(order.id), event):
                    blocked += 1
                    continue
                written.append(str(order.id))
        degraded = unavailable + blocked
        if degraded:
            return JobResult.partly(
                {DegradedKey.ERROR: degraded}, written=tuple(dict.fromkeys(written))
            )
        return JobResult.succeeded(written=tuple(dict.fromkeys(written)))
