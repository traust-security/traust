from __future__ import annotations

import logging
from uuid import UUID

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.release_inventory import RELEASE_INVENTORY_FEED

from traust.ops.materializers import _order_id
from traust.release_config import RELEASE_ROUTING

log = logging.getLogger(__name__)


class ReleaseDiscoveryMaterializer:
    asset = "release_discovery"

    def __init__(self, services: Services, principal: Principal) -> None:
        self._releases, self._principal = services.releases, principal

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            report = self._releases.discover(
                self._principal, RELEASE_ROUTING, _order_id(request.run_id)
            )
        except (ValueError, ConfigError, ValidationError) as error:
            log.warning("run %s: release discovery refused: %s", request.run_id, error)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        except ServiceError as error:
            log.warning("run %s: release discovery unavailable: %s", request.run_id, error)
            return JobResult.failed(OrderReason.SOURCE_UNAVAILABLE)
        return JobResult.partly(
            {RELEASE_INVENTORY_FEED: len(report.skipped)} if report.skipped else {},
            written=tuple(map(str, report.release_ids + report.order_ids)),
        )


class ReleasePassthroughMaterializer:
    asset = "release_passthrough"

    def __init__(self, services: Services, principal: Principal) -> None:
        self._releases, self._principal = services.releases, principal

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            order_id: UUID | None = _order_id(request.run_id)
            orders = self._releases.passthrough(self._principal, RELEASE_ROUTING, order_id)
        except (ValueError, ConfigError, ValidationError) as error:
            log.warning("run %s: release passthrough refused: %s", request.run_id, error)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        except NotFoundError as error:
            log.warning("run %s: release targets unavailable: %s", request.run_id, error)
            return JobResult.refused(OrderReason.NOT_FOUND)
        return JobResult.succeeded(written=tuple(str(order.id) for order in orders))
