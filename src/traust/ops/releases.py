"""The security pack's ``release_passthrough`` asset: the router's rule-1 `release-passthrough`
lane for a release event.

NEED(release-passthrough): traust-core has no release door. The rewire target is a release feed
registered with ``core.feeds.register`` whose observations plan the container and RPM audits
through ``services.ops.plan``; until that lands, a passthrough order is refused rather than run
against a guess. Release recording and planning from the input inventory are retired (R11: a
release's identity never comes from inventory paths; the router's ``released`` re-models).
"""

from __future__ import annotations

import logging

from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason

log = logging.getLogger(__name__)


class ReleasePassthroughMaterializer:
    asset = "release_passthrough"

    def materialize(self, request: AssetRequest) -> JobResult:
        log.warning(
            "run %s: release passthrough refused: no traust-core release feed to plan from"
            " (NEED(release-passthrough))",
            request.run_id,
        )
        return JobResult.refused(OrderReason.SOURCE_UNAVAILABLE)
