"""``traust portfolio release-passthrough``: the ``release_passthrough`` asset's door."""

from __future__ import annotations

from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import answer, parser
from traust.ops.materializers import MANUAL
from traust.ops.releases import ReleasePassthroughMaterializer


def passthrough(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "release-passthrough",
        "Plan container and RPM audits for a release (refused: NEED(release-passthrough)).",
    )
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    materializer = ReleasePassthroughMaterializer()
    return answer(
        materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
    )
