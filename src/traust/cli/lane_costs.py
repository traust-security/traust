"""``traust metrics lane-costs``: each lane's median settled cost per order over the last days,
from the spend `traust-engine claim` recorded against its orders (`SpendService.lane_costs`)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from traust_core.v1.models.common import TimeWindow

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "metrics",
        "lane-costs",
        "Each lane's median settled cost per order, with the orders and events behind it: the "
        "measure to set a lane's admission estimate_usd from.",
    )
    ap.add_argument("--days", type=int, default=30, help="the window: the last N days (default 30)")
    args = ap.parse_args(argv)
    if args.days < 1:
        ap.error("--days must be at least 1")

    def call() -> Any:
        end = datetime.now(UTC)
        window = TimeWindow(start=end - timedelta(days=args.days), end=end)
        lanes = load(args.config_home).services().spend.lane_costs(window)
        return {
            "window": window.model_dump(mode="json"),
            "lanes": [lane.model_dump(mode="json") for lane in lanes],
        }

    return run(call)
