"""``traust impact calibrate-rule-pack``: score a rule pack's recorded scans against the confirmed
true positives in traust-core (`DetectionQualityService.calibrate`).

Record the pack's scans first (``traust triage intake``); this reads them, it scans nothing.
"""

from __future__ import annotations

import uuid

from traust_core.v1.errors import NotFoundError

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("impact", "calibrate-rule-pack", "Score a rule pack's scans against confirmed TPs.")
    ap.add_argument("pack", help="the rule pack's name (one of DetectionQualityService.rule_packs)")
    ap.add_argument(
        "--scan", action="append", required=True, type=uuid.UUID, help="a scan's id (repeatable)"
    )
    args = ap.parse_args(argv)

    def call() -> str:
        services = load(args.config_home).services()
        packs = {p.name: p for p in services.detection_quality.rule_packs()}
        if args.pack not in packs:
            raise NotFoundError(f"rule pack {args.pack!r}: not one of {sorted(packs)}")
        calibration = services.detection_quality.calibrate(packs[args.pack], args.scan)
        return calibration.model_dump_json(indent=2)

    return run(call)
