"""Rule-pack fixture sanity, confirmed-TP checkout/rescans, or recorded-scan scoring."""

from __future__ import annotations

import uuid
from pathlib import Path

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.rule_calibration import (
    CalibrationStatus,
    PackCalibrationRun,
    RuleCalibrationRequest,
)

from traust.cli._doors import parser, run
from traust.cli.findings import _quoted_json
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("impact", "calibrate-rule-pack", "Calibrate a rule pack against confirmed TPs.")
    ap.add_argument(
        "pack", nargs="?", default="traust", help="registered rule pack (default: traust)"
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--scan", action="append", type=uuid.UUID, help="recorded scan id (repeatable)"
    )
    mode.add_argument("--fixtures", action="store_true", help="scan the pack's own fixture tree")
    ap.add_argument("--rules", help="local rules tree/file or HTTPS rules repository pinned @SHA")
    ap.add_argument("--limit", type=int, help="maximum confirmed-TP commits to check out")
    ap.add_argument("--timeout", type=int, default=900, help="scanner timeout in seconds")
    ap.add_argument("--opengrep-bin", default="opengrep", help="opengrep binary")
    ap.add_argument(
        "--out", "--out-dir", dest="out", type=Path, help="summary/review output directory"
    )
    args = ap.parse_args(argv)
    if args.scan and (args.rules or args.limit is not None):
        ap.error("--rules and --limit apply to live calibration, not --scan")
    exit_code = 0

    def call() -> str:
        nonlocal exit_code
        services = load(args.config_home).services()
        if args.scan:
            packs = {p.name: p for p in services.detection_quality.rule_packs()}
            if args.pack not in packs:
                raise NotFoundError(f"rule pack {args.pack!r}: not one of {sorted(packs)}")
            calibration = services.detection_quality.calibrate(packs[args.pack], args.scan)
            if args.out:
                args.out.mkdir(parents=True, exist_ok=True)
                (args.out / "calibration.json").write_text(
                    calibration.model_dump_json(indent=2) + "\n", encoding="utf-8"
                )
            return calibration.model_dump_json(indent=2)
        result = services.detection_quality.calibrate_pack(
            RuleCalibrationRequest(
                pack=args.pack,
                rules=args.rules,
                fixtures=args.fixtures,
                limit=args.limit,
                timeout=args.timeout,
                binary=args.opengrep_bin,
            )
        )
        exit_code = 0 if result.status is CalibrationStatus.COMPLETED else 1
        if args.out:
            _write_run(args.out, result)
        return result.model_dump_json(indent=2)

    rc = run(call)
    return rc or exit_code


def _write_run(out: Path, result: PackCalibrationRun) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "calibration.json").write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    summary = {"pack": result.pack.name, "status": result.status, **result.summary}
    if result.fixture:
        summary["fixture"] = result.fixture.model_dump(mode="json")
    (out / "summary.md").write_text(
        "# Rule-pack calibration\n\n" + _quoted_json(summary) + "\n", encoding="utf-8"
    )
    samples = result.review_sample
    if result.fixture:
        samples = result.fixture.scan.hits[:100]
    (out / "review-samples.jsonl").write_text(
        "".join(sample.model_dump_json() + "\n" for sample in samples), encoding="utf-8"
    )
