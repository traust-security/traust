"""Export the campaign's critical candidate worklist without ingesting findings."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from traust_core.v1.context.critical_misses import critical_miss_markdown, read_critical_campaign
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeWindow

from traust.cli._doors import parser, run
from traust.cli.groups._registry import OpSpec
from traust.cli.impact import harness_version
from traust.context import analysis_results_dir, load


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--campaign-dir", type=Path, required=True, help="campaign directory to read")
    ap.add_argument("--out", type=Path, help="Markdown destination (default: CRITICAL-MISSES.md)")
    ap.add_argument("--json-out", type=Path, help="JSON destination (default: beside Markdown)")
    ap.add_argument("--start", type=datetime.fromisoformat, help="recorded findings window start")
    ap.add_argument(
        "--end", type=datetime.fromisoformat, help="recorded findings window end, exclusive"
    )


def call(args: argparse.Namespace) -> int:
    def export() -> dict[str, str | int]:
        window = None
        if args.start is not None or args.end is not None:
            if args.start is None or args.end is None:
                raise ValidationError("--start and --end must be supplied together")
            if args.start.tzinfo is None or args.end.tzinfo is None:
                raise ValidationError("--start and --end must include time zones")
            if args.start >= args.end:
                raise ValidationError("--start must precede --end")
            window = TimeWindow(start=args.start, end=args.end)
        core = load(args.config_home)
        campaign = read_critical_campaign(args.campaign_dir)
        report = core.services().detection_quality.critical_miss_report(
            campaign, window=window, harness_version=harness_version()
        )
        out = args.out or analysis_results_dir(core) / "CRITICAL-MISSES.md"
        json_out = args.json_out or out.with_suffix(".json")
        if out.resolve() == json_out.resolve():
            raise ValidationError("Markdown and JSON destinations must differ")
        out.parent.mkdir(parents=True, exist_ok=True)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(critical_miss_markdown(report), encoding="utf-8")
        json_out.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return {
            "markdown": str(out),
            "json": str(json_out),
            "campaign_candidates": len(report.candidates),
            "recorded_misses": len(report.recorded_misses),
        }

    return run(export)


CRITICAL_MISSES = OpSpec(
    add_args=add_args,
    call=call,
    help="export critical campaign candidates, triage and human-gated routing states",
)


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "critical-misses", __doc__ or "")
    add_args(ap)
    return call(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
