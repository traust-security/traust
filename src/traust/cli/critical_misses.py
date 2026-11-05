"""Export the recorded critical misses of a window: critical findings first reported in it that an
earlier audit of the repository missed (`DetectionQualityService.critical_misses`)."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.detection_quality import CriticalMiss
from traust_core.v1.rendering.markdown import markdown_table, markdown_text

from traust.cli._doors import parser, run
from traust.cli.groups._registry import OpSpec
from traust.context import analysis_results_dir, load


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--out", type=Path, help="Markdown destination (default: CRITICAL-MISSES.md)")
    ap.add_argument("--json-out", type=Path, help="JSON destination (default: beside Markdown)")
    ap.add_argument("--start", type=datetime.fromisoformat, help="recorded findings window start")
    ap.add_argument(
        "--end", type=datetime.fromisoformat, help="recorded findings window end, exclusive"
    )


def _window(args: argparse.Namespace) -> TimeWindow:
    if args.start is None or args.end is None:
        raise ValidationError("--start and --end must be supplied together")
    if args.start.tzinfo is None or args.end.tzinfo is None:
        raise ValidationError("--start and --end must include time zones")
    if args.start >= args.end:
        raise ValidationError("--start must precede --end")
    return TimeWindow(start=args.start, end=args.end)


def critical_miss_markdown(window: TimeWindow, misses: Sequence[CriticalMiss]) -> str:
    """The misses as one table; titles come from audited reports and validity from recorded
    decisions, so every text cell is escaped."""
    lines = [
        "# Critical misses",
        "",
        f"Window: {window.start.isoformat()} to {window.end.isoformat()} (end exclusive).",
        f"Misses: {len(misses)}; an `area_reported` row is for adjudication, not a hit.",
        "",
    ]
    rows = [
        (
            str(m.repository_id),
            str(m.finding_id),
            markdown_text(m.title),
            m.found_at.isoformat(),
            str(m.found_by),
            str(m.missed_by),
            m.reason.value,
            markdown_text(m.validity) if m.validity else "",
        )
        for m in misses
    ]
    columns = ("Repository", "Finding", "Title", "Found at", "Found by", "Missed by", "Reason")
    lines += markdown_table((*columns, "Validity"), rows)
    return "\n".join(lines) + "\n"


def call(args: argparse.Namespace) -> int:
    def export() -> dict[str, str | int]:
        window = _window(args)
        core = load(args.config_home)
        misses = core.services().detection_quality.critical_misses(window)
        out = args.out or analysis_results_dir(core) / "CRITICAL-MISSES.md"
        json_out = args.json_out or out.with_suffix(".json")
        if out.resolve() == json_out.resolve():
            raise ValidationError("Markdown and JSON destinations must differ")
        out.parent.mkdir(parents=True, exist_ok=True)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(critical_miss_markdown(window, misses), encoding="utf-8")
        document = [m.model_dump(mode="json") for m in misses]
        json_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return {"markdown": str(out), "json": str(json_out), "recorded_misses": len(misses)}

    return run(export)


CRITICAL_MISSES = OpSpec(
    add_args=add_args,
    call=call,
    help="export a window's recorded critical misses",
)


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "critical-misses", __doc__ or "")
    add_args(ap)
    return call(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
