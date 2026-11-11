"""Export the recorded critical misses of a window: critical findings first reported in it that an
earlier audit of the repository missed (`DetectionQualityService.critical_misses`)."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import cast

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.insight import CriticalMisses, ViewFilter, ViewName

from traust.cli._doors import parser, run
from traust.cli._report_files import report_paths, write_reports
from traust.cli.groups._registry import OpSpec
from traust.context import analysis_results_dir, load


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--json-out", type=Path, help="JSON destination (default: CRITICAL-MISSES.json)"
    )
    ap.add_argument(
        "--out", type=Path, help="Markdown destination (default: beside JSON, with an HTML sibling)"
    )
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


def call(args: argparse.Namespace) -> int:
    def export() -> dict[str, str | int]:
        window = _window(args)
        core = load(args.config_home)
        json_out = args.json_out or analysis_results_dir(core) / "CRITICAL-MISSES.json"
        markdown_out = args.out or json_out.with_suffix(".md")
        html_out = markdown_out.with_suffix(".html")
        json_path, markdown_path, html_path = report_paths((json_out, markdown_out, html_out))
        rendered = core.services().insight.publish(
            ViewName.CRITICAL_MISSES, ViewFilter(window=window)
        )
        model = cast(CriticalMisses, rendered.model)
        outputs = {
            json_path: json.dumps([miss.model_dump(mode="json") for miss in model.misses], indent=2)
            + "\n",
            markdown_path: rendered.markdown,
            html_path: rendered.html,
        }
        write_reports(outputs)
        return {
            "json": str(json_out),
            "markdown": str(markdown_out),
            "html": str(html_out),
            "recorded_misses": len(model.misses),
        }

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
