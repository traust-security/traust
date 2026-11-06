"""Export the recorded critical misses of a window: critical findings first reported in it that an
earlier audit of the repository missed (`DetectionQualityService.critical_misses`)."""

from __future__ import annotations

import argparse
import json
import shutil
import stat
from datetime import datetime
from pathlib import Path
from tempfile import mkdtemp
from typing import cast

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.insight import CriticalMisses, ViewFilter, ViewName

from traust.cli._doors import parser, run
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


def _report_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    resolved = tuple(path.resolve() for path in paths)
    if len(set(resolved)) != len(resolved):
        raise ValidationError("JSON, Markdown and HTML destinations must be distinct")
    identities = set()
    for path in resolved:
        if any(path in other.parents for other in resolved):
            raise ValidationError("Report destinations cannot contain one another")
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f"Report destination is not a regular file: {path}")
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValidationError("JSON, Markdown and HTML destinations must be distinct")
        identities.add(identity)
    return resolved


def _write_reports(outputs: dict[Path, str]) -> None:
    """Stage the complete set; restore previous files after a handled publication failure."""
    directories: list[Path] = []
    staged: list[tuple[Path, Path, Path | None]] = []
    changed: list[tuple[Path, Path | None]] = []
    retain_backups = False
    try:
        for path, content in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            directory = Path(mkdtemp(prefix=".critical-misses-", dir=path.parent))
            directories.append(directory)
            new = directory / "new"
            new.write_text(content, encoding="utf-8")
            backup = None
            if path.exists():
                new.chmod(stat.S_IMODE(path.stat().st_mode))
                backup = directory / "previous"
            staged.append((new, path, backup))
        try:
            for new, path, backup in staged:
                if backup is not None:
                    path.replace(backup)
                changed.append((path, backup))
                new.replace(path)
        except OSError as failure:
            recovery_errors = []
            for path, backup in reversed(changed):
                try:
                    if backup is None:
                        path.unlink(missing_ok=True)
                    else:
                        backup.replace(path)
                except OSError as recovery_error:
                    recovery_errors.append(f"{path}: {recovery_error}")
            if recovery_errors:
                retain_backups = True
                locations = ", ".join(str(directory) for directory in directories)
                raise OSError(
                    f"Report publication failed ({failure}); rollback incomplete: "
                    f"{'; '.join(recovery_errors)}. Recovery files retained in: {locations}"
                ) from failure
            raise
    finally:
        if not retain_backups:
            for directory in directories:
                shutil.rmtree(directory)


def call(args: argparse.Namespace) -> int:
    def export() -> dict[str, str | int]:
        window = _window(args)
        core = load(args.config_home)
        json_out = args.json_out or analysis_results_dir(core) / "CRITICAL-MISSES.json"
        markdown_out = args.out or json_out.with_suffix(".md")
        html_out = markdown_out.with_suffix(".html")
        json_path, markdown_path, html_path = _report_paths((json_out, markdown_out, html_out))
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
        _write_reports(outputs)
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
