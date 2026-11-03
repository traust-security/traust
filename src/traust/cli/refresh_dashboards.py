#!/usr/bin/env python3
"""Rebuild every deterministic dashboard: the `dashboards` asset, by hand or from a runner.

Packages the "Dashboards rebuild" job from docs/continuous-operations.md
as one command: first traust-core's insight views (`DashboardsMaterializer`,
one `InsightService.refresh`, the leadership scoreboard among them), then the
builders of the dashboards core has no view for yet.

All stages are deterministic (~$0, no agent). A failure is recorded and
the remaining stages still run; the exit code is non-zero if anything failed.
The summary goes to stderr: a runner reads the views stage's JobResult as the last stdout line.

The spend-actuals leg (collect_session_spend.py --append) reads Claude
Code session transcripts on the operator's workstation, so it is NOT
part of the default job (which must stay orchestrator-portable). Opt in
with --spend-actuals when running on a workstation that has transcripts.

Usage:
  python3 -m traust.cli.refresh_dashboards               # full chain
  python3 -m traust.cli.refresh_dashboards --list        # show stages
  python3 -m traust.cli.refresh_dashboards --only views validation-fuzz
  python3 -m traust.cli.refresh_dashboards --view findings-rollup --out /tmp/dashboards
  python3 -m traust.cli.refresh_dashboards --skip validation-fuzz
  python3 -m traust.cli.refresh_dashboards --dry-run
  python3 -m traust.cli.refresh_dashboards --spend-actuals
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

from traust_core.v1.models.insight import ViewName
from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import EXIT_CODES
from traust.context import (
    add_config_home_arg,
    load,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)
from traust.ops.materializers import MANUAL, DashboardsMaterializer
from traust.paths import HARNESS_ROOT

VIEWS = "views"

PYTHON = sys.executable or "python3"


def _config_home_arg(config_home: Path | None) -> list[str]:
    if config_home is None:
        return []
    return ["--config-home", str(config_home)]


def build_stages(
    workspace: Path,
    results_root: Path,
    spend_actuals: bool,
    *,
    config_home: Path | None = None,
):
    """Ordered (name, tier, argv) stage list, each continue-on-error. The VIEWS stage renders
    every built traust-core insight view in-process; the remaining stages are spend capture."""
    cfg = _config_home_arg(config_home)
    stages = [
        (VIEWS, "core", []),  # InsightService.refresh renders every built view, in-process
    ]
    if spend_actuals:
        stages.append(
            (
                "spend-actuals",
                "consumer",
                [
                    PYTHON,
                    "-m",
                    "traust.cli",
                    "metrics",
                    "collect-spend",
                    *cfg,
                    "--append",
                    "--workspace",
                    str(workspace),
                ],
            )
        )
    return stages


def run_views(args, out: Path) -> int:
    """The `dashboards` asset's materializer: one InsightService.refresh; prints its JobResult."""
    materializer = DashboardsMaterializer(load(args.config_home).services(), out)
    result = materializer.materialize(
        AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.view)
    )
    print(result.model_dump_json(), flush=True)
    return EXIT_CODES[result.outcome]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Rebuild all deterministic dashboards: traust-core's views, "
        "then the remaining builders."
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="Campaign workspace holding the inputs inventory (default: configured workspace)",
    )
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (default: --results-root / $AUDIT_RESULTS_ROOT / config)",
    )
    ap.add_argument(
        "--only",
        nargs="*",
        default=None,
        metavar="STAGE",
        help="Run only these stages (still in canonical order)",
    )
    ap.add_argument(
        "--skip", action="append", default=[], metavar="STAGE", help="Skip a stage (repeatable)"
    )
    ap.add_argument(
        "--spend-actuals",
        action="store_true",
        help="Also append spend actuals from local session "
        "transcripts (operator workstations only)",
    )
    ap.add_argument(
        "--view",
        choices=[v.value for v in ViewName],
        help="the views stage renders only this insight view (default: every built view)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="where the views stage writes <view>/<stem>.{md,html,json} "
        "(default: <progress-tracker>/metrics/dashboards)",
    )
    ap.add_argument("--run-id", default=MANUAL, help="the run order this refresh is for")
    ap.add_argument("--list", action="store_true", help="List stages and exit")
    ap.add_argument(
        "--dry-run", action="store_true", help="Print the commands without running them"
    )
    args = ap.parse_args(argv)

    core = load(args.config_home)
    workspace = (args.workspace_root or workspace_dir(core)).resolve()
    results_root = resolve_results_root(args)
    spend_actuals = args.spend_actuals or args.list or "spend-actuals" in (args.only or [])
    stages = build_stages(workspace, results_root, spend_actuals, config_home=args.config_home)

    if args.list:
        for name, tier, _ in stages:
            print(f"{name:20s} {tier}")
        return 0

    known = {name for name, _, _ in stages}
    for requested in (args.only or []) + args.skip:
        if requested not in known:
            ap.error(f"unknown stage '{requested}' (see --list; known: {', '.join(sorted(known))})")

    if not results_root.is_dir():
        ap.error(f"results root not found: {results_root}")

    selected = [
        (n, t, cmd)
        for n, t, cmd in stages
        if (args.only is None or n in args.only) and n not in args.skip
    ]

    out = args.out or progress_tracker_dir(core) / "metrics" / "dashboards"
    results = []
    views_rc = 0
    for name, tier, cmd in selected:
        if args.dry_run:
            print(f"[dry-run] {name}: {' '.join(cmd) or f'InsightService.refresh -> {out}'}")
            continue
        print(f"==> {name} ({tier})", flush=True)
        start = time.monotonic()
        if name == VIEWS:
            views_rc = run_views(args, out)
            rc = views_rc
        else:
            rc = subprocess.run(cmd, cwd=HARNESS_ROOT).returncode
        results.append((name, tier, rc == 0, time.monotonic() - start))

    if args.dry_run:
        return 0

    print("\n== refresh-dashboards summary ==", file=sys.stderr)
    failed = [n for n, _, ok, _ in results if not ok]
    for name, tier, ok, elapsed in results:
        mark = "ok  " if ok else "FAIL"
        print(f"  {mark} {name:20s} {tier:10s} {elapsed:6.1f}s", file=sys.stderr)
    skipped = [
        n
        for n, _, _ in stages
        if n not in {r[0] for r in results} and (args.only is None or n in args.only)
    ]
    if skipped:
        print(f"  not run: {', '.join(skipped)}", file=sys.stderr)
    if not spend_actuals and args.only is None:
        print(
            "  note: spend actuals not appended (operator-side leg; "
            "rerun with --spend-actuals on a workstation with "
            "session transcripts)",
            file=sys.stderr,
        )
    return views_rc or (1 if failed else 0)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["dashboard", "refresh", *sys.argv[1:]]))
