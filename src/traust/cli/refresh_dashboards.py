#!/usr/bin/env python3
"""Rebuild every deterministic dashboard in dependency order.

Packages the "Dashboards rebuild" job from docs/continuous-operations.md
as one command: projections first (findings.db, census), then the
per-dashboard builders, then the leadership scoreboard last because it
harvests from the other dashboards' output.

All stages are deterministic scripts (~$0, no agent). A projection
failure aborts the run — every consumer downstream would read stale
data. A consumer failure is recorded and the remaining consumers still
run; the exit code is non-zero if anything failed.

The spend-actuals leg (collect_session_spend.py --append) reads Claude
Code session transcripts on the operator's workstation, so it is NOT
part of the default job (which must stay orchestrator-portable). Opt in
with --spend-actuals when running on a workstation that has transcripts.

Usage:
  python3 -m traust.cli.refresh_dashboards               # full chain
  python3 -m traust.cli.refresh_dashboards --list        # show stages
  python3 -m traust.cli.refresh_dashboards --only trends spend
  python3 -m traust.cli.refresh_dashboards --skip scoreboard
  python3 -m traust.cli.refresh_dashboards --dry-run
  python3 -m traust.cli.refresh_dashboards --spend-actuals --note "weekly"
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)
from traust.paths import HARNESS_ROOT

PYTHON = sys.executable or "python3"


def _config_home_arg(config_home: Path | None) -> list[str]:
    if config_home is None:
        return []
    return ["--config-home", str(config_home)]


def _results_root_arg(results_root: Path) -> list[str]:
    return ["--results-root", str(results_root)]


def _engine_path_args(config_home: Path | None, results_root: Path) -> list[str]:
    return _config_home_arg(config_home) + _results_root_arg(results_root)


def build_stages(
    workspace: Path,
    results_root: Path,
    note: str,
    spend_actuals: bool,
    *,
    config_home: Path | None = None,
    progress_tracker: Path | None = None,
):
    """Ordered (name, tier, argv) stage list. tier: projection stages
    abort the run on failure; consumer stages continue-on-error."""
    h = HARNESS_ROOT
    pt = progress_tracker or (workspace / "progress-tracker")
    path_args = _engine_path_args(config_home, results_root)
    cfg = _config_home_arg(config_home)
    stages = [
        # Both run BEFORE findings-db so the projection picks up stamps
        # written this cycle. Consumer tier deliberately: a network blip
        # or an off-VPN run must not abort the dashboard rebuild — the
        # reconciler is idempotent and simply catches up next week.
        (
            "cve-feed",
            "consumer",
            [PYTHON, "-m", "traust.cli.fetch_feeds", "--feed", "rh-cve", *cfg],
        ),
        (
            "cve-provenance",
            "consumer",
            [
                PYTHON,
                "-m",
                "traust.cli.reconcile_cve_provenance",
                *path_args,
                "--apply",
                "--report",
                str(pt / "metrics" / "first-discovery" / "first-discovery-current.json"),
            ],
        ),
        (
            "findings-db",
            "projection",
            [PYTHON, "-m", "traust.cli", "corpus", "findings-db", *path_args],
        ),
        (
            "census",
            "projection",
            [
                PYTHON,
                str(h / "harnessing/census/scripts/build_census.py"),
                *path_args,
                "--workspace-root",
                str(workspace),
            ],
        ),
        (
            "exec-summary",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/executive-summary-findings/scripts/build_executive_summary.py"),
                *path_args,
            ],
        ),
        (
            "trends",
            "consumer",
            [PYTHON, str(h / "harnessing/findings-trends/scripts/build_trends.py"), *path_args],
        ),
        (
            "insecure-patterns",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/insecure-patterns/scripts/build_insecure_patterns.py"),
                *path_args,
            ],
        ),
        (
            "validation-fuzz",
            "consumer",
            [
                PYTHON,
                str(
                    h / "harnessing/validation-fuzz-dashboard/scripts/"
                    "build_validation_fuzz_dashboard.py"
                ),
                *path_args,
            ],
        ),
        (
            "rbac-tenancy",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/rbac-tenancy-rollup/scripts/build_rbac_tenancy_rollup.py"),
                *cfg,
                "--analysis-results",
                str(results_root),
            ],
        ),
        ("sla", "consumer", [PYTHON, "-m", "traust.cli", "metrics", "sla", *cfg]),
        (
            "compliance",
            "consumer",
            [PYTHON, "-m", "traust.cli", "compliance", "dashboard", *path_args],
        ),
        (
            "attack-coverage",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/attack-coverage/scripts/build_attack_coverage.py"),
                *path_args,
            ],
        ),
        # --no-fetch: rebuild from the committed gh-languages cache only;
        # refreshing the cache hits the GitHub API and stays with the
        # owning skill (see gh-api fleet-sweep constraints).
        (
            "loc",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/loc-dashboard/scripts/build_loc_dashboard.py"),
                *path_args,
                "--no-fetch",
            ],
        ),
        # Dependency exposure reads the portfolio graph's dependency layer
        # + impact/fleet-OSV artifacts (consumer-side; degrades gracefully
        # when the graph or impact dir is absent).
        (
            "dependency-exposure",
            "consumer",
            [
                PYTHON,
                str(h / "harnessing/refresh-dashboards/scripts/build_dependency_exposure.py"),
                *path_args,
            ],
        ),
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
    stages.append(
        (
            "spend",
            "consumer",
            [PYTHON, "-m", "traust.cli", "metrics", "spend", *cfg, "--workspace", str(workspace)],
        )
    )
    # Last on purpose: the scoreboard harvests from the dashboards above.
    scoreboard = [
        PYTHON,
        str(h / "harnessing/traust-metrics/scripts/collect_harness_metrics.py"),
        *path_args,
        "--workspace-root",
        str(workspace),
    ]
    if note:
        scoreboard += ["--note", note]
    stages.append(("scoreboard", "consumer", scoreboard))
    return stages


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Rebuild all deterministic dashboards in "
        "dependency order (projections before consumers)."
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
        "--note", default="", help="Forwarded to the scoreboard's metrics-history snapshot row"
    )
    ap.add_argument("--list", action="store_true", help="List stages and exit")
    ap.add_argument(
        "--dry-run", action="store_true", help="Print the commands without running them"
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    workspace = (args.workspace_root or workspace_dir(engine)).resolve()
    results_root = resolve_results_root(args)
    tracker = progress_tracker_dir(engine)
    spend_actuals = args.spend_actuals or args.list or "spend-actuals" in (args.only or [])
    stages = build_stages(
        workspace,
        results_root,
        args.note,
        spend_actuals,
        config_home=args.config_home,
        progress_tracker=tracker,
    )

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

    results = []
    for name, tier, cmd in selected:
        if args.dry_run:
            print(f"[dry-run] {name}: {' '.join(cmd)}")
            continue
        print(f"==> {name} ({tier})", flush=True)
        start = time.monotonic()
        proc = subprocess.run(cmd, cwd=HARNESS_ROOT)
        elapsed = time.monotonic() - start
        ok = proc.returncode == 0
        results.append((name, tier, ok, elapsed))
        if not ok and tier == "projection":
            print(
                f"ABORT: projection stage '{name}' failed "
                f"(rc={proc.returncode}); consumers would read stale "
                f"data. Nothing after it was run.",
                file=sys.stderr,
            )
            break

    if args.dry_run:
        return 0

    print("\n== refresh-dashboards summary ==")
    failed = [n for n, _, ok, _ in results if not ok]
    for name, tier, ok, elapsed in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {name:20s} {tier:10s} {elapsed:6.1f}s")
    skipped = [
        n
        for n, _, _ in stages
        if n not in {r[0] for r in results} and (args.only is None or n in args.only)
    ]
    if skipped:
        print(f"  not run: {', '.join(skipped)}")
    if not spend_actuals and (args.only is None or "spend" in args.only):
        print(
            "  note: spend actuals not appended (operator-side leg; "
            "rerun with --spend-actuals on a workstation with "
            "session transcripts)"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["dashboard", "refresh", *sys.argv[1:]]))
