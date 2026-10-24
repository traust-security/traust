"""``traust sweep …`` — class-generalization sweep, benchmark, rule-mining lane."""

from __future__ import annotations

import sys
from pathlib import Path

from traust_contracts import DeploymentConfigMissing
from traust_core.v1.errors import NotFoundError
from traust_engine.locations import SWEEPS_REL
from traust_engine.sweep.engine import DEFAULT_SWEEP_LIMIT

from traust.cli._doors import run
from traust.cli.groups._registry import OpSpec, passthrough_op
from traust.context import load_engine_core, rule_drafts_dir


def _add_common_sweep_args(ap) -> None:
    ap.add_argument(
        "--sweeps-root",
        type=Path,
        default=None,
        help="default <analysis-results>/scan-testing/sweeps",
    )
    ap.add_argument("--analysis-results", default=None)
    ap.add_argument(
        "--pack",
        type=Path,
        default=None,
        help="rule pack dir (default: locations.opengrep_rules, env, bundled)",
    )
    ap.add_argument(
        "--drafts-dir",
        type=Path,
        default=None,
        help=(
            "rule drafts dir (default: locations.rule_drafts or"
            " <progress_tracker>/metrics/rule-mining/rule-drafts)"
        ),
    )


def _analysis_results(engine, arg: str | None) -> Path:
    if arg:
        return Path(arg)
    return engine.sweep._analysis_results()


def _sweeps_root(engine, args) -> Path:
    if args.sweeps_root is not None:
        return args.sweeps_root
    return _analysis_results(engine, args.analysis_results) / SWEEPS_REL


def _resolve_pack(engine, pack: Path | None) -> Path:
    if pack is not None:
        return pack
    try:
        return engine.adapters.rule_pack_dir()
    except ValueError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2) from e


def _resolve_drafts_dir(engine, drafts_dir: Path | None) -> Path:
    if drafts_dir is not None:
        return drafts_dir
    try:
        return rule_drafts_dir(engine)
    except DeploymentConfigMissing as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2) from e


def add_collect_args(ap) -> None:
    _add_common_sweep_args(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="findings tree (default <analysis-results>/findings)",
    )
    ap.add_argument(
        "--phase0-root",
        type=Path,
        default=None,
        help="Phase-0 artifacts (default <analysis-results>/scan-testing/phase-0)",
    )
    ap.add_argument("--force", action="store_true")


def call_collect(engine, args) -> int:
    ops = engine.sweep
    sweeps_root = _sweeps_root(engine, args)
    res = ops.collect(
        results_root=args.results_root,
        phase0_root=args.phase0_root,
        sweeps_root=sweeps_root,
        force=args.force,
    )
    if res["skipped"]:
        print(f"collect: state exists, skipping ({res['state']}) — use --force to re-collect")
    else:
        print(
            f"collect: {res['confirmed_findings']} confirmed "
            f"finding(s) ({res['by_source']}); "
            f"{res['rule_expressible']} rule-expressible across "
            f"{res['classes']} class(es); "
            f"{res['not_expressible']} not expressible (reasons "
            f"recorded) -> {res['state']}"
        )
    return 0


def add_draft_args(ap) -> None:
    _add_common_sweep_args(ap)


def call_draft(engine, args) -> int:
    ops = engine.sweep
    pack = _resolve_pack(engine, args.pack)
    drafts_dir = _resolve_drafts_dir(engine, args.drafts_dir)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.draft(pack, drafts_dir, sweeps_root=sweeps_root)
    print(
        f"draft: {len(res['emitted'])} draft(s) staged "
        f"({', '.join(res['emitted']) or 'none'}); "
        f"{len(res['skipped'])} class(es) skipped — author "
        "patterns, calibrate via mine-ledger, then `sweep` runs "
        "by default"
    )
    return 0


def add_sweep_args(ap) -> None:
    _add_common_sweep_args(ap)
    ap.add_argument("--rule", required=True, help="rule id, yaml path, or draft dir/name")
    ap.add_argument("--limit", type=int, default=DEFAULT_SWEEP_LIMIT)
    ap.add_argument(
        "--repos",
        type=Path,
        default=None,
        help="JSON [{slug,url}] override for the corpus resolver (url may be a local dir)",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="clone root (default: fresh temp dir, removed after the run)",
    )
    ap.add_argument("--opengrep", default="opengrep")
    ap.add_argument("--timeout", type=int, default=600, help="per-repo scan timeout seconds")


def call_sweep(engine, args) -> int:
    ops = engine.sweep
    pack = _resolve_pack(engine, args.pack)
    drafts_dir = _resolve_drafts_dir(engine, args.drafts_dir)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.sweep(
        args.rule,
        pack,
        drafts_dir,
        sweeps_root=sweeps_root,
        repos=args.repos,
        limit=args.limit,
        work_dir=args.work_dir,
        opengrep=args.opengrep,
        timeout=args.timeout,
    )
    print(
        f"sweep [{res['rule_id']}]: {res['swept']} repo(s) swept, "
        f"{res['skipped']} resumed/skipped, "
        f"{res['repo_errors']} errored, {res['hits']} raw hit(s) "
        f"-> {res['repo_results']}"
    )
    return 0


def add_emit_args(ap) -> None:
    _add_common_sweep_args(ap)
    ap.add_argument("--rule", required=True)
    ap.add_argument("--force", action="store_true")


def call_emit(engine, args) -> int:
    ops = engine.sweep
    pack = _resolve_pack(engine, args.pack)
    drafts_dir = _resolve_drafts_dir(engine, args.drafts_dir)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.emit(args.rule, pack, drafts_dir, sweeps_root=sweeps_root, force=args.force)
    if res["skipped"]:
        print(f"emit: candidates exist, skipping ({res['out']}) — use --force to re-emit")
    else:
        print(
            f"emit: {res['candidates']} candidate(s) from "
            f"{res['repos_swept']} repo(s) "
            f"({res['repos_with_hits']} with hits) -> {res['out']} "
            "(+ sweep-summary.md). Results enter the triage workflow."
        )
    return 0


def add_benchmark_args(ap) -> None:
    ap.add_argument(
        "--benchmark-dir",
        type=Path,
        default=None,
        help="validate-findings benchmark dir "
        "(default: locations.analysis_results/.../validation-benchmark)",
    )
    sub = ap.add_subparsers(dest="benchmark_cmd", required=True)
    sub.add_parser("plan", help="emit benchmark worklist and deploy commands")
    p = sub.add_parser("check-trigger", help="exit 10 if validation-lane paths changed since ref")
    p.add_argument("--since", required=True, help="git ref of the last benchmarked release")
    p.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="git repo to diff (default: BENCHMARK_REPO_ROOT or locations.workspace/traust)",
    )
    p = sub.add_parser("score", help="score one lane run against expectations")
    p.add_argument("--report", required=True)
    p.add_argument("--variant", required=True, choices=["vuln", "safe"])
    sub.add_parser("scorecard", help="print the current scorecard state")


def _benchmark_results_dir(engine, args) -> Path:
    if args.benchmark_dir:
        return args.benchmark_dir
    return engine.sweep._benchmark_dir()


def call_benchmark(engine, args) -> int:
    from traust_engine.sweep import benchmark as bench

    if args.benchmark_cmd == "check-trigger":
        return bench.cmd_check_trigger(args)
    results_dir = _benchmark_results_dir(engine, args)
    return {
        "plan": bench.cmd_plan,
        "score": bench.cmd_score,
        "scorecard": bench.cmd_scorecard,
    }[args.benchmark_cmd](args, results_dir=results_dir)


def add_rule_lane_args(ap) -> None:
    ap.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="campaign workspace holding analysis-results/ and metrics output",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="rule-mining output dir (default: <progress-tracker>/metrics/rule-mining)",
    )
    ap.add_argument(
        "--draft-limit",
        type=int,
        default=6,
        help="max regression drafts staged per run (0 skips the stage; default 6)",
    )
    ap.add_argument(
        "--skip-sweep", action="store_true", help="skip the sweep-engine collect/draft stages"
    )
    ap.add_argument(
        "--emit-drafts-script",
        type=Path,
        default=None,
        help="optional emit_rule_drafts.py path (env: EMIT_RULE_DRAFTS_SCRIPT)",
    )


def call_rule_lane(engine, args) -> int:
    from traust_engine.sweep import rule_lane as lane

    return lane.execute_rule_lane(
        workspace=args.workspace,
        out=args.out,
        draft_limit=args.draft_limit,
        skip_sweep=args.skip_sweep,
        emit_drafts_script=args.emit_drafts_script,
        engine=engine,
    )


COLLECT = OpSpec(
    add_args=add_collect_args,
    call=call_collect,
    help="gather and classify confirmed findings for class-generalization",
)
DRAFT = OpSpec(
    add_args=add_draft_args,
    call=call_draft,
    help="stage candidate rules for uncovered expressible classes",
)
SWEEP = OpSpec(
    add_args=add_sweep_args,
    call=call_sweep,
    help="run one rule corpus-wide (bounded, resumable per repo)",
)
EMIT = OpSpec(
    add_args=add_emit_args,
    call=call_emit,
    help="aggregate sweep hits into triage-ready candidates",
)
BENCHMARK = OpSpec(
    add_args=add_benchmark_args,
    call=call_benchmark,
    help="validation-lane benchmark (plan, check-trigger, score, scorecard)",
)
RULE_LANE = OpSpec(
    add_args=add_rule_lane_args,
    call=call_rule_lane,
    help="rule-mining lane: mine → sweep collect/draft → delta",
)


def add_mine_args(ap) -> None:
    ap.add_argument(
        "--pack",
        default="traust",
        help="rule pack name (default: traust, from locations.opengrep_rules or bundled; an "
        "enabled rule-pack-allowlist supplement by its name)",
    )
    ap.add_argument("--out", type=Path, default=None, help="also write the result here (JSON)")


def call_mine(engine, args) -> int:
    """The confirmed TPs in traust-core against a rule pack from traust-engine's RulePackSource."""

    def call() -> dict:
        quality = load_engine_core(args.config_home).services().detection_quality
        packs = {p.name: p for p in quality.rule_packs()}
        if args.pack not in packs:
            raise NotFoundError(f"no rule pack {args.pack!r}; have {sorted(packs)}")
        mining = quality.mine_rules(packs[args.pack])
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(mining.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return {
            "pack": f"{mining.pack.name} {mining.pack.version}",
            "pack_rules": len(mining.pack.rules),
            "confirmed_tps": len(mining.corpus),
            "ruleable_tps": mining.ruleable,
            **mining.model_dump(mode="json", exclude={"pack", "corpus"}),
        }

    return run(call)


MINE = OpSpec(
    add_args=add_mine_args,
    call=call_mine,
    help="Mine ledger-confirmed TPs for opengrep rule authoring",
)

BENCHMARK_TARGETS = passthrough_op(
    "recall", "Record the recall benchmark's answer key (benchmark-targets).", "targets"
)
