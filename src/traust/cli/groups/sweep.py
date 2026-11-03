"""``traust sweep …`` — class-generalization sweep, benchmark, rule-mining lane."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from traust_core.v1.context import Context
from traust_core.v1.context.tool_reports import opengrep_report
from traust_core.v1.context.tools import load_rule_allowlist
from traust_core.v1.errors import (
    DeploymentConfigMissing,
    NotFoundError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.detection_quality import RegressionPairFilter
from traust_core.v1.models.rule_mining import (
    DEFAULT_DRAFT_LIMIT,
    DEFAULT_SWEEP_LIMIT,
    Allowlist,
    RuleLane,
    RuleLaneRequest,
    RuleProposal,
    RuleSweepRequest,
    StageStatus,
    SweepRepo,
)
from traust_core.v1.models.validation_benchmark import (
    BenchmarkVariant,
    ValidationBenchmark,
    ValidationRun,
)

from traust.cli._doors import run
from traust.cli.groups._registry import OpSpec, passthrough_op
from traust.context import (
    analysis_results_dir,
    load,
    progress_tracker_dir,
    rule_drafts_dir,
)
from traust.paths import skill_dir

SWEEPS_REL = Path("scan-testing") / "sweeps"
VALIDATION_BENCHMARK_REL = Path("scan-testing") / "validation-benchmark"


def _add_rule_args(ap) -> None:
    ap.add_argument(
        "--pack",
        type=Path,
        default=None,
        help="rule pack dir (default: locations.opengrep_rules, else the security pack's)",
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


def _core(args, *, drafts: bool = False) -> Context:
    """traust-core on the rule pack and drafts dir the flags name; exit 2 when a stage that
    stages or resolves drafts has no drafts dir."""
    core = load(
        args.config_home,
        rule_pack=getattr(args, "pack", None),
        rule_drafts=getattr(args, "drafts_dir", None),
    )
    if drafts and core.rule_drafts is None:
        _required(lambda: rule_drafts_dir(core))
    return core


def _required(location: Callable[[], Path]) -> Path:
    """A configured location, or exit 2 naming what is unset."""
    try:
        return location()
    except DeploymentConfigMissing as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2) from e


def _door(call) -> int:
    """Run one door; a refusal is one ERROR line and exit 2."""
    try:
        return call()
    except (OSError, ValueError, TraustError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


def add_collect_args(ap) -> None:
    _add_rule_args(ap)
    ap.add_argument("--force", action="store_true")


def call_collect(args) -> int:
    def call() -> int:
        res = _core(args).services().detection_quality.sweep_collect(force=args.force)
        if res.skipped or res.stats is None:
            print(f"collect: state exists, skipping ({res.state}) — use --force to re-collect")
            return 0
        st = res.stats
        print(
            f"collect: {st.confirmed_findings} confirmed finding(s) ({st.by_source}); "
            f"{st.rule_expressible} rule-expressible across {st.classes} class(es); "
            f"{st.not_expressible} not expressible (reasons recorded) -> {res.state}"
        )
        return 0

    return _door(call)


def add_draft_args(ap) -> None:
    _add_rule_args(ap)


def call_draft(args) -> int:
    def call() -> int:
        res = _core(args, drafts=True).services().detection_quality.sweep_drafts()
        print(
            f"draft: {len(res.emitted)} draft(s) staged ({', '.join(res.emitted) or 'none'}); "
            f"{len(res.skipped)} class(es) skipped — author patterns, calibrate via mine-ledger, "
            "then `sweep` runs by default"
        )
        return 0

    return _door(call)


def add_sweep_args(ap) -> None:
    _add_rule_args(ap)
    ap.add_argument("--rule", required=True, help="rule id, yaml path, or draft dir/name")
    ap.add_argument("--limit", type=int, default=DEFAULT_SWEEP_LIMIT)
    ap.add_argument(
        "--repos",
        type=Path,
        default=None,
        help="JSON [{slug,url}] instead of the audited repositories (url may be dir:<path>)",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="clone root (default: fresh temp dir, removed after the run)",
    )
    ap.add_argument("--opengrep", default="opengrep")
    ap.add_argument("--timeout", type=int, default=600, help="per-repo scan timeout seconds")


def call_sweep(args) -> int:
    def call() -> int:
        repos = None
        if args.repos is not None:
            raw = json.loads(args.repos.read_text(encoding="utf-8"))
            repos = tuple(SweepRepo.model_validate(r) for r in raw)
        request = RuleSweepRequest(
            rule=args.rule,
            limit=args.limit,
            repos=repos,
            work_dir=args.work_dir,
            binary=args.opengrep,
            timeout=args.timeout,
        )
        res = _core(args, drafts=True).services().detection_quality.sweep_rule(request)
        print(
            f"sweep [{res.rule_id}]: {res.swept} repo(s) swept, {res.skipped} resumed/skipped, "
            f"{res.repo_errors} errored, {res.hits} raw hit(s) -> {res.repo_results}"
        )
        return 0

    return _door(call)


def add_emit_args(ap) -> None:
    _add_rule_args(ap)
    ap.add_argument(
        "--sweeps-root",
        type=Path,
        default=None,
        help="where sweep-candidates.json lands (default <analysis-results>/scan-testing/sweeps)",
    )
    ap.add_argument("--analysis-results", type=Path, default=None)
    ap.add_argument("--rule", required=True)
    ap.add_argument("--force", action="store_true")


def call_emit(args) -> int:
    def call() -> int:
        core = _core(args, drafts=True)
        root = args.sweeps_root or (
            (args.analysis_results or _required(lambda: analysis_results_dir(core))) / SWEEPS_REL
        )
        res = core.services().detection_quality.emit_sweep(args.rule, force=args.force)
        out = root / res.rule_id / "sweep-candidates.json"
        if res.skipped or res.candidates is None or res.summary is None:
            print(f"emit: candidates exist, skipping ({res.out}) — use --force to re-emit")
            return 0
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(res.candidates.model_dump_json(indent=2) + "\n", encoding="utf-8")
        (out.parent / "sweep-summary.md").write_text(res.summary, encoding="utf-8")
        c = res.candidates
        print(
            f"emit: {len(c.candidates)} candidate(s) from {c.repos_swept} repo(s) "
            f"({c.repos_with_hits} with hits) -> {out} (+ sweep-summary.md). Results enter the "
            "triage workflow."
        )
        return 0

    return _door(call)


def add_benchmark_args(ap) -> None:
    ap.add_argument(
        "--benchmark-dir",
        type=Path,
        default=None,
        help="validate-findings benchmark dir: expected.json + fixtures/, and the plan's output "
        "(default: the shipped benchmark, with the plan's output under "
        "<analysis_results>/scan-testing/validation-benchmark)",
    )
    sub = ap.add_subparsers(dest="benchmark_cmd", required=True)
    sub.add_parser("plan", help="emit benchmark worklist and deploy commands")
    p = sub.add_parser("check-trigger", help="exit 10 if validation-lane paths changed since ref")
    p.add_argument("--since", required=True, help="git ref of the last benchmarked release")
    p.add_argument("--repo-root", type=Path, default=None, help="the mono checkout to diff")
    p = sub.add_parser("score", help="score one lane run against expectations")
    p.add_argument("--report", required=True)
    p.add_argument("--variant", required=True, choices=[v.value for v in BenchmarkVariant])
    sub.add_parser("scorecard", help="print the current scorecard state")


def _benchmark(bench: Path) -> ValidationBenchmark:
    return ValidationBenchmark.model_validate_json(
        (bench / "expected.json").read_text(encoding="utf-8")
    )


def call_benchmark(args) -> int:
    core = load(args.config_home)
    quality = core.services().detection_quality
    if args.benchmark_cmd == "check-trigger":
        if args.repo_root is None:
            raise SystemExit("--repo-root required")
        return _door(lambda: _check_trigger(quality, args))
    if args.benchmark_cmd == "scorecard":
        return _door(lambda: _scorecard(quality))
    # The harness ships the benchmark (expected.json, fixtures/); a plan writes to the estate.
    bench = args.benchmark_dir or skill_dir("validate-findings") / "benchmark"
    if args.benchmark_cmd == "plan":
        runs = args.benchmark_dir or (
            _required(lambda: analysis_results_dir(core)) / VALIDATION_BENCHMARK_REL
        )
        return _door(lambda: _plan(quality, bench, runs))
    return _door(lambda: _score(quality, bench, args))


def _plan(quality, bench: Path, runs: Path) -> int:
    expected = _benchmark(bench)
    worklist = quality.benchmark_worklist(expected)
    runs.mkdir(parents=True, exist_ok=True)
    out = runs / "benchmark-findings.json"
    out.write_text(worklist.model_dump_json(indent=1) + "\n", encoding="utf-8")
    print(f"benchmark worklist: {len(worklist.findings)} claims → {out}")
    print("\nDeploy (vuln variant):")
    print(f"  oc new-project {expected.namespace} 2>/dev/null || true")
    for fx in expected.fixtures:
        print(f"  oc apply -f {bench}/fixtures/{fx.vuln_manifest}")
    print(f"\nThen: /validate-findings {out} --namespace {expected.namespace}")
    print("Then: traust sweep benchmark score --report <report> --variant vuln")
    print("Swap each fixture to its .safe.yaml twin and repeat with --variant safe.")
    return 0


def _check_trigger(quality, args) -> int:
    trigger = quality.benchmark_trigger(ToolRequest(workspace=args.repo_root), args.since)
    if trigger.paths:
        print(
            f"validation-lane paths changed since {args.since} — benchmark REQUIRED before release:"
        )
        for path in trigger.paths:
            print(f"  {path}")
        return 10
    print(f"no validation-lane changes since {args.since} — benchmark not required")
    return 0


def _score(quality, bench: Path, args) -> int:
    expected = _benchmark(bench)
    report = ValidationRun.model_validate_json(Path(args.report).read_text(encoding="utf-8"))
    variant = BenchmarkVariant(args.variant)
    score = quality.score_benchmark(expected, report, variant, str(args.report))
    floor = expected.required_floors().floor(variant)
    print(json.dumps(score.model_dump(mode="json")["rows"], indent=1))
    severity = (
        f" · severity_accuracy: {score.severity_accuracy}"
        if score.severity_accuracy is not None
        else ""
    )
    print(f"{variant.metric}: {score.value} (floor {floor}){severity}")
    if score.value is not None and score.value < floor:
        print(
            f"BELOW FLOOR — a lane change that drops {variant.metric} under {floor} must not ship",
            file=sys.stderr,
        )
        return 1
    return 0


def _scorecard(quality) -> int:
    card = quality.benchmark_scorecard()
    if not card.runs:
        print("no benchmark runs recorded yet (plan → deploy → validate → score)")
        return 0
    for r in card.runs[-10:]:
        scored = r.scored_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.scored_at else "?"
        print(
            f"{scored}  {r.variant.value:4s}  {r.variant.metric}={r.value}  "
            f"severity={r.severity_accuracy}  n={r.n}"
        )
    return 0


def add_rule_lane_args(ap) -> None:
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="rule-mining output dir (default: <progress-tracker>/metrics/rule-mining)",
    )
    ap.add_argument(
        "--draft-limit",
        type=int,
        default=DEFAULT_DRAFT_LIMIT,
        help="max regression drafts staged per run (0 skips the stage; default 6)",
    )
    ap.add_argument("--skip-sweep", action="store_true", help="skip the sweep collect/draft stages")


def _allowlist(path: Path | None) -> Allowlist | None:
    """The rules ``overrides.rule_pack_allowlist`` in traust.yaml enables; None when unset."""
    if path is None:
        return None
    try:
        allow = load_rule_allowlist(f"@{path}")
    except ValidationError as e:
        return Allowlist(unreadable=str(e))
    return Allowlist(rules=allow.rules if allow else frozenset())


def call_rule_lane(args) -> int:
    core = load(args.config_home)
    out = args.out or _required(lambda: progress_tracker_dir(core)) / "metrics" / "rule-mining"
    try:
        lane = core.services().detection_quality.rule_lane(
            RuleLaneRequest(
                draft_limit=args.draft_limit,
                skip_sweep=args.skip_sweep,
                allowlist=_allowlist(core.config.overrides.rule_pack_allowlist),
            )
        )
    except TraustError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    out = out.resolve()
    for stage in lane.stages:
        if stage.status == StageStatus.FAILED:
            print(
                f"[{stage.stage}] FAILED (rc {stage.returncode}): {stage.summary[:400]}",
                file=sys.stderr,
            )
        else:
            print(f"[{stage.stage}] {stage.summary}")
    if lane.mining is not None:
        _write_mining(out, lane)
    if lane.delta is None or lane.delta_report is None:
        return lane.exit_code
    (out / "lane-delta.json").write_text(
        lane.delta.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (out / "lane-delta.md").write_text(lane.delta_report, encoding="utf-8")
    d = lane.delta
    growth = f" ({d.tp_corpus.growth:+d})" if d.tp_corpus.growth is not None else ""
    attention = "; ".join(d.attention.reasons) if d.attention.needed else "none"
    print(
        f"rule-mining lane: TPs {d.tp_corpus.confirmed_tps}{growth}; uncovered clusters "
        f"+{len(d.new_uncovered_clusters)} new / {len(d.resolved_uncovered_clusters)} resolved"
        f" / {len(d.changed_uncovered_clusters)} changed; gate crossings "
        f"{len(d.precision_gate_crossings)}; attention: {attention} -> {out}/lane-delta.{{json,md}}"
    )
    return lane.exit_code


def _write_mining(out: Path, lane: RuleLane) -> None:
    assert lane.mining is not None and lane.mining_report is not None
    out.mkdir(parents=True, exist_ok=True)
    corpus = [tp.model_dump_json() for tp in lane.mining.corpus]
    (out / "tp-corpus.jsonl").write_text("".join(f"{line}\n" for line in corpus), encoding="utf-8")
    (out / "rule-mining.json").write_text(lane.mining.model_dump_json(indent=2), encoding="utf-8")
    (out / "rule-mining.md").write_text(lane.mining_report, encoding="utf-8")


def add_propose_args(ap) -> None:
    _add_rule_args(ap)
    ap.add_argument("--rule", type=Path, required=True, help="the proposed rule's yaml (one rule)")
    ap.add_argument(
        "--example",
        type=Path,
        required=True,
        help="a test target with `ruleid:` and `ok:` comment lines for the rule",
    )
    ap.add_argument("--shape", required=True, help="the uncovered shape it is proposed for")
    ap.add_argument(
        "--checkout", type=Path, required=True, help="the repository the shape came from"
    )
    ap.add_argument("--opengrep", default="opengrep")
    ap.add_argument("--timeout", type=int, default=300, help="per-scan timeout seconds")
    ap.add_argument("--json", action="store_true", help="print the verdict as JSON")


def call_propose(args) -> int:
    """Exit 0 admitted (staged as a draft), 1 refused by the gate, 2 an error."""

    def call() -> int:
        proposal = RuleProposal(
            rule=args.rule.read_text(encoding="utf-8"),
            example=args.example.read_text(encoding="utf-8"),
            example_name=args.example.name,
            shape=args.shape,
            checkout=args.checkout,
            binary=args.opengrep,
            timeout=args.timeout,
        )
        verdict = _core(args, drafts=True).services().detection_quality.propose_rule(proposal)
        if args.json:
            print(verdict.model_dump_json(indent=2))
        else:
            for c in verdict.checks:
                detail = f": {c.detail}" if c.detail else ""
                print(f"  {'ok  ' if c.passed else 'FAIL'} {c.name}{detail}")
            state = f"admitted, staged as draft {verdict.draft}" if verdict.admitted else "refused"
            print(f"propose-rule [{verdict.rule_id}]: {state}")
        return 0 if verdict.admitted else 1

    return _door(call)


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
PROPOSE = OpSpec(
    add_args=add_propose_args,
    call=call_propose,
    help="admit an inference-proposed rule through the deterministic gate into the drafts",
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


def call_mine(args) -> int:
    """The confirmed TPs in traust-core against a rule pack from core's RulePackSource."""

    def call() -> dict:
        quality = load(args.config_home).services().detection_quality
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
BUILD_CANARIES = passthrough_op(
    "recall", "Materialise canaries (or --seeded fixtures) as answer-key targets.", "canaries"
)
CARDS = passthrough_op(
    "precedent_cards", "Validate semantic precedent cards; sweep them over a checkout.", "main"
)
SCORE_BENCHMARK = passthrough_op(
    "recall", "Score recall-benchmark runs (a runs dir, or the recorded audits).", "score"
)
SCREEN_INJECTION = passthrough_op(
    "recall", "Screen recorded audit reports for prompt injection (report-only).", "screen"
)


def add_regression_drafts_args(ap) -> None:
    ap.add_argument(
        "--drafts-dir",
        type=Path,
        default=None,
        help="rule drafts dir (default: locations.rule_drafts or"
        " <progress_tracker>/metrics/rule-mining/rule-drafts)",
    )
    ap.add_argument("--cwe", default=None, help="only fixes of this CWE (e.g. CWE-78)")
    ap.add_argument("--limit", type=int, default=6, help="max drafts staged (default 6)")
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="never re-stage a draft dir that already exists (protects authored-but-unpromoted "
        "patterns; the rule-mining lane's mode)",
    )


def call_regression_drafts(args) -> int:
    """Stage one draft dir per confirmed fix from `DetectionQualityService.regression_pairs`."""
    core = _core(args, drafts=True)

    def call() -> dict:
        found = core.services().detection_quality.stage_regression_drafts(
            RegressionPairFilter(cwe=args.cwe, limit=args.limit), skip_existing=args.skip_existing
        )
        return {
            "drafts_dir": str(core.rule_drafts.root if core.rule_drafts else None),
            "drafted": [
                {"draft": p.id, "language": p.language, "cwe": p.cwes[0], "files": len(p.files)}
                for p in found.pairs
            ],
            "skipped_by_reason": found.skipped_by_reason,
            "skipped": found.model_dump(mode="json")["skipped"],
        }

    return run(call)


def add_verify_draft_args(ap) -> None:
    ap.add_argument("draft", type=Path, help="draft dir (holds before/ and after/)")
    ap.add_argument(
        "--rule",
        type=Path,
        default=None,
        help="candidate rule (default: <draft>/rule.skeleton.yaml)",
    )


def call_verify_draft(args) -> int:
    """The calibration gate: the candidate rule fires on before/ and is silent on after/."""
    rule = args.rule or args.draft / "rule.skeleton.yaml"
    if not rule.is_file():
        print(
            f"ERROR: opengrep over {args.draft / 'before'}: no rule file at {rule}", file=sys.stderr
        )
        return 2
    core = load(args.config_home)
    counts = {}
    for side in ("before", "after"):
        target = args.draft / side
        try:
            counts[side] = len(opengrep_report(core, target, [str(rule)])["facts"])
        except (ValueError, OSError, RuntimeError, TraustError) as e:
            print(f"ERROR: opengrep over {target}: {e}", file=sys.stderr)
            return 2
    ok = counts["before"] > 0 and counts["after"] == 0
    print(
        f"{args.draft.name}: before={counts['before']} (need >0), "
        f"after={counts['after']} (need 0) -> {'PASS' if ok else 'FAIL'}"
    )
    return 0 if ok else 1


REGRESSION_DRAFTS = OpSpec(
    add_args=add_regression_drafts_args,
    call=call_regression_drafts,
    help="stage regression-rule drafts (pre/post-fix fixtures) from confirmed fixes",
)
VERIFY_DRAFT = OpSpec(
    add_args=add_verify_draft_args,
    call=call_verify_draft,
    help="check a draft rule fires on before/ and not on after/ (opengrep)",
)
