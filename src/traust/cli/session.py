"""``traust session run``: a skill session for a pack order, started headless. The model is the
role's (the model registry's `resolve_role`); the session's last line is the JobResult, whose
outcome is the exit code.

A diff scan whose order carries the router's threat-model PR stamp (`--rule`) then runs
`/threat-model pr` on the same checkout, at the anchor `traust assessments prepare --diff`
resolves; report-only.

Repo-config isolation (check-skill-security S9): the agent's working directory is this harness,
never a checkout. A checkout the session reviews is a separate temporary directory passed as an
argument; its own agent config (`.claude/`, `CLAUDE.md`, hooks) is data under audit, never loaded
as configuration.

Spend: the agent answers Claude Code's JSON result; its reply text is printed, and its measured
usage per model rides on the JobResult, which `traust-engine claim` settles as the order's spend.
The session runs with its own Claude config dir (`<config home>/claude-runner`, as
`CLAUDE_CONFIG_DIR`; log in there once, or set `ANTHROPIC_API_KEY`), so its transcripts never
land in `~/.claude/projects`, where `traust metrics collect-spend` reads workstation sessions:
nothing is counted twice.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pydantic
from pydantic import Field
from traust_core.v1.context import (
    TRAUST_CONFIG_HOME_ENV,
    CheckoutRequest,
    Context,
    Services,
    Workspace,
)
from traust_core.v1.errors import NotFoundError, ServiceError, TraustError, ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind, DiffRefused
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    JobResult,
    ModelName,
    ModelUsage,
    OrderReason,
    ProviderName,
    RecordKind,
    SessionResult,
    SkillName,
    WorkerId,
)
from traust_core.v1.models.remediation import SweepSkip, VerificationFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import (
    ORDER_STARTED_ENV,
    RUN_ORDER_ENV,
    answer,
    parser,
    scoped_recording_order,
)
from traust.cli._doors import run as door
from traust.cli.assessments import REFUSED
from traust.context import MODEL_REGISTRY, TRAUST_CONFIG_HOME_DEFAULT, load, resolve_config_home
from traust.ops.materializers import _order_id
from traust.ops.router import THREAT_MODEL_PR
from traust.ops.session_guard import flags as confinement_flags
from traust.ops.sessions import SESSIONS, SessionRunner
from traust.paths import HARNESS_ROOT, HARNESSING_DIR, skill_dir, skill_dirs

# PENDING(agents): Claude Code is the agent sessions start in; Crush is the other implementation.
AGENT = ("claude", "-p", "--output-format", "json")
# Claude Code bills Anthropic API requests.
PROVIDER = ProviderName("anthropic")
# PENDING(roles): the pack's threat-model role, as on its threat_model_quarterly asset.
THREAT_MODEL_ROLE = "threat-model"
# Skills whose ordered run is only done once it has recorded an assessment for the order (a
# threat-model review may rightly change nothing, so it isn't one).
# The skills whose ordered session must record an assessment of their kind for the order.
RECORDING_SKILLS = {
    "secure-code-audit": AssessmentKind.SECURE_CODE_CANONICAL,
    "vuln-scan": AssessmentKind.VULN_SCAN_CANONICAL,
    "cloud-config-audit": AssessmentKind.CLOUD_CONFIG_CANONICAL,
    "triage": AssessmentKind.TRIAGE,
    "validate-findings": AssessmentKind.VALIDATION,
    "verify-remediation": AssessmentKind.VERIFICATION,
}
# Skills whose ordered session must leave a report on the work item its order names.
REPORTING_SKILLS = frozenset({"remediate-finding"})


class _Tokens(Dto):
    tokens_in: int = Field(alias="inputTokens")
    tokens_out: int = Field(alias="outputTokens")
    cache_read: int = Field(0, alias="cacheReadInputTokens")
    cache_creation: int = Field(0, alias="cacheCreationInputTokens")


class AgentResult(Dto):
    """Claude Code's `--output-format json` result: the reply, and the session's usage per model."""

    result: str = ""
    is_error: bool = False
    session_id: str
    model_usage: dict[str, _Tokens] = Field(alias="modelUsage")

    def usage(self, skill: str, at: datetime) -> tuple[ModelUsage, ...]:
        return tuple(
            ModelUsage(
                provider=PROVIDER,
                model=ModelName(model),
                occurred_at=at,
                skill=SkillName(skill),
                session=self.session_id,
                **tokens.model_dump(),
            )
            for model, tokens in sorted(self.model_usage.items())
        )


def claude_dir(config_home: Path | None) -> Path:
    """The Claude config dir runner sessions use, apart from the workstation's `~/.claude`."""
    return (resolve_config_home(config_home) or TRAUST_CONFIG_HOME_DEFAULT) / "claude-runner"


def artifact_claude_dir(config_home: Path | None) -> Path:
    """The artifact-only sessions' Claude config dir: the harness skills and nothing else.

    The audit runner's dir carries credentials and permission grants for unconfined
    sessions; an artifact-only session is confined (the guard hook gates every call) and
    needs only its skills resolvable — `--setting-sources user` against this dir loads
    them while CLAUDE_CONFIG_DIR keeps the workstation's config out. Symlinks are
    refreshed idempotently, so a payload update reaches the next session."""
    root = (resolve_config_home(config_home) or TRAUST_CONFIG_HOME_DEFAULT) / "claude-artifact"
    skills = root / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    # The confinement's settings travel on the command line; a stored settings file in this
    # harness-owned directory can only weaken them (disableAllHooks would strip the guard
    # hook), so none survives a session start. Nothing but the skill symlinks belongs here.
    for stored in (root / "settings.json", root / "settings.local.json"):
        if stored.is_symlink() or stored.is_file():
            stored.unlink()
    for directory in skill_dirs():
        link = skills / directory.name
        if link.is_symlink() and link.resolve() == directory.resolve():
            continue
        if link.is_symlink() or link.is_file():
            link.unlink()
        elif link.is_dir():
            # Not deleted: an installed skill's files are the operator's. The slot is the
            # harness's, so the session refuses until the install is moved aside.
            raise ValidationError(
                f"{link} is a real directory, not the harness's skill symlink; "
                "move the installed skill aside"
            )
        link.symlink_to(directory, target_is_directory=True)
    return root


def session(
    command: list[str], skill: str, env: Mapping[str, str]
) -> tuple[subprocess.CompletedProcess[str], tuple[ModelUsage, ...]]:
    """Run the agent, print its reply and return its measured model usage."""
    done, reply = execute(command, skill, env)
    print(reply.result)
    return done, reply.usage(skill, datetime.now(UTC))


def execute(
    command: list[str], skill: str, env: Mapping[str, str]
) -> tuple[subprocess.CompletedProcess[str], AgentResult]:
    done = subprocess.run(
        command, cwd=HARNESS_ROOT, env=dict(env), stdout=subprocess.PIPE, text=True, check=False
    )
    try:
        reply = AgentResult.model_validate_json(done.stdout or "")
    except pydantic.ValidationError as e:
        raise ServiceError(f"/{skill}: not Claude Code's JSON result: {e}") from e
    if reply.is_error and done.returncode == 0:
        done.returncode = 1
    return done, reply


def _traust(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "traust.cli", *argv], capture_output=True, text=True, check=False
    )


def resolve_model(role: str) -> str:
    """The role's model, from the model registry."""
    catalog = load().model_catalog
    if catalog is None:
        raise ValidationError(f"role {role!r}: no model registry ({MODEL_REGISTRY})")
    return catalog.resolve_role(role)


def diff_anchor(url: str, clone: Path) -> str:
    """The commit the diff scan's diff starts from, resolved by the same door the scan asks."""
    head = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    done = _traust(
        *("assessments", "prepare", "--kind", "vuln-scan"),
        *("--repo-url", url, "--sha", head, "--diff", str(clone)),
    )
    if done.returncode == REFUSED:
        raise DiffRefused(json.loads(done.stdout)["reason"])
    if done.returncode != 0:
        raise ServiceError(f"assessments prepare exited {done.returncode}: {done.stderr.strip()}")
    return str(json.loads(done.stdout)["diff"]["anchor"])


@contextmanager
def checkout(
    url: str, config_home: Path | None, ref: GitSha | None = None
) -> Iterator[Workspace]:
    """Check out a registered repository at the supplied commit or its observed default head.

    The mirror's worktree holds the history a diff scan anchors at; it is released after use.
    """
    core = load(config_home)
    services = core.services()
    parsed = HttpsRepoUrl.parse(url, core.config.forge_hosts)
    repo = services.portfolio.find_repository(parsed)
    if repo is None or repo.id is None:
        raise NotFoundError(f"{url}: not in the inventory (`traust portfolio observe` records it)")
    if ref is None:
        head = services.portfolio.default_ref(repo.id)
        if head is None:
            raise NotFoundError(f"{url}: no observed default head to check out")
        ref = GitSha.parse(head.sha)
    workspace = services.checkouts.checkout(CheckoutRequest(repo=parsed, ref=ref)).data
    try:
        yield workspace
    finally:
        # the session's outcome stands: a failed release is reported alongside it, never
        # instead of it (a completed run is not a missing repository)
        try:
            services.checkouts.release(workspace)
        except TraustError as e:
            print(f"workspace release failed, left at {workspace.path}: {e}", file=sys.stderr)


def prompt(skill: str, args: list[str]) -> str:
    return " ".join([f"/{skill}", *args])


def run(argv: list[str] | None = None) -> int:
    ap = parser(
        "session",
        "run",
        "Start a skill session headless for a pack order, e.g. "
        "`--skill vuln-scan --role vuln-scan --repo <url> --checkout -- --diff`. Its measured "
        "usage rides on the JobResult and settles as the order's spend; it runs with its own "
        "Claude config dir (<config home>/claude-runner: log in there once, or set "
        "ANTHROPIC_API_KEY), so `traust metrics collect-spend` never counts it again.",
    )
    ap.add_argument("--skill", required=True, help="the skill the session runs")
    ap.add_argument(
        "--role", help="its model-registry role (artifact-only modes use their review role)"
    )
    ap.add_argument("--repo", help="the repository the order is for")
    ap.add_argument(
        "--checkout",
        action="store_true",
        help="pass a checkout of --repo's observed default head (the order's commit), not its URL",
    )
    ap.add_argument(
        "--mode", help="the skill's mode token, before the repository (e.g. threat-model review)"
    )
    ap.add_argument("--run-id", default="manual", help="the run order this session is for")
    ap.add_argument("--worker", help="the engine worker holding the order's lease")
    ap.add_argument("--rule", help="the router rule that routed the order")
    argv = sys.argv[1:] if argv is None else argv
    split = argv.index("--") if "--" in argv else len(argv)
    args, extra = ap.parse_args(argv[:split]), argv[split + 1 :]
    if (args.skill, args.mode) in SESSIONS:
        return artifact_run(
            args.skill,
            args.mode,
            args.role,
            args.repo,
            args.run_id,
            args.worker,
            args.config_home,
            extra,
        )
    if args.role is None:
        ap.error("--role is required for this session mode")
    if args.checkout and not args.repo:
        ap.error("--checkout needs --repo")
    stamped = bool(args.rule) and args.rule.endswith(THREAT_MODEL_PR)
    if stamped and not args.checkout:
        ap.error(f"{THREAT_MODEL_PR} needs --checkout")
    try:
        skill_dir(args.skill)
        model = resolve_model(args.role)
        pr_model = resolve_model(THREAT_MODEL_ROLE) if stamped else None
    except (ValidationError, NotFoundError, FileNotFoundError, KeyError) as e:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {e}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    mode = [args.mode] if args.mode else []
    kind = RECORDING_SKILLS.get(args.skill)
    triage_source: UUID | None = None
    triage_ref: GitSha | None = None
    full_sweep_repo: UUID | None = None
    verification_item: UUID | None = None
    try:
        order_id = _order_id(args.run_id)
        # Scoped recording writers authorize before reading the order's prior output.
        before = (
            set()
            if order_id is None or kind is None or args.skill in {"triage", "verify-remediation"}
            else _recorded(order_id, kind, args)
        )
        if order_id is not None and args.skill == "triage":
            if args.checkout or mode or extra:
                raise ValidationError("scheduled triage input comes from its repository order")
            triage_source, triage_ref, completed = _triage_source(order_id, args)
            if completed:
                return answer(JobResult.succeeded(written=completed))
            extra = ["--auto", "--fresh"]
        if order_id is not None and args.skill == "verify-remediation":
            core = load(args.config_home)
            order = scoped_recording_order(
                core, order_id, RecordKind.VERIFICATION, SourceType.VERIFICATION_REPORT
            )
            if order.asset != "verify_remediation" or args.checkout or mode or extra:
                raise ValidationError("verification inputs must come from the repository order")
            services = core.services()
            assert order.repository_id is not None
            repository = services.portfolio.get_repository(order.repository_id)
            if args.repo != repository.url:
                raise ValidationError("verification repository differs from the leased order")
            before = _recorded(order_id, kind, args)
            if order.work_item_id is not None:
                verification_item = order.work_item_id
                if before:
                    matching = _work_item_covered(
                        services, order.repository_id, order_id, verification_item, before
                    )
                    if matching:
                        return answer(JobResult.succeeded(written=tuple(sorted(matching))))
            if order.work_item_id is not None:
                prepared = services.verification.prepare(order.work_item_id)
                item = prepared.work_item
                if prepared.subject.repository_id != order.repository_id or not (
                    item.fork and item.fix_commit
                ):
                    raise ValidationError("verification order has no bound patched work item")
                mode, args.repo = [str(order.work_item_id)], f"{item.fork.url}@{item.fix_commit}"
            else:
                sweep = services.verification.sweep([order.repository_id])
                if sweep.queued:
                    full_sweep_repo = order.repository_id
                    mode = ["full-sweep", "--repo-url"]
                else:
                    ids = before
                    evidence_order = order_id
                    if not ids and any(e.skip == SweepSkip.ALREADY_VERIFIED for e in sweep.skipped):
                        evidence_order = None
                        ids = {
                            str(a.id)
                            for a in services.assessment.list_for_repository(
                                order.repository_id, AssessmentKind.VERIFICATION
                            )
                            if a.id is not None and a.status == "completed"
                        }
                    if (before or evidence_order is None) and not _sweep_covered(
                        services, order.repository_id, evidence_order, ids
                    ):
                        print(
                            f"run {args.run_id}: verification sweep coverage is not proven",
                            file=sys.stderr,
                        )
                        return answer(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID))
                    return answer(JobResult.succeeded(written=tuple(sorted(before))))
    except ValueError:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: not a run order id", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    except SystemExit:
        # `load` exits on an unusable configuration rather than raising
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    except (TraustError, OSError) as e:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {type(e).__name__}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    reported = None
    if order_id is not None and args.skill in REPORTING_SKILLS:
        try:
            reported = _ordered_work_item(order_id, args)
        except (ValidationError, NotFoundError) as e:  # the order can't be run as it stands
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {e}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.BAD_REQUEST))
        except SystemExit:  # `load` exits on an unusable configuration rather than raising
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.BAD_REQUEST))
        except (TraustError, OSError) as e:  # core or the store didn't answer: try again later
            print(f"run {args.run_id}: work-item lookup: {type(e).__name__}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.RUNNER_CRASHED))
    env = {**os.environ, "CLAUDE_CONFIG_DIR": str(claude_dir(args.config_home))}
    # The record doors default to this order and home: a manual session inherits neither.
    env.pop(RUN_ORDER_ENV, None)
    if order_id is not None:
        env[RUN_ORDER_ENV] = str(order_id)
    else:
        env.pop(ORDER_STARTED_ENV, None)
    if args.config_home is not None:
        env[TRAUST_CONFIG_HOME_ENV] = str(args.config_home)
    usage: tuple[ModelUsage, ...] = ()
    if triage_ref is not None:
        entered = checkout(args.repo, args.config_home, triage_ref)
    else:
        entered = checkout(args.repo, args.config_home) if args.checkout else nullcontext(None)
    try:
        with entered as workspace:
            if triage_source is not None:
                assert workspace is not None
                target = [str(triage_source), "--repo", shlex.quote(str(workspace.path))]
            else:
                target = (
                    [str(workspace.path)]
                    if workspace is not None
                    else ([args.repo] if args.repo else [])
                )
            command = [*AGENT, "--model", model, prompt(args.skill, [*mode, *target, *extra])]
            try:
                done, usage = session(command, args.skill, env)
                if done.returncode == 0 and pr_model:
                    pr = threat_model_pr(args.run_id, args.repo, Path(target[0]), pr_model, env)
                    if pr is not None:
                        done, usage = pr[0], usage + pr[1]
            except (OSError, ServiceError, subprocess.CalledProcessError) as e:
                print(f"run {args.run_id}: {OrderReason.RUNNER_CRASHED}: {e}", file=sys.stderr)
                return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    except (ValidationError, NotFoundError, ServiceError) as e:
        print(f"run {args.run_id}: {OrderReason.NOT_FOUND}: {e}", file=sys.stderr)
        return answer(JobResult.refused(OrderReason.NOT_FOUND))
    if done.returncode != 0:
        print(f"run {args.run_id}: session exited {done.returncode}", file=sys.stderr)
        return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    if reported is not None:
        try:
            reporter = _report_recorded_by(reported, args)
        except SystemExit:
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.BAD_REQUEST), usage))
        except (TraustError, OSError) as e:
            print(
                f"run {args.run_id}: work-item report lookup: {type(e).__name__}", file=sys.stderr
            )
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
        # only a report this order's run recorded counts — a retry's included, never one a
        # manual run or another order recorded
        if reporter != order_id:
            print(
                f"run {args.run_id}: /{args.skill} recorded no report on work item {reported}",
                file=sys.stderr,
            )
            return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
        return answer(_spent(JobResult.succeeded(written=(str(reported),)), usage))
    if triage_source is not None:
        try:
            source, _, completed = _triage_source(order_id, args)
            if source != triage_source or not completed:
                print(f"run {args.run_id}: triage did not record its source", file=sys.stderr)
                return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
            return answer(_spent(JobResult.succeeded(written=completed), usage))
        except SystemExit:
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.BAD_REQUEST), usage))
        except (TraustError, OSError) as e:
            print(f"run {args.run_id}: triage lookup: {type(e).__name__}", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    if full_sweep_repo is not None:
        try:
            services = load(args.config_home).services()
            recorded = _recorded(order_id, AssessmentKind.VERIFICATION, args)
            if (
                not recorded
                or services.verification.sweep([full_sweep_repo]).queued
                or not _sweep_covered(services, full_sweep_repo, order_id, recorded)
            ):
                print(
                    f"run {args.run_id}: /{args.skill} left work queued or coverage unproved",
                    file=sys.stderr,
                )
                return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
            return answer(_spent(JobResult.succeeded(written=tuple(sorted(recorded))), usage))
        except SystemExit:
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.BAD_REQUEST), usage))
        except (TraustError, OSError) as e:
            print(f"run {args.run_id}: verification sweep: {type(e).__name__}", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    if verification_item is not None:
        try:
            services = load(args.config_home).services()
            recorded = _recorded(order_id, AssessmentKind.VERIFICATION, args)
            matching = _work_item_covered(
                services, order.repository_id, order_id, verification_item, recorded
            )
            if not matching:
                print(f"run {args.run_id}: work-item verification incomplete", file=sys.stderr)
                return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
            return answer(_spent(JobResult.succeeded(written=tuple(sorted(matching))), usage))
        except SystemExit:
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.BAD_REQUEST), usage))
        except (TraustError, OSError) as e:
            print(f"run {args.run_id}: verification lookup: {type(e).__name__}", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    if order_id is not None and kind is not None:
        try:
            recorded = _recorded(order_id, kind, args)
        except SystemExit:
            print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: configuration", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.BAD_REQUEST), usage))
        except (TraustError, OSError) as e:
            print(
                f"run {args.run_id}: recorded-assessment lookup: {type(e).__name__}",
                file=sys.stderr,
            )
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
        if not recorded:
            print(
                f"run {args.run_id}: /{args.skill} recorded no {kind} assessment", file=sys.stderr
            )
            return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
        # This attempt's when it recorded new; otherwise the order's own. A retry that re-records
        # an unchanged report is handed the earlier assessment back (re-recording adds nothing),
        # which no row distinguishes from a retry that recorded nothing — so the order holding
        # its assessment of this kind is the contract this gate can enforce.
        written = sorted(recorded - before) or sorted(recorded)
        return answer(_spent(JobResult.succeeded(written=tuple(written)), usage))
    return answer(_spent(JobResult.succeeded(), usage))


def order_assessments(order_id: UUID, config_home: Path | None) -> list[Assessment]:
    """What the order recorded, as its record doors bound it (`--run-id`)."""
    return load(config_home).services().assessment.list_for_order(order_id)


def _work_item_covered(
    services: Services, repository_id: UUID, order_id: UUID, item_id: UUID, ids: set[str]
) -> set[str]:
    prepared = services.verification.prepare(item_id)
    item = prepared.work_item
    if prepared.subject.repository_id != repository_id or not (item.fork and item.fix_commit):
        raise ValidationError("verification order has no bound patched work item")
    runs = {
        a.id for a in services.assessment.list_for_order(order_id)
        if str(a.id) in ids and a.run_order_id == order_id and a.status == "completed"
    }
    return {
        str(v.verification_id)
        for v in prepared.verifications
        if v.verification_id in runs
        and bool(item.finding_ids)
        and set(item.finding_ids) <= {verdict.finding_id for verdict in v.verdicts}
        and (
            (ref := services.portfolio.inventory.get_ref(v.repository_ref_id)).repository_id
            == repository_id
            and ref.sha == item.fix_commit
        )
    }


def _sweep_covered(
    services: Services, repository_id: UUID, order_id: UUID | None, ids: set[str]
) -> bool:
    """Require verdicts for every reported finding in the repository.

    Core's default sweep considers every line and skips a head after any decision there;
    that does not prove report coverage. With no saved worklist, including closed and
    newly reported findings is conservative.
    """
    candidates = (
        services.assessment.list_for_order(order_id)
        if order_id is not None
        else services.assessment.list_for_repository(repository_id, AssessmentKind.VERIFICATION)
    )
    runs = [
        a for a in candidates
        if str(a.id) in ids
        and (order_id is None or a.run_order_id == order_id)
        and a.status == "completed"
    ]
    head = services.portfolio.default_ref(repository_id)
    if not runs or {str(a.id) for a in runs} != ids or head is None or head.id is None:
        return False
    expected = set(services.findings.records.ids_for_repository(repository_id))
    recorded = {a.id for a in runs}
    covered: set[UUID] = set()
    regressions: set[UUID] = set()
    current_runs: set[UUID] = set()
    for v in every_item(
        lambda page: services.verification.list(VerificationFilter(repository_id=repository_id), page)
    ):
        if v.verification_id not in recorded:
            continue
        ref = services.portfolio.inventory.get_ref(v.repository_ref_id)
        if (ref.repository_id, ref.name, ref.kind, ref.sha) == (
            repository_id, head.name, head.kind, head.sha
        ):
            current_runs.add(v.verification_id)
            covered.update(verdict.finding_id for verdict in v.verdicts)
            regressions.update(v.regression_ids)
    if regressions:
        origins: dict[UUID, set[UUID]] = {}
        for occurrence in services.findings.occurrences(finding_ids=regressions):
            origins.setdefault(occurrence.finding_id, set()).add(occurrence.assessment_id)
        # Newly discovered regressions were not targets in the original worklist. A finding
        # reported anywhere else remains in scope, even if this order also called it a regression.
        expected -= {
            finding for finding in regressions
            if origins.get(finding) and origins[finding] <= current_runs
        }
    latest = services.portfolio.default_ref(repository_id)
    return (
        latest is not None
        and (latest.id, latest.sha) == (head.id, head.sha)
        and bool(expected)
        and expected <= covered
    )


def _triage_source(
    order_id: UUID, args: argparse.Namespace
) -> tuple[UUID, GitSha, tuple[str, ...]]:
    core = load(args.config_home)
    order = scoped_recording_order(core, order_id, RecordKind.TRIAGE, SourceType.TRIAGE_REPORT)
    assert order.repository_id is not None
    services = core.services()
    repository = services.portfolio.get_repository(order.repository_id)
    if args.repo != repository.url:
        raise ValidationError("triage repository differs from the leased order")
    recorded = [
        a for a in order_assessments(order_id, args.config_home) if a.kind == AssessmentKind.TRIAGE
    ]
    if recorded:
        # The scheduled writer commits its assessment, decisions, reviews and ledger seal in
        # one lease-checked transaction. A naked assessment without its binding is not proof.
        if len({a.baseline_assessment_id for a in recorded}) != 1:
            raise ValidationError("order has triages of different audits")
        for a in recorded:
            if (
                a.id is None
                or a.run_order_id != order_id
                or a.status != "completed"
                or a.assessor != "triage"
                or a.baseline_assessment_id is None
            ):
                raise ValidationError("order has an invalid triage assessment")
            baseline = services.assessment.get(a.baseline_assessment_id)
            ref = services.portfolio.inventory.get_ref(a.repository_ref_id)
            if (
                ref.repository_id != order.repository_id
                or baseline.id != a.baseline_assessment_id
                or baseline.repository_ref_id != a.repository_ref_id
                or baseline.kind != AssessmentKind.SECURE_CODE_CANONICAL
                or baseline.status != "completed"
                or not services.assessment.list_artifacts(a.id, "triage")
            ):
                raise ValidationError("order triage is not bound to its repository audit")
        return baseline.id, GitSha.parse(ref.sha), tuple(sorted(str(a.id) for a in recorded))
    audit = services.assessment.latest_on_default_line(
        order.repository_id, AssessmentKind.SECURE_CODE_CANONICAL
    )
    if audit is None or audit.id is None:
        raise NotFoundError("no completed secure-code assessment on the repository's default line")
    ref = services.portfolio.inventory.get_ref(audit.repository_ref_id)
    if ref.repository_id != order.repository_id:
        raise ValidationError("triage audit is outside the leased repository")
    return audit.id, GitSha.parse(ref.sha), ()


def _recorded(order_id: UUID, kind: AssessmentKind, args: argparse.Namespace) -> set[str]:
    """The ids of the order's assessments of `kind`."""
    return {str(a.id) for a in order_assessments(order_id, args.config_home) if a.kind == kind}


def _ordered_work_item(order_id: UUID, args: argparse.Namespace) -> UUID:
    """The work item the order runs; an order naming none can't be run."""
    order = load(args.config_home).services().ops.get(order_id)
    if order.work_item_id is None:
        raise ValidationError(f"order {order_id} names no work item")
    return order.work_item_id


def _report_recorded_by(work_item_id: UUID, args: argparse.Namespace) -> UUID | None:
    """The order whose run recorded the work item's report; None without one, or by hand."""
    item = load(args.config_home).services().remediation.get(work_item_id)
    return None if item.report is None else item.reported_by


def _spent(result: JobResult, usage: tuple[ModelUsage, ...]) -> JobResult:
    return result.model_copy(update={"usage": usage})


def _runner(config_home: Path | None) -> tuple[Context, SessionRunner]:
    from traust.cli.impact import _core

    core = _core(config_home)  # feeds registered there: below-range reads OSV through them
    if core.model_catalog is None:
        raise ValidationError("artifact-only sessions require the model registry")
    return core, SessionRunner(
        core.services(),
        core.clock,
        core.model_catalog.resolve_role,
        core.config.forge_hosts,
        core.config.feeds.osv_access,
    )


def prepare(argv: list[str] | None = None) -> int:
    ap = parser("session", "prepare", "Stage an artifact-only skill's inputs and task contract.")
    ap.add_argument("--skill", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--task", required=True, type=Path)
    ap.add_argument("--run-id", default="manual")
    ap.add_argument("--worker")
    args = ap.parse_args(argv)

    def call() -> str:
        _, runner = _runner(args.config_home)
        task = runner.prepare(
            args.skill,
            args.mode,
            args.repo,
            args.task,
            _order_id(args.run_id),
            WorkerId(args.worker) if args.worker else None,
        )
        return task.payload.decode()

    return door(call, redact=True)


def record(argv: list[str] | None = None) -> int:
    ap = parser("session", "record", "Validate and record the staged task's declared output.")
    ap.add_argument("--task", required=True, type=Path)
    ap.add_argument("--worker")
    args = ap.parse_args(argv)
    try:
        _, runner = _runner(args.config_home)
        result = runner.record(
            args.task.resolve(), worker=WorkerId(args.worker) if args.worker else None
        )
    except (OSError, TraustError, pydantic.ValidationError, ValueError) as error:
        print(f"session record: {type(error).__name__}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    return answer(result)


def artifact_run(
    skill: str,
    mode: str,
    role: str | None,
    repo: str | None,
    run_id: str,
    worker: str | None,
    config_home: Path | None,
    extra: list[str],
) -> int:
    result: SessionResult | None = None
    holder = WorkerId(worker) if worker else None
    try:
        core, runner = _runner(config_home)
        model = core.model_catalog.resolve_role(
            role or SESSIONS[(skill, mode)].models["reviewer_b"][0]
        )
        order_id = _order_id(run_id)
        if repo is None:
            raise ValidationError("below-range sessions require a repository")
    except (TraustError, ValueError) as error:
        print(f"session setup: {type(error).__name__}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    with tempfile.TemporaryDirectory(prefix="traust-session-") as temporary:
        root = (Path(temporary) / "task").resolve()
        try:
            runner.prepare(skill, mode, repo, root, order_id, holder, extra)
            staged = runner.task(root)
        except NotFoundError:
            return answer(JobResult.refused(OrderReason.NOT_FOUND))
        except ValidationError:
            return answer(JobResult.refused(OrderReason.BAD_REQUEST))
        except (OSError, TraustError) as error:
            print(f"session prepare: {type(error).__name__}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.RUNNER_CRASHED))
        env = {
            key: value
            for key, value in os.environ.items()
            if key
            in {
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                "CLAUDE_CODE_OAUTH_TOKEN",
            }
        }
        try:
            env["CLAUDE_CONFIG_DIR"] = str(artifact_claude_dir(config_home))
        except (TraustError, ValueError) as error:
            print(f"session setup: {type(error).__name__}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.BAD_REQUEST))
        except OSError as error:
            print(f"session setup: {type(error).__name__}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.RUNNER_CRASHED))
        command = [
            *AGENT,
            *confinement_flags(root, HARNESSING_DIR.resolve(), root / staged[0].output.path),
            "--model",
            model,
            shlex.join([f"/{skill}", mode, "--task", str(root)]),
        ]
        failed = True
        try:
            done, reply = execute(command, skill, env)
            measured = reply.usage(skill, core.clock.now())
            result = SessionResult.from_document(
                {
                    "session": reply.session_id,
                    "usage": [item.model_dump(mode="json") for item in measured],
                    "error": "executor-failed" if done.returncode != 0 else None,
                }
            )
            failed = done.returncode != 0
        except (OSError, TraustError, pydantic.ValidationError) as error:
            print(f"session executor: {type(error).__name__}", file=sys.stderr)
        try:
            outcome = runner.record(root, result, holder, failed, staged)
        except (OSError, TraustError, pydantic.ValidationError) as error:
            from traust.ops.sessions import usage

            print(f"session recording: {type(error).__name__}", file=sys.stderr)
            outcome = _spent(
                JobResult.failed(OrderReason.RUNNER_CRASHED), usage(result) if result else ()
            )
    return answer(outcome)


def threat_model_pr(
    run_id: str, url: str, clone: Path, model: str, env: Mapping[str, str]
) -> tuple[subprocess.CompletedProcess[str], tuple[ModelUsage, ...]] | None:
    """The stamp's report-only `/threat-model pr` session on the scan's checkout; None when the
    diff is refused, said on stderr."""
    try:
        anchor = diff_anchor(url, clone)
    except DiffRefused as e:
        print(f"run {run_id}: {THREAT_MODEL_PR} skipped: diff refused: {e}", file=sys.stderr)
        return None
    pr = prompt("threat-model", ["pr", str(clone), "--base", anchor])
    return session([*AGENT, "--model", model, pr], "threat-model", env)
