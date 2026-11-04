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
from traust_core.v1.context import TRAUST_CONFIG_HOME_ENV, CheckoutRequest, Context, Workspace
from traust_core.v1.errors import NotFoundError, ServiceError, TraustError, ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind, DiffRefused
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import (
    JobResult,
    ModelName,
    ModelUsage,
    OrderReason,
    ProviderName,
    SessionResult,
    SkillName,
    WorkerId,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli._doors import RUN_ORDER_ENV, answer, parser
from traust.cli._doors import run as door
from traust.cli.assessments import REFUSED
from traust.context import MODEL_REGISTRY, TRAUST_CONFIG_HOME_DEFAULT, load, resolve_config_home
from traust.ops.materializers import _order_id
from traust.ops.router import THREAT_MODEL_PR
from traust.ops.session_guard import flags as confinement_flags
from traust.ops.sessions import SESSIONS, SessionRunner
from traust.paths import HARNESS_ROOT, HARNESSING_DIR, skill_dir

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
}


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
def checkout(url: str, config_home: Path | None) -> Iterator[Workspace]:
    """The order's commit — the head its repo_state observation recorded, not the branch's
    current tip — through the checkout service, released when the session ends. The mirror's
    worktree holds the history a diff scan anchors at (the anchor itself only resolves once
    the checkout exists, so the request names no bound)."""
    core = load(config_home)
    services = core.services()
    parsed = HttpsRepoUrl.parse(url, core.config.forge_hosts)
    repo = services.portfolio.find_repository(parsed)
    if repo is None or repo.id is None:
        raise NotFoundError(f"{url}: not in the inventory (`traust portfolio observe` records it)")
    head = services.portfolio.default_ref(repo.id)
    if head is None:
        raise NotFoundError(f"{url}: no observed default head to check out")
    workspace = services.checkouts.checkout(
        CheckoutRequest(repo=parsed, ref=GitSha.parse(head.sha))
    ).data
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
    try:
        order_id = _order_id(args.run_id)
        # an earlier attempt's assessments are not this one's
        before = set() if order_id is None or kind is None else _recorded(order_id, kind, args)
    except ValueError:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: not a run order id", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    except (TraustError, OSError) as e:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {type(e).__name__}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    env = {**os.environ, "CLAUDE_CONFIG_DIR": str(claude_dir(args.config_home))}
    # The record doors default to this order and home: a manual session inherits neither.
    env.pop(RUN_ORDER_ENV, None)
    if order_id is not None:
        env[RUN_ORDER_ENV] = str(order_id)
    if args.config_home is not None:
        env[TRAUST_CONFIG_HOME_ENV] = str(args.config_home)
    usage: tuple[ModelUsage, ...] = ()
    entered = checkout(args.repo, args.config_home) if args.checkout else nullcontext(None)
    try:
        with entered as workspace:
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
    if order_id is not None and kind is not None:
        try:
            written = sorted(_recorded(order_id, kind, args) - before)
        except (TraustError, OSError) as e:
            print(
                f"run {args.run_id}: recorded-assessment lookup: {type(e).__name__}",
                file=sys.stderr,
            )
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
        if not written:
            print(
                f"run {args.run_id}: /{args.skill} recorded no {kind} assessment", file=sys.stderr
            )
            return answer(_spent(JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID), usage))
        return answer(_spent(JobResult.succeeded(written=tuple(written)), usage))
    return answer(_spent(JobResult.succeeded(), usage))


def order_assessments(order_id: UUID, config_home: Path | None) -> list[Assessment]:
    """What the order recorded, as its record doors bound it (`--run-id`)."""
    return load(config_home).services().assessment.list_for_order(order_id)


def _recorded(order_id: UUID, kind: AssessmentKind, args: argparse.Namespace) -> set[str]:
    """The ids of the order's assessments of `kind`."""
    return {str(a.id) for a in order_assessments(order_id, args.config_home) if a.kind == kind}


def _spent(result: JobResult, usage: tuple[ModelUsage, ...]) -> JobResult:
    return result.model_copy(update={"usage": usage})


def _runner(config_home: Path | None) -> tuple[Context, SessionRunner]:
    from traust.cli.impact import _core

    core = _core(config_home)
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
        env["CLAUDE_CONFIG_DIR"] = str(claude_dir(config_home))
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
