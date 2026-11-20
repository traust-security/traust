"""`traust session run`: the role's model, the skill's prompt, a checkout outside the harness when
asked, the agent started in the harness, and the outcome as a JobResult."""

from __future__ import annotations

import contextlib
import io
import json
import shlex
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError

from traust.cli import session
from traust.paths import HARNESS_ROOT

REPO = "https://github.com/example/app"
HEAD = "b" * 40
ANCHOR = "a" * 40
PREPARED = json.dumps({"kind": "vuln-scan", "diff": {"anchor": ANCHOR}})
CLAUDE_RESULT = (Path(__file__).parent / "fixtures" / "session" / "claude-result.json").read_text()


class Processes:
    """Answers the model registry's `resolve_role`, `git rev-parse`, `assessments prepare`
    and the agent; records each call."""

    def __init__(
        self,
        model: str = "claude-opus-5-5",
        agent: int = 0,
        prepare: tuple[int, str] = (0, PREPARED),
        pr_agent: int = 0,
        unknown_role: str = "",
        reply: str = CLAUDE_RESULT,
    ) -> None:
        self.model, self.agent, self.reply = model, agent, reply
        self.prepare, self.pr_agent, self.unknown_role = prepare, pr_agent, unknown_role
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.roles: list[str] = []

    def resolve_role(self, role: str) -> str:
        self.roles.append(role)
        if not self.model or role == self.unknown_role:
            raise NotFoundError(f"unknown role '{role}'")
        return self.model

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kw))
        if argv[1:5] == ["-m", "traust.cli", "assessments", "prepare"]:
            code, out = self.prepare
            return subprocess.CompletedProcess(argv, code, out, "not registered")
        if argv[0] == "git" and argv[-2:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, HEAD + "\n", "")
        pr = argv[-1].startswith("/threat-model pr ")
        code = self.pr_agent if pr else self.agent
        return subprocess.CompletedProcess(argv, code, self.reply)

    def agent_call(self) -> tuple[list[str], dict[str, Any]]:
        (call,) = self.agent_calls()
        return call

    def agent_calls(self) -> list[tuple[list[str], dict[str, Any]]]:
        return [c for c in self.calls if c[0][0] == "claude"]

    def argv_of(self, *op: str) -> list[list[str]]:
        return [c[0] for c in self.calls if c[0][3 : 3 + len(op)] == list(op)]


@pytest.fixture(autouse=True)
def model_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """The registry is whichever Processes the test installed as `subprocess.run`."""
    monkeypatch.setattr(
        session, "load", lambda: SimpleNamespace(model_catalog=session.subprocess.run)
    )


@pytest.fixture
def processes(monkeypatch: pytest.MonkeyPatch) -> Processes:
    fake = Processes()
    monkeypatch.setattr(session.subprocess, "run", fake)
    return fake


class Checkout:
    """Stands in for `session.checkout`: a workspace under a temporary directory, released
    (recorded) when the session ends."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error, self.released, self.path = error, False, None

    def __call__(self, url: str, config_home: Path | None, ref: object = None) -> Checkout:
        self.url, self.ref = url, ref
        return self

    def __enter__(self) -> Checkout:
        if self.error is not None:
            raise self.error
        self.path = Path(tempfile.mkdtemp(prefix="traust-session-")) / "checkout"
        self.path.mkdir()
        (self.path / "cited.py").write_text("source at the assessed commit\n")
        return self

    def __exit__(self, *exc: object) -> None:
        shutil.rmtree(self.path.parent)
        self.released = True


@pytest.fixture(autouse=True)
def checkout(monkeypatch: pytest.MonkeyPatch) -> Checkout:
    """Every `--checkout` run in these tests gets the same stubbed workspace."""
    fake = Checkout()
    monkeypatch.setattr(session, "checkout", fake)
    return fake


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = session.run(list(argv))
    return rc, json.loads(out.getvalue().splitlines()[-1])


def test_a_session_runs_the_skill_on_the_roles_model_in_the_harness(processes: Processes) -> None:
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict", "--", "full-sweep"
    )
    assert (rc, result["outcome"]) == (0, "succeeded")
    argv, kw = processes.agent_call()
    assert argv[-3:] == ["--model", "claude-opus-5-5", "/verify-remediation full-sweep"]
    assert kw["cwd"] == HARNESS_ROOT
    assert processes.roles == ["verification-verdict"]


def test_a_repository_is_passed_by_url(processes: Processes) -> None:
    run("--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO)
    assert processes.agent_call()[0][-1] == f"/secure-code-audit {REPO}"


def test_a_checkout_is_a_workspace_outside_the_harness_released_when_the_session_ends(
    processes: Processes, checkout: Checkout
) -> None:
    rc, _ = run(
        "--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout", "--", "--diff"
    )
    prompt = processes.agent_call()[0][-1]
    path = Path(prompt.split()[1])
    assert prompt.startswith("/vuln-scan ") and prompt.endswith(" --diff") and rc == 0
    assert path == checkout.path
    assert not path.is_relative_to(HARNESS_ROOT) and not path.exists()  # gone after the session


def test_a_mode_token_comes_before_the_checkout(processes: Processes, checkout: Checkout) -> None:
    run(
        *("--skill", "threat-model", "--mode", "review", "--role", "threat-model"),
        *("--repo", REPO, "--checkout", "--", "--auto", "--apply-ratings"),
    )
    skill, mode, path, *flags = processes.agent_call()[0][-1].split()
    assert (skill, mode, flags) == ("/threat-model", "review", ["--auto", "--apply-ratings"])
    assert Path(path) == checkout.path


@pytest.mark.parametrize(
    ("fake", "argv", "outcome", "reason"),
    [
        (
            Processes(agent=3),
            ["--skill", "dependency-watch", "--role", "fact-judge"],
            "failed",
            "runner-crashed",
        ),
        (
            Processes(model=""),
            ["--skill", "dependency-watch", "--role", "nope"],
            "failed",
            "bad_request",
        ),
        (
            Processes(),
            ["--skill", "no-such-skill", "--role", "fact-judge"],
            "failed",
            "bad_request",
        ),
    ],
    ids=["session fails", "unknown role", "unknown skill"],
)
def test_what_cannot_run_is_answered_with_a_registered_reason(
    monkeypatch: pytest.MonkeyPatch, fake: Processes, argv: list[str], outcome: str, reason: str
) -> None:
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*argv)
    assert (result["outcome"], result["reason"]) == (outcome, reason)
    assert rc == {"failed": 1, "refused": 5}[outcome]


@pytest.mark.parametrize(
    ("error", "repo"),
    [
        (ServiceError("cannot check out: commit not in the repository"), REPO),
        (ValidationError("repo url must be https: 'http://x.io/a/b'"), "http://x.io/a/b"),
    ],
    ids=["checkout fails", "not https"],
)
def test_a_checkout_that_cannot_be_made_is_refused(
    monkeypatch: pytest.MonkeyPatch, error: Exception, repo: str
) -> None:
    monkeypatch.setattr(session, "checkout", Checkout(error))
    monkeypatch.setattr(session.subprocess, "run", Processes())
    rc, result = run("--skill", "vuln-scan", "--role", "vuln-scan", "--repo", repo, "--checkout")
    assert (result["outcome"], result["reason"]) == ("refused", "not_found")
    assert rc == 5


def test_checkout_needs_a_repository() -> None:
    with pytest.raises(SystemExit):
        session.run(["--skill", "vuln-scan", "--role", "vuln-scan", "--checkout"])


STAMPED_SCAN = (
    *("--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout"),
    *("--rule", "rule-5+threat-model-pr", "--", "--diff"),
)


def test_a_stamped_diff_scan_runs_threat_model_pr_on_the_same_checkout_at_its_anchor(
    processes: Processes,
    checkout: Checkout,
) -> None:
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"]) == (0, "succeeded")
    (scan, _), (pr, kw) = processes.agent_calls()
    clone = scan[-1].split()[1]
    assert scan[-1] == f"/vuln-scan {clone} --diff"
    assert pr[-1] == f"/threat-model pr {clone} --base {ANCHOR}" and kw["cwd"] == HARNESS_ROOT
    assert processes.roles == ["vuln-scan", "threat-model"]
    (prepare,) = processes.argv_of("assessments", "prepare")
    assert prepare[5:] == [
        *("--kind", "vuln-scan", "--repo-url", REPO, "--sha", HEAD, "--diff", clone)
    ]
    assert checkout.released  # the workspace outlives both sessions, then goes


@pytest.mark.parametrize("rule", ["rule-5", "rule-3+preroute"])
def test_an_unstamped_rule_runs_only_the_scan(processes: Processes, rule: str) -> None:
    rc, _ = run(
        *("--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout"),
        *("--rule", rule, "--", "--diff"),
    )
    assert rc == 0 and len(processes.agent_calls()) == 1
    assert processes.argv_of("assessments", "prepare") == []


def test_a_refused_diff_skips_the_pr_pass_and_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = {"refuse": True, "recommend": "full-audit", "reason": "anchor not reachable"}
    fake = Processes(prepare=(3, json.dumps(refusal)))
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"]) == (0, "succeeded")
    assert [c[0][-1].split()[0] for c in fake.agent_calls()] == ["/vuln-scan"]
    assert "+threat-model-pr skipped: diff refused: anchor not reachable" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("fake", "agents", "reason"),
    [
        (Processes(agent=3), ["/vuln-scan"], "runner-crashed"),
        (Processes(pr_agent=3), ["/vuln-scan", "/threat-model"], "runner-crashed"),
        (Processes(prepare=(2, "")), ["/vuln-scan"], "runner-crashed"),
        (Processes(unknown_role="threat-model"), [], "bad_request"),
    ],
    ids=["scan fails", "pr session fails", "prepare fails", "no threat-model model"],
)
def test_a_stamped_scan_that_cannot_finish_fails(
    monkeypatch: pytest.MonkeyPatch, fake: Processes, agents: list[str], reason: str
) -> None:
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", reason)
    assert [c[0][-1].split()[0] for c in fake.agent_calls()] == agents


def test_the_stamp_needs_a_checkout() -> None:
    with pytest.raises(SystemExit):
        session.run(
            [
                "--skill",
                "vuln-scan",
                "--role",
                "vuln-scan",
                "--repo",
                REPO,
                "--rule",
                "r+threat-model-pr",
            ]
        )


def test_the_session_answers_its_reply_then_a_job_result_carrying_its_usage(
    processes: Processes, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = session.run(["--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO])
    *text, last = capsys.readouterr().out.splitlines()
    assert rc == 0 and text == ["Scan recorded: 2 findings."]
    usage = json.loads(last)["usage"]
    assert [
        {k: u[k] for k in ("provider", "model", "tokens_in", "tokens_out", "cache_read",
                           "cache_creation", "skill", "session")}
        for u in usage
    ] == [
        {"provider": "anthropic", "model": "claude-haiku-4-5-20251001", "tokens_in": 20,
         "tokens_out": 100, "cache_read": 0, "cache_creation": 1000, "skill": "vuln-scan",
         "session": "00000000-0000-4000-8000-000000000001"},
        {"provider": "anthropic", "model": "claude-opus-5-5", "tokens_in": 1500,
         "tokens_out": 24000, "cache_read": 1830000, "cache_creation": 60000,
         "skill": "vuln-scan", "session": "00000000-0000-4000-8000-000000000001"},
    ]  # fmt: skip
    argv, _ = processes.agent_call()
    assert argv[:4] == ["claude", "-p", "--output-format", "json"]


def test_a_stamped_scan_carries_both_sessions_usage(processes: Processes) -> None:
    _, result = run(*STAMPED_SCAN)
    assert [(u["skill"], u["model"]) for u in result["usage"]] == [
        ("vuln-scan", "claude-haiku-4-5-20251001"),
        ("vuln-scan", "claude-opus-5-5"),
        ("threat-model", "claude-haiku-4-5-20251001"),
        ("threat-model", "claude-opus-5-5"),
    ]


def test_a_failed_session_still_carries_what_it_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session.subprocess, "run", Processes(agent=1))
    rc, result = run("--skill", "dependency-watch", "--role", "fact-judge")
    assert (rc, result["outcome"], len(result["usage"])) == (1, "failed", 2)


@pytest.mark.parametrize(
    ("reply", "usage"),
    [
        (json.dumps({**json.loads(CLAUDE_RESULT), "is_error": True}), 2),
        ("Not logged in", 0),
        ("", 0),
    ],
    ids=["an error result", "not json", "nothing"],
)
def test_a_session_without_a_good_json_result_fails(
    monkeypatch: pytest.MonkeyPatch, reply: str, usage: int
) -> None:
    monkeypatch.setattr(session.subprocess, "run", Processes(reply=reply))
    rc, result = run("--skill", "dependency-watch", "--role", "fact-judge")
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "runner-crashed")
    assert len(result["usage"]) == usage


def test_a_session_runs_with_the_runners_own_claude_config_dir(
    processes: Processes, tmp_path: Path
) -> None:
    run("--config-home", str(tmp_path), "--skill", "dependency-watch", "--role", "fact-judge")
    _, kw = processes.agent_call()
    assert kw["env"]["CLAUDE_CONFIG_DIR"] == str(tmp_path / "claude-runner")
    assert not Path(kw["env"]["CLAUDE_CONFIG_DIR"]).is_relative_to(Path.home() / ".claude")


ORDER = "8f7d5e2a-1c3b-4d5e-9f60-7a8b9c0d1e2f"


class Recorded:
    """The order's assessments before the agent runs, then after."""

    def __init__(self, before: list[tuple[str, str]], after: list[tuple[str, str]]) -> None:
        self.answers = [before, after]
        self.asked: list[object] = []

    def __call__(self, order_id: object, config_home: object) -> list[SimpleNamespace]:
        self.asked.append(order_id)
        return [SimpleNamespace(id=i, kind=k) for i, k in self.answers[len(self.asked) - 1]]


@pytest.mark.parametrize(
    ("before", "after", "outcome", "written"),
    [
        ([], [], "failed", []),
        ([], [("a-1", "secure_code")], "succeeded", ["a-1"]),
        # A retry that re-records an unchanged report is handed the earlier assessment
        # back, indistinguishable from a retry that recorded nothing: the order holding
        # its assessment of the kind is the contract, so this succeeds with the order's own.
        ([("a-0", "secure_code")], [("a-0", "secure_code")], "succeeded", ["a-0"]),
        (
            [("a-0", "secure_code")],
            [("a-0", "secure_code"), ("a-1", "secure_code")],
            "succeeded",
            ["a-1"],
        ),
        ([], [("t-1", "threat_model")], "failed", []),
    ],
    ids=["nothing", "recorded", "an idempotent retry", "a retry's own", "another kind"],
)
def test_an_ordered_audit_succeeds_only_if_this_attempt_recorded_its_kind_for_the_order(
    processes: Processes,
    monkeypatch: pytest.MonkeyPatch,
    before: list[tuple[str, str]],
    after: list[tuple[str, str]],
    outcome: str,
    written: list[str],
) -> None:
    recorded = Recorded(before, after)
    monkeypatch.setattr(session, "order_assessments", recorded)
    _, result = run(
        "--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO, "--run-id", ORDER
    )
    assert result["outcome"] == outcome
    assert result.get("reason") == (None if written else "session-output-invalid")
    assert result["written"] == written
    assert [str(o) for o in recorded.asked] == [ORDER, ORDER]
    assert processes.agent_call()[1]["env"]["TRAUST_RUN_ID"] == ORDER


@pytest.mark.parametrize(
    ("assessments", "outcome"), [([], "failed"), ([("t-1", "triage")], "succeeded")]
)
def test_scheduled_triage_requires_its_bound_assessment(
    processes: Processes,
    monkeypatch: pytest.MonkeyPatch,
    assessments: list[tuple[str, str]],
    outcome: str,
) -> None:
    monkeypatch.setattr(session, "order_assessments", Recorded([], assessments))
    replies = iter([
        (UUID(ORDER), HEAD, ()),
        (UUID(ORDER), HEAD, tuple(aid for aid, _ in assessments)),
    ])
    monkeypatch.setattr(session, "_triage_source", lambda *_: next(replies))
    _, result = run(
        "--skill", "triage", "--role", "triage-verifier", "--repo", REPO, "--run-id", ORDER
    )
    assert result["outcome"] == outcome
    assert result["written"] == [aid for aid, _ in assessments]
    words = shlex.split(processes.agent_call()[0][-1])
    assert words[:3] == ["/triage", ORDER, "--repo"]
    assert words[4:] == ["--auto", "--fresh"]


def test_a_failed_lookup_after_the_session_still_carries_what_it_spent(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter([[]])

    def lookup(*_: object) -> list[SimpleNamespace]:
        try:
            return next(answers)
        except StopIteration:
            raise ServiceError("core unavailable") from None

    monkeypatch.setattr(session, "order_assessments", lookup)
    rc, result = run(
        "--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "runner-crashed")
    assert len(result["usage"]) == 2


def test_a_configuration_that_exits_rather_than_raising_answers_bad_request(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`load` exits on an unusable configuration instead of raising; the caller still gets a
    structured result, and the post-session lookup carries what the run spent."""
    answers = iter([[], SystemExit(2)])

    def lookup(*_: object) -> list[SimpleNamespace]:
        answer = next(answers)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(session, "order_assessments", lookup)
    rc, result = run(
        "--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert len(result["usage"]) == 2
    assert processes.agent_calls()


def test_a_malformed_run_id_is_a_bad_request_before_the_agent_starts(
    processes: Processes,
) -> None:
    rc, result = run(
        "--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO, "--run-id", "x-1"
    )
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert processes.agent_calls() == []


def test_the_agent_records_into_the_sessions_config_home(
    processes: Processes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(tmp_path / "ambient"))
    run("--config-home", str(tmp_path), "--skill", "dependency-watch", "--role", "fact-judge")
    assert processes.agent_call()[1]["env"]["TRAUST_CONFIG_HOME"] == str(tmp_path)


def test_a_manual_or_non_recording_session_is_not_checked(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session, "order_assessments", lambda *_: pytest.fail("checked"))
    monkeypatch.setenv("TRAUST_RUN_ID", ORDER)  # inherited from an outer ordered session
    _, result = run("--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO)
    assert result["outcome"] == "succeeded"
    assert "TRAUST_RUN_ID" not in processes.agent_call()[1]["env"]
    _, result = run("--skill", "threat-model", "--role", "threat-model", "--run-id", ORDER)
    assert result["outcome"] == "succeeded"


@pytest.mark.parametrize(
    ("reporter", "outcome"),
    [
        (ORDER, "succeeded"),  # this order's run, a retry whose report already landed too
        (None, "failed"),  # no report, or one recorded by hand
        ("a6bf6a2c-6f6c-4a8f-9a5b-3f4f6c1d2e10", "failed"),  # another order's report
    ],
    ids=["this order's report", "no order's report", "another order's report"],
)
def test_an_ordered_fix_succeeds_only_when_this_order_recorded_its_report(
    processes: Processes,
    monkeypatch: pytest.MonkeyPatch,
    reporter: str | None,
    outcome: str,
) -> None:
    item = "6c703684-575d-43f9-8ad6-419be0241a14"
    monkeypatch.setattr(session, "_ordered_work_item", lambda order, args: item)
    monkeypatch.setattr(
        session,
        "_report_recorded_by",
        lambda work_item, args: None if reporter is None else UUID(reporter),
    )
    _, result = run("--skill", "remediate-finding", "--role", "remediation", "--run-id", ORDER)
    succeeded = outcome == "succeeded"
    assert (result["outcome"], result.get("reason")) == (
        outcome,
        None if succeeded else "session-output-invalid",
    )
    assert result["written"] == ([item] if succeeded else [])
    assert processes.agent_call()[1]["env"]["TRAUST_RUN_ID"] == ORDER


def test_an_order_naming_no_work_item_is_refused_before_the_agent_starts(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_item(order: object, args: object) -> str:
        raise ValidationError(f"order {order} names no work item")

    monkeypatch.setattr(session, "_ordered_work_item", no_item)
    rc, result = run("--skill", "remediate-finding", "--role", "remediation", "--run-id", ORDER)
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert processes.agent_calls() == []


def test_a_lookup_core_cannot_answer_before_the_session_is_not_a_bad_request(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(order: object, args: object) -> None:
        raise ServiceError("core unavailable")

    monkeypatch.setattr(session, "_ordered_work_item", unavailable)
    rc, result = run("--skill", "remediate-finding", "--role", "remediation", "--run-id", ORDER)
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "runner-crashed")
    assert processes.agent_calls() == []


def test_a_configuration_that_exits_before_a_fix_session_still_answers(
    processes: Processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    def exits(*_: object) -> None:
        raise SystemExit(2)

    monkeypatch.setattr(session, "_ordered_work_item", exits)
    rc, result = run("--skill", "remediate-finding", "--role", "remediation", "--run-id", ORDER)
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert processes.agent_calls() == []


@pytest.fixture
def scheduled_triage(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repo_id, ref_id, audit_id = uuid4(), uuid4(), uuid4()
    order = SimpleNamespace(repository_id=repo_id)
    ref = SimpleNamespace(id=ref_id, repository_id=repo_id, sha=ANCHOR)
    audit = SimpleNamespace(
        id=audit_id, repository_ref_id=ref_id, kind="secure_code", status="completed"
    )
    records: list[SimpleNamespace] = []
    services = SimpleNamespace(
        portfolio=SimpleNamespace(
            get_repository=lambda _: SimpleNamespace(url=REPO),
            inventory=SimpleNamespace(get_ref=lambda _: ref),
        ),
        assessment=SimpleNamespace(
            latest_on_default_line=lambda *_: audit,
            get=lambda _: audit,
            list_artifacts=lambda *_: [object()],
        ),
    )
    monkeypatch.setattr(session, "load", lambda _: SimpleNamespace(services=lambda: services))
    monkeypatch.setattr(session, "resolve_model", lambda _: "fixture-model")
    monkeypatch.setattr(session, "scoped_recording_order", lambda *_: order)
    monkeypatch.setattr(session, "order_assessments", lambda *_: list(records))

    def record(**changes: object) -> SimpleNamespace:
        values = {
            "id": uuid4(), "kind": "triage", "run_order_id": UUID(ORDER),
            "repository_ref_id": ref_id, "baseline_assessment_id": audit_id,
            "assessor": "triage", "status": "completed",
        }
        values.update(changes)
        row = SimpleNamespace(**values)
        records.append(row)
        return row

    return SimpleNamespace(
        order=order, ref=ref, audit=audit, records=records, services=services, record=record
    )


def test_scheduled_triage_reads_the_audited_commit_and_records_that_source(
    monkeypatch: pytest.MonkeyPatch, checkout: Checkout, scheduled_triage: SimpleNamespace
) -> None:
    monkeypatch.setenv("TRAUST_ORDER_STARTED_AT", "2026-01-01T00:00:00+00:00")

    def agent(command: list[str], skill: str, env: dict[str, str]) -> tuple[Any, tuple]:
        words = shlex.split(command[-1])
        assert words == [
            "/triage", str(scheduled_triage.audit.id), "--repo", str(checkout.path),
            "--auto", "--fresh",
        ]
        assert not checkout.path.is_relative_to(HARNESS_ROOT)
        assert (Path(words[3]) / "cited.py").read_text() == "source at the assessed commit\n"
        assert env["TRAUST_RUN_ID"] == ORDER
        assert env["TRAUST_ORDER_STARTED_AT"] == "2026-01-01T00:00:00+00:00"
        scheduled_triage.record()
        return subprocess.CompletedProcess(command, 0), ()

    monkeypatch.setattr(session, "session", agent)
    rc, result = run(
        "--skill", "triage", "--role", "triage-verifier", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["outcome"]) == (0, "succeeded")
    assert result["written"] == [str(scheduled_triage.records[0].id)]
    assert checkout.url == REPO and checkout.ref.value == ANCHOR and checkout.released


def test_completed_triage_is_reclaimed_without_a_checkout_or_model(
    processes: Processes, checkout: Checkout, scheduled_triage: SimpleNamespace
) -> None:
    recorded = scheduled_triage.record()
    # A later audit must not change which assessment this order already triaged.
    scheduled_triage.services.assessment.latest_on_default_line = lambda *_: pytest.fail("latest")
    rc, result = run(
        "--skill", "triage", "--role", "triage-verifier", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["written"]) == (0, [str(recorded.id)])
    assert not processes.agent_calls() and checkout.path is None


@pytest.mark.parametrize(
    "mutation", ["wrong-order", "wrong-repository", "wrong-baseline", "incomplete", "no-artifact"]
)
def test_triage_reclaim_rejects_invalid_completion_evidence(
    processes: Processes, scheduled_triage: SimpleNamespace, mutation: str
) -> None:
    row = scheduled_triage.record()
    if mutation == "wrong-order":
        row.run_order_id = uuid4()
    elif mutation == "wrong-repository":
        scheduled_triage.ref.repository_id = uuid4()
    elif mutation == "wrong-baseline":
        scheduled_triage.audit.repository_ref_id = uuid4()
    elif mutation == "incomplete":
        row.status = "running"
    else:
        scheduled_triage.services.assessment.list_artifacts = lambda *_: []
    rc, result = run(
        "--skill", "triage", "--role", "triage-verifier", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert not processes.agent_calls()


def test_triage_reclaim_checks_order_authorization_and_repository_first(
    processes: Processes, scheduled_triage: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    scheduled_triage.record()
    rc, result = run(
        "--skill", "triage", "--role", "triage-verifier",
        "--repo", "https://github.com/example/other", "--run-id", ORDER,
    )
    assert (rc, result["reason"]) == (1, "bad_request")
    monkeypatch.setattr(
        session, "scoped_recording_order",
        lambda *_: (_ for _ in ()).throw(ValidationError("wrong lease attempt")),
    )
    rc, result = run(
        "--skill", "triage", "--role", "triage-verifier", "--repo", REPO, "--run-id", ORDER
    )
    assert (rc, result["reason"]) == (1, "bad_request")
    assert not processes.agent_calls()


@pytest.fixture
def scheduled_sweep(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repo_id, ref_id, first, second = uuid4(), uuid4(), uuid4(), uuid4()
    order = SimpleNamespace(asset="verify_remediation", repository_id=repo_id, work_item_id=None)
    head = SimpleNamespace(id=ref_id, repository_id=repo_id, sha=HEAD, name="main", kind="branch")
    records: list[SimpleNamespace] = []
    reports: list[SimpleNamespace] = []
    state = SimpleNamespace(queued=True, skip="already_verified")

    def record(*findings: UUID) -> SimpleNamespace:
        row = SimpleNamespace(
            id=uuid4(), kind="verification", run_order_id=UUID(ORDER),
            status="completed", occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        records.append(row)
        reports.append(SimpleNamespace(
            verification_id=row.id, repository_ref_id=ref_id,
            verdicts=tuple(SimpleNamespace(finding_id=i) for i in findings),
            regression_ids=(),
        ))
        return row

    views = [SimpleNamespace(finding=SimpleNamespace(id=i)) for i in (first, second)]
    services = SimpleNamespace(
        portfolio=SimpleNamespace(
            get_repository=lambda _: SimpleNamespace(url=REPO),
            default_ref=lambda _: head,
            inventory=SimpleNamespace(get_ref=lambda _: head),
        ),
        assessment=SimpleNamespace(
            list_for_order=lambda _: [r for r in records if r.run_order_id == UUID(ORDER)],
            list_for_repository=lambda *_: list(records),
        ),
        findings=SimpleNamespace(on_ref=lambda _: views),
        verification=SimpleNamespace(
            sweep=lambda _: SimpleNamespace(
                queued=[object()] if state.queued else [],
                skipped=[] if state.queued else [SimpleNamespace(skip=state.skip)],
            ),
            list=lambda *_: SimpleNamespace(items=tuple(reports), next=None),
        ),
    )
    monkeypatch.setattr(session, "load", lambda _: SimpleNamespace(services=lambda: services))
    monkeypatch.setattr(session, "resolve_model", lambda _: "fixture-model")
    monkeypatch.setattr(session, "scoped_recording_order", lambda *_: order)
    monkeypatch.setattr(
        session, "order_assessments",
        lambda *_: [r for r in records if r.run_order_id == UUID(ORDER)],
    )
    return SimpleNamespace(
        order=order, head=head, first=first, second=second, records=records,
        reports=reports, views=views, state=state, services=services, record=record,
    )


@pytest.mark.parametrize(
    ("still_queued", "finish_second", "outcome"),
    [(True, False, "failed"), (False, False, "failed"), (False, True, "succeeded")],
)
def test_reclaimed_sweep_runs_remaining_work_and_requires_complete_coverage(
    monkeypatch: pytest.MonkeyPatch,
    scheduled_sweep: SimpleNamespace,
    still_queued: bool,
    finish_second: bool,
    outcome: str,
) -> None:
    sweep = scheduled_sweep
    sweep.record(sweep.first)
    called = []
    monkeypatch.setenv("TRAUST_ORDER_STARTED_AT", "2026-01-02T00:00:00+00:00")

    def agent(command: list[str], skill: str, env: dict[str, str]) -> tuple[Any, tuple]:
        called.append(command[-1])
        assert env["TRAUST_RUN_ID"] == ORDER
        assert env["TRAUST_ORDER_STARTED_AT"] == "2026-01-02T00:00:00+00:00"
        sweep.state.queued = still_queued
        if finish_second:
            sweep.record(sweep.second)
        return subprocess.CompletedProcess(command, 0), ()

    monkeypatch.setattr(session, "session", agent)
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert called == [f"/verify-remediation full-sweep --repo-url {REPO}"]
    assert result["outcome"] == outcome
    if outcome == "succeeded":
        assert rc == 0
        assert result["written"] == sorted(str(r.id) for r in sweep.records)
    else:
        assert (rc, result["reason"]) == (1, "session-output-invalid")


@pytest.mark.parametrize("complete", [False, True])
def test_unqueued_reclaimed_sweep_requires_proof_without_launching(
    processes: Processes, scheduled_sweep: SimpleNamespace, complete: bool
) -> None:
    sweep = scheduled_sweep
    row = sweep.record(*(sweep.first, sweep.second) if complete else (sweep.first,))
    sweep.state.queued = False
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert not processes.agent_calls()
    if complete:
        assert (rc, result["outcome"], result["written"]) == (0, "succeeded", [str(row.id)])
    else:
        assert (rc, result["outcome"], result["reason"]) == (1, "failed", "session-output-invalid")


@pytest.mark.parametrize("complete", [False, True])
def test_new_sweep_does_not_accept_another_orders_partial_verification(
    processes: Processes, scheduled_sweep: SimpleNamespace, complete: bool
) -> None:
    sweep = scheduled_sweep
    row = sweep.record(*(sweep.first, sweep.second) if complete else (sweep.first,))
    row.run_order_id = uuid4()
    sweep.state.queued = False
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert not processes.agent_calls()
    if complete:
        assert (rc, result["outcome"], result["written"]) == (0, "succeeded", [])
    else:
        assert (rc, result["reason"]) == (1, "session-output-invalid")


def test_sweep_coverage_does_not_count_another_line_or_order(
    processes: Processes, scheduled_sweep: SimpleNamespace
) -> None:
    sweep = scheduled_sweep
    sweep.record(sweep.first, sweep.second)
    sweep.state.queued = False
    sweep.head.name = "release"
    other = SimpleNamespace(
        repository_id=sweep.head.repository_id, sha=HEAD, name="main", kind="branch"
    )
    sweep.services.portfolio.inventory.get_ref = lambda _: other
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert (rc, result["reason"]) == (1, "session-output-invalid")
    assert not processes.agent_calls()


def test_sweep_does_not_accept_proof_if_the_observed_head_moves_during_the_check(
    processes: Processes, scheduled_sweep: SimpleNamespace
) -> None:
    sweep = scheduled_sweep
    sweep.record(sweep.first, sweep.second)
    sweep.state.queued = False
    heads = iter([sweep.head, SimpleNamespace(id=uuid4(), sha=ANCHOR)])
    sweep.services.portfolio.default_ref = lambda _: next(heads)
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert (rc, result["reason"]) == (1, "session-output-invalid")
    assert not processes.agent_calls()


def test_finding_reported_since_partial_sweep_is_not_silently_skipped(
    processes: Processes, scheduled_sweep: SimpleNamespace
) -> None:
    sweep = scheduled_sweep
    sweep.record(sweep.first, sweep.second)
    sweep.views.append(SimpleNamespace(finding=SimpleNamespace(id=uuid4())))
    sweep.state.queued = False
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert (rc, result["reason"]) == (1, "session-output-invalid")
    assert not processes.agent_calls()


def test_default_sweep_ignores_findings_only_on_other_lines(
    processes: Processes, scheduled_sweep: SimpleNamespace
) -> None:
    sweep = scheduled_sweep
    row = sweep.record(sweep.first, sweep.second)
    branch_only = uuid4()
    sweep.services.findings.records = SimpleNamespace(
        ids_for_repository=lambda _: {sweep.first, sweep.second, branch_only}
    )
    sweep.state.queued = False
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert (rc, result["outcome"], result["written"]) == (0, "succeeded", [str(row.id)])
    assert not processes.agent_calls()


@pytest.mark.parametrize("external_origin", [False, True])
def test_new_regression_is_excluded_only_if_the_order_first_reported_it(
    processes: Processes, scheduled_sweep: SimpleNamespace, external_origin: bool
) -> None:
    sweep = scheduled_sweep
    row = sweep.record(sweep.first, sweep.second)
    regression = uuid4()
    sweep.views.append(SimpleNamespace(finding=SimpleNamespace(id=regression)))
    sweep.reports[0].regression_ids = (regression,)
    origins = [SimpleNamespace(finding_id=regression, assessment_id=row.id)]
    if external_origin:
        origins.append(SimpleNamespace(finding_id=regression, assessment_id=uuid4()))
    sweep.services.findings.occurrences = lambda **_: origins
    sweep.state.queued = False
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    assert not processes.agent_calls()
    if external_origin:
        assert (rc, result["reason"]) == (1, "session-output-invalid")
    else:
        assert (rc, result["written"]) == (0, [str(row.id)])


@pytest.mark.parametrize("full", [False, True])
def test_work_item_reclaim_only_skips_a_report_covering_all_its_findings(
    monkeypatch: pytest.MonkeyPatch, scheduled_sweep: SimpleNamespace, full: bool
) -> None:
    sweep = scheduled_sweep
    sweep.order.work_item_id = uuid4()
    row = sweep.record(*(sweep.first, sweep.second) if full else (sweep.first,))
    item = SimpleNamespace(
        finding_ids=(sweep.first, sweep.second),
        fork=SimpleNamespace(url=REPO), fix_commit=HEAD,
    )
    sweep.services.verification.prepare = lambda _: SimpleNamespace(
        subject=SimpleNamespace(repository_id=sweep.order.repository_id),
        work_item=item,
        verifications=tuple(sweep.reports),
    )
    called = []

    def agent(command: list[str], skill: str, env: dict[str, str]) -> tuple[Any, tuple]:
        called.append(command[-1])
        return subprocess.CompletedProcess(command, 0), ()

    monkeypatch.setattr(session, "session", agent)
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict",
        "--repo", REPO, "--run-id", ORDER,
    )
    if full:
        assert (rc, result["written"], called) == (0, [str(row.id)], [])
    else:
        assert (rc, result["reason"]) == (1, "session-output-invalid")
        assert called == [f"/verify-remediation {sweep.order.work_item_id} {REPO}@{HEAD}"]
