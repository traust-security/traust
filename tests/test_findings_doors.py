"""`traust auth` and `traust findings` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import base64
import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from traust_core.v1.models.attestation import Comment, ExternalHandle
from traust_core.v1.models.vocabulary import ReviewReason, SourceType
from traust_core.v1.providers.base import Acquisition, Result

from tests.test_triage_doors import SARIF, SHA
from tests.test_validate_report import _canonical_report
from tests.test_validate_vuln_findings import _valid_doc as _canonical_vuln_findings
from traust.cli import auth, findings, triage
from traust.cli.__main__ import main
from traust.context import load

REPO = "https://github.com/example/canary"


def config_home(tmp_path: Path, **core: Any) -> Path:
    home = tmp_path / "config"
    home.mkdir(exist_ok=True)
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store"), **core}))
    return home


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A solo install: SQLite under the test's directory, and core trusts its own local tokens."""
    return config_home(tmp_path, identity={"trust_local": True})


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    try:
        return rc, json.loads(text)
    except json.JSONDecodeError:
        return rc, text


def scanned(home: Path, tmp_path: Path) -> str:
    """One finding at entry.c, recorded through the triage skill's intake door."""
    scan = tmp_path / "scan.sarif"
    scan.write_text(json.dumps(SARIF))
    argv = ("--format", "sarif", "--repo-url", REPO, "--sha", SHA)
    rc, out = run(triage.intake, home, str(scan), *argv)
    assert rc == 0, out
    rc, listed = run(findings.baseline, home, "--repo-url", REPO)
    assert rc == 0, listed
    [view] = listed
    return view["finding"]["id"]


def test_a_report_label_resolves_to_its_finding(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    report = tmp_path / "canary-security-audit.json"
    entry = {"id": "CANARY-aaaaaaa-001", "locations": [{"path": "./entry.c", "line_start": 25}]}
    report.write_text(json.dumps({"findings": [entry]}))
    argv = ("--label", "CANARY-aaaaaaa-001", "--repo-url", REPO)
    assert run(findings.find, home, str(report), *argv) == (
        0,
        {"label": "CANARY-aaaaaaa-001", "finding_id": finding_id},
    )


def test_a_label_never_accepted_finds_nothing(home: Path, tmp_path: Path) -> None:
    scanned(home, tmp_path)
    report = tmp_path / "other.json"
    report.write_text(json.dumps({"findings": [{"id": "X-1", "locations": [{"path": "b.c"}]}]}))
    rc, out = run(findings.find, home, str(report), "--label", "X-1", "--repo-url", REPO)
    assert (rc, out["finding_id"]) == (0, None)


def test_a_label_missing_from_the_report_is_an_error(home: Path, tmp_path: Path) -> None:
    scanned(home, tmp_path)
    report = tmp_path / "empty.json"
    report.write_text(json.dumps({"findings": []}))
    rc, _ = run(findings.find, home, str(report), "--label", "X-1", "--repo-url", REPO)
    assert rc == 2


def test_a_local_humans_ungraded_judgement_does_not_infer_assurance(
    home: Path, tmp_path: Path
) -> None:
    finding_id = scanned(home, tmp_path)
    rc, before = run(findings.status, home, finding_id)
    assert (rc, before["disposition"], before["effective_severity"]) == (0, None, "high")

    rc, made = run(auth.local, home, "--identity", "alice@example.com")
    assert (rc, made["kind"], made["identity"]) == (0, "human", "alice@example.com")
    rc, who = run(auth.status, home)
    assert (rc, who["verified"], who["actor"]) == (0, True, "human:alice@example.com")

    why = "the length is checked against the buffer at entry.c:20"
    rc, decision = run(
        findings.decide, home, finding_id, "--validity", "false_positive", "--rationale", why
    )
    assert rc == 0, decision
    assert (decision["actor"], decision["source_channel"]) == (
        "human:alice@example.com",
        "interactive",
    )
    assert decision["evidence_grade"] is None

    rc, after = run(findings.status, home, finding_id)
    assert (after["disposition"]["validity"], after["disposition"]["assurance"]) == (
        "false_positive",
        "claimed",
    )
    assert after["sla_due"] is None
    rc, decisions = run(findings.history, home, finding_id)
    assert [d["rationale"] for d in decisions] == [why]


def test_the_same_statement_twice_is_one_decision(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    argv = (finding_id, "--resolution", "open", "--rationale", "MR !17 fixes it")
    argv += ("--occurred-at", "2026-10-23T09:00:00+00:00")
    _, first = run(findings.decide, home, *argv)
    _, again = run(findings.decide, home, *argv)
    assert first["id"] == again["id"]
    assert len(run(findings.history, home, finding_id)[1]) == 1


def test_a_machine_cannot_state_a_verdict_directly(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "triage/0.34.2", "--machine")
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced in the sandbox")
    assert run(findings.decide, home, *argv)[0] == 2
    assert run(findings.history, home, finding_id)[1] == []


def test_deciding_needs_a_login(home: Path, tmp_path: Path, capsys: Any) -> None:
    finding_id = scanned(home, tmp_path)
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced it by hand")
    assert run(findings.decide, home, *argv)[0] == 2
    assert "traust auth login" in capsys.readouterr().err


def test_without_an_identity_section_core_trusts_no_token(tmp_path: Path, capsys: Any) -> None:
    home = config_home(tmp_path)
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced it by hand")
    assert run(findings.decide, home, *argv)[0] == 2
    assert "trust_local: true" in capsys.readouterr().err
    rc, who = run(auth.status, home)
    assert (rc, who["logged_in"], who["verified"]) == (0, True, False)


def test_saying_nothing_is_refused(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    assert run(findings.decide, home, finding_id, "--rationale", "nothing to add here")[0] == 2


def test_token_and_logout(home: Path) -> None:
    run(auth.local, home, "--identity", "alice@example.com")
    rc, token = run(auth.token, home)
    assert rc == 0 and token.count(".") == 2
    assert run(auth.logout, home) == (0, {"logged_in": False})
    assert run(auth.status, home) == (0, {"logged_in": False})
    assert run(auth.token, home)[0] == 2


def test_an_imported_token_is_stored(home: Path, tmp_path: Path) -> None:
    run(auth.local, home, "--identity", "alice@example.com")
    _, token = run(auth.token, home)
    run(auth.logout, home)
    path = tmp_path / "token"
    path.write_text(token + "\n")
    rc, made = run(auth.login, home, "--token-file", str(path))
    assert (rc, made["issuer"], made["identity"]) == (0, "local", "alice@example.com")
    assert run(auth.status, home)[1]["verified"] is True


@pytest.mark.parametrize("door", [auth.login, auth.service_account, auth.refresh])
def test_provider_flows_need_identity_login(home: Path, door: Any, capsys: Any) -> None:
    assert run(door, home)[0] == 2
    err = capsys.readouterr().err
    assert "identity.login" in err or "traust auth login" in err


def test_an_unregistered_repository_is_an_error(home: Path) -> None:
    assert run(findings.baseline, home, "--repo-url", "https://github.com/example/none")[0] == 2


class Said:
    """A comment source standing in for gh / glab / jira: returns what the test put on it."""

    def __init__(self, name: str, comments: list[Any]) -> None:
        self.name, self.said = name, comments

    def check(self) -> Any:
        return None

    def comments(self, ref: Any) -> Any:
        from datetime import UTC, datetime

        return Result(
            list(self.said), Acquisition(provider=self.name, acquired_at=datetime.now(UTC))
        )


MR = "https://github.com/example/canary/pull/7"


def comment(body: str, n: int, **kw: Any) -> Any:
    values: dict[str, Any] = {
        "source": SourceType.MR_COMMENT,
        "author": ExternalHandle("maint"),
        "body": body,
        "at": datetime(2026, 10, 22, 9, n, tzinfo=UTC),
        "url": f"{MR}#issuecomment-{n}",
        "maintainer": True,
    }
    return Comment(**{**values, **kw})


@pytest.fixture
def forge(monkeypatch: pytest.MonkeyPatch) -> dict[str, Said]:
    sources = {"forge": Said("forge", []), "jira": Said("jira", [])}
    monkeypatch.setattr("traust_core.v1.context.context.comment_sources", lambda *a, **k: sources)
    return sources


def audit_report(tmp_path: Path) -> Path:
    report = tmp_path / "canary-security-audit.json"
    entry = {"id": "CANARY-aaaaaaa-001", "locations": [{"path": "entry.c", "line_start": 25}]}
    report.write_text(json.dumps({"findings": [entry]}))
    return report


def test_import_records_what_stands_and_queues_the_rest(
    home: Path, tmp_path: Path, forge: dict[str, Said]
) -> None:
    finding_id = scanned(home, tmp_path)
    report = audit_report(tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    forge["forge"].said = [
        comment("/traust false-positive CANARY-aaaaaaa-001 the length is checked at entry.c:20", 1),
    ]
    argv = (MR, "--repo-url", REPO, "--report", str(report))
    rc, got = run(findings.import_, home, *argv)
    assert rc == 0, got
    [made] = got["recorded"]
    assert (made["finding_id"], made["validity"], made["actor"]) == (
        finding_id,
        "false_positive",
        "human:alice@example.com",
    )
    assert run(findings.import_, home, *argv)[1]["already_imported"] == 1
    rc, fps = run(findings.refuted, home, "--repo-url", REPO)
    assert [v["finding"]["id"] for v in fps] == [finding_id]


def test_a_queued_statement_is_reviewed_then_confirmed(
    home: Path, tmp_path: Path, forge: dict[str, Said]
) -> None:
    finding_id = scanned(home, tmp_path)
    report = audit_report(tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    forge["forge"].said = [comment("CANARY-aaaaaaa-001 looks like a false positive to me", 2)]
    rc, got = run(findings.import_, home, MR, "--repo-url", REPO, "--report", str(report))
    [item] = got["queued"]
    assert item["reason"] == "ambiguous_statement"

    rc, waiting = run(findings.queue, home, "--repo-url", REPO, "--report", str(report))
    [shown] = waiting
    assert shown["sources"] == [f"{MR}#issuecomment-2"]
    assert [s["body"] for s in shown["said"]] == [
        "CANARY-aaaaaaa-001 looks like a false positive to me"
    ]

    why = f'maint on {MR}#issuecomment-2, confirmed with them: "length checked at entry.c:20"'
    argv = (item["id"], finding_id, "--validity", "false_positive", "--rationale", why)
    argv += ("--source", "mr_comment")
    rc, closed = run(findings.confirm, home, *argv)
    assert (rc, closed["status"]) == (0, "accepted"), closed
    assert run(findings.queue, home)[1] == []
    assert run(findings.status, home, finding_id)[1]["disposition"]["validity"] == "false_positive"


def test_full_review_cases_re_read_sources_without_changing_the_summary_queue(
    home: Path, tmp_path: Path, forge: dict[str, Said]
) -> None:
    finding_id = scanned(home, tmp_path)
    report = audit_report(tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    forge["forge"].said = [comment("CANARY-aaaaaaa-001 needs a human review", 2)]
    _, imported = run(findings.import_, home, MR, "--repo-url", REPO, "--report", str(report))
    [item] = imported["queued"]
    arguments = ("--repo-url", REPO, "--report", str(report))
    rc, page = run(findings.review_cases, home, *arguments)
    assert rc == 0 and page["next"] is None
    [card] = page["items"]
    assert card["review_item"]["id"] == item["id"]
    assert card["finding"]["finding"]["id"] == finding_id
    assert card["history"] == []
    assert card["sources"] == [f"{MR}#issuecomment-2"]
    assert [statement["body"] for statement in card["said"]] == [
        "CANARY-aaaaaaa-001 needs a human review"
    ]

    forge["forge"].said = [comment("CANARY-aaaaaaa-001 has edited evidence, not approval", 2)]
    _, refreshed = run(findings.review_cases, home, *arguments)
    assert [statement["body"] for statement in refreshed["items"][0]["said"]] == [
        "CANARY-aaaaaaa-001 has edited evidence, not approval"
    ]
    _, summary = run(findings.queue, home, *arguments)
    [shown] = summary
    assert shown["id"] == item["id"] and shown["status"] == "pending"
    assert shown["said"] == refreshed["items"][0]["said"]
    assert run(findings.history, home, finding_id) == (0, [])


def test_a_queued_statement_can_be_rejected(
    home: Path, tmp_path: Path, forge: dict[str, Said]
) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    forge["forge"].said = [comment("CANARY-aaaaaaa-001?", 3, maintainer=False)]
    _, got = run(
        findings.import_, home, MR, "--repo-url", REPO, "--report", str(audit_report(tmp_path))
    )
    [item] = got["queued"]
    why = "Reviewed the reachable operation; the ambiguous comment does not refute it."
    argv = (item["id"], finding_id, "--validity", "confirmed", "--rationale", why)
    rc, closed = run(findings.reject, home, *argv)
    assert (rc, closed["status"]) == (0, "rejected")
    rc, history = run(findings.history, home, finding_id)
    [decision] = history
    assert rc == 0 and decision["validity"] == "confirmed"
    assert decision["rationale"] == why and decision["evidence_grade"] is None
    assert closed["resolved_by_decision_id"] == decision["id"]
    assert run(findings.reject, home, *argv) == (0, closed)
    assert run(findings.history, home, finding_id)[1] == history
    assert run(findings.queue, home)[1] == []


def test_tickets_name_the_jira_keys_on_a_repositorys_findings(
    home: Path, tmp_path: Path, forge: dict[str, Said]
) -> None:
    scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    forge["jira"].said = [
        comment(
            "Filed for CANARY-aaaaaaa-001",
            4,
            source=SourceType.JIRA,
            author="",
            status="In Progress",
            url="https://example.atlassian.net/browse/SEC-12",
        )
    ]
    _, got = run(
        findings.import_,
        home,
        "SEC-12",
        "--repo-url",
        REPO,
        "--report",
        str(audit_report(tmp_path)),
    )
    assert [i["reason"] for i in got["queued"]] == ["unverified_identity"]
    assert run(findings.tickets, home, "--repo-url", REPO) == (0, ["SEC-12"])


def test_sarif_and_surfaces(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    argv = ("--repo-url", REPO, "--as-of", "2099-01-01T00:00:00+00:00")
    rc, doc = run(findings.sarif, home, *argv)
    assert rc == 0 and doc["version"] == "2.1.0"
    [result] = doc["runs"][0]["results"]
    assert result["partialFingerprints"]["traustFindingId/v1"] == finding_id
    assert doc["runs"][0]["versionControlProvenance"] == [{"repositoryUri": REPO}]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "entry.c"
    out = tmp_path / "canary.sarif"
    assert run(findings.sarif, home, *argv, "-o", str(out))[0] == 0
    assert json.loads(out.read_text()) == doc
    assert run(findings.surfaces, home, "--repo-url", REPO) == (0, {})


def registered(home: Path, *argv: str) -> tuple[int, Any]:
    group, operation, *rest = argv
    return run(lambda options: main([group, operation, *options]), home, *rest)


def test_stored_auth_local_records_and_applies_countersign(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, caplog: Any
) -> None:
    finding_id = scanned(home, tmp_path)
    assert registered(home, "auth", "local", "--identity", "alice@example.com")[0] == 0
    assert registered(home, "auth", "status")[1]["actor"] == "human:alice@example.com"
    login = load(home).credentials.load()
    assert login is not None
    token = login.grant.access_token.get_secret_value()

    class NoTokenInput(io.StringIO):
        def read(self, *args: Any, **kwargs: Any) -> str:
            pytest.fail("stored login must not read stdin")

    monkeypatch.setattr("sys.stdin", NoTokenInput())
    why = "The human verified the reachable impact and selected a medium rating."
    rc, recorded = registered(
        home,
        "findings",
        "record",
        "--finding",
        finding_id,
        "--decision",
        "severity",
        "--severity",
        "medium",
        "--rationale",
        why,
    )
    assert rc == 0 and recorded["actor"] == "human:alice@example.com"
    assert recorded["severity"] == "medium" and recorded["evidence_grade"] is None
    rc, item = registered(
        home,
        "findings",
        "request",
        "--finding",
        finding_id,
        "--reason",
        "ambiguous_statement",
    )
    assert rc == 0 and item["status"] == "pending"
    answer = tmp_path / "reviewed.json"
    rationale = "The human inspected the concrete call path and confirmed the finding."
    answer.write_text(
        json.dumps(
            {
                "review_item_id": item["id"],
                "decision": "reject",
                "answer": {
                    "finding_id": finding_id,
                    "validity": "confirmed",
                    "rationale": rationale,
                },
            }
        )
    )
    rc, applied = registered(home, "findings", "apply", str(answer))
    assert rc == 0
    receipt = applied["results"][0]["review_item"]
    assert receipt["status"] == "rejected"
    assert receipt["finding"]["disposition"]["validity"] == "confirmed"
    assert registered(home, "findings", "apply", str(answer)) == (0, applied)
    decisions = load(home).services().findings.history(UUID(finding_id))
    assert len(decisions) == 2
    assert {d.actor for d in decisions} == {"human:alice@example.com"}
    assert {d.rationale for d in decisions} == {why, rationale}
    resolving = next(d for d in decisions if str(d.id) == receipt["resolved_by_decision_id"])
    assert resolving.validity == "confirmed" and resolving.rationale == rationale
    output = capsys.readouterr()
    serialized = json.dumps([recorded, applied])
    assert token not in output.out + output.err + serialized + caplog.text
    assert why not in serialized + output.err and rationale not in serialized + output.err


@pytest.mark.parametrize("explicit", ["invalid", "empty", "machine", "human"])
def test_explicit_token_never_falls_back_to_the_stored_login(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, explicit: str
) -> None:
    finding_id = scanned(home, tmp_path)
    registered(home, "auth", "local", "--identity", "alice@example.com")
    core = load(home)
    token = (
        core.local_issuer.mint(
            "bob@example.com", machine=explicit == "machine"
        ).token.get_secret_value()
        if explicit in ("human", "machine")
        else "invalid-do-not-print"
        if explicit == "invalid"
        else ""
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    rc, receipt = registered(
        home,
        "findings",
        "record",
        "--finding",
        finding_id,
        "--decision",
        "severity",
        "--severity",
        "medium",
        "--rationale",
        "The reviewer checked the impact against the reachable path.",
        "--token-stdin",
    )
    history = core.services().findings.history(UUID(finding_id))
    if explicit == "human":
        assert rc == 0 and receipt["actor"] == "human:bob@example.com"
        assert len(history) == 1 and history[0].actor == "human:bob@example.com"
    else:
        assert rc == 2 and history == []
    if token:
        output = capsys.readouterr()
        assert token not in output.out + output.err + json.dumps(receipt)
    assert registered(home, "auth", "status")[1]["actor"] == "human:alice@example.com"


@pytest.mark.parametrize("state", ["logged-out", "machine-admin", "untrusted-local"])
@pytest.mark.parametrize("operation", ["record", "request", "apply"])
def test_stored_unauthorized_caller_cannot_countersign(
    home: Path, tmp_path: Path, state: str, operation: str
) -> None:
    finding_id = scanned(home, tmp_path)
    services = load(home).services()
    item = services.attestation.request(UUID(finding_id), None, ReviewReason.AMBIGUOUS_STATEMENT)
    if state == "machine-admin":
        (home / "traust.yaml").write_text(
            yaml.safe_dump(
                {
                    "home": str(tmp_path / "store"),
                    "identity": {"trust_local": True, "admins": ["reviewer@example.com"]},
                }
            )
        )
    flags = ("--machine",) if state == "machine-admin" else ()
    assert registered(home, "auth", "local", "--identity", "reviewer@example.com", *flags)[0] == 0
    if state == "machine-admin":
        assert "admin" in registered(home, "auth", "status")[1]["roles"]
    elif state == "logged-out":
        assert registered(home, "auth", "logout") == (0, {"logged_in": False})
    else:
        (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    if operation == "record":
        arguments = (
            "--finding",
            finding_id,
            "--decision",
            "severity",
            "--severity",
            "high",
            "--rationale",
            "The reviewer inspected the reachable security impact.",
        )
    elif operation == "request":
        arguments = ("--finding", finding_id, "--reason", "insufficient_authority")
    else:
        path = tmp_path / "answer.json"
        path.write_text(
            json.dumps(
                {
                    "review_item_id": str(item.id),
                    "decision": "confirm",
                    "answer": {
                        "finding_id": finding_id,
                        "validity": "confirmed",
                        "rationale": "The reviewer inspected the reachable security impact.",
                    },
                }
            )
        )
        arguments = (str(path),)
    assert registered(home, "findings", operation, *arguments)[0] == 2
    assert services.findings.history(UUID(finding_id)) == []
    assert services.attestation.for_finding(UUID(finding_id)) == [item]


@pytest.mark.parametrize("operation", ["confirm", "reject"])
@pytest.mark.parametrize(
    "boundary", ["rationale-only", "short-rationale", "cross-finding", "machine"]
)
def test_findings_review_refusal_preserves_pending_item(
    home: Path, tmp_path: Path, capsys: Any, operation: str, boundary: str
) -> None:
    finding_id = scanned(home, tmp_path)
    services = load(home).services()
    item = services.attestation.request(UUID(finding_id), None, ReviewReason.AMBIGUOUS_STATEMENT)
    flags = ("--machine",) if boundary == "machine" else ()
    run(auth.local, home, "--identity", "alice@example.com", *flags)
    judged_id = str(uuid4()) if boundary == "cross-finding" else finding_id
    why = (
        "short" if boundary == "short-rationale" else "The human inspected the actual claimed path."
    )
    judged = () if boundary == "rationale-only" else ("--validity", "confirmed")
    rc, receipt = registered(
        home, "findings", operation, str(item.id), judged_id, "--rationale", why, *judged
    )
    assert rc == 2 and receipt == ""
    assert why not in capsys.readouterr().err
    assert services.findings.history(UUID(finding_id)) == []
    assert services.attestation.for_finding(UUID(finding_id)) == [item]


def test_async_workbench_uses_stored_login_without_stdin(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_countersign_record import edit_workbench_answers

    finding_id = scanned(home, tmp_path)
    services = load(home).services()
    item = services.attestation.request(UUID(finding_id), None, ReviewReason.AMBIGUOUS_STATEMENT)
    assert registered(home, "auth", "local", "--identity", "alice@example.com")[0] == 0

    class NoTokenInput(io.StringIO):
        def read(self, *args: Any, **kwargs: Any) -> str:
            pytest.fail("stored login must not read stdin for a Markdown workbench")

    monkeypatch.setattr("sys.stdin", NoTokenInput())
    path = tmp_path / "countersign-queue.md"
    rc, receipt = registered(home, "findings", "review-cases", "--output", str(path))
    assert (rc, receipt["items"]) == (0, 1)
    assert registered(home, "findings", "apply", str(path)) == (
        0,
        {"results": [], "deferred": True},
    )
    assert services.findings.history(UUID(finding_id)) == []
    rationale = "I followed the concrete call path and confirmed the reviewed finding."
    edit_workbench_answers(
        path,
        [
            {
                "review_item_id": str(item.id),
                "decision": "confirm",
                "answer": {
                    "finding_id": finding_id,
                    "validity": "confirmed",
                    "rationale": rationale,
                },
            }
        ],
    )
    rc, applied = registered(home, "findings", "apply", str(path))
    assert rc == 0 and applied["results"][0]["review_item"]["status"] == "accepted"
    [decision] = services.findings.history(UUID(finding_id))
    assert (decision.actor, decision.rationale, decision.evidence_grade) == (
        "human:alice@example.com",
        rationale,
        None,
    )
    assert (
        services.attestation.for_finding(UUID(finding_id))[0].resolved_by_decision_id == decision.id
    )


def test_review_evidence_retains_a_non_json_companion() -> None:
    payload = b"# Scan transcript\nDECISION: [x] false_positive\n"
    evidence = findings._review_evidence(UUID(int=1), payload)
    assert evidence["text"].encode("utf-8") == payload
    assert "document" not in evidence


def test_review_evidence_preserves_binary_bytes_losslessly() -> None:
    payload = b"\xff\x00\x80scan-evidence"
    evidence = findings._review_evidence(UUID(int=1), payload)
    assert evidence["encoding"] == "base64"
    assert base64.b64decode(evidence["payload"], validate=True) == payload
    assert "document" not in evidence


@pytest.mark.parametrize("kind", ["container", "rpm", "vuln_scan"])
def test_recorded_audit_findings_are_ready_for_native_triage(
    home: Path, tmp_path: Path, kind: str
) -> None:
    document = _canonical_vuln_findings() if kind == "vuln_scan" else _canonical_report()
    if kind != "vuln_scan":
        document["metadata"]["repository"] = REPO
    report = tmp_path / "audit.json"
    report.write_text(json.dumps(document))
    original = report.read_bytes()

    rc, recorded = registered(
        home,
        "reporting",
        "record",
        str(report),
        "--kind",
        kind,
        "--repo-url",
        REPO,
        "--sha",
        SHA,
    )
    assert rc == 0, recorded
    rc, prepared = run(triage.prepare, home, recorded["id"])
    assert rc == 0, prepared
    items = {item["finding"]["title"]: item for item in prepared["items"]}
    assert items.keys() == {entry["title"] for entry in document["findings"]}
    for entry in document["findings"]:
        item = items[entry["title"]]
        expected_path = entry["file"] if kind == "vuln_scan" else entry["locations"][0]["path"]
        assert item["occurrence"]["severity"] == entry["severity"]
        assert item["locations"][0]["path"] == expected_path
        if kind != "vuln_scan":
            assert run(
                findings.find, home, str(report), "--label", entry["id"], "--repo-url", REPO
            ) == (0, {"label": entry["id"], "finding_id": item["finding"]["id"]})
    assert report.read_bytes() == original


def test_secure_code_recording_is_not_native_finding_admission(home: Path, tmp_path: Path) -> None:
    document = _canonical_report()
    document["metadata"]["repository"] = REPO
    report = tmp_path / "canary-security-audit.json"
    report.write_text(json.dumps(document))
    original = report.read_bytes()
    entry = document["findings"][0]

    rc, recorded = registered(
        home,
        "reporting",
        "record",
        str(report),
        "--kind",
        "secure_code",
        "--repo-url",
        REPO,
        "--sha",
        SHA,
    )
    assert rc == 0, recorded
    lookup = (str(report), "--label", entry["id"], "--repo-url", REPO)
    assert run(findings.find, home, *lookup) == (
        0,
        {"label": entry["id"], "finding_id": None},
    )
    rc, empty = run(triage.prepare, home, recorded["id"])
    assert rc == 0 and empty["items"] == []
    assert report.read_bytes() == original

    scan = json.loads(json.dumps(SARIF))
    rule = scan["runs"][0]["tool"]["driver"]["rules"][0]
    rule["properties"]["tags"] = [f"external/cwe/{entry['cwes'][0].lower()}"]
    scan["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        entry["locations"][0]["path"]
    )
    source = tmp_path / "independent-scan.sarif"
    source.write_text(json.dumps(scan))
    rc, admitted = run(
        triage.intake,
        home,
        str(source),
        "--format",
        "sarif",
        "--repo-url",
        REPO,
        "--sha",
        SHA,
    )
    assert rc == 0, admitted
    assert admitted["assessment_id"] != recorded["id"]
    rc, prepared = run(triage.prepare, home, admitted["assessment_id"])
    assert rc == 0, prepared
    [item] = prepared["items"]
    assert run(findings.find, home, *lookup) == (
        0,
        {"label": entry["id"], "finding_id": item["finding"]["id"]},
    )
    rc, unchanged_audit = run(triage.prepare, home, recorded["id"])
    assert rc == 0 and unchanged_audit["items"] == []
    assert report.read_bytes() == original
