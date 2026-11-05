"""``traust findings …``: track-findings' doors on traust-core.

find      the finding a report entry is (its label, e.g. OPERATOR-abcdef0-001), by fingerprint
correction-request  refused: claim correction waits on a traust-core decision (plan 15, decision 1)
rebaseline  refused: claim correction waits on a traust-core decision (plan 15, decision 1)
claim     refused: claim correction waits on a traust-core decision (plan 15, decision 1)
status    one finding now: disposition (evidence precedence), effective severity, SLA due
history   every decision on a finding, in judgement order
baseline  a repository's findings as they stood at a time
decide    record your statement on a finding (needs `traust auth`)
import    what people said in an MR / PR / commit / Jira ticket: recorded if it stands, else queued
queue     statements waiting for a person, re-read from their source
review-cases  paged full finding/history/evidence cards, optionally a private review workbench
request   request human review of an existing finding or decision
record    record a verified human's selected judgement, with shared login or stdin token
apply     apply explicit typed JSON/Markdown reviewed answers atomically per review item
confirm   accept a queued proposal with your judgement; reject: reject it with your judgement
refuted   a repository's false positives (the refuted register)
surfaces  review-surface coverage (the audit, with later scans merged)
sarif     a repository's findings as SARIF for code scanning
tickets   the Jira tickets on a repository's findings
summary   a repository's findings counted by state per group (severity, CWE, label, …)
timeline  a repository's findings replayed by day, week or month (open, new, resolved, MTTR, risk)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr, TypeAdapter
from pydantic import ValidationError as ModelValidationError
from traust_core.v1.context import Context
from traust_core.v1.errors import (
    AuthenticationError,
    ForbiddenError,
    NotFoundError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.common import Cursor, PageRequest, TimeBucket
from traust_core.v1.models.findings import (
    FindingDimension,
    FindingFilter,
    RecordDecision,
    ReviewFilter,
)
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    EvidenceGrade,
    ReviewItemStatus,
    ReviewReason,
    Severity,
    SourceChannel,
    SourceType,
    Validity,
)
from traust_core.v1.providers.comments import FORGE, JIRA

from traust.cli._doors import parser, run, when
from traust.context import load, load_caller
from traust.lib.pending_decisions import Decision, PendingCoreDecision

_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9]+-\d+$")
_BROWSE = re.compile(r"/browse/([A-Z][A-Z0-9]+-\d+)")

# What a person states directly; machine reports record through their own skill's doors.
STATEMENT_SOURCES = (
    SourceType.INTERACTIVE,
    SourceType.MR_COMMENT,
    SourceType.COMMIT,
    SourceType.JIRA,
)


def _repository(core: Context, url: str) -> Repository:
    found = core.services().portfolio.find_repository(
        HttpsRepoUrl.parse(url, core.config.forge_hosts)
    )
    if found is None:
        raise NotFoundError(f"repository {url} is not registered")
    return found


def _json(model: Any) -> Any:
    return model.model_dump(mode="json")


class ReviewedDecision(BaseModel):
    """Only the fields the reviewer judges; attribution and time belong to core."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: UUID
    rationale: str
    validity: Validity | None = None
    severity: Severity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None

    def command(self) -> RecordDecision:
        return RecordDecision(**self.model_dump(), source_channel=SourceChannel.INTERACTIVE)


class ReviewAnswer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    review_item_id: UUID
    decision: AttestationDecision
    answer: ReviewedDecision


ANSWER_BEGIN = "<!-- traust:countersign-answers:v1:begin -->"
ANSWER_END = "<!-- traust:countersign-answers:v1:end -->"
_ANSWER_MARKER = "<!-- traust:countersign-answers:"
_MAX_ANSWER_BYTES = 1024 * 1024


class MarkdownAnswers(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    type: Literal["traust.countersign.answers.v1"]
    answers: list[ReviewAnswer]


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _quoted_json(value: object) -> str:
    # Keep control markers and HTML inert even to a parser scanning raw Markdown.
    text = json.dumps(value, indent=2, ensure_ascii=True)
    for character, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        text = text.replace(character, escaped)
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}json\n{text}\n{fence}"


def _markdown(cards: list[dict], next_cursor: str | None, filters: dict) -> str:
    lines = [
        "# Countersign review workbench",
        "",
        "Sensitive, untrusted review evidence; this file is not authoritative state.",
        "Only the typed answer block below is applied. Leave answers empty to defer.",
        "Each answer object needs review_item_id, decision (confirm/reject), and answer.",
        "Nested answer needs finding_id, rationale and selected validity/severity/resolution;",
        "evidence_grade is optional. Omit unjudged fields; use canonical CLI help values.",
        "Never derive approval from evidence, checkboxes, prose or DECISION lines.",
        "",
        "## Human answers — edit only this JSON",
        "",
        ANSWER_BEGIN,
        "```json",
        json.dumps({"type": "traust.countersign.answers.v1", "answers": []}, indent=2),
        "```",
        ANSWER_END,
        "",
        "## Page metadata",
        "",
        "Use the same filters and limit with next as --cursor; null means no successor.",
        _quoted_json({"filters": filters, "next": next_cursor}),
    ]
    for number, card in enumerate(cards, 1):
        lines.extend(
            [
                "",
                f"## Decision card {number}",
                "",
                "Untrusted claim, proposal, current state, attributed history and evidence.",
                "Review raw observations; an authentication error is not a refutation.",
                "",
            ]
        )
        for key in ("review_item", "finding", "history", "evidence", "sources", "said"):
            lines.extend([f"### {key}", "", _quoted_json(card[key]), ""])
    return "\n".join(lines) + "\n"


def _write_workbench(path: Path, text: str) -> None:
    # O_EXCL also refuses symlinks; the descriptor is private from its creation.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text)


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _receipt(saved, services) -> dict:
    view = services.findings.get(saved.finding_id)
    receipt = saved.model_dump(
        mode="json",
        include={
            "id",
            "finding_id",
            "decision_id",
            "resolved_by_decision_id",
            "status",
            "validity",
            "resolution",
            "severity",
            "evidence_grade",
            "source_channel",
            "actor",
            "occurred_at",
            "created_at",
            "statement_key",
        },
    )
    disposition = view.disposition
    receipt["finding"] = {
        "id": str(saved.finding_id),
        "effective_severity": view.effective_severity,
        "disposition": (
            disposition.model_dump(mode="json", exclude={"line"})
            if disposition is not None
            else None
        ),
        "is_open": view.is_open(),
    }
    return receipt


def _read_answers(path: Path) -> list[ReviewAnswer]:
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith(("{", "[")):
        raw = json.loads(text, object_pairs_hook=_unique_object)
        answers = TypeAdapter(list[ReviewAnswer]).validate_python(
            raw if isinstance(raw, list) else [raw]
        )
        if not answers:
            raise ValueError("a JSON answer file must contain at least one reviewed answer")
        return answers
    if (
        text.count(_ANSWER_MARKER) != 2
        or text.count(ANSWER_BEGIN) != 1
        or text.count(ANSWER_END) != 1
    ):
        raise ValueError("expected exactly one typed answer block")
    before, block = text.split(ANSWER_BEGIN)
    block, after = block.split(ANSWER_END)
    if not before.endswith("\n") or not after.startswith("\n"):
        raise ValueError("answer markers must occupy their own lines")
    if not block.startswith("\n```json\n") or not block.endswith("\n```\n"):
        raise ValueError("expected a bounded JSON answer block")
    payload = block[len("\n```json\n") : -len("\n```\n")]
    if len(payload.encode("utf-8")) > _MAX_ANSWER_BYTES:
        raise ValueError("answer block exceeds one MiB")
    return MarkdownAnswers.model_validate(
        json.loads(payload, object_pairs_hook=_unique_object)
    ).answers


def _token_arg(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--token-stdin",
        action="store_true",
        help="Read an identity token from stdin instead of the stored `traust auth` login.",
    )


def _human_review(args: argparse.Namespace) -> int:
    try:
        answers = _read_answers(args.answers) if args.operation == "apply" else []
    except (OSError, ValueError, UnicodeError):
        print("findings: invalid answer file; expected explicit typed answers.", file=sys.stderr)
        return 2

    token = None
    if args.token_stdin:
        if sys.stdin.isatty():
            print(
                "findings: pipe an identity token on stdin; interactive token entry is disabled.",
                file=sys.stderr,
            )
            return 2
        try:
            token = SecretStr(sys.stdin.read().strip())
        except (OSError, UnicodeError):
            print("findings: cannot read the identity token from stdin.", file=sys.stderr)
            return 2
        if not token.get_secret_value():
            print("findings: stdin contained no identity token.", file=sys.stderr)
            return 2

    try:
        core = load(args.config_home)
        services = core.services()
        if token is None:
            principal = load_caller(core)
        else:
            if services.identity is None:
                print("findings: core identity is not configured in traust.yaml.", file=sys.stderr)
                return 2
            principal = services.identity.authenticate(Credential(token=token))
        if not principal.is_verified_human():
            raise ForbiddenError("a verified human is required")
        if args.operation == "apply" and not answers:
            _emit({"results": [], "deferred": True})
            return 0
        if args.operation == "request":
            saved = services.attestation.request(args.finding, args.decision, args.reason)
        elif args.operation == "record":
            saved = services.findings.decisions.decide(
                RecordDecision(
                    finding_id=args.finding,
                    rationale=args.rationale,
                    **{args.decision: getattr(args, args.decision)},
                    evidence_grade=args.evidence_grade,
                    source_channel=SourceChannel.INTERACTIVE,
                ),
                principal,
            )
        else:
            receipts = []
            failed = False
            for answer in answers:
                try:
                    saved = services.attestation.attest(
                        answer.review_item_id,
                        principal,
                        answer.decision,
                        answer.answer.command(),
                    )
                    receipts.append({"ok": True, "review_item": _receipt(saved, services)})
                except (TraustError, ModelValidationError) as error:
                    failed = True
                    receipts.append(
                        {
                            "ok": False,
                            "review_item_id": str(answer.review_item_id),
                            "error": type(error).__name__,
                        }
                    )
            _emit({"results": receipts})
            return 2 if failed else 0
        _emit(_receipt(saved, services))
        return 0
    except AuthenticationError:
        print("findings: authentication refused by core.", file=sys.stderr)
        return 2
    except ForbiddenError:
        print(
            "findings: a verified human and core decision authorization are required.",
            file=sys.stderr,
        )
        return 2
    except (TraustError, ModelValidationError, OSError, UnicodeError) as error:
        print(f"findings: core refused the operation ({type(error).__name__}).", file=sys.stderr)
        return 2


def request(argv: list[str] | None = None) -> int:
    ap = parser("findings", "request", "Request human review of an existing core finding.")
    ap.set_defaults(operation="request")
    ap.add_argument("--finding", type=UUID, required=True)
    ap.add_argument("--decision", type=UUID, help="The proposed decision UUID, when present.")
    ap.add_argument("--reason", type=ReviewReason, choices=tuple(ReviewReason), required=True)
    _token_arg(ap)
    return _human_review(ap.parse_args(argv))


def record(argv: list[str] | None = None) -> int:
    ap = parser("findings", "record", "Record a verified human's explicit judgement.")
    ap.set_defaults(operation="record")
    ap.add_argument("--finding", type=UUID, required=True, help="Core finding UUID.")
    ap.add_argument("--decision", choices=("severity", "validity", "resolution"), required=True)
    ap.add_argument("--severity", type=Severity, choices=tuple(Severity))
    ap.add_argument("--validity", type=Validity, choices=tuple(Validity))
    ap.add_argument(
        "--resolution", type=DispositionResolution, choices=tuple(DispositionResolution)
    )
    ap.add_argument("--rationale", required=True, help="The human reviewer's own rationale.")
    ap.add_argument("--evidence-grade", type=EvidenceGrade, choices=tuple(EvidenceGrade))
    _token_arg(ap)
    args = ap.parse_args(argv)
    for field in ("severity", "validity", "resolution"):
        value = getattr(args, field)
        if field == args.decision and value is None:
            ap.error(f"--decision {field} requires --{field}")
        if field != args.decision and value is not None:
            ap.error(f"--{field} does not match --decision {args.decision}")
    return _human_review(args)


def apply(argv: list[str] | None = None) -> int:
    ap = parser("findings", "apply", "Apply reviewed JSON or typed Markdown answers.")
    ap.set_defaults(operation="apply")
    ap.add_argument("answers", type=Path, help="Reviewed JSON or a typed Markdown answer block.")
    _token_arg(ap)
    return _human_review(ap.parse_args(argv))


def correction_request(argv: list[str] | None = None) -> int:
    ap = parser(
        "findings", "correction-request", "Queue an immutable corrected claim for human review."
    )
    ap.add_argument("report", type=Path, help="a corrected copy of the original contract report")
    ap.add_argument("--finding", type=UUID, required=True)
    ap.add_argument(
        "--assessment", type=UUID, required=True, help="the original reporting assessment"
    )
    ap.add_argument("--label", required=True, help="the corrected entry's report label")
    ap.add_argument("--ticket", required=True)
    ap.add_argument("--rationale", required=True)
    ap.parse_args(argv)

    def call() -> dict:
        raise PendingCoreDecision(Decision.CLAIM_CORRECTION)

    return run(call)


def rebaseline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "rebaseline", "Accept and apply the exact stored corrected claim.")
    ap.add_argument("review_item_id", type=UUID)
    ap.add_argument("--ticket", required=True)
    ap.add_argument("--rationale", required=True, help="the authenticated human's review rationale")
    ap.parse_args(argv)

    def call() -> dict:
        raise PendingCoreDecision(Decision.CLAIM_CORRECTION)

    return run(call)


def claim(argv: list[str] | None = None) -> int:
    ap = parser("findings", "claim", "Read an accepted corrected claim, if there is one.")
    ap.add_argument("finding_id", type=UUID)
    ap.add_argument("--as-of", type=when)
    ap.parse_args(argv)

    def call() -> dict | None:
        raise PendingCoreDecision(Decision.CLAIM_CORRECTION)

    return run(call)


def find(argv: list[str] | None = None) -> int:
    ap = parser("findings", "find", "Find the recorded finding a report entry is.")
    ap.add_argument("report", type=Path, help="the report JSON the label comes from")
    ap.add_argument("--label", required=True, help="the entry's id in that report")
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        entries = json.loads(args.report.read_text(encoding="utf-8")).get("findings") or []
        entry = next((e for e in entries if e.get("id") == args.label), None)
        if entry is None:
            raise NotFoundError(f"{args.report}: no finding {args.label}")
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        reported = FingerprintInput.from_report(entry, repo.url)
        found = core.services().findings.intake.match(repo.id, reported)
        return {"label": args.label, "finding_id": found}

    return run(call)


def status(argv: list[str] | None = None) -> int:
    ap = parser("findings", "status", "Show one finding's current state.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)
    return run(lambda: _json(load(args.config_home).services().findings.get(args.finding_id)))


def history(argv: list[str] | None = None) -> int:
    ap = parser("findings", "history", "List every decision on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        return [
            _json(d) for d in load(args.config_home).services().findings.history(args.finding_id)
        ]

    return run(call)


def baseline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "baseline", "List a repository's findings as they stood at a time.")
    ap.add_argument("--repo-url", required=True)
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--as-of", help="ISO time with a zone (default: now)")
    scope.add_argument("--ref-id", type=uuid.UUID, help="current findings on this registered line")
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        if args.ref_id is not None:
            services = core.services()
            ref = services.portfolio.inventory.get_ref(args.ref_id)
            if ref.repository_id != repo.id:
                raise ValidationError(f"ref {args.ref_id} is not in repository {repo.id}")
            return [_json(v) for v in services.findings.on_ref(args.ref_id)]
        as_of = when(args.as_of) or datetime.now(UTC)
        return [_json(v) for v in core.services().findings.baseline(repo.id, as_of)]

    return run(call)


def _statement_args(ap: Any) -> None:
    ap.add_argument("--rationale", required=True, help="why, in your words (quoted verbatim)")
    ap.add_argument("--validity", choices=[v.value for v in Validity])
    ap.add_argument("--resolution", choices=[r.value for r in DispositionResolution])
    ap.add_argument("--severity", choices=[s.value for s in Severity], help="a re-rating")
    ap.add_argument("--evidence-grade", choices=[g.value for g in EvidenceGrade])
    ap.add_argument("--reason")
    ap.add_argument(
        "--source",
        default=SourceType.INTERACTIVE.value,
        choices=[s.value for s in STATEMENT_SOURCES],
        help="where it was said (default: interactive)",
    )
    ap.add_argument("--occurred-at", help="when it was said, ISO with a zone (default: now)")


def _statement(args: Any, finding_id: uuid.UUID) -> RecordDecision:
    if not (args.validity or args.resolution or args.severity):
        raise ValidationError("say something: --validity, --resolution or --severity")
    return RecordDecision(
        finding_id=finding_id,
        rationale=args.rationale,
        validity=args.validity,
        resolution=args.resolution,
        severity=args.severity,
        evidence_grade=args.evidence_grade,
        reason=args.reason,
        source_channel=SourceType(args.source),
        occurred_at=when(args.occurred_at),
    )


def _labels(core: Context, repo: Repository, reports: list[Path]) -> dict[str, uuid.UUID]:
    """Each report's labels (`findings[].id`) to the findings they are, by fingerprint."""
    assert repo.id is not None
    intake = core.services().findings.intake
    out: dict[str, uuid.UUID] = {}
    for report in reports:
        for entry in json.loads(report.read_text(encoding="utf-8")).get("findings") or []:
            label = entry.get("id")
            if isinstance(label, str) and entry.get("locations"):
                found = intake.match(repo.id, FingerprintInput.from_report(entry, repo.url))
                if found is not None:
                    out[label] = found
    return out


def _reports_and_repo(ap: Any) -> None:
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    ap.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        help="a report whose labels the comments use (repeatable)",
    )


def decide(argv: list[str] | None = None) -> int:
    ap = parser("findings", "decide", "Record your statement on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    _statement_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        statement = _statement(args, args.finding_id)
        core = load(args.config_home)
        return _json(core.services().findings.decisions.decide(statement, load_caller(core)))

    return run(call)


def import_(argv: list[str] | None = None) -> int:
    ap = parser("findings", "import", "Record what people said in an MR, PR, commit or ticket.")
    ap.add_argument("ref", help="an MR / PR / commit URL, or a Jira key")
    _reports_and_repo(ap)
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        source = JIRA if _JIRA_KEY.match(args.ref) else FORGE
        report = core.services().attestation.import_statements(
            source,
            ExternalRef(system=source, ref=args.ref),
            _labels(core, repo, args.report),
            load_caller(core),
        )
        return {
            "recorded": [_json(d) for d in report.recorded],
            "queued": [_json(i) for i in report.queued],
            "unmatched": [
                {"label": s.label, "author": s.author, "url": s.url} for s in report.unmatched
            ],
            "already_imported": report.already_imported,
        }

    return run(call)


def _review_evidence(artifact_id: UUID, payload: bytes) -> dict[str, Any]:
    entry: dict[str, Any] = {"artifact_id": str(artifact_id)}
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {**entry, "encoding": "base64", "payload": base64.b64encode(payload).decode("ascii")}
    try:
        entry["document"] = json.loads(text)
    except json.JSONDecodeError:
        entry["text"] = text
    return entry


def review_cases(argv: list[str] | None = None) -> int:
    ap = parser(
        "findings", "review-cases", "Read full review cards and integrity-checked evidence."
    )
    ap.add_argument("--finding", type=UUID, help="Filter by core finding UUID.")
    ap.add_argument("--reason", type=ReviewReason, choices=tuple(ReviewReason))
    ap.add_argument(
        "--status",
        type=ReviewItemStatus,
        choices=tuple(ReviewItemStatus),
        default=ReviewItemStatus.PENDING,
    )
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--cursor", help="Opaque next cursor from the preceding page.")
    ap.add_argument(
        "--output", type=Path, help="Create a new private Markdown workbench; never overwrite."
    )
    ap.add_argument("--repo-url", help="with --report: re-read each item's source statements")
    ap.add_argument("--report", type=Path, action="append", default=[])
    args = ap.parse_args(argv)

    def call() -> None:
        core = load(args.config_home)
        services = core.services()
        attestation = services.attestation
        page = attestation.pending(
            ReviewFilter(finding_id=args.finding, reason=args.reason, status=args.status),
            PageRequest(limit=args.limit, cursor=Cursor(args.cursor) if args.cursor else None),
        )
        names: dict[str, UUID] = {}
        if args.repo_url:
            names = _labels(core, _repository(core, args.repo_url), args.report)
        reader = services.findings.artifacts
        cards = []
        for case in page.items:
            item, view, history = case.review_item, case.finding, case.history
            assert item.id is not None
            cards.append(
                {
                    "review_item": _json(item),
                    "finding": _json(view),
                    "history": [_json(d) for d in history],
                    "evidence": [
                        _review_evidence(artifact_id, reader.payload(artifact_id))
                        for artifact_id in case.evidence_artifact_ids
                    ],
                    "sources": [source.ref for source in case.external_refs],
                    "said": [_json(s) for s in attestation.statements(item.id, names)]
                    if names
                    else [],
                }
            )
        if args.output is None:
            _emit({"items": cards, "next": page.next})
        else:
            _write_workbench(
                args.output,
                _markdown(
                    cards,
                    page.next,
                    {
                        "finding": str(args.finding) if args.finding else None,
                        "reason": args.reason,
                        "status": args.status,
                        "limit": args.limit,
                        "repo_url": args.repo_url,
                        "report": [str(report) for report in args.report],
                    },
                ),
            )
            _emit({"written": str(args.output), "items": len(cards), "next": page.next})

    try:
        return run(call, redact=True)
    except (json.JSONDecodeError, UnicodeError) as error:
        print(f"findings: invalid evidence document ({type(error).__name__}).", file=sys.stderr)
        return 2


def queue(argv: list[str] | None = None) -> int:
    ap = parser("findings", "queue", "List statements waiting for a person, re-read from source.")
    ap.add_argument("--repo-url", help="with --report: re-read each item's statements")
    ap.add_argument("--report", type=Path, action="append", default=[])
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args(argv)

    def call() -> list[dict[str, Any]]:
        core = load(args.config_home)
        attestation = core.services().attestation
        names: dict[str, uuid.UUID] = {}
        if args.repo_url:
            names = _labels(core, _repository(core, args.repo_url), args.report)
        out = []
        for case in attestation.pending(ReviewFilter(), PageRequest(limit=args.limit)).items:
            item = case.review_item
            assert item.id is not None
            out.append(
                {
                    **_json(item),
                    "sources": [s.ref for s in attestation.sources(item.finding_id)],
                    "said": [_json(s) for s in attestation.statements(item.id, names)]
                    if names
                    else [],
                }
            )
        return out

    return run(call)


def confirm(argv: list[str] | None = None) -> int:
    ap = parser("findings", "confirm", "Confirm a queued statement as your own decision.")
    ap.add_argument("item_id", type=uuid.UUID)
    ap.add_argument("finding_id", type=uuid.UUID, help="the item's finding (from `queue`)")
    _statement_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        statement = _statement(args, args.finding_id)
        core = load(args.config_home)
        caller = load_caller(core)
        attestation = core.services().attestation
        answer = AttestationDecision.CONFIRM
        return _json(attestation.attest(args.item_id, caller, answer, statement))

    return run(call, redact=True)


def reject(argv: list[str] | None = None) -> int:
    ap = parser("findings", "reject", "Reject a queued proposal with your own judged decision.")
    ap.add_argument("item_id", type=uuid.UUID)
    ap.add_argument("finding_id", type=uuid.UUID, help="the item's finding (from `queue`)")
    _statement_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        statement = _statement(args, args.finding_id)
        core = load(args.config_home)
        attestation = core.services().attestation
        caller = load_caller(core)
        return _json(
            attestation.attest(args.item_id, caller, AttestationDecision.REJECT, statement)
        )

    return run(call, redact=True)


def refuted(argv: list[str] | None = None) -> int:
    ap = parser("findings", "refuted", "List a repository's false positives (refuted register).")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        wanted = FindingFilter(repository_id=repo.id, validity=Validity.FALSE_POSITIVE)
        out, page = [], PageRequest()
        while True:
            got = core.services().findings.list(wanted, page)
            out += [_json(v) for v in got.items]
            if got.next is None:
                return out
            page = PageRequest(cursor=got.next)

    return run(call)


def surfaces(argv: list[str] | None = None) -> int:
    ap = parser("findings", "surfaces", "Review-surface coverage: the audit plus later scans.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        merged = core.services().findings.review_surfaces(repo.id, when(args.as_of))
        return {surface: _json(c) for surface, c in merged.items()}

    return run(call)


def sarif(argv: list[str] | None = None) -> int:
    ap = parser("findings", "sarif", "Export a repository's findings as SARIF (code scanning).")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("-o", "--out", type=Path, help="write here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        views = core.services().findings.baseline(repo.id, when(args.as_of) or datetime.now(UTC))
        doc = core.services().reporting.sarif_findings(views, repo.url)
        if args.out is None:
            return doc
        args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        return None

    return run(call)


def tickets(argv: list[str] | None = None) -> int:
    ap = parser("findings", "tickets", "The Jira tickets filed against a repository's findings.")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> list[str]:
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        found = (_BROWSE.search(t.ref) for t in core.services().attestation.tickets(repo.id))
        return sorted({m[1] for m in found if m})

    return run(call)


def _filter_args(ap: Any) -> None:
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("--validity", choices=[v.value for v in Validity])
    state = ap.add_mutually_exclusive_group()
    state.add_argument("--open", dest="open", action="store_const", const=True)
    state.add_argument("--closed", dest="open", action="store_const", const=False)


def _filter(core: Context, args: Any) -> FindingFilter:
    repo = _repository(core, args.repo_url)
    assert repo.id is not None
    return FindingFilter(
        repository_id=repo.id,
        validity=args.validity,
        open=args.open,
        as_of=when(args.as_of) or datetime.now(UTC),
    )


def summary(argv: list[str] | None = None) -> int:
    ap = parser("findings", "summary", "Count a repository's findings by state per group.")
    _filter_args(ap)
    ap.add_argument("--group-by", required=True, choices=[d.value for d in FindingDimension])
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load(args.config_home)
        group_by = FindingDimension(args.group_by)
        return [_json(r) for r in core.services().findings.summary(_filter(core, args), group_by)]

    return run(call)


def timeline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "timeline", "Replay a repository's findings bucket by bucket.")
    _filter_args(ap)
    ap.add_argument(
        "--bucket", default=TimeBucket.WEEK.value, choices=[b.value for b in TimeBucket]
    )
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load(args.config_home)
        bucket = TimeBucket(args.bucket)
        return [_json(p) for p in core.services().findings.timeline(_filter(core, args), bucket)]

    return run(call)


def verified_fix_mtta(argv: list[str] | None = None) -> int:
    ap = parser("findings", "verified-fix-mtta", "Verified-fix mean time by effective severity.")
    _filter_args(ap)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load(args.config_home)
        return [
            _json(row) for row in core.services().findings.verified_fix_mtta(_filter(core, args))
        ]

    return run(call)
