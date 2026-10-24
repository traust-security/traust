"""``traust remediation …``: the remediation loop's doors on traust-core.

open                 a work item for confirmed, open findings of a commit
work-items           a repository's work items, oldest first
next                 a repository's oldest work item still waiting for a patch
prepare              what a patch of one work item fixes (findings, decisions, strategy, fork)
fork                 the private fork a repository's fixes are pushed to
progress             move a work item to a status (forward only)
mutation-evidence    a mewt campaign's status JSON as one patch_evidence item
record               a validated remediation report on its work item
verify-sweep         which repositories are worth re-verifying, by tier, and why the rest are not
verify-prepare       what a verification of one work item re-checks, as JSON
verify-differential  the scanner that backed a work item's findings, compared on a patched commit
verify-record        a validated verification report: verdicts as decisions, regressions as findings
verifications        a repository's recorded verifications
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import RemediationArtifact, VerificationArtifact
from traust_core.v1.models.common import Provenance, every_item
from traust_core.v1.models.inventory import Repository, RepositoryFilter
from traust_core.v1.models.remediation import (
    VerificationFilter,
    WorkItemFilter,
    mutation_evidence,
)
from traust_core.v1.models.values import GitSha, ProductSlug
from traust_core.v1.models.vocabulary import RemediationStatus, SourceType

from traust.cli._doors import parser, run
from traust.cli.findings import _repository
from traust.context import load_core


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    return parser("remediation", op, about)


def _emit(text: str, out: Path | None) -> str | None:
    if out is None:
        return text
    out.write_text(text + "\n", encoding="utf-8")
    return None


def open_(argv: list[str] | None = None) -> int:
    ap = _parser("open", "Open a work item for confirmed, open findings of a commit.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--sha", required=True, help="the commit the findings were found on")
    ap.add_argument("--finding", type=uuid.UUID, action="append", required=True, help="repeatable")
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load_core(args.config_home)
        services = core.services()
        repo = _repository(core, args.repo_url)
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)  # type: ignore[arg-type]
        return services.remediation.open(args.finding, ref.id).model_dump(mode="json")  # type: ignore[arg-type]

    return run(call)


def work_items(argv: list[str] | None = None) -> int:
    ap = _parser("work-items", "List a repository's work items, oldest first.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--status", choices=[s.value for s in RemediationStatus])
    args = ap.parse_args(argv)

    def call() -> list:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        wanted = WorkItemFilter(repository_id=repo.id, status=args.status)  # type: ignore[arg-type]
        found = every_item(lambda p: core.services().remediation.list(wanted, p))
        return [i.model_dump(mode="json") for i in found]

    return run(call)


def fork(argv: list[str] | None = None) -> int:
    ap = _parser("fork", "Print the private fork a repository's fixes are pushed to.")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        found = core.services().remediation.resolve_fork(repo.id)  # type: ignore[arg-type]
        return {**found.model_dump(mode="json"), "url": str(found.url)}

    return run(call)


def progress(argv: list[str] | None = None) -> int:
    ap = _parser("progress", "Move a work item to a status (forward only).")
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("status", choices=[s.value for s in RemediationStatus])
    args = ap.parse_args(argv)

    def call() -> dict:
        remediation = load_core(args.config_home).services().remediation
        moved = remediation.record_progress(args.work_item_id, RemediationStatus(args.status))
        return moved.model_dump(mode="json")

    return run(call)


def mutation_evidence_(argv: list[str] | None = None) -> int:
    ap = _parser("mutation-evidence", "Turn a mewt campaign's result into one patch_evidence item.")
    ap.add_argument("--target", required=True, help="the package the patch touched")
    ap.add_argument("--rc", type=int, required=True, help="the campaign's exit code")
    ap.add_argument("--tool-version", default="")
    ap.add_argument("--log", required=True, help="the campaign log")
    ap.add_argument("--status-json", type=Path, required=True, help="mewt status --format json")
    ap.add_argument("--boundary", default="", help="how the campaign was contained")
    args = ap.parse_args(argv)

    def call() -> dict:
        status = args.status_json.read_bytes() if args.status_json.is_file() else None
        found = mutation_evidence(
            args.target, args.rc, args.tool_version, args.log, status, args.boundary
        )
        return found.model_dump(mode="json", exclude_none=True)

    return run(call)


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a validated remediation report on its work item.")
    ap.add_argument("report", type=Path, help="the remediation report JSON")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = RemediationArtifact.parse(args.report.read_bytes())
        when = datetime.now(UTC)
        made = (
            load_core(args.config_home)
            .services()
            .remediation.record(
                doc,
                Provenance(run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=when),
            )
        )
        return made.model_dump(mode="json")

    return run(call)


def next_(argv: list[str] | None = None) -> int:
    ap = _parser("next", "Print a repository's oldest work item still waiting for a patch.")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> dict | str:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        item = core.services().remediation.next_pending(WorkItemFilter(repository_id=repo.id))  # type: ignore[arg-type]
        return "null" if item is None else item.model_dump(mode="json")

    return run(call)


def prepare(argv: list[str] | None = None) -> int:
    ap = _parser("prepare", "Print what a patch of one work item fixes.")
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        prepared = load_core(args.config_home).services().remediation.prepare(args.work_item_id)
        return _emit(prepared.model_dump_json(indent=2), args.out)

    return run(call)


def verify_sweep(argv: list[str] | None = None) -> int:
    ap = _parser("verify-sweep", "Which repositories are worth re-verifying, and why not the rest.")
    ap.add_argument("--repo-url", action="append", default=[], help="repeatable; default: all")
    ap.add_argument("--product", action="append", default=[], help="a product slug, repeatable")
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        core = load_core(args.config_home)
        services = core.services()
        repos: dict[uuid.UUID, Repository] = {
            r.id: r  # type: ignore[misc]
            for r in [_repository(core, u) for u in args.repo_url]
        }
        for slug in args.product:
            product = services.portfolio.find_product(ProductSlug(slug))
            if product is None:
                raise NotFoundError(f"product {slug} is not registered")
            for ref in services.portfolio.list_product_refs(product.id):  # type: ignore[arg-type]
                repos.setdefault(
                    ref.repository_id, services.portfolio.get_repository(ref.repository_id)
                )
        if not args.repo_url and not args.product:
            repos = {
                r.id: r  # type: ignore[misc]
                for r in every_item(
                    lambda p: services.portfolio.list_repositories(RepositoryFilter(), p)
                )
            }
        sweep = services.verification.sweep(list(repos))
        doc: dict[str, Any] = sweep.model_dump(mode="json")
        for entry in (*doc["queued"], *doc["skipped"]):
            entry["repository"] = repos[uuid.UUID(entry["repository_id"])].url
        return _emit(json.dumps(doc, indent=2), args.out)

    return run(call)


def verify_prepare(argv: list[str] | None = None) -> int:
    ap = _parser("verify-prepare", "Print what a verification of one work item re-checks.")
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        prepared = load_core(args.config_home).services().verification.prepare(args.work_item_id)
        return _emit(prepared.model_dump_json(indent=2), args.out)

    return run(call)


def verify_differential(argv: list[str] | None = None) -> int:
    ap = _parser(
        "verify-differential",
        "Compare the scanner that backed a work item's findings on a patched commit.",
    )
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("--repo-url", required=True, help="https URL of the work item's repository")
    ap.add_argument("--sha", required=True, help="the patched commit")
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load_core(args.config_home)
        services = core.services()
        repo = _repository(core, args.repo_url)
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)  # type: ignore[arg-type]
        found = services.verification.differential(args.work_item_id, ref.id)  # type: ignore[arg-type]
        return found.model_dump(mode="json")

    return run(call)


def verify_record(argv: list[str] | None = None) -> int:
    ap = _parser("verify-record", "Record a validated verification report.")
    ap.add_argument("report", type=Path, help="the verification report JSON")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = VerificationArtifact.parse(args.report.read_bytes())
        when = datetime.now(UTC)
        made = (
            load_core(args.config_home)
            .services()
            .verification.record(
                doc,
                Provenance(
                    run_id=uuid.uuid4(), source=SourceType.VERIFICATION_REPORT, occurred_at=when
                ),
            )
        )
        return made.model_dump(mode="json")

    return run(call)


def verifications(argv: list[str] | None = None) -> int:
    ap = _parser("verifications", "List a repository's recorded verifications, oldest first.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--work-item", type=uuid.UUID, help="only those touching this work item")
    args = ap.parse_args(argv)

    def call() -> list:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        wanted = VerificationFilter(repository_id=repo.id, work_item_id=args.work_item)  # type: ignore[arg-type]
        found = every_item(lambda p: core.services().verification.list(wanted, p))
        return [v.model_dump(mode="json") for v in found]

    return run(call)
