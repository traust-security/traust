"""``traust remediation …``: the remediation loop's doors on traust-core.

open                 a work item for confirmed, open findings of a commit
work-items           a repository's work items, oldest first
next                 a repository's oldest work item still waiting for a patch
prepare              what a patch of one work item fixes (findings, decisions, strategy, fork)
fork                 the private fork a repository's fixes are pushed to
progress             move a work item to a status (forward only)
mutation-evidence    a mewt campaign's status JSON as one patch_evidence item
assemble             a work item's remediation report from its worktree (not recorded)
property-evidence    a property test's base-versus-patched exit codes as one evidence item
record               a validated remediation report on its work item
candidates           a product's confirmed, open findings no work item covers, by repository
fleet-submit         a recorded fleet-fix spec's run orders, one per target, held for approval
fleet-approve        fleet-fix run orders, by a verified person (your `traust auth` login)
fleet-claim          the next approved fleet-fix order: its spec applied to the target (diff only)
fleet-record         a fleet-fix transform spec, once its golden tests pass
fleet-targets        the repositories a fleet fix targets, widest product reach first, with owners
verify-sweep         which repositories are worth re-verifying, by tier, and why the rest are not
verify-prepare       what a verification of one work item re-checks, as JSON
verify-differential  the scanner that backed a work item's (or named) findings, on a patched commit
verify-record        a validated verification report: verdicts as decisions, regressions as findings
verifications        a repository's recorded verifications
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pydantic
import yaml
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    FleetFixArtifact,
    RemediationArtifact,
    VerificationArtifact,
)
from traust_core.v1.models.common import Provenance, every_item
from traust_core.v1.models.dependencies import ImpactExport
from traust_core.v1.models.inventory import Repository, RepositoryFilter
from traust_core.v1.models.operations import WorkerId
from traust_core.v1.models.remediation import (
    Check,
    EvidenceItem,
    FleetScope,
    FleetTarget,
    PatchNarrative,
    VerificationFilter,
    WorkItemFilter,
    mutation_evidence,
    property_evidence,
)
from traust_core.v1.models.values import GitSha, ProductSlug
from traust_core.v1.models.vocabulary import (
    Ecosystem,
    ImpactClassification,
    RemediationStatus,
    SourceType,
)

from traust.cli._doors import add_branch_arg, parser, products, register_commit, run
from traust.cli._doors import package_id as find_package_id
from traust.cli.findings import _repository
from traust.cli.impact import harness_version
from traust.context import load, load_caller


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
        core = load(args.config_home)
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
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        wanted = WorkItemFilter(repository_id=repo.id, status=args.status)  # type: ignore[arg-type]
        found = every_item(lambda p: core.services().remediation.list(wanted, p))
        return [i.model_dump(mode="json") for i in found]

    return run(call)


def fork(argv: list[str] | None = None) -> int:
    ap = _parser("fork", "Print the private fork a repository's fixes are pushed to.")
    scope = ap.add_mutually_exclusive_group(required=True)
    scope.add_argument("--repo-url")
    scope.add_argument("--list", action="store_true", help="enumerate inventory fork mappings")
    args = ap.parse_args(argv)

    def call() -> dict | list:
        core = load(args.config_home)
        if args.list:
            return _fork_mappings(core.services())
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
        remediation = load(args.config_home).services().remediation
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


def _items(path: Path) -> list[Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc if isinstance(doc, list) else [doc]


def assemble(argv: list[str] | None = None) -> int:
    ap = _parser("assemble", "Draft a work item's remediation report from its worktree.")
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("--worktree", type=Path, required=True, help="the fix branch's checkout")
    ap.add_argument("--product", required=True, help="metadata.logical_product")
    ap.add_argument("--out", type=Path, required=True, help="the report; the diff goes beside it")
    ap.add_argument("--checks", type=Path, required=True, help="run_checks.sh's checks.json")
    ap.add_argument("--strategy", default="other")
    ap.add_argument("--rationale", required=True)
    ap.add_argument("--behaviour", default="none")
    ap.add_argument("--residual")
    ap.add_argument("--tests-added", default="", help="comma-separated")
    ap.add_argument("--evidence", type=Path, action="append", default=[], help="repeatable")
    ap.add_argument("--status", choices=[s.value for s in RemediationStatus])
    ap.add_argument("--notes")
    args = ap.parse_args(argv)

    def call() -> dict:
        try:
            narrative = PatchNarrative(
                logical_product=args.product,
                harness_version=harness_version(),
                strategy=args.strategy,
                rationale=args.rationale,
                behaviour_change=args.behaviour,
                residual_risk=args.residual,
                tests_added=tuple(t.strip() for t in args.tests_added.split(",") if t.strip()),
                evidence=tuple(
                    EvidenceItem.model_validate(e) for p in args.evidence for e in _items(p)
                ),
                status=args.status,
                notes=args.notes,
            )
            checks = [Check.model_validate(c) for c in _items(args.checks)]
        except (json.JSONDecodeError, pydantic.ValidationError) as e:
            raise ValidationError(f"assemble {args.work_item_id}: {e}") from e
        remediation = load(args.config_home).services().remediation
        draft = remediation.assemble(args.work_item_id, args.worktree, narrative, checks)
        diff = args.out.parent / draft.report.patch.diff_path
        args.out.parent.mkdir(parents=True, exist_ok=True)
        diff.write_bytes(draft.diff)
        args.out.write_bytes(draft.report.payload)
        return {"report": str(args.out), "diff": str(diff), "status": draft.report.summary.status}

    return run(call)


def candidates(argv: list[str] | None = None) -> int:
    ap = _parser("candidates", "A product's confirmed, open findings no work item covers yet.")
    ap.add_argument("--product", required=True, help="a product slug")
    args = ap.parse_args(argv)

    def call() -> list:
        services = load(args.config_home).services()
        (product,) = products(services, [args.product])
        found = services.remediation.candidates(product.id)
        return [c.model_dump(mode="json") for c in found]

    return run(call)


def property_evidence_(argv: list[str] | None = None) -> int:
    ap = _parser(
        "property-evidence", "Turn a property test's two runs into one patch_evidence item."
    )
    ap.add_argument("--test-path", required=True)
    ap.add_argument("--base-ref", required=True, help="the unpatched revision")
    ap.add_argument("--base-rc", type=int, required=True)
    ap.add_argument("--patched-rc", type=int, required=True)
    ap.add_argument("--tool-version", default="")
    ap.add_argument("--base-log", default="")
    ap.add_argument("--patched-log", default="")
    ap.add_argument("--boundary", default="", help="how the runs were contained")
    args = ap.parse_args(argv)

    def call() -> dict:
        found = property_evidence(
            args.test_path,
            args.base_ref,
            args.base_rc,
            args.patched_rc,
            args.tool_version,
            args.base_log,
            args.patched_log,
            args.boundary,
        )
        return found.model_dump(mode="json", exclude_none=True)

    return run(call)


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a validated remediation report on its work item.")
    ap.add_argument("report", type=Path, help="the remediation report JSON")
    ap.add_argument(
        "--work-item",
        type=uuid.UUID,
        help="the work item this run prepared (the report doesn't name it; core refuses to "
        "guess between a failed attempt and its retry)",
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = RemediationArtifact.parse(args.report.read_bytes())
        when = datetime.now(UTC)
        made = (
            load(args.config_home)
            .services()
            .remediation.record(
                doc,
                Provenance(run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=when),
                work_item_id=args.work_item,
            )
        )
        return made.model_dump(mode="json")

    return run(call)


def _cwe(raw: str) -> str:
    if not re.fullmatch(r"CWE-\d{1,5}", raw):
        raise argparse.ArgumentTypeError(f"{raw}: give a CWE id like CWE-1104")
    return raw


def fleet_record(argv: list[str] | None = None) -> int:
    ap = _parser("fleet-record", "Record a fleet-fix transform spec once its golden tests pass.")
    ap.add_argument("spec", type=Path, help="the spec (YAML or JSON)")
    args = ap.parse_args(argv)

    def call() -> dict:
        try:
            raw = yaml.safe_load(args.spec.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise ValidationError(f"{args.spec}: not YAML or JSON: {e}") from e
        doc = FleetFixArtifact.parse(json.dumps(raw, default=str).encode())
        when = datetime.now(UTC)
        made = (
            load(args.config_home)
            .services()
            .remediation.record(
                doc,
                Provenance(run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=when),
            )
        )
        return made.model_dump(mode="json")

    return run(call)


def fleet_submit(argv: list[str] | None = None) -> int:
    ap = _parser("fleet-submit", "Submit a fleet fix's run orders, held for a person's approval.")
    ap.add_argument("fleet_fix_id", type=uuid.UUID, help="the id fleet-record printed")
    targets = ap.add_mutually_exclusive_group(required=True)
    targets.add_argument("--fleet", type=Path, help="fleet-targets' JSON")
    targets.add_argument("--repo-url", action="append", help="a target repository, repeatable")
    args = ap.parse_args(argv)

    def call() -> list:
        core = load(args.config_home)
        if args.fleet is not None:
            try:
                ids = [uuid.UUID(t["repository_id"]) for t in json.loads(args.fleet.read_bytes())]
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                raise ValidationError(f"{args.fleet}: not fleet-targets JSON: {e}") from e
        else:
            ids = [_repository(core, u).id for u in args.repo_url]
        orders = core.services().remediation.submit_fleet_fix(
            args.fleet_fix_id, ids, load_caller(core)
        )
        return [o.model_dump(mode="json") for o in orders]

    return run(call)


def fleet_approve(argv: list[str] | None = None) -> int:
    ap = _parser("fleet-approve", "Approve fleet-fix run orders as yourself (a verified person).")
    ap.add_argument("order", type=uuid.UUID, nargs="+", help="fleet-submit's order ids")
    args = ap.parse_args(argv)

    def call() -> list:
        core = load(args.config_home)
        principal = load_caller(core)
        remediation_ = core.services().remediation
        return [
            remediation_.approve_fleet_fix(o, principal).model_dump(mode="json") for o in args.order
        ]

    return run(call)


def fleet_claim(argv: list[str] | None = None) -> int:
    ap = _parser("fleet-claim", "Apply the next approved fleet-fix order's spec (diff only).")
    ap.add_argument("--worker", help="this runner's id (default: host:pid)")
    ap.add_argument("--lease-minutes", type=int, default=30, help="how long the order is held")
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    worker = WorkerId(args.worker or f"{socket.gethostname()}:{os.getpid()}")

    def call() -> str | None:
        remediation_ = load(args.config_home).services().remediation
        found = remediation_.claim_fleet_fix(worker, timedelta(minutes=args.lease_minutes))
        doc = {"claimed": None} if found is None else found.model_dump(mode="json")
        return _emit(json.dumps(doc, indent=2), args.out)

    return run(call)


def fleet_targets(argv: list[str] | None = None) -> int:
    ap = _parser("fleet-targets", "The repositories a fleet fix targets, widest reach first.")
    scope = ap.add_mutually_exclusive_group(required=True)
    scope.add_argument("--cwe", type=_cwe, help="repositories with an open finding of this CWE")
    scope.add_argument("--package-id", type=uuid.UUID, help="repositories depending on it")
    scope.add_argument("--module", help="repositories depending on this package (--ecosystem)")
    scope.add_argument("--repo-url", action="append", help="named repositories, repeatable")
    scope.add_argument("--rollup", help="regex matching explicit target rows in --progress")
    ap.add_argument("--progress", type=Path, help="the caller's PROGRESS.md, with --rollup")
    ap.add_argument("--ecosystem", choices=[e.value for e in Ecosystem], help="with --module")
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    if (args.module is None) != (args.ecosystem is None):
        ap.error("--module and --ecosystem go together")
    if (args.rollup is None) != (args.progress is None):
        ap.error("--rollup and --progress go together")

    def call() -> str | None:
        core = load(args.config_home)
        services = core.services()
        if args.rollup is not None:
            progress = args.progress.read_text(encoding="utf-8")
            found = _rollup_targets(services, progress, args.rollup)
            return _emit(json.dumps([t.model_dump(mode="json") for t in found], indent=2), args.out)
        package_id = args.package_id
        if args.module is not None:
            package_id = find_package_id(services, args.ecosystem, args.module)
        named = tuple(_repository(core, u).id for u in args.repo_url or ())
        wanted = FleetScope(cwe=args.cwe, package_id=package_id, repository_ids=named)  # type: ignore[arg-type]
        found = [t.model_dump(mode="json") for t in services.remediation.fleet_targets(wanted)]
        return _emit(json.dumps(found, indent=2), args.out)

    return run(call)


def _fork_mappings(services: Any) -> list[dict[str, Any]]:
    """Every registered repository with the private fork its fixes go to, under the same fork
    policy as prepare (`resolve_fork`); a repository without one says why."""
    mappings: list[dict[str, Any]] = []
    for repository in every_item(
        lambda p: services.portfolio.list_repositories(RepositoryFilter(), p)
    ):
        assert repository.id is not None
        mapping: dict[str, Any] = {
            "repository_id": str(repository.id),
            "repository_url": repository.url,
            "fork": None,
            "unavailable_reason": None,
        }
        try:
            fork = services.remediation.resolve_fork(repository.id)
        except (NotFoundError, ConfigError) as error:
            mapping["unavailable_reason"] = str(error)
        else:
            mapping["fork"] = {**fork.model_dump(mode="json"), "url": str(fork.url)}
        mappings.append(mapping)
    return mappings


_ROLLUP_ROW = re.compile(r"^\|\s*\d+\s*\|\s*([^|]+)\|")
_ROLLUP_LINK = re.compile(r"\[[^\]]+\]\((https://[^\s)]+)\)")


def _rollup_targets(services: Any, markdown: str, pattern: str) -> list[FleetTarget]:
    """The PROGRESS table's numbered rows matching ``pattern``, each resolved to exactly one
    registered repository, then core's ``fleet_targets`` over them. An unregistered or
    ambiguous row is refused, never dropped."""
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as error:
        raise ValidationError(f"invalid rollup pattern {pattern!r}: {error}") from error
    targets = []
    for row in markdown.splitlines():
        match = _ROLLUP_ROW.match(row)
        if match is not None and rx.search(row):
            cell = match[1].strip().strip("`")
            link = _ROLLUP_LINK.fullmatch(cell)
            targets.append(link[1] if link else cell)
    if not targets:
        return []
    registered: dict[str, list[uuid.UUID]] = {}
    for repository in every_item(
        lambda p: services.portfolio.list_repositories(RepositoryFilter(), p)
    ):
        assert repository.id is not None
        path = urlsplit(repository.url).path.strip("/").removesuffix(".git")
        for key in {repository.url.rstrip("/").removesuffix(".git"), path}:
            registered.setdefault(key, []).append(repository.id)
    named = []
    for target in dict.fromkeys(targets):
        found = registered.get(target.rstrip("/").removesuffix(".git"), [])
        if not found:
            raise NotFoundError(f"PROGRESS rollup target {target!r} is not registered")
        if len(found) != 1:
            raise ValidationError(
                f"PROGRESS rollup target {target!r} is ambiguous; use its registered URL"
            )
        named.append(found[0])
    evidence = f"PROGRESS.md rollup match: /{pattern}/"
    return [
        target.model_copy(update={"evidence": evidence})
        for target in services.remediation.fleet_targets(FleetScope(repository_ids=tuple(named)))
    ]


def next_(argv: list[str] | None = None) -> int:
    ap = _parser("next", "Print a repository's oldest work item still waiting for a patch.")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> dict | str:
        core = load(args.config_home)
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
        prepared = load(args.config_home).services().remediation.prepare(args.work_item_id)
        return _emit(prepared.model_dump_json(indent=2), args.out)

    return run(call)


def verify_sweep(argv: list[str] | None = None) -> int:
    ap = _parser("verify-sweep", "Which repositories are worth re-verifying, and why not the rest.")
    ap.add_argument("--repo-url", action="append", default=[], help="repeatable; default: all")
    ap.add_argument("--product", action="append", default=[], help="a product slug, repeatable")
    ap.add_argument(
        "--include-branches",
        action="store_true",
        help="also sweep observed or explicitly registered non-default branch tips",
    )
    ap.add_argument(
        "--impact-filter",
        type=Path,
        help="scope to affected/likely_affected repos in impact export",
    )
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    if args.out is not None and args.out.suffix == ".md":
        ap.error("--out is the JSON path; its .md companion must have a distinct path")

    def call() -> str | None:
        core = load(args.config_home)
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
        if args.impact_filter is not None:
            impact = ImpactExport.model_validate_json(args.impact_filter.read_bytes())
            wanted = {
                row.repository_url
                for row in impact.repos
                if row.classification
                in (ImpactClassification.AFFECTED, ImpactClassification.LIKELY_AFFECTED)
            }
            repos = {id_: repo for id_, repo in repos.items() if repo.url in wanted}
        sweep = services.verification.sweep(list(repos), args.include_branches)
        doc: dict[str, Any] = sweep.model_dump(mode="json")
        for entry in (*doc["queued"], *doc["skipped"]):
            entry["repository"] = repos[uuid.UUID(entry["repository_id"])].url
        if args.out is not None:
            args.out.with_suffix(".md").write_text(
                services.verification.sweep_markdown(sweep), encoding="utf-8"
            )
        return _emit(json.dumps(doc, indent=2), args.out)

    return run(call)


def verify_prepare(argv: list[str] | None = None) -> int:
    ap = _parser("verify-prepare", "Print what a verification of one work item re-checks.")
    ap.add_argument("work_item_id", type=uuid.UUID)
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        prepared = load(args.config_home).services().verification.prepare(args.work_item_id)
        return _emit(prepared.model_dump_json(indent=2), args.out)

    return run(call)


def verify_differential(argv: list[str] | None = None) -> int:
    ap = _parser(
        "verify-differential",
        "Compare the scanner that backed a work item's (or named) findings on a patched commit.",
    )
    ap.add_argument("work_item_id", type=uuid.UUID, nargs="?", help="or --finding + --base-sha")
    ap.add_argument("--repo-url", required=True, help="https URL of the findings' repository")
    ap.add_argument("--sha", required=True, help="the patched commit")
    add_branch_arg(ap)
    ap.add_argument("--finding", type=uuid.UUID, action="append", help="without a work item")
    ap.add_argument("--base-sha", help="without a work item: the commit the findings were on")
    ap.add_argument("--base-branch", help="the branch --base-sha was scanned on, as --branch")
    args = ap.parse_args(argv)
    loose = (args.finding, args.base_sha, args.base_branch)
    if not all(loose[:2]) if args.work_item_id is None else any(loose):
        ap.error("give a work item, or --finding and --base-sha instead of one")

    def call() -> dict:
        core = load(args.config_home)
        services = core.services()
        repo = _repository(core, args.repo_url)
        ref = register_commit(services, repo.id, args.sha, args.branch)  # type: ignore[arg-type]
        if args.work_item_id is not None:
            found = services.verification.differential(args.work_item_id, ref.id)  # type: ignore[arg-type]
        else:
            base = register_commit(services, repo.id, args.base_sha, args.base_branch)  # type: ignore[arg-type]
            found = services.verification.differential_of(args.finding, base.id, ref.id)  # type: ignore[arg-type]
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
            load(args.config_home)
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
        core = load(args.config_home)
        repo = _repository(core, args.repo_url)
        wanted = VerificationFilter(repository_id=repo.id, work_item_id=args.work_item)  # type: ignore[arg-type]
        found = every_item(lambda p: core.services().verification.list(wanted, p))
        return [v.model_dump(mode="json") for v in found]

    return run(call)
