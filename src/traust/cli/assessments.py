"""``traust assessments prepare|coverage|threats``: the audit skills' doors on traust-core.

prepare  what an assessment of one commit starts from, as JSON: the repository's findings, its
         baseline audit, its latest threat model and, with ``--diff``, the changes since that audit
         (clusters, hunks, callers, each cluster's baseline findings). A refused diff prints
         the verdict and exits 3: run the full audit, never a wider or narrower scan.
coverage what the registered repositories' latest default-line audits say they could not
         examine, as gap families ranked by repositories affected (the enumerator backlog)
threats  the threats the registered repositories' latest threat models state (the threat
         register's rows), narrowed by status or ATT&CK technique
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID

import pydantic
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, UnresolvedTargetError, ValidationError
from traust_core.v1.models.assessment import (
    AssessmentFilter,
    AssessmentKind,
    DiffRefused,
    DiffRequest,
    ThreatFilter,
)
from traust_core.v1.models.common import every_item
from traust_core.v1.models.component_target import ComponentTarget, ComponentTargetRequest
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind, ThreatStatus

from traust.cli._doors import parser, run
from traust.context import load

REFUSED = 3


def _repositories(core: Context) -> dict[UUID, str]:
    """Every registered repository's URL by id."""
    portfolio = core.services().portfolio
    return {
        r.id: r.url
        for r in every_item(lambda page: portfolio.list_repositories(RepositoryFilter(), page))
        if r.id is not None
    }


def prepare(argv: list[str] | None = None) -> int:
    ap = parser("assessments", "prepare", "Print what an assessment of one commit starts from.")
    ap.add_argument("--repo-url", required=True, help="https URL of the registered repository")
    ap.add_argument("--sha", help="the commit to assess (required unless --purl + --release-ref)")
    ap.add_argument("--kind", required=True, choices=[k.value for k in AssessmentKind])
    ap.add_argument("--purl", help="versioned component PURL to audit within the pinned repo")
    ap.add_argument("--release-ref", help="release tag pinning the component PURL")
    ap.add_argument("--module-path", help="optional module path hint verified against manifests")
    ap.add_argument(
        "--checkout",
        type=Path,
        metavar="CHECKOUT",
        help="pinned local checkout for deterministic component PURL resolution",
    )
    ap.add_argument("--diff", type=Path, metavar="CHECKOUT", help="diff mode over this checkout")
    ap.add_argument("--since", help="diff mode: the commit the diff starts from (override)")
    ap.add_argument(
        "--baseline-assessment", type=uuid.UUID, help="diff mode: the baseline audit (override)"
    )
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    refused: DiffRefused | UnresolvedTargetError | None = None

    def call() -> str | None:
        nonlocal refused
        if args.diff is None and (args.since or args.baseline_assessment):
            raise ValidationError("--since and --baseline-assessment need --diff")
        if args.purl is None and not args.sha:
            raise ValidationError("--sha is required unless --purl resolves a pinned commit")
        if args.purl is None and (args.release_ref or args.module_path):
            raise ValidationError("--release-ref and --module-path require --purl")
        if args.purl is not None and args.diff is not None:
            raise ValidationError("--purl component audits are initial source audits, not diffs")
        if args.purl is not None and args.checkout is None:
            raise ValidationError("--purl requires --checkout pointing at the pinned tree")
        try:
            diff = (
                DiffRequest(
                    checkout=args.diff,
                    baseline_assessment_id=args.baseline_assessment,
                    since=args.since,
                )
                if args.diff
                else None
            )
        except pydantic.ValidationError as e:
            raise ValidationError(f"--since {args.since}: give 7-40 hex characters") from e
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.find_repository(url)
        if repo is None or repo.id is None:
            raise NotFoundError(f"repository {args.repo_url} is not registered")
        component_target: ComponentTarget | None = None
        commit_sha = args.sha
        ref_name: str | None = None
        ref_kind: RefKind | None = None
        if args.purl is not None:
            assert args.checkout is not None
            try:
                component_target = services.component_targets.resolve(
                    ComponentTargetRequest(
                        purl=args.purl,
                        repository=str(url),
                        commit=args.sha,
                        release_ref=args.release_ref,
                        module_path=args.module_path,
                    ),
                    args.checkout,
                )
            except UnresolvedTargetError as e:
                refused = e
                return json.dumps({"unresolved": True, "reason": str(e.reason), "detail": e.detail})
            commit_sha = component_target.commit
            if component_target.release_ref:
                ref_name = component_target.release_ref
                ref_kind = RefKind.TAG
        assert commit_sha is not None
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(commit_sha), ref_name, ref_kind)
        assert ref.id is not None
        try:
            if component_target is not None:
                prepared = services.assessment.prepare(
                    ref.id, AssessmentKind(args.kind), diff, component_target=component_target
                )
            else:
                prepared = services.assessment.prepare(ref.id, AssessmentKind(args.kind), diff)
        except DiffRefused as e:
            refused = e
            return json.dumps({"refuse": True, "recommend": e.recommend, "reason": e.reason})
        text = prepared.model_dump_json(indent=2)
        if args.out is None:
            return text
        args.out.write_text(text + "\n", encoding="utf-8")
        return None

    rc = run(call)
    return REFUSED if rc == 0 and refused is not None else rc


def coverage(argv: list[str] | None = None) -> int:
    ap = parser("assessments", "coverage", "What the latest audits say they could not examine.")
    ap.add_argument(
        "--kind", choices=[k.value for k in AssessmentKind], help="default: secure-code"
    )
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        urls = _repositories(core)
        kind = None if args.kind is None else AssessmentKind(args.kind)
        found = core.services().assessment.coverage(AssessmentFilter(kind=kind), list(urls))
        return {
            "examined": found.examined,
            "total": found.total,
            "ratio": found.ratio(),
            "gaps": [
                {
                    **gap.model_dump(mode="json", exclude={"example_repository_ids"}),
                    "examples": [urls[i] for i in gap.example_repository_ids if i in urls],
                }
                for gap in found.gaps
            ],
        }

    return run(call)


def threats(argv: list[str] | None = None) -> int:
    ap = parser("assessments", "threats", "The threats the latest threat models state.")
    ap.add_argument(
        "--status", action="append", default=[], choices=[t.value for t in ThreatStatus]
    )
    ap.add_argument("--technique", help="only threats mapped to this ATT&CK technique id")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        urls = _repositories(core)
        scope = ThreatFilter(
            repository_ids=tuple(urls),
            statuses=tuple(ThreatStatus(s) for s in args.status),
            technique=args.technique,
        )
        assessment = core.services().assessment
        rows = [
            {
                "id": str(t.id),
                "repository": urls.get(t.repository_id) if t.repository_id else None,
                **t.model_dump(mode="json", exclude={"repository_id"}),
            }
            for t in every_item(lambda page: assessment.threats(scope, page))
        ]
        return {"total": len(rows), "threats": rows}

    return run(call)
