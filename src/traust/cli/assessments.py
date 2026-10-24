"""``traust assessments prepare``: the audit skills' first door on traust-core.

prepare  what an assessment of one commit starts from, as JSON: the repository's findings, its
         latest threat model and, with ``--diff``, the changes since the baseline audit
         (clusters, hunks, callers, each cluster's baseline findings). A refused diff prints
         the verdict and exits 3: run the full audit, never a wider or narrower scan.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pydantic
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind, DiffRefused, DiffRequest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli._doors import parser, run
from traust.context import load_core

REFUSED = 3


def prepare(argv: list[str] | None = None) -> int:
    ap = parser("assessments", "prepare", "Print what an assessment of one commit starts from.")
    ap.add_argument("--repo-url", required=True, help="https URL of the registered repository")
    ap.add_argument("--sha", required=True, help="the commit to assess (the checkout's HEAD)")
    ap.add_argument("--kind", required=True, choices=[k.value for k in AssessmentKind])
    ap.add_argument("--diff", type=Path, metavar="CHECKOUT", help="diff mode over this checkout")
    ap.add_argument("--since", help="diff mode: the commit the diff starts from (override)")
    ap.add_argument(
        "--baseline-assessment", type=uuid.UUID, help="diff mode: the baseline audit (override)"
    )
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    refused: DiffRefused | None = None

    def call() -> str | None:
        nonlocal refused
        if args.diff is None and (args.since or args.baseline_assessment):
            raise ValidationError("--since and --baseline-assessment need --diff")
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
        core = load_core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.find_repository(url)
        if repo is None or repo.id is None:
            raise NotFoundError(f"repository {args.repo_url} is not registered")
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
        assert ref.id is not None
        try:
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
