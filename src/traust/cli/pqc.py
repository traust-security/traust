"""``traust pqc record|check|prepare|summary|blockers|dashboard``: the pqc-readiness skill's doors
on traust-core.

record    a commit's Layer-1 facts (`pqc_facts.py`; `PqcService.prescan` waits on the engine's
          pqc-scan provider) or its Layer-2 report; a verified zero-hit is not applicable
check     a readiness report against its gate past the schema (`record` applies the same gate)
prepare   what Layer 2 scores from: the commit's facts, its route (full/light/skip) and prior report
summary   the latest readiness per commit in scope, rolled up by bucket or dominant provenance
blockers  the remediations of each commit's latest readiness, in the vocabulary /patch reads
dashboard the PQC view (per product, by bucket and provenance) written as an md/html pair
"""

from __future__ import annotations

import argparse
import uuid
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import PqcFactsArtifact, PqcReadinessArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.pqc import PqcDimension, PqcFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    PqcReadinessBucket,
    PqcRemediationCategory,
    SourceType,
)

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.context import load_core
from traust.ops.materializers import write_view


def _parser(op: str, about: str, *, commit: bool = True) -> argparse.ArgumentParser:
    ap = parser("pqc", op, about)
    if commit:
        ap.add_argument("--repo-url", required=True, help="https URL of the repository")
        ap.add_argument("--sha", required=True, help="the commit")
    return ap


def _register(core: Context, args: argparse.Namespace) -> UUID:
    portfolio = core.services().portfolio
    repo = portfolio.register_repository(
        HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts), args.public
    )
    ref = portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
    assert ref.id is not None
    return ref.id


def _find(core: Context, repo_url: str, sha: str) -> UUID:
    portfolio = core.services().portfolio
    repo = portfolio.find_repository(HttpsRepoUrl.parse(repo_url, core.config.forge_hosts))
    if repo is None or repo.id is None:
        raise NotFoundError(f"{repo_url} is not a registered repository")
    ref = portfolio.inventory.find_ref(repo.id, str(GitSha.parse(sha)))
    assert ref.id is not None
    return ref.id


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a commit's pqc-facts, or its Layer-2 readiness report.")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    doc = ap.add_mutually_exclusive_group(required=True)
    doc.add_argument("--facts", type=Path, help="a <slug>-pqc-facts.json (pqc_facts.py output)")
    doc.add_argument("--report", type=Path, help="a <slug>-pqc-readiness.json you wrote")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load_core(args.config_home)
        ref_id = _register(core, args)
        source = Provenance(
            run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=datetime.now(UTC)
        )
        pqc = core.services().pqc
        if args.facts is not None:
            done = pqc.record(ref_id, PqcFactsArtifact.parse(args.facts.read_bytes()), source)
            return done.model_dump_json(indent=2, exclude={"cbom"})
        report = PqcReadinessArtifact.parse(args.report.read_bytes())
        return pqc.record(ref_id, report, source).model_dump_json(indent=2)

    return run(call)


def check(argv: list[str] | None = None) -> int:
    ap = _parser(
        "check", "Check a readiness report against its gate; exit 1 when it fails.", commit=False
    )
    ap.add_argument("report", type=Path, help="a <slug>-pqc-readiness.json")
    args = ap.parse_args(argv)
    failed = False

    def call() -> dict:
        nonlocal failed
        doc = PqcReadinessArtifact.parse(args.report.read_bytes())
        violations = load_core(args.config_home).services().pqc.check(doc).violations
        failed = bool(violations)
        return {"ok": not failed, "violations": [v.model_dump(mode="json") for v in violations]}

    rc = run(call)
    return 1 if rc == 0 and failed else rc


def prepare(argv: list[str] | None = None) -> int:
    ap = _parser("prepare", "What Layer 2 scores from: facts, route and prior readiness.")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load_core(args.config_home)
        ref_id = _find(core, args.repo_url, args.sha)
        return core.services().pqc.prepare(ref_id).model_dump_json(indent=2)

    return run(call)


def _filter_parser(op: str, about: str) -> argparse.ArgumentParser:
    ap = _parser(op, about, commit=False)
    ap.add_argument("--product", help="only the commits this product ships (slug)")
    ap.add_argument(
        "--repo", nargs=2, action="append", metavar=("URL", "SHA"), help="only this commit"
    )
    ap.add_argument(
        "--bucket", action="append", default=[], choices=[b.value for b in PqcReadinessBucket]
    )
    return ap


def _filter(core: Context, args: argparse.Namespace, **more: object) -> PqcFilter:
    product_id = _doors.products(core.services(), [args.product])[0].id if args.product else None
    refs = None if args.repo is None else tuple(_find(core, u, s) for u, s in args.repo)
    return PqcFilter(
        repository_ref_ids=refs,
        product_id=product_id,
        buckets=tuple(PqcReadinessBucket(b) for b in args.bucket),
        **more,
    )


def summary(argv: list[str] | None = None) -> int:
    ap = _filter_parser("summary", "Latest readiness per commit in scope, rolled up.")
    ap.add_argument(
        "--by", default=PqcDimension.BUCKET.value, choices=[d.value for d in PqcDimension]
    )
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        core = load_core(args.config_home)
        rollups = core.services().pqc.summary(_filter(core, args), PqcDimension(args.by))
        return [r.model_dump(mode="json") for r in rollups]

    return run(call)


def blockers(argv: list[str] | None = None) -> int:
    ap = _filter_parser("blockers", "The remediations of each commit's latest readiness.")
    ap.add_argument(
        "--category",
        action="append",
        default=[],
        choices=[c.value for c in PqcRemediationCategory],
    )
    anchored = ap.add_mutually_exclusive_group()
    anchored.add_argument(
        "--patchable", action="store_true", help="only items anchored in the repository"
    )
    anchored.add_argument(
        "--not-patchable", action="store_true", help="only items with no local location"
    )
    args = ap.parse_args(argv)
    patchable = True if args.patchable else False if args.not_patchable else None

    def call() -> list[dict]:
        core = load_core(args.config_home)
        found = core.services().pqc.blockers(
            _filter(
                core,
                args,
                categories=tuple(PqcRemediationCategory(c) for c in args.category),
                patchable=patchable,
            )
        )
        return [{**b.model_dump(mode="json"), "patchable": b.patchable} for b in found]

    return run(call)


def dashboard(argv: list[str] | None = None) -> int:
    ap = _parser("dashboard", "Write the PQC view as pqc-dashboard.{md,html}.", commit=False)
    ap.add_argument("--product", action="append", default=[], help="a product slug (repeatable)")
    ap.add_argument("--out", type=Path, required=True, help="the folder the pair is written to")
    args = ap.parse_args(argv)

    def call() -> dict:
        services = load_core(args.config_home).services()
        scope = ViewFilter(product_ids=tuple(p.id for p in _doors.products(services, args.product)))
        rendered = services.insight.publish(ViewName.PQC, scope)
        written = write_view(rendered, args.out / "pqc-dashboard", model=True)
        return {"written": [str(p) for p in written]}

    return run(call)
