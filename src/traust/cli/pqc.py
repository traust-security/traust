"""``traust pqc …``: the pqc-readiness skill's doors on traust-core.

prescan   persist native source/SBOM facts and export their exact stored payload
record    a commit's Layer-1 facts or its Layer-2 report; verified zero-hit source scans
          are not applicable (the sweep uses Core's registered scanner provider)
check     a readiness report against its gate past the schema (`record` applies the same gate)
prepare   what Layer 2 scores from: the commit's facts, its route (full/light/skip) and prior report
summary   the latest readiness per commit in scope, rolled up by bucket or dominant provenance
blockers  the remediations of each commit's latest readiness, in the vocabulary /patch reads
vendor-claims  the next version of the curated vendor PQC claims (`dashboard view pqc-vendors`)
worklist  one entry per repository in scope, chokepoints (config home `pqc-priority.yaml`) first
sweep     prescan a bounded batch with Core's registered pqc-scan provider
"""

from __future__ import annotations

import argparse
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    PqcFactsArtifact,
    PqcReadinessArtifact,
    PqcVendorClaimsArtifact,
)
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.dependencies import NoManifestSbomError
from traust_core.v1.models.pqc import PqcDimension, PqcFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    PqcReadinessBucket,
    PqcRemediationCategory,
)

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.context import load, pqc_priority
from traust.ops.pqc import PqcSweep


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


def prescan(argv: list[str] | None = None) -> int:
    ap = _parser("prescan", "Prescan a commit and export its persisted native pqc-facts.")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--repo-dir", type=Path, help="the commit's checkout (read-only)")
    source.add_argument("--from-sbom", type=Path, help="prescan only this manifest SBOM")
    ap.add_argument("--sbom", type=Path, help="source mode's manifest SBOM, recorded first")
    ap.add_argument("--out", type=Path, required=True, help="export the stored pqc-facts JSON")
    ap.add_argument("--cbom-out", type=Path, help="export raw scanner CBOM bytes (source only)")
    args = ap.parse_args(argv)
    if args.repo_dir is None and (args.sbom is not None or args.cbom_out is not None):
        ap.error("--sbom and --cbom-out require --repo-dir")

    def call() -> dict:
        if args.cbom_out is not None and args.out.resolve() == args.cbom_out.resolve():
            raise ValidationError("--out and --cbom-out must name different destinations")
        core = load(args.config_home)
        ref_id = _register(core, args)
        services = core.services()
        sbom = args.from_sbom if args.from_sbom is not None else args.sbom
        if sbom is not None:
            services.exposure.ingest_sbom(sbom.read_bytes(), ref_id)
        request = None if args.repo_dir is None else ToolRequest(workspace=args.repo_dir)
        try:
            done = services.pqc.prescan(ref_id, request)
        except NoManifestSbomError as e:
            raise ValidationError(
                f"commit {args.sha} has no manifest SBOM recorded: run "
                f"`syft dir:{args.repo_dir} -o cyclonedx-json` and pass it as --sbom"
            ) from e
        if args.cbom_out is not None and done.cbom is None:
            reason = "cached facts reuse" if not done.scanned else "this scanner run"
            raise ValidationError(
                f"CBOM unavailable for {reason}: Core stores facts, not CBOM bytes"
            )
        artifact = services.artifacts.latest_for_assessment(done.assessment_id, PqcFactsArtifact)
        if artifact is None:
            raise NotFoundError(f"assessment {done.assessment_id} has no persisted pqc-facts")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(artifact.payload)
        if args.cbom_out is not None:
            assert done.cbom is not None
            args.cbom_out.parent.mkdir(parents=True, exist_ok=True)
            args.cbom_out.write_bytes(done.cbom)
        return {
            "repository_ref_id": str(ref_id),
            "assessment_id": str(done.assessment_id),
            "scanned": done.scanned,
            "facts": len(done.facts),
            "out": str(args.out),
            "cbom_out": None if args.cbom_out is None else str(args.cbom_out),
        }

    return run(call)


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a commit's pqc-facts, or its Layer-2 readiness report.")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    doc = ap.add_mutually_exclusive_group(required=True)
    doc.add_argument("--facts", type=Path, help="a native <slug>-pqc-facts.json")
    doc.add_argument("--report", type=Path, help="a <slug>-pqc-readiness.json you wrote")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load(args.config_home)
        ref_id = _register(core, args)
        source = _doors.interactive()
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
        violations = load(args.config_home).services().pqc.check(doc).violations
        failed = bool(violations)
        return {"ok": not failed, "violations": [v.model_dump(mode="json") for v in violations]}

    rc = run(call)
    return 1 if rc == 0 and failed else rc


def prepare(argv: list[str] | None = None) -> int:
    ap = _parser("prepare", "What Layer 2 scores from: facts, route and prior readiness.")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load(args.config_home)
        ref_id = _find(core, args.repo_url, args.sha)
        return core.services().pqc.prepare(ref_id).model_dump_json(indent=2)

    return run(call)


def _filter_parser(op: str, about: str, *, buckets: bool = True) -> argparse.ArgumentParser:
    ap = _parser(op, about, commit=False)
    ap.add_argument("--product", help="only the commits this product ships (slug)")
    ap.add_argument(
        "--repo", nargs=2, action="append", metavar=("URL", "SHA"), help="only this commit"
    )
    if buckets:
        ap.add_argument(
            "--bucket", action="append", default=[], choices=[b.value for b in PqcReadinessBucket]
        )
    else:
        ap.set_defaults(bucket=[])
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
        core = load(args.config_home)
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
        core = load(args.config_home)
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


def vendor_claims(argv: list[str] | None = None) -> int:
    ap = _parser(
        "vendor-claims", "Record the next version of the curated vendor claims.", commit=False
    )
    ap.add_argument("claims", type=Path, help="a pqc-vendor-claims document (JSON)")
    args = ap.parse_args(argv)

    def call() -> str:
        doc = PqcVendorClaimsArtifact.parse(args.claims.read_bytes())
        recorded = load(args.config_home).services().pqc.record_claims(doc, _doors.interactive())
        return recorded.model_dump_json(indent=2)

    return run(call)


def _sweep(core: Context, config_home: Path | None) -> PqcSweep:
    """The sweep over this deployment's chokepoints, with the Context's registered scanner."""
    return PqcSweep(
        core.services(),
        tuple(core.config.forge_hosts),
        chokepoints=pqc_priority(config_home),
        scanner=core.pqc_scanner,
    )


def worklist(argv: list[str] | None = None) -> int:
    ap = _filter_parser(
        "worklist", "One entry per repository, priority-tiered from inventory.", buckets=False
    )
    args = ap.parse_args(argv)

    def call() -> object:
        core = load(args.config_home)
        entries = _sweep(core, args.config_home).worklist(_filter(core, args))
        return [e.model_dump(mode="json") for e in entries]

    return run(call)


def sweep(argv: list[str] | None = None) -> int:
    ap = _filter_parser(
        "sweep", "Prescan a bounded batch; completed stamps resume the sweep.", buckets=False
    )
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--after", help="next_cursor returned by the previous batch")
    ap.add_argument("--refresh", action="store_true", help="also refresh stale pack stamps")
    args = ap.parse_args(argv)
    incomplete = False

    def call() -> str:
        nonlocal incomplete
        core = load(args.config_home)
        result = _sweep(core, args.config_home).refresh(
            _filter(core, args),
            limit=args.limit,
            after=args.after,
            refresh=args.refresh,
        )
        incomplete = any(r.status in ("failed", "access-request") for r in result.results)
        return result.model_dump_json(indent=2)

    rc = run(call)
    return 1 if rc == 0 and incomplete else rc
