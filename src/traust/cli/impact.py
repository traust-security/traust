"""``traust impact find|package|sbom|symbols|analyze|sweep|below-range``: the impact-analysis
and dependency-watch skills' doors on traust-core.

find     an advisory as its source states it now: identity, aliases, affected packages and ranges
package  the advisories affecting one package version, as their source lists them now
sbom     a commit's manifest SBOM (CycloneDX / SPDX JSON from syft or osv-scanner), or syft over a
         checkout of the commit when no document is given
symbols  the functions the advisory's fix touched: published, or mined from its fix commits
analyze  every commit the advisory reaches (or one): evidence, classification, an `impact`
         assessment each, and a dependency finding for each `affected` commit
sweep    which known advisories touch the recorded SBOMs at all, each with its `analyze` argv
document a registered feed source's document for one identifier (NVD, Red Hat CSAF or VEX, ...)
enrich   EPSS and KEV on the CVE-bearing items of findings/candidates artifacts, with the
         repository's product reach (an enrichment tagger: routes attention, never a severity)
below-range  evidence packets for advisories whose stated range starts above a commit's installed
         version, for review; every candidate is a packet or a coverage gap
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.context import CheckoutRequest, Context, Services
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import BelowRangeVerdictsArtifact
from traust_core.v1.models.below_range import BelowRangeInput, BelowRangeStatus
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import (
    AdvisoryRecord,
    SweepStatus,
    Version,
    parse_advisory_identifier,
)
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    Ecosystem,
    ImpactClassification,
    ScannerSeverity,
    SourceType,
)

from traust.cli._doors import add_branch_arg, answer, parser, register_commit, run
from traust.context import load
from traust.ops.materializers import MANUAL, BelowRangePacketsMaterializer, ManifestSbomMaterializer
from traust.paths import HARNESS_ROOT
from traust.registry.osv_urls import osv_access

UNDECIDED = (ImpactClassification.INCONCLUSIVE, ImpactClassification.LIKELY_AFFECTED)
SWEEP_EXIT = {SweepStatus.COMPLETE: 0, SweepStatus.DEGRADED: 3, SweepStatus.FAILED: 2}
BELOW_RANGE_EXIT = {BelowRangeStatus.COMPLETE: 0, BelowRangeStatus.DEGRADED: 3}


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    return parser("impact", op, about)


def _core(config_home: Path | None) -> Context:
    """Core with the feeds registry's sources, so advisories come from `osv`, never from memory."""
    core = load(config_home)
    core.register_feeds()  # NEED(core: feeds registered lazily)
    return core


def _advisory_files(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--advisory-file",
        type=Path,
        action="append",
        default=[],
        help="exported OSV JSON; repeat for aliases (uses only these files, never the live API)",
    )


def _advisory_core(args: argparse.Namespace) -> Context:
    core = _core(args.config_home)
    if args.advisory_file:
        core.use_exported_advisories(args.advisory_file)
    return core


def _advisory(services: Services, identifier: str) -> AdvisoryRecord:
    record = services.exposure.find_advisory(parse_advisory_identifier(identifier))
    if record is None or record.advisory_id is None:
        raise NotFoundError(f"advisory {identifier}: its source doesn't know it; not assessed")
    return record


def find(argv: list[str] | None = None) -> int:
    ap = _parser("find", "Print an advisory as its source states it now, as JSON.")
    ap.add_argument("advisory", help="CVE-/GHSA-/MAL-/PYSEC-/GO-/RUSTSEC-/OSV- id")
    _advisory_files(ap)
    args = ap.parse_args(argv)

    def call() -> str:
        return _advisory(_advisory_core(args).services(), args.advisory).model_dump_json(indent=2)

    return run(call)


def package(argv: list[str] | None = None) -> int:
    ap = _parser("package", "Print the advisories affecting one package version, as JSON.")
    ap.add_argument("name", help="the package as its ecosystem names it")
    ap.add_argument("version")
    ap.add_argument("--ecosystem", required=True, choices=[e.value for e in Ecosystem])
    _advisory_files(ap)
    args = ap.parse_args(argv)

    def call() -> str:
        found = (
            _advisory_core(args)
            .services()
            .exposure.package_advisories(
                Ecosystem(args.ecosystem), args.name, Version(args.version)
            )
        )
        return found.model_dump_json(indent=2)

    return run(call)


def sbom(argv: list[str] | None = None) -> int:
    ap = _parser("sbom", "Record a commit's manifest SBOM (CycloneDX or SPDX JSON).")
    ap.add_argument(
        "sbom",
        type=Path,
        nargs="?",
        help="the SBOM document (default: syft over the commit's manifests)",
    )
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the commit the SBOM was read from")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    add_branch_arg(ap)
    args = ap.parse_args(argv)

    def call() -> dict:
        core = _core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        if args.sbom is not None:
            kept = services.exposure.ingest_sbom(args.sbom.read_bytes(), ref.id)
            return {"repository_ref_id": ref.id, "sbom_id": kept.id}
        kept = services.exposure.record_manifest_sbom(ref.id)
        return {"repository_ref_id": ref.id, "sbom_id": kept.id}

    return run(call)


def symbols(argv: list[str] | None = None) -> int:
    ap = _parser("symbols", "Print the functions the advisory's fix touched, as JSON.")
    ap.add_argument("advisory")
    _advisory_files(ap)
    args = ap.parse_args(argv)

    def call() -> str:
        services = _advisory_core(args).services()
        record = _advisory(services, args.advisory)
        assert record.advisory_id is not None
        return services.exposure.resolve_symbols(record.advisory_id).model_dump_json(indent=2)

    return run(call)


def analyze(argv: list[str] | None = None) -> int:
    ap = _parser("analyze", "Assess every commit an advisory reaches, or one, and record each.")
    ap.add_argument("advisory")
    _advisory_files(ap)
    ap.add_argument("--repo-url", help="assess only this repository's commit (with --sha)")
    ap.add_argument("--sha", help="the commit to assess (with --repo-url)")
    add_branch_arg(ap)
    ap.add_argument(
        "--scan",
        action="store_true",
        help="clone each commit the SBOMs leave undecided and run the analysis tiers on it",
    )
    ap.add_argument(
        "--symbols",
        default="",
        help="comma-separated vulnerable symbols read off the fix diff (join any found)",
    )
    ap.add_argument("--feature-desc", default=None, help="what capability must be in use")
    args = ap.parse_args(argv)
    if bool(args.repo_url) != bool(args.sha):
        ap.error("--repo-url and --sha go together")
    if args.branch and not args.sha:
        ap.error("--branch names the assessed commit's branch: give --repo-url and --sha")

    def call() -> dict:
        core = _advisory_core(args)
        services = core.services()
        exposure = services.exposure
        record = _advisory(services, args.advisory)
        advisory_id = record.advisory_id
        assert advisory_id is not None
        if args.repo_url:
            url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
            repo = services.portfolio.register_repository(url, False)
            commits = [register_commit(services, repo.id, args.sha, args.branch).id]
        else:
            commits = list(
                dict.fromkeys(
                    r.repository_ref_id
                    for r in exposure.affected(advisory_id)
                    if r.repository_ref_id
                )
            )
        version = harness_version()
        judged = [s.strip() for s in args.symbols.split(",") if s.strip()]
        recorded = []
        for ref_id in commits:
            # Core prepares one commit against the advisory (one analysis per commit).
            prepared = (exposure.prepare(advisory_id, ref_id, judged=judged),)
            if args.scan and any(
                p.evidence.classification(p.package.ecosystem) in UNDECIDED for p in prepared
            ):
                [subject] = {item.subject for item in prepared}
                workspace = services.checkouts.checkout(
                    CheckoutRequest(
                        repo=HttpsRepoUrl.parse(subject.repository_url, core.config.forge_hosts),
                        ref=GitSha.parse(subject.sha),
                    )
                ).data
                try:
                    prepared = (exposure.prepare(advisory_id, ref_id, workspace.path, judged),)
                finally:
                    services.checkouts.release(workspace)
            for item in prepared:
                source = Provenance(
                    run_id=uuid.uuid4(),
                    source=SourceType.IMPACT_REPORT,
                    occurred_at=datetime.now(UTC),
                )
                doc = item.document(version, args.feature_desc)
                done = exposure.record(ref_id, doc, source)
                recorded.append((item.subject.repository_url, item.subject.sha, done))
        return {
            "advisory": record.identifier,
            "commits": len(commits),
            "analyses": len(recorded),
            "classifications": dict(Counter(d.classification.value for *_, d in recorded)),
            "affected": [
                {"repository": url, "sha": sha, "finding_id": d.finding_id}
                for url, sha, d in recorded
                if d.classification == ImpactClassification.AFFECTED
            ],
        }

    return run(call)


def export(argv: list[str] | None = None) -> int:
    ap = _parser("export", "Export all recorded commit/package verdicts for one advisory.")
    ap.add_argument("advisory")
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        report = (
            load(args.config_home)
            .services()
            .exposure.export_impacts(parse_advisory_identifier(args.advisory))
        )
        text = report.model_dump_json(indent=2)
        if args.out is None:
            return text
        args.out.write_text(text + "\n", encoding="utf-8")
        return None

    return run(call)


def sweep(argv: list[str] | None = None) -> int:
    ap = _parser(
        "sweep",
        "Which known advisories touch the recorded SBOMs, as JSON. Exit 0 complete, "
        "3 degraded (some package versions or advisories unanswered), 2 failed.",
    )
    ap.add_argument(
        "--min-severity",
        default="critical",
        choices=["critical", "high", "medium", "low"],
        help="the lowest severity listed (malicious packages are critical)",
    )
    ap.add_argument(
        "--deep-scan-cap",
        type=int,
        default=100,
        help="advisories reaching more commits than this get SBOM-only analyze (no --scan)",
    )
    ap.add_argument(
        "--ecosystem",
        default="all",
        help="comma list (go,npm,pypi,maven,cargo,ruby,nuget,actions) or 'all'",
    )
    ap.add_argument("--out", type=Path, help="also write the result here")
    _advisory_files(ap)
    args = ap.parse_args(argv)
    wanted = [] if args.ecosystem == "all" else args.ecosystem.lower().split(",")
    try:
        ecosystems = [Ecosystem(e.strip()) for e in wanted]
    except ValueError as e:
        ap.error(str(e))
    status: list[SweepStatus] = []

    def call() -> str:
        swept = (
            _advisory_core(args)
            .services()
            .exposure.sweep(ScannerSeverity(args.min_severity), args.deep_scan_cap, ecosystems)
        )
        status.append(swept.status)
        doc = swept.model_dump(mode="json")
        for row in doc["advisories"]:
            # argv only: run each as given, one call per array, never joined into a shell string
            row["impact_argv"] = ["python3", "-m", "traust.cli", "impact", "analyze"]
            row["impact_argv"] += [row["identifier"], *(["--scan"] if row["scan"] else [])]
            for path in args.advisory_file:
                row["impact_argv"] += ["--advisory-file", str(path.resolve())]
        text = json.dumps(doc, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n")
        return text

    code = run(call)
    return code or SWEEP_EXIT[status[0]]


def document(argv: list[str] | None = None) -> int:
    ap = _parser("document", "Print a feed source's document for one identifier, as served.")
    ap.add_argument("source", help="a registry feed source (nvd, redhat-csaf, vex, ...)")
    ap.add_argument("ident", help="the identifier the source is keyed by (CVE, RHSA, repo)")
    args = ap.parse_args(argv)

    def call() -> str:
        services = _core(args.config_home).services()
        raw = services.exposure.source_document(args.source, args.ident)
        return raw.decode("utf-8", errors="replace")

    return run(call)


def enrich(argv: list[str] | None = None) -> int:
    ap = _parser("enrich", "EPSS, KEV and product reach for an artifact's CVEs, as JSON.")
    ap.add_argument(
        "--in", dest="inputs", action="append", required=True, type=Path,
        help="a findings or candidates artifact (repeatable)",
    )  # fmt: skip
    ap.add_argument("--repo-url", help="https URL of the repository the artifacts are about")
    ap.add_argument(
        "--workloads", type=Path,
        help="JSON list of repository URLs running in an authorized lab cluster",
    )  # fmt: skip
    ap.add_argument("--out", type=Path, help="also write the result here")
    args = ap.parse_args(argv)

    def call() -> str:
        core = _core(args.config_home)
        hosts = core.config.forge_hosts
        url = HttpsRepoUrl.parse(args.repo_url, hosts) if args.repo_url else None
        deployed = None
        if args.workloads is not None:
            try:
                listed = json.loads(args.workloads.read_text())
            except ValueError as e:
                raise ValidationError(f"{args.workloads}: not JSON: {e}") from e
            if not isinstance(listed, list) or not all(isinstance(u, str) for u in listed):
                raise ValidationError(f"{args.workloads}: expected a JSON list of repository URLs")
            deployed = [HttpsRepoUrl.parse(u, hosts) for u in listed]
        found = core.services().exposure.exploit_context(
            {str(p): p.read_bytes() for p in args.inputs}, url, deployed
        )
        text = found.model_dump_json(indent=2)
        if args.out:
            args.out.write_text(text + "\n")
        return text

    return run(call)


def below_range(argv: list[str] | None = None) -> int:
    ap = _parser(
        "below-range",
        "Evidence packets for advisories whose stated range starts above the installed version, "
        "for the commit's recorded manifest SBOM (`traust impact sbom` first). Exit 0 complete, "
        "3 degraded (some packages or advisories unanswered), 2 refused.",
    )
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the commit whose installed packages are checked")
    add_branch_arg(ap)
    ap.add_argument("--out", type=Path, help="packet directory (default: ./<repo>-below-range)")
    ap.add_argument(
        "--ecosystems",
        default="go,pypi,npm,maven,cargo,ruby,nuget",
        help="comma list of the ecosystems to check",
    )
    ap.add_argument("--max-candidates", type=int, default=100)
    args = ap.parse_args(argv)
    try:
        ecosystems = {Ecosystem(e.strip()) for e in args.ecosystems.lower().split(",") if e.strip()}
    except ValueError as e:
        ap.error(str(e))
    status: list[BelowRangeStatus] = []

    def call() -> dict:
        _no_air_gap()
        core = _core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, False)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        out = args.out or Path(f"{url.path.rsplit('/', 1)[-1]}-below-range")
        found = services.below_range.prepare(
            ref.id, out, ecosystems=ecosystems, max_candidates=args.max_candidates
        )
        status.append(found.status)
        return write_packets(found, out)

    code = run(call)
    return code or BELOW_RANGE_EXIT[status[0]]


def write_packets(
    found: BelowRangeInput, out: Path, packets_assessment_id: uuid.UUID | None = None
) -> dict:
    """What the review reads: `<case>/packet.json` and `fix.patch` beside the sources, and the
    `below-range.json` index (with the recorded packets' assessment when there is one)."""
    for packet in found.packets:
        (out / packet.case).mkdir(parents=True, exist_ok=True)
        (out / packet.case / "fix.patch").write_text(packet.patch)
        doc = packet.model_dump_json(indent=1, exclude={"patch"})
        (out / packet.case / "packet.json").write_text(doc + "\n")
    index = found.model_dump(mode="json", exclude={"packets"})
    index["packets"] = [
        {"case": p.case, "kind": p.candidate.kind, "ecosystem": p.candidate.ecosystem}
        for p in found.packets
    ]
    if packets_assessment_id is not None:
        index["packets_assessment_id"] = str(packets_assessment_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / "below-range.json").write_text(json.dumps(index, indent=1) + "\n")
    return {
        "out": str(out),
        "installed_exact": found.installed_exact,
        "candidates": found.candidates,
        "packets": len(found.packets),
        "coverage_gaps": dict(Counter(g.reason.value for g in found.coverage_gaps)),
        "status": found.status.value,
    }


def _no_air_gap() -> None:
    if osv_access() == "air-gapped":
        raise ValidationError(
            "below-range needs the OSV API and the package registries; traust.yaml sets "
            "feeds.osv_access: air-gapped"
        )


def manifest_sbom(argv: list[str] | None = None) -> int:
    ap = _parser(
        "manifest-sbom",
        "The manifest_sbom asset's materializer: the dependency SBOM of an inventory repository's "
        "observed default head, from its manifests on the forge. Prints the JobResult; its "
        "outcome is the exit code.",
    )
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this SBOM is for")
    args = ap.parse_args(argv)
    core = _core(args.config_home)
    materializer = ManifestSbomMaterializer(core.services(), core.config.forge_hosts)
    request = AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.repo)
    return answer(materializer.materialize(request))


def below_range_scan(argv: list[str] | None = None) -> int:
    ap = _parser(
        "below-range-scan",
        "The below_range_packets asset's materializer: packets for an inventory repository's "
        "default-branch head, recorded for review. Prints the JobResult; its outcome is the "
        "exit code.",
    )
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this scan is for")
    args = ap.parse_args(argv)
    try:
        _no_air_gap()
    except ValidationError as e:
        print(e, file=sys.stderr)
        return answer(JobResult.refused(OrderReason.BAD_REQUEST))
    core = _core(args.config_home)
    materializer = BelowRangePacketsMaterializer(core.services(), core.config.forge_hosts)
    request = AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.repo)
    return answer(materializer.materialize(request))


def below_range_review(argv: list[str] | None = None) -> int:
    ap = _parser(
        "below-range-review",
        "Write a repository's newest recorded below-range packets for review, with each "
        "installed source refetched and checked against its recorded digest.",
    )
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--out", type=Path, required=True, help="packet directory to write")
    args = ap.parse_args(argv)

    def call() -> dict:
        _no_air_gap()
        core = _core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo, core.config.forge_hosts)
        repo = services.portfolio.find_repository(url)
        if repo is None or repo.id is None:
            raise NotFoundError(f"{url} is not in the inventory")
        latest = services.below_range.latest(repo.id)
        services.below_range.fetch(latest.packets, args.out)
        return {
            "packets_assessment_id": str(latest.assessment_id),
            **write_packets(latest.packets, args.out, latest.assessment_id),
        }

    return run(call)


def below_range_record(argv: list[str] | None = None) -> int:
    ap = _parser(
        "below-range-record",
        "Record a below-range review (verdicts.json): each applicable case becomes the "
        "commit's dependency finding; the rest stay in the recorded document.",
    )
    ap.add_argument("verdicts", type=Path, help="the below-range-verdicts document")
    args = ap.parse_args(argv)

    def call() -> dict:
        services = _core(args.config_home).services()
        doc = BelowRangeVerdictsArtifact.parse(args.verdicts.read_bytes())
        source = Provenance(
            run_id=uuid.uuid4(), source=SourceType.IMPACT_REPORT, occurred_at=datetime.now(UTC)
        )
        return services.below_range.record(doc, source).model_dump(mode="json")

    return run(call)


def harness_version() -> str:
    """`<VERSION>-<short sha>` of this harness, as the impact artifact records it."""
    version = (HARNESS_ROOT / "VERSION").read_text().strip()
    sha = subprocess.run(
        ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return f"{version}-{sha}" if sha else version
