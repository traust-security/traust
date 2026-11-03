"""``traust compliance …``: compliance-check's doors on traust-core.

declare   record one boundary declaration (a compliance-scope document); signed only when you, the
          verified caller, are its declarant, otherwise DRAFT; an existing boundary needs --replace
scopes    the current declaration of each boundary, newest first
resolve   a boundary's repositories now, under its current declaration
policy    record the next version of the control mapping, the ADR registers or the org parameters
evaluate  the deterministic runner over a boundary: writes draft JSON and per-control Markdown,
          lists evidence_review controls awaiting artifacts; exit 1 when the citation gate fails
evidence  hash one JSON artifact the agent pass judged into the evidence bundle; cite the result
check     the citation gate over an (edited) assessment; exit 1 on any violation
record    record a gated assessment against each in-scope commit
latest    a boundary's newest recorded assessment of a framework, with its posture
adrs      the decisions of the pinned registers governing a product
docs      fetch the registered product's official guides using configured or explicit targets
calibrate evaluate twice: identical inputs must give identical verdicts; given an answer key,
          score the run on it; exit 1 on any divergence or failure
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any, TypeVar
from uuid import UUID

import yaml
from traust_core.v1.context import DocsTarget, Services
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
    OrgParametersArtifact,
)
from traust_core.v1.models.code_facts import CryptoFact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.compliance import (
    CLOUD_INVENTORY,
    CRYPTO_AUDIT,
    FINDINGS_DB,
    Collector,
    ComplianceScope,
    EfficacyKey,
    EvaluationRequest,
    InventorySnapshot,
    ScopeFilter,
)
from traust_core.v1.models.vocabulary import (
    ComplianceEvidenceKind,
    ComplianceFramework,
    ComplianceTargetKind,
)

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.context import load, load_caller

T = TypeVar("T")
BUILT = {  # collectors traust-core builds itself
    FINDINGS_DB: "traust-core reads the boundary's findings itself",
    CRYPTO_AUDIT: "pass the crypto census as --crypto",
    CLOUD_INVENTORY: "pass the snapshot as --inventory",
}
POLICY = {
    "mapping": ComplianceMappingArtifact,
    "adr-registry": AdrRegistryArtifact,
    "org-parameters": OrgParametersArtifact,
}


def declare(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "declare", "Record one compliance boundary declaration.")
    ap.add_argument("scope", type=Path, help="a compliance-scope document (YAML) of one boundary")
    ap.add_argument("--replace", action="store_true", help="supersede the boundary's declaration")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load(args.config_home)
        doc = ComplianceScopeArtifact.from_document(yaml.safe_load(args.scope.read_text()))
        scope = core.services().compliance.set_scope(doc, load_caller(core), replace=args.replace)
        return scope.model_dump_json(indent=2)

    return run(call)


def scopes(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "scopes", "The current declaration of each boundary.")
    ap.add_argument("--framework", help="only boundaries declaring this framework")
    ap.add_argument("--product", help="only boundaries of this product")
    drafts = ap.add_mutually_exclusive_group()
    drafts.add_argument("--draft", action="store_true", help="only unsigned declarations")
    drafts.add_argument("--signed", action="store_true", help="only signed declarations")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--cursor", help="the previous page's `next`")
    args = ap.parse_args(argv)
    draft = True if args.draft else False if args.signed else None

    def call() -> str:
        page = (
            load(args.config_home)
            .services()
            .compliance.scopes(
                ScopeFilter(framework=args.framework, product=args.product, draft=draft),
                PageRequest(limit=args.limit, cursor=args.cursor),
            )
        )
        return page.model_dump_json(indent=2)

    return run(call)


def current(services: Services, boundary: str) -> ComplianceScope:
    """A boundary's current declaration, by scope id or by boundary name."""
    try:
        return services.compliance.get_scope(UUID(boundary))
    except ValueError:
        pass
    page, cursor = None, None
    while page is None or cursor:
        page = services.compliance.scopes(ScopeFilter(), PageRequest(limit=500, cursor=cursor))
        if found := next((s for s in page.items if s.boundary == boundary), None):
            return found
        cursor = page.next
    raise NotFoundError(f"no compliance boundary {boundary!r} is declared")


def resolve(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "resolve", "A boundary's repositories under its current declaration.")
    ap.add_argument("boundary", help="the boundary name or its scope id")
    args = ap.parse_args(argv)

    def call() -> str:
        services = load(args.config_home).services()
        scope = current(services, args.boundary)
        assert scope.scope_id is not None
        return services.compliance.resolve(scope.scope_id).model_dump_json(indent=2)

    return run(call)


def _load(path: Path, build: Callable[[Any], T] = lambda raw: raw) -> T:
    """``build`` over the file's JSON; a malformed file is a refused input."""
    try:
        return build(json.loads(path.read_text()))
    except (ValueError, KeyError, TypeError) as e:  # bad JSON, a pydantic error, a missing key
        raise ValidationError(f"{path}: {e}") from e


def _csv(raw: str | None) -> tuple[str, ...]:
    return tuple(v.strip() for v in (raw or "").split(",") if v.strip())


def policy(argv: list[str] | None = None) -> int:
    ap = parser(
        "compliance", "policy", "Record the control mapping, the ADR registers or org parameters."
    )
    ap.add_argument("kind", choices=sorted(POLICY))
    ap.add_argument("document", type=Path, help="the policy document (YAML)")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = POLICY[args.kind].from_document(yaml.safe_load(args.document.read_text()))
        published = load(args.config_home).services().compliance.record(doc, _doors.interactive())
        return {"artifact_id": published.artifact_id}

    return run(call)


def _evaluation_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("boundary", help="the boundary name or its scope id")
    ap.add_argument("--frameworks", help="comma list or 'all' (default: the boundary's)")
    ap.add_argument("--target-kind", choices=("product", "environment", "both"), default="product")
    ap.add_argument("--environment")
    ap.add_argument("--cde-boundary", help="PCI: the declared CDE boundary")
    ap.add_argument("--personal-data-stores", help="GDPR: comma list of declared stores")
    ap.add_argument("--trust-categories", help="SOC 2: comma list (security is mandatory)")
    ap.add_argument(
        "--collector",
        action="append",
        default=[],
        metavar="KIND=PATH",
        help="a collector snapshot you ran, e.g. scan_k8s_hardening=khs.json (repeatable)",
    )
    ap.add_argument("--crypto", type=Path, help="`traust adapters crypto-source` output")
    ap.add_argument("--inventory", type=Path, help="a cloud-inventory snapshot")


def _request(services: Services, args: argparse.Namespace) -> EvaluationRequest:
    scope = current(services, args.boundary)
    assert scope.scope_id is not None
    frameworks = tuple(ComplianceFramework) if args.frameworks == "all" else _csv(args.frameworks)
    snapshots = {}
    for spec in args.collector:
        kind, _, path = spec.partition("=")
        if kind in BUILT:
            raise ValidationError(f"--collector {kind}: {BUILT[kind]}")
        snapshots[Collector(kind)] = _load(Path(path))
    inventory = args.inventory and _load(
        args.inventory,
        lambda raw: InventorySnapshot.of(
            raw["metadata"]["collector"], raw["resources"], raw["gaps"]
        ),
    )
    crypto = args.crypto and _load(
        args.crypto, lambda raw: tuple(CryptoFact.model_validate(f) for f in raw["facts"])
    )
    return EvaluationRequest(
        scope_id=scope.scope_id,
        harness_version=version("traust"),
        frameworks=tuple(ComplianceFramework(f) for f in frameworks),
        target_kind=ComplianceTargetKind(args.target_kind),
        environment=args.environment,
        cde_boundary=args.cde_boundary,
        personal_data_stores=_csv(args.personal_data_stores),
        trust_categories=_csv(args.trust_categories),
        snapshots=snapshots,
        crypto=crypto,
        inventory=inventory,
    )


def _answer(body: dict, passed: bool) -> int:
    print(json.dumps(body, indent=2, default=str))
    return 0 if passed else 1


def evaluate(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "evaluate", "The deterministic runner over a boundary.")
    _evaluation_args(ap)
    ap.add_argument("--out", type=Path, required=True, help="where the draft assessment goes")
    ap.add_argument("--markdown", type=Path, help="per-run report (default: --out with .md suffix)")
    args = ap.parse_args(argv)
    found: dict = {}

    def call() -> None:
        markdown = args.markdown or args.out.with_suffix(".md")
        if markdown.resolve() == args.out.resolve():
            raise ValidationError("assessment JSON and Markdown must have different output paths")
        services = load(args.config_home).services()
        evaluated = services.compliance.evaluate(_request(services, args))
        prepared = services.compliance.prepare(evaluated)
        rendered = services.compliance.render_assessment(evaluated.document)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(evaluated.document.payload)
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_bytes(rendered)
        found.update(
            wrote=str(args.out),
            markdown=str(markdown),
            skipped=prepared.assessment["metadata"]["skipped_frameworks"],
            coverage=prepared.assessment["coverage"],
            evidence=len(evaluated.evidence),
            awaiting=[a.model_dump(mode="json") for a in prepared.awaiting],
            gate=list(evaluated.failures),
        )

    return run(call) or _answer(found, not found["gate"])


def evidence(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "evidence", "Hash a judged artifact into the evidence bundle.")
    ap.add_argument("artifact", type=Path, help="the artifact, as a JSON document")
    ap.add_argument("--locator", required=True, help="what it is, e.g. attestation:<id>")
    ap.add_argument("--kind", default="human_artifact", choices=list(ComplianceEvidenceKind))
    args = ap.parse_args(argv)

    def call() -> str:
        added = (
            load(args.config_home)
            .services()
            .compliance.add_evidence(
                ComplianceEvidenceKind(args.kind), args.locator, _load(args.artifact)
            )
        )
        return added.model_dump_json(indent=2, exclude_none=True)

    return run(call)


def _assessment(path: Path) -> ComplianceAssessmentArtifact:
    return ComplianceAssessmentArtifact.parse(path.read_bytes())


def check(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "check", "The citation gate over an assessment.")
    ap.add_argument("assessment", type=Path)
    args = ap.parse_args(argv)
    found: dict = {}

    def call() -> None:
        report = load(args.config_home).services().compliance.check(_assessment(args.assessment))
        found["violations"] = [v.model_dump(mode="json") for v in report.violations]

    return run(call) or _answer(found, not found["violations"])


def record(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "record", "Record a gated assessment against its commits.")
    ap.add_argument("assessment", type=Path)
    args = ap.parse_args(argv)

    def call() -> str:
        services = load(args.config_home).services()
        recorded = services.compliance.record(_assessment(args.assessment), _doors.interactive())
        return recorded.model_dump_json(indent=2)

    return run(call)


def latest(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "latest", "A boundary's newest recorded assessment of a framework.")
    ap.add_argument("boundary", help="the boundary name or its scope id")
    ap.add_argument("--framework", required=True)
    args = ap.parse_args(argv)

    def call() -> dict | None:
        services = load(args.config_home).services()
        scope = current(services, args.boundary)
        assert scope.scope_id is not None
        found = services.compliance.latest(scope.scope_id, ComplianceFramework(args.framework))
        if found is None:
            return None
        return {
            "assessment": found.model_dump(mode="json"),
            "posture": found.posture().model_dump(mode="json"),
        }

    return run(call)


def adrs(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "adrs", "The decisions of the registers governing a product.")
    ap.add_argument("product", help="the product slug")
    args = ap.parse_args(argv)

    def call() -> list:
        services = load(args.config_home).services()
        (product,) = _doors.products(services, [args.product])
        return [a.model_dump(mode="json") for a in services.compliance.adrs(product.id)]

    return run(call)


def docs(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "docs", "Fetch official documentation for a registered product.")
    ap.add_argument("product", help="the registered product slug")
    ap.add_argument("--product-slug", help="the official docs.redhat.com product slug")
    ap.add_argument("--version", help="the official documentation version")
    guides = ap.add_mutually_exclusive_group()
    guides.add_argument("--guide", action="append", help="an official guide slug (repeatable)")
    guides.add_argument(
        "--all-guides", action="store_true", help="discover guides on the product page"
    )
    args = ap.parse_args(argv)

    def call() -> list:
        core = load(args.config_home)
        services = core.services()
        (product,) = _doors.products(services, [args.product])
        explicit = args.product_slug or args.version or args.guide or args.all_guides
        if explicit:
            if not args.product_slug or not args.version:
                raise ValidationError(
                    "explicit documentation targets require --product-slug and --version"
                )
            core.register_compliance_sources(
                {product.id: DocsTarget(args.product_slug, args.version, tuple(args.guide or ()))}
            )
            services = core.services()
        return [
            guide.model_dump(mode="json")
            for guide in services.compliance.collect_product_docs(product.id)
        ]

    return run(call)


def calibrate(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "calibrate", "Evaluate twice; score on an answer key if given.")
    _evaluation_args(ap)
    ap.add_argument("--key", type=Path, help="a seeded target's answer key (JSON)")
    args = ap.parse_args(argv)
    found: dict = {}

    def call() -> None:
        services = load(args.config_home).services()
        key = args.key and _load(args.key, EfficacyKey.model_validate)
        result = services.compliance.calibrate(_request(services, args), key)
        found.update(result.model_dump(mode="json"), passed=result.passed)

    return run(call) or _answer(found, found["passed"])
