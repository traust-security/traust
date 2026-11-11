"""``traust adapters crypto-source|crypto-image|crypto-cluster``: crypto-analysis doors on core.

crypto-source   a commit's crypto census: what its checkout configures, then its manifest SBOM's
                crypto packages
crypto-image    an image's crypto census: what it ships, then its SBOM's crypto packages; the
                image is pulled by digest and never run
crypto-cluster  a cluster's runtime crypto census over `oc exec`, every namespace gated by the
                engagement's targets.yaml first
"""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

import pydantic
import yaml
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import ClusterRequest, ImageRequest
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.dependencies import NoImageSbomError, NoManifestSbomError
from traust_core.v1.models.validation import (
    ClusterScope,
    OffLimit,
    ScopeBindingMode,
    ValidationScope,
)
from traust_core.v1.models.values import HttpsRepoUrl

from traust.cli._doors import add_branch_arg, parser, register_commit, run
from traust.context import load


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    ap = parser("adapters", op, about)
    ap.add_argument("--out", type=Path, help="write the census JSON here (default: stdout)")
    return ap


def _emit(census: dict, out: Path | None) -> dict:
    if out is None:
        return census
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(census, indent=2, default=str) + "\n", encoding="utf-8")
    return {"wrote": str(out), "facts": len(census["facts"]), "gaps": len(census.get("gaps", ()))}


def source(argv: list[str] | None = None) -> int:
    ap = _parser("crypto-source", "A commit's crypto census: checkout config and SBOM packages.")
    ap.add_argument("checkout", type=Path, help="the commit's checkout (read-only)")
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the checked-out commit")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    add_branch_arg(ap)
    ap.add_argument(
        "--sbom", type=Path, help="the commit's manifest SBOM (syft dir:<checkout>), recorded first"
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        assert ref.id is not None
        if args.sbom is not None:
            services.exposure.ingest_sbom(args.sbom.read_bytes(), ref.id)
        try:
            facts = services.code_facts.crypto(ref.id, ToolRequest(workspace=args.checkout))
        except NoManifestSbomError as e:
            raise ValidationError(
                f"commit {args.sha} has no manifest SBOM recorded: run "
                f"`syft dir:{args.checkout} -o cyclonedx-json` and pass it as --sbom"
            ) from e
        census = {
            "repository_ref_id": str(ref.id),
            "facts": [f.model_dump(mode="json", exclude_none=True) for f in facts],
        }
        return _emit(census, args.out)

    return run(call)


def image(argv: list[str] | None = None) -> int:
    ap = _parser("crypto-image", "An image's crypto census: what it ships and its SBOM packages.")
    ap.add_argument("image", help="the image pinned by digest: <name>@sha256:<hex>")
    ap.add_argument("--no-pull", action="store_true", help="use only the local image store")
    ap.add_argument("--sbom", type=Path, help="the image's SBOM (syft <image>), recorded first")
    args = ap.parse_args(argv)
    name, _, digest = args.image.rpartition("@")
    if not name or not digest.startswith("sha256:"):
        ap.error("pin the image by digest: <name>@sha256:<hex>")

    def call() -> dict:
        services = load(args.config_home).services()
        if args.sbom is not None:
            services.exposure.ingest_image_sbom(args.sbom.read_bytes(), digest)
        try:
            census = services.code_facts.image_crypto(
                digest, ImageRequest(name=name, pull=not args.no_pull)
            )
        except NoImageSbomError as e:
            raise ValidationError(
                f"image {digest} has no SBOM recorded: run "
                f"`syft {args.image} -o cyclonedx-json` and pass it as --sbom"
            ) from e
        return _emit(census.model_dump(mode="json", exclude_none=True), args.out)

    return run(call)


def engagement_scope(path: Path) -> ValidationScope:
    """A mode-1 targets.yaml as the scope its k8s actions are gated by (expiry, clusters,
    off-limits, images); legacy validate-findings `Scope.from_targets_file`."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return _scope(data)
    except (yaml.YAMLError, KeyError, TypeError, ValueError, pydantic.ValidationError) as e:
        raise ValidationError(f"targets {path}: {e}") from e


def _scope(data: dict) -> ValidationScope:
    expires = data.get("expires")
    return ValidationScope(
        expires=date.fromisoformat(str(expires)) if expires else None,
        modes=frozenset({ScopeBindingMode.EXPLICIT}),
        clusters=tuple(
            ClusterScope(
                context=c["context"],
                namespaces=tuple(str(n) for n in c.get("namespaces", [])),
                verbs_denied=frozenset(str(v) for v in c.get("verbs_denied", [])),
                explicit_namespaces=frozenset(str(n) for n in c.get("namespaces", [])),
            )
            for c in data.get("clusters", [])
        ),
        off_limits=tuple(OffLimit(**rule) for rule in data.get("off_limits", [])),
        images=tuple(data.get("images", [])),
    )


def cluster(argv: list[str] | None = None) -> int:
    ap = _parser("crypto-cluster", "A cluster's runtime crypto census, scope-gated per namespace.")
    ap.add_argument("--context", required=True, help="kubeconfig context")
    ap.add_argument("--namespaces", nargs="+", required=True, help="namespaces to probe")
    ap.add_argument("--targets", type=Path, required=True, help="mode-1 targets.yaml")
    ap.add_argument("--discover", action="store_true", help="probe every service port for TLS")
    ap.add_argument("--groups", help="TLS groups to offer, e.g. X25519MLKEM768:X25519")
    args = ap.parse_args(argv)

    try:
        request = ClusterRequest(
            context=args.context,
            namespaces=tuple(args.namespaces),
            discover=args.discover,
            groups=args.groups,
        )
    except pydantic.ValidationError as e:
        ap.error(str(e))

    def call() -> dict:
        census = (
            load(args.config_home)
            .services()
            .code_facts.cluster_crypto(request, engagement_scope(args.targets))
        )
        return _emit(census.model_dump(mode="json", exclude_none=True), args.out)

    return run(call)
