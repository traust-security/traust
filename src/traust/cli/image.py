"""``traust adapters image-sbom|image-packages``: secure-container-audit's image doors on core.

image-sbom      record an image's SBOM (syft's CycloneDX) on the image's row, keyed by digest
image-packages  the packages that SBOM holds, counted per ecosystem; the image is never run
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from traust_core.v1.models.values import HttpsRepoUrl

from traust.cli._doors import add_branch_arg, parser, register_commit, run
from traust.context import load


def _digest(ap: argparse.ArgumentParser, image: str) -> str:
    digest = image.rpartition("@")[2]
    if not digest.startswith("sha256:"):
        ap.error("pin the image by digest: [<name>@]sha256:<hex>")
    return digest


def sbom(argv: list[str] | None = None) -> int:
    ap = parser("adapters", "image-sbom", "Record an image's SBOM on its row, keyed by digest.")
    ap.add_argument("image", help="the image pinned by digest: <name>@sha256:<hex>")
    ap.add_argument("--sbom", type=Path, required=True, help="syft's CycloneDX JSON of the image")
    ap.add_argument("--platform", help="the audited platform, e.g. linux/amd64")
    ap.add_argument("--repo-url", help="declared source (vcs-url label); with --sha")
    ap.add_argument("--sha", help="declared source commit (vcs-ref label); with --repo-url")
    ap.add_argument("--public", action="store_true", help="the declared source is public")
    add_branch_arg(ap)
    args = ap.parse_args(argv)
    digest = _digest(ap, args.image)
    if (args.repo_url is None) != (args.sha is None):
        ap.error("--repo-url and --sha go together (the image's declared source)")
    if args.branch and args.sha is None:
        ap.error("--branch names the declared source's branch: give --repo-url and --sha")

    def call() -> dict:
        core = load(args.config_home)
        services = core.services()
        ref_id = None
        if args.repo_url is not None:
            url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
            repo = services.portfolio.register_repository(url, args.public)
            ref_id = register_commit(services, repo.id, args.sha, args.branch).id
        image = services.exposure.ingest_image_sbom(
            args.sbom.read_bytes(), digest, args.platform, ref_id
        )
        return image.model_dump(mode="json", exclude_none=True)

    return run(call)


def packages(argv: list[str] | None = None) -> int:
    ap = parser("adapters", "image-packages", "The packages an image's recorded SBOM holds.")
    ap.add_argument("image", help="the image pinned by digest: [<name>@]sha256:<hex>")
    ap.add_argument("--list", action="store_true", help="also list every package")
    args = ap.parse_args(argv)
    digest = _digest(ap, args.image)

    def call() -> dict:
        rows = load(args.config_home).services().exposure.image_dependencies(digest)
        out: dict = {
            "digest": digest,
            "total": len(rows),
            "by_ecosystem": dict(Counter(r.package.ecosystem for r in rows).most_common()),
        }
        if args.list:
            out["packages"] = [
                {
                    "ecosystem": r.package.ecosystem,
                    "name": r.package.name,
                    "version": r.dependency.version,
                }
                for r in rows
            ]
        return out

    return run(call)
