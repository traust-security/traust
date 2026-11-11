"""``traust portfolio dependencies|dependents``: portfolio-graph's dependency reads on traust-core.

dependencies  the packages in a commit's manifest SBOM (record it with ``traust impact sbom``)
dependents    the commits a package (by id, or ecosystem + name) reaches: directly, through a base
              image or an internal library
"""

from __future__ import annotations

import uuid
from typing import Any

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli._doors import package_id as find_package_id
from traust.cli._doors import parser, run
from traust.context import load


def dependencies(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "dependencies", "The packages in a commit's manifest SBOM.")
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the commit")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.find_repository(url)
        if repo is None or repo.id is None:
            raise NotFoundError(f"{url} is not a registered repository")
        ref = services.portfolio.inventory.find_ref(repo.id, args.sha)
        return [
            {
                "package_id": str(d.package.id),
                "ecosystem": d.package.ecosystem,
                "name": d.package.name,
                "version": d.dependency.version,
                "direct": d.dependency.direct,
            }
            for d in services.exposure.dependencies(ref.id)
        ]

    return run(call)


def dependents(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "dependents", "The commits a package reaches (its blast radius).")
    package = ap.add_mutually_exclusive_group(required=True)
    package.add_argument(
        "--package-id", type=uuid.UUID, help="from `traust portfolio dependencies`"
    )
    package.add_argument("--name", help="the package name, e.g. golang.org/x/net")
    ap.add_argument("--ecosystem", choices=[e.value for e in Ecosystem], default="go")
    ap.add_argument("--version", help="start only from SBOMs holding this version")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load(args.config_home).services()
        package_id = args.package_id or find_package_id(services, args.ecosystem, args.name)
        narrowed = () if args.version is None else (args.version,)
        out = []
        for ref_id in services.exposure.dependents(package_id, *narrowed):
            ref, repo = services.portfolio.inventory.resolve(ref_id)
            out.append({"repository_ref_id": str(ref_id), "repository": repo.url, "sha": ref.sha})
        return out

    return run(call)
