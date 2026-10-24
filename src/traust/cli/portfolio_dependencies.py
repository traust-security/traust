"""``traust portfolio dependencies|dependents``: portfolio-graph's dependency reads on traust-core.

dependencies  the packages in a commit's manifest SBOM (record it with ``traust impact sbom``)
dependents    the commits a package reaches: directly, through a base image or an internal library
"""

from __future__ import annotations

import uuid
from typing import Any

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.values import HttpsRepoUrl

from traust.cli._doors import parser, run
from traust.context import load_core


def dependencies(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "dependencies", "The packages in a commit's manifest SBOM.")
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the commit")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
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
    ap.add_argument(
        "--package-id", required=True, type=uuid.UUID, help="from `traust portfolio dependencies`"
    )
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load_core(args.config_home).services()
        out = []
        for ref_id in services.exposure.dependents(args.package_id):
            ref, repo = services.portfolio.inventory.resolve(ref_id)
            out.append({"repository_ref_id": str(ref_id), "repository": repo.url, "sha": ref.sha})
        return out

    return run(call)
