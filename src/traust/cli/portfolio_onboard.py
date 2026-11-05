"""``traust portfolio plan|onboard|owner-hints|file|import-owners|import-release``: add-inputs' and
inventory-repositories' doors on traust-core (onboarding and portfolio sync).

plan           what onboard would register and order, writing nothing (the dry run)
onboard        register the product (when --label names a new one), the repositories and an
               organisation's non-archived, non-fork repositories; re-runs are no-ops
owner-hints    OWNERS / CODEOWNERS approvers, then top contributors: hints, never stored
file           one file's text at a pinned commit, read at the forge: untrusted, never stored
import-owners  mirror the declared ownership source onto every registered repository
import-release a product version and the commits it ships (a payload's commit URLs)
inventory-export every registered repository with its owning teams, products and contacts
release-changes a recorded version against the highest one recorded before it (or --previous):
               its bump, whether it re-models the threat surface (major/minor), the commits moved
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pydantic
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import (
    OrgName,
    OwnerAssignment,
    OwnershipSource,
    RefName,
    ReleaseCommit,
    RepositoryFilter,
    TeamName,
    VersionLabel,
)
from traust_core.v1.models.onboarding import OnboardingRequest, RepositorySpec
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, ProductSlug, RepoPath

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.context import load, load_caller


def _json(value: Any) -> Any:
    """A model as JSON values, repository URLs as their https string."""
    if isinstance(value, HttpsRepoUrl):
        return str(value)
    if isinstance(value, pydantic.BaseModel):
        return {name: _json(getattr(value, name)) for name in type(value).model_fields}
    if isinstance(value, tuple | list):
        return [_json(v) for v in value]
    return value


def _request_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--product", required=True, help="the product slug the repositories join")
    ap.add_argument("--label", help="the display name, to register a product not registered yet")
    ap.add_argument(
        "--repo", action="append", default=[], help="an https repository URL (repeatable)"
    )
    ap.add_argument("--org", help="a GitHub organisation or GitLab group to list")
    ap.add_argument("--host", default="github.com", help="the forge host --org lists on")


def _url(core: Context, raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw, core.config.forge_hosts)


def _request(core: Context, args: argparse.Namespace) -> OnboardingRequest:
    if not (args.repo or args.org):
        raise ValidationError("name something to add: --repo or --org")
    return OnboardingRequest(
        product=ProductSlug.parse(args.product),
        label=args.label,
        repositories=tuple(RepositorySpec(url=_url(core, r)) for r in args.repo),
        org=None if args.org is None else OrgName(args.org),
        host=args.host,
    )


def plan(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "plan", "What onboard would register, writing nothing.")
    _request_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        return _json(core.services().onboarding.plan(_request(core, args)))

    return run(call)


def onboard(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "onboard", "Register a product's repositories in the inventory.")
    _request_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        request = _request(core, args)
        return _json(core.services().onboarding.onboard(request, load_caller(core)))

    return run(call)


def owner_hints(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "owner-hints", "Who may own a repository, from its forge.")
    ap.add_argument("--repo", required=True, help="an https repository URL")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        return [_json(h) for h in core.services().sync.owner_hints(_url(core, args.repo))]

    return run(call)


def file(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "file", "One file's text at a pinned commit, from its forge.")
    ap.add_argument("--repo", required=True, help="an https repository URL")
    ap.add_argument("--sha", required=True, help="the full commit sha to read at")
    ap.add_argument("path", help="the file's path inside the repository")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        url, sha, path = _url(core, args.repo), GitSha.parse(args.sha), RepoPath.parse(args.path)
        text = core.services().sync.find_file(url, path, sha)
        return {"repo": str(url), "sha": str(sha), "path": str(path), "file": text}

    return run(call)


class _Assignment(Model):
    repo: str
    teams: tuple[str, ...]


class _SourceFile(Dto):
    """Other keys are ignored, so the inventory descriptor's `org_teams:` serves as a source."""

    assignments: tuple[_Assignment, ...] = ()
    org_teams: dict[str, str] = pydantic.Field(default_factory=dict)


def _source(core: Context, path: Path) -> OwnershipSource:
    try:
        doc = _SourceFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    except (yaml.YAMLError, pydantic.ValidationError) as e:
        raise ValidationError(f"{path}: not an ownership source: {e}") from e
    return OwnershipSource(
        assignments=tuple(
            OwnerAssignment(repo=_url(core, a.repo), teams=tuple(TeamName(t) for t in a.teams))
            for a in doc.assignments
        ),
        org_teams={OrgName(o): TeamName(t) for o, t in doc.org_teams.items()},
    )


def import_owners(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "import-owners", "Mirror the declared ownership source.")
    ap.add_argument(
        "--source",
        type=Path,
        required=True,
        help="YAML with assignments: [{repo, teams}] and/or org_teams: {org: team}",
    )
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        return _json(core.services().sync.import_owners(_source(core, args.source)))

    return run(call)


_COMMIT_URL = re.compile(r"(?P<repo>https://\S+?)(?:/-)?/commit/(?P<sha>[0-9a-f]{40})/?")


def _commits(core: Context, path: Path, branch: str | None) -> list[ReleaseCommit]:
    """One commit per non-blank line whose last field is a commit URL (`oc adm release info
    --commit-urls`: `<image> <commit URL>`)."""
    commits = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        found = _COMMIT_URL.fullmatch(line.split()[-1])
        if found is None:
            raise ValidationError(f"{path}:{n}: not a commit URL: {line.strip()!r}")
        commits.append(
            ReleaseCommit(
                url=_url(core, found["repo"]),
                sha=GitSha.parse(found["sha"]),
                branch=None if branch is None else RefName(branch),
            )
        )
    return commits


def import_release(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "import-release", "Record a product version and its commits.")
    ap.add_argument("--product", required=True, help="the product slug")
    ap.add_argument("--version", required=True, help="the release version, e.g. 4.21.3")
    ap.add_argument("--commits", type=Path, required=True, help="lines of `<image> <commit URL>`")
    ap.add_argument("--branch", help="the branch every commit was built from (release-4.21)")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        services = core.services()
        commits = _commits(core, args.commits, args.branch)
        [product] = _doors.products(services, [args.product])
        release = services.portfolio.import_release(product.id, VersionLabel(args.version), commits)
        return release.model_dump(mode="json")

    return run(call)


def release_changes(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "release-changes", "What a recorded product version changed.")
    ap.add_argument("--product", required=True, help="the product slug")
    ap.add_argument("--version", required=True, help="the recorded release version, e.g. 4.21.0")
    ap.add_argument("--previous", help="compare with this version (default: the high-water mark)")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load(args.config_home).services()
        [product] = _doors.products(services, [args.product])

        def release(version: str) -> Any:
            found = services.portfolio.find_release(product.id, VersionLabel(version))
            if found is None:
                raise NotFoundError(f"{args.product} {version} is not a recorded release")
            return found.id

        previous = None if args.previous is None else release(args.previous)
        change = services.portfolio.release_changes(release(args.version), previous)
        return {**change.model_dump(mode="json"), "remodels": change.remodels()}

    return run(call)


INVENTORY_COLUMNS = (
    "Repository",
    "URL",
    "Host",
    "Organization/Group",
    "Repo Name",
    "Owner Team",
    "Products",
    "Accountable Contacts",
)


def inventory_export(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "inventory-export", "Joined inventory, owners and contacts.")
    ap.add_argument(
        "--pd-cache-dir",
        type=Path,
        help="product-definitions snapshot for contacts (default: locations.feeds_cache)",
    )
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        rows = _inventory_rows(core, args.pd_cache_dir)
        return [dict(zip(INVENTORY_COLUMNS, row, strict=True)) for row in rows]

    return run(call)


def _inventory_rows(core: Context, cache_dir: Path | None) -> list[tuple[object, ...]]:
    """Every registered repository with its current owning teams, the products shipping it and
    the product-definitions contacts for its URL: composed from the portfolio's own lists."""
    portfolio = core.services().portfolio
    repositories = list(
        every_item(lambda page: portfolio.list_repositories(RepositoryFilter(), page))
    )
    resolution = portfolio.resolve_products(
        core.product_definitions(cache_dir).read(),
        portfolio.product_mappings(),
        repo_urls=[repo.url for repo in repositories],
    )
    contacts = {
        match.query.value: [
            f"{c.kerberos_id} ({c.field}; embargo_cleared={c.embargo_cleared})"
            for c in match.contacts
        ]
        for match in resolution.results
        if match.query is not None
    }
    rows = []
    # NEED(core: bulk owners/products for inventory export): PortfolioService at the pinned core
    # answers owners (`list_owners`) and shipping products (`list_products_of`) one repository at
    # a time, with no list or by-ids variant, so this export makes two store queries per
    # repository until core has one.
    for repo in repositories:
        assert repo.id is not None
        parts = urlsplit(repo.url)
        organization, _, name = parts.path.strip("/").rpartition("/")
        rows.append(
            (
                f"{organization}/{name}" if organization else name,
                repo.url,
                parts.hostname or "",
                organization,
                name,
                [team.name for team in portfolio.list_owners(repo.id)],
                [str(product.slug) for product in portfolio.list_products_of(repo.id)],
                contacts.get(repo.url, []),
            )
        )
    return rows
