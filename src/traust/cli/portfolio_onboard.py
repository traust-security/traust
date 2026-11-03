"""``traust portfolio plan|onboard|owner-hints|file|import-owners|import-release``: add-inputs' and
inventory-repositories' doors on traust-core (onboarding and portfolio sync).

plan           what onboard would register and order, writing nothing (the dry run)
onboard        register the product (when --label names a new one), the repositories and an
               organisation's non-archived, non-fork repositories; re-runs are no-ops
owner-hints    OWNERS / CODEOWNERS approvers, then top contributors; --save retains the hints
file           one file's text at a pinned commit, read at the forge: untrusted, never stored
import-owners  mirror the declared ownership source onto every registered repository
import-release a product version and the commits it ships (a payload's commit URLs)
release-changes a recorded version against the highest one recorded before it (or --previous):
               its bump, whether it re-models the threat surface (major/minor), the commits moved
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import pydantic
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.inventory import (
    OrgName,
    OwnerAssignment,
    OwnershipSource,
    RefName,
    ReleaseCommit,
    TeamName,
    VersionLabel,
)
from traust_core.v1.models.inventory_reference import (
    IntakeKind,
    InventoryDeclaration,
    InventoryReference,
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
    ap.add_argument("--reference", type=Path, help="declared inventory YAML with repositories")
    ap.add_argument("--sub-service", help="declared service label; org intake defaults to org")
    ap.add_argument("--individual-owner", action="append", default=None)
    ap.add_argument("--payload-version", action="append", default=None)
    ap.add_argument("--operator-version", action="append", default=None)
    for field in (
        "ownership-source",
        "manager",
        "business-unit",
        "jira-project",
        "jira-component",
        "escalation-contact",
    ):
        ap.add_argument(f"--{field}")


def _url(core: Context, raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw, core.config.forge_hosts)


def _request(core: Context, args: argparse.Namespace) -> OnboardingRequest:
    supplied = InventoryReference()
    if args.reference is not None:
        try:
            supplied = InventoryReference.model_validate(
                yaml.safe_load(args.reference.read_text(encoding="utf-8"))
            )
            if supplied.version != 1:
                raise ValidationError(f"unsupported inventory reference version {supplied.version}")
        except (yaml.YAMLError, pydantic.ValidationError) as e:
            raise ValidationError(f"{args.reference}: not an inventory reference: {e}") from e
    if not (args.repo or args.org or supplied.repositories):
        raise ValidationError("name something to add: --repo or --org (or --reference)")
    values = {
        field: getattr(args, field)
        for field in (
            "ownership_source",
            "manager",
            "business_unit",
            "jira_project",
            "jira_component",
            "escalation_contact",
        )
        if getattr(args, field) is not None
    }
    if args.sub_service is not None:
        values["service"] = args.sub_service
    if args.individual_owner is not None:
        values["individual_owners"] = tuple(args.individual_owner)
    if args.payload_version is not None:
        values["payload_versions"] = tuple(args.payload_version)
    if args.operator_version is not None:
        values["operator_versions"] = tuple(args.operator_version)
    declaration = InventoryDeclaration(resource_type=IntakeKind.ADHOC, **values)
    specs = {
        str(_url(core, row.repo_url)): RepositorySpec(
            url=_url(core, row.repo_url),
            declaration=InventoryDeclaration(
                **row.model_dump(exclude={"repo_url"}, exclude_unset=True)
            ),
        )
        for row in supplied.repositories
    }
    for raw in args.repo:
        url = _url(core, raw)
        specs.setdefault(str(url), RepositorySpec(url=url))
    return OnboardingRequest(
        product=ProductSlug.parse(args.product),
        label=args.label,
        repositories=tuple(specs.values()),
        declaration=declaration,
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
    ap.add_argument("--save", action="store_true", help="retain hints and provenance in reference")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load(args.config_home)
        url = _url(core, args.repo)
        services = core.services()
        hints = (
            services.sync.owner_hints(url, retain=True)
            if args.save
            else services.sync.owner_hints(url)
        )
        return [_json(hint) for hint in hints]

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


def inventory_export(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "inventory-export", "Joined inventory, contacts and tracker routing.")
    ap.add_argument("--format", choices=("json", "csv"), default="json")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load(args.config_home).services()
        rows = services.portfolio.inventory_export()
        if args.format == "json":
            return [_json(row) for row in rows]
        columns = (
            "Repository",
            "URL",
            "Host",
            "Organization/Group",
            "Repo Name",
            "App/Sub-Service",
            "Resource Type",
            "Owner Team",
            "Manager",
            "Individual Owners",
            "Ownership Source",
            "Business Unit",
            "Jira Project",
            "Jira Component",
            "Payload Versions",
            "Operator Versions",
            "Recorded Product Versions",
            "Escalation Contact",
            "Accountable Contacts",
        )
        values = []
        for row in rows:
            declaration = row.declaration
            values.append(
                (
                    row.repository,
                    row.url,
                    row.host,
                    row.organization,
                    row.repo_name,
                    declaration.service or "",
                    declaration.resource_type or "",
                    "; ".join(row.owner_teams),
                    declaration.manager or "",
                    "; ".join(row.individual_owners),
                    row.ownership_source or "",
                    "; ".join(row.business_units),
                    declaration.jira_project or "",
                    declaration.jira_component or "",
                    "; ".join(declaration.payload_versions),
                    "; ".join(declaration.operator_versions),
                    "; ".join(row.versions),
                    declaration.escalation_contact or "",
                    "; ".join(
                        f"{contact.kerberos_id} ({contact.field}; "
                        f"embargo_cleared={contact.embargo_cleared})"
                        for contact in row.accountable_contacts
                    ),
                )
            )
        return services.reporting.export_csv(columns, values).rstrip("\r\n")

    return run(call)


def import_reference(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "import-reference", "Retain adopter-declared inventory metadata.")
    ap.add_argument("--source", type=Path, required=True)
    args = ap.parse_args(argv)

    def call() -> Any:
        try:
            reference = InventoryReference.model_validate(
                yaml.safe_load(args.source.read_text(encoding="utf-8"))
            )
        except (yaml.YAMLError, pydantic.ValidationError) as e:
            raise ValidationError(f"{args.source}: not an inventory reference: {e}") from e
        if reference.version != 1:
            raise ValidationError(f"unsupported inventory reference version {reference.version}")
        portfolio = load(args.config_home).services().portfolio
        portfolio.declare_inventory(reference.repositories)
        return [_json(row) for row in portfolio.inventory_declarations()]

    return run(call)
