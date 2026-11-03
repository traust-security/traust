from __future__ import annotations

import argparse
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Services
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import ToolRequest, every_item
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli._doors import interactive, parser, run
from traust.context import load


def _parser(operation: str, about: str) -> argparse.ArgumentParser:
    ap = parser("portfolio", operation, about)
    ap.add_argument(
        "--repository-ref-id",
        type=UUID,
        action="append",
        default=[],
        help="registered commit; repeat for a fleet (default: observed default heads)",
    )
    return ap


def _refs(services: Services, explicit: list[UUID]) -> list[UUID]:
    return explicit or services.code_facts.fleet_refs()


def collect(argv: list[str] | None = None) -> int:
    ap = _parser("facts-collect", "Persist fleet package and Kubernetes interface facts.")
    ap.add_argument(
        "--checkout",
        action="append",
        default=[],
        metavar="REF_ID=PATH",
        help="use an already materialized checkout for this ref; otherwise use the Core cache",
    )
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        refs = _refs(services, args.repository_ref_id)
        checkouts = {}
        for value in args.checkout:
            ref, sep, path = value.partition("=")
            try:
                ref_id = UUID(ref)
            except ValueError as exc:
                raise ValidationError(f"checkout must be REF_ID=PATH: {value}") from exc
            if not sep or not path or ref_id not in refs or ref_id in checkouts:
                raise ValidationError(f"checkout must name one selected ref exactly once: {value}")
            checkouts[ref_id] = ToolRequest(workspace=Path(path))
        return [
            result.model_dump(mode="json")
            for result in services.code_facts.collect_fleet(
                refs, interactive(), checkouts=checkouts
            )
        ]

    return run(call)


def crd_consumers(argv: list[str] | None = None) -> int:
    ap = _parser("crd-consumers", "Fleet CRD owners, consumers, RBAC grants and webhooks.")
    ap.add_argument("api_group")
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        return [
            row.model_dump(mode="json")
            for row in services.code_facts.crd_consumers(
                _refs(services, args.repository_ref_id), args.api_group
            )
        ]

    return run(call)


def _packages(operation: str, argv: list[str] | None) -> int:
    ap = _parser(operation, "Query persisted fleet module, package-import and export facts.")
    ap.add_argument("package", nargs="?" if operation == "exports-of" else None)
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        query = {
            "imports-package": services.code_facts.imports_package,
            "exports-of": services.code_facts.exports_of,
        }[operation]
        return [
            row.model_dump(mode="json")
            for row in query(_refs(services, args.repository_ref_id), args.package)
        ]

    return run(call)


def imports_package(argv: list[str] | None = None) -> int:
    return _packages("imports-package", argv)


def exports_of(argv: list[str] | None = None) -> int:
    return _packages("exports-of", argv)


def ships_module(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "ships-module", "Images whose persisted SBOM ships a package.")
    ap.add_argument("package")
    ap.add_argument("--ecosystem", choices=[e.value for e in Ecosystem], default="go")
    ap.add_argument("--version")
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        return [
            row.model_dump(mode="json")
            for row in services.exposure.ships_module(
                Ecosystem(args.ecosystem), args.package, args.version
            )
        ]

    return run(call)


def internal_coupling(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "internal-coupling", "Rank portfolio-produced package fan-in.")
    ap.add_argument("--repository-id", type=UUID, action="append", default=[])
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        repositories = args.repository_id or [
            repo.id
            for repo in every_item(
                lambda page: services.portfolio.list_repositories(RepositoryFilter(), page)
            )
            if repo.id is not None
        ]
        return [
            row.model_dump(mode="json") for row in services.exposure.internal_coupling(repositories)
        ]

    return run(call)
