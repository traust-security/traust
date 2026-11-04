"""``traust portfolio ships-module``: the images whose recorded SBOMs ship a package.

Exposure's ``find_package`` names the recorded package; ``image_dependents`` walks the images
that ship it, directly or through a base image or internal library.
"""

from __future__ import annotations

from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli._doors import package_id, parser, run
from traust.context import load


def ships_module(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "ships-module", "Images whose persisted SBOM ships a package.")
    ap.add_argument("package")
    ap.add_argument("--ecosystem", choices=[e.value for e in Ecosystem], default="go")
    ap.add_argument("--version")
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        services = load(args.config_home).services()
        package = package_id(services, args.ecosystem, args.package)
        return [
            row.model_dump(mode="json")
            for row in services.exposure.image_dependents(package, args.version)
        ]

    return run(call)
