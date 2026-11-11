"""``traust tools list|run``: one door over traust-core's tool registry.

list  every registered tool: readiness, version and database (core's ProviderCatalog)
run   one registered tool over one target (a checkout, an SBOM, an image or symbols in a
      checkout), printing its typed result and provenance as JSON; exit 2 on a refusal
"""

from __future__ import annotations

from pathlib import Path

from pydantic_core import to_jsonable_python
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.common import SymbolQuery, ToolRequest

from traust.cli._doors import parser, run
from traust.context import load

TOOL = "tool"  # core's CapabilityKind.TOOL (a StrEnum; its module is core-internal to traust)


def list_(argv: list[str] | None = None) -> int:
    """Print every registered tool with its readiness, version and database."""
    ap = parser("tools", "list", "Every registered tool: readiness, version and database.")
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        catalog = load(args.config_home).services().catalog
        databases = {db.tool: db.model_dump(mode="json") for db in catalog.databases()}
        return [
            {
                "tool": b.capability.name,
                "ready": b.readiness.ready,
                "detail": b.readiness.detail,
                "version": b.version,
                "database": databases.get(b.capability.name),
            }
            for b in catalog.readiness(None, network=False)
            if b.capability.kind == TOOL
        ]

    return run(call)


def run_(argv: list[str] | None = None) -> int:
    """Run one registered tool over one target and print its result as JSON."""
    ap = parser("tools", "run", "Run one registered tool over one target; print its result.")
    ap.add_argument("name", help="the registered tool (see `traust tools list`)")
    ap.add_argument("--workspace", type=Path, help="a checkout; with --symbols, the one searched")
    ap.add_argument("--sbom", type=Path, help="an SBOM file")
    ap.add_argument("--image", help="an image reference")
    ap.add_argument("--symbols", nargs="+", metavar="NAME", help="symbols to look for")
    ap.add_argument(
        "--param", action="append", default=[], metavar="KEY=VALUE", help="a tool param"
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        request = _request(args)
        tool = load(args.config_home).tools.get(args.name)
        if not (readiness := tool.check()).ready:
            raise ConfigError(f"tool {args.name} not ready: {readiness.detail}")
        result = tool.acquire(request)
        return {
            "tool": args.name,
            "acquisition": result.acquisition.model_dump(mode="json"),
            "data": to_jsonable_python(result.data),
        }

    return run(call)


def _request(args) -> ToolRequest:
    """The request the flags name; ValidationError on a malformed param or target."""
    params: dict[str, str] = {}
    for raw in args.param:
        key, sep, value = raw.partition("=")
        if not sep or not key:
            raise ValidationError(f"--param takes KEY=VALUE, got {raw!r}")
        if key in params:
            raise ValidationError(f"--param {key} given twice")
        params[key] = value
    if not args.symbols:
        return ToolRequest(
            workspace=args.workspace, sbom=args.sbom, image=args.image, params=params
        )
    if args.workspace is None:
        raise ValidationError("--symbols needs --workspace, the checkout to search")
    query = SymbolQuery(workspace=args.workspace, names=tuple(args.symbols))
    return ToolRequest(symbols=query, sbom=args.sbom, image=args.image, params=params)
