"""``traust registry …`` — model registry and product catalog."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.operations import ModelName, SpendEvent, TokenUsage

from traust.cli import _doors
from traust.cli.groups._registry import OpSpec
from traust.context import MODEL_REGISTRY, load, load_spend_core

NO_MAP = "no product map recorded; record one with `traust registry product-map <file>`"
# NEED(data-model: spend calibration tuple repo/loc/batch/note)
UNSTORED = "not stored: spend_event has no column for it"


def add_models_args(ap) -> None:
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    p = sub.add_parser("resolve")
    p.add_argument("role")
    p.add_argument("--tier", default=None)
    p = sub.add_parser("stamp")
    p.add_argument("role")
    p.add_argument("model")
    p = sub.add_parser("spend")
    p.add_argument("--skill", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--tokens-in", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--tokens-out", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--cache-read", type=int, default=0)
    p.add_argument("--cache-creation", type=int, default=0)
    p.add_argument("--batch", default=None, help=f"batch id ({UNSTORED})")
    p.add_argument(
        "--repo", default=None, help=f"repo slug this spend audited, calibration tuple ({UNSTORED})"
    )
    p.add_argument(
        "--loc", type=int, default=None, help=f"target size in LoC/bytes at audit time ({UNSTORED})"
    )
    p.add_argument("--note", default=None, help=f"free text ({UNSTORED})")


def call_models(args) -> int:
    if args.cmd == "spend":
        return _declare_spend(args)
    catalog = load_spend_core(args.config_home).model_catalog
    if args.cmd == "validate":
        errors = catalog.validate()
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(f"model registry: {'OK' if not errors else f'{len(errors)} error(s)'}")
        return 1 if errors else 0
    if args.cmd == "list":
        for r in catalog.list_roles():
            print(f"{r.name:22s} floor={r.floor:13s} approved={','.join(r.approved)}")
        return 0
    if args.cmd == "resolve":
        try:
            print(catalog.resolve_role(args.role, args.tier))
            return 0
        except (NotFoundError, ValidationError) as e:
            print(str(e), file=sys.stderr)
            return 1
    if args.cmd == "stamp":
        routing = catalog.stamp(args.role, ModelName(args.model))
        print(json.dumps(routing.model_dump(mode="json", exclude_none=True)))
        return 0
    return 2


def _declare_spend(args) -> int:
    core = load(args.config_home)
    if core.model_catalog is None:
        print(
            f"spend: no {MODEL_REGISTRY} in the config home — copy config/{MODEL_REGISTRY} "
            "there (spend pricing and the spend view need it)",
            file=sys.stderr,
        )
        return 1
    for flag in ("repo", "loc", "batch", "note"):
        if getattr(args, flag) is not None:
            print(f"spend: --{flag} {UNSTORED}", file=sys.stderr)
    model = ModelName(args.model)
    try:
        provider = core.model_catalog.resolve(model).provider
        cost = core.model_catalog.cost(
            model,
            TokenUsage(
                tokens_in=args.tokens_in,
                tokens_out=args.tokens_out,
                cache_read=args.cache_read,
                cache_creation=args.cache_creation,
            ),
        )
    except (NotFoundError, ConfigError) as e:
        print(f"spend: {e}", file=sys.stderr)
        return 1
    # NEED(spend: declared vs measured): a declaration adds to the totals `metrics collect-spend
    # --append` records from transcripts, so non-zero declared tokens count twice.
    core.services().spend.record(
        SpendEvent(
            provider=provider,
            model=model,
            skill=args.skill,
            tokens_in=args.tokens_in,
            tokens_out=args.tokens_out,
            cost_usd=cost,
            occurred_at=datetime.now(UTC),
        )
    )
    return 0


MODELS = OpSpec(
    add_args=add_models_args,
    call=call_models,
    help="Model registry validate, list, resolve, stamp, spend",
)


def add_products_args(ap) -> None:
    ap.add_argument(
        "--package",
        action="append",
        default=[],
        help="findings package name (-findings suffix optional)",
    )
    ap.add_argument("--repo-url", action="append", default=[])
    ap.add_argument("--product", action="append", default=[], help="ps_product id")
    ap.add_argument(
        "--all",
        action="store_true",
        help="propose a match for every package under processed-results/",
    )
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--json", action="store_true", help="JSON only, no human-readable summary")


def call_products(args) -> int:
    core = load(args.config_home)
    snapshot = core.product_definitions(args.cache_dir).read()
    portfolio = core.services().portfolio
    mappings = portfolio.product_mappings()
    notes = [] if mappings.packages or mappings.repos else [NO_MAP]
    packages = list(args.package)
    if args.all and snapshot.document is not None:
        tracker = core.config.locations.progress_tracker_dir()
        packages_dir = tracker / "processed-results" if tracker else None
        if packages_dir and packages_dir.is_dir():
            packages += sorted(
                p.name for p in packages_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
            )
        else:
            notes.append(f"{packages_dir} not found — --all resolved no packages")
    resolution = portfolio.resolve_products(
        snapshot, mappings, packages, args.repo_url, args.product
    )
    out = resolution.model_dump(mode="json", exclude_unset=True)
    if notes:
        out["warnings"] = [*notes, *out.get("warnings", [])]
    print(json.dumps(out, indent=2))
    if snapshot.document is not None and not args.json:
        _summarise(out)
    return 0


def _summarise(out: dict) -> None:
    lines = ["", f"# source_status={out['source_status']}"]
    for r in out["results"]:
        q = r["query"]
        lines.append(
            f"{q['kind']}={q['value']}  tier={r['match_tier']}  "
            f"lifecycle={r['lifecycle']['state']}  "
            f"embargo_cc={r['embargo_cc']}"
        )
        for c in r["contacts"]:
            flag = " [embargo-cleared]" if c["embargo_cleared"] else ""
            lines.append(f"    {c['kerberos_id']:14} tier{c['tier']} {c['field']}{flag}")
        if r["match_tier"] == "slug":
            lines.append("    (advisory slug match — confirm into the map)")
    for w in out.get("warnings") or []:
        lines.append(f"! {w}")
    print("\n".join(lines), file=sys.stderr)


PRODUCTS = OpSpec(
    add_args=add_products_args,
    call=call_products,
    help="Resolve ownership context from the product registry",
)


def add_product_map_args(ap) -> None:
    ap.add_argument("map", type=Path, help="a product-definitions-map document (YAML)")


def call_product_map(args) -> int:
    def call() -> dict:
        doc = ProductDefinitionsMapArtifact.from_document(yaml.safe_load(args.map.read_text()))
        portfolio = load(args.config_home).services().portfolio
        return {"artifact_id": portfolio.record_product_map(doc, _doors.interactive()).artifact_id}

    return _doors.run(call)


PRODUCT_MAP = OpSpec(
    add_args=add_product_map_args,
    call=call_product_map,
    help="Record the reviewed package/repo -> product map product lookups use",
)
