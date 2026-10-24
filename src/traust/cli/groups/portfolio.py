"""``traust portfolio …`` — portfolio graph build and query."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_engine.portfolio import graph
from traust_engine.portfolio.graph import (
    ALL_ECOSYSTEMS,
    DEFAULT_LANG_CACHE,
    DEFAULT_SUPPORTED_RELEASES,
    MAX_SYMBOL_FILES,
    UNIVERSAL_ECOSYSTEMS,
)

from traust.cli.groups._registry import OpSpec, passthrough_op


def _resolve_spine_db(engine, spine: str | None, db: str | None) -> tuple[Path, Path] | None:
    try:
        return graph._resolve_portfolio_paths(
            spine,
            db,
            default_spine=engine.portfolio.repo_graph(),
            default_db=engine.portfolio.portfolio_graph_db(),
        )
    except Exception as e:
        print(f"portfolio paths unavailable: {e}", file=sys.stderr)
        return None


def _resolve_db(engine, db: str | None) -> Path | None:
    resolved = _resolve_spine_db(engine, None, db)
    return resolved[1] if resolved else None


def add_build_args(ap) -> None:
    ap.add_argument("--spine")
    ap.add_argument("--db")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument(
        "--enrich-refs",
        nargs="?",
        const="",
        metavar="N|branch,branch",
        help="OPT-IN per-release ref enrichment: fetch go.mod "
        "at the supported release branches' repo-ref "
        "nodes and attach depends_on_ref edges. Bare flag "
        f"= top {DEFAULT_SUPPORTED_RELEASES} release-X.Y "
        "branches by ships_ref count; a number overrides "
        "N; a comma list names branches verbatim. "
        "Without this flag the stage never runs and "
        "output is byte-identical to previous releases.",
    )
    ap.add_argument(
        "--allow-stale",
        action="store_true",
        help="Build even when the spine fails the freshness check.",
    )
    ap.add_argument("--max-age-days", type=int, default=30)
    ap.add_argument(
        "--ecosystems",
        default="all",
        help="Comma list of non-Go L1 ecosystems to build after "
        f"the Go layer ({', '.join(ALL_ECOSYSTEMS)}); "
        '"all" (default) builds every one — the six '
        "package ecosystems plus the universal "
        "docker/actions/helm surfaces. Manifests are "
        "discovered anywhere in each repo's git tree. build "
        "stays exit 0 (omnibus); a silently-broken ecosystem "
        "prints a WARNING.",
    )
    ap.add_argument(
        "--no-universal",
        action="store_true",
        help="Skip the universal surfaces (docker/actions/helm) "
        "and build only code-package deps — bounds the gh "
        "call budget when only library deps are wanted.",
    )
    ap.add_argument(
        "--lang-cache",
        default=DEFAULT_LANG_CACHE,
        help="gh-languages jsonl used ONLY for the truncated-tree "
        "root-candidate fallback of the multi-ecosystem "
        "L1 layer.",
    )
    ap.add_argument(
        "--stats-out",
        help="Override the path build_deps_multi's stats dict is "
        "persisted to (default: deps-multi-stats.json next to "
        "--db).",
    )
    ap.add_argument(
        "--sleep-ms",
        type=int,
        default=0,
        help="Inter-call pacing (ms) for each live gh fetch in the "
        "multi-ecosystem L1 layer. 0 (default) = no pacing; a "
        "small value gentles huge fleet sweeps against the "
        "GitHub secondary rate limit.",
    )


def call_build(engine, args) -> int:
    resolved = _resolve_spine_db(engine, args.spine, args.db)
    if resolved is None:
        return 2
    spine, db = resolved
    try:
        result = graph.build(
            spine,
            db,
            limit=args.limit,
            jobs=args.jobs,
            enrich_refs=args.enrich_refs,
            allow_stale=args.allow_stale,
            max_age_days=args.max_age_days,
            ecosystems=args.ecosystems,
            no_universal=args.no_universal,
            lang_cache=args.lang_cache,
            stats_out=args.stats_out,
            sleep_ms=args.sleep_ms,
        )
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    except ValueError as e:
        print(str(e), file=sys.stderr)
        if "STALE" in str(e):
            print(
                "run /repo-graph to regenerate it, then rebuild "
                "(or pass --allow-stale to proceed anyway)",
                file=sys.stderr,
            )
        return 2
    s0, s1 = result["l0"], result["l1"]
    if result.get("stale"):
        print(
            f"WARNING: building from a stale spine ({'; '.join(result['stale_reasons'])})",
            file=sys.stderr,
        )
    print(f"L0 spine: {s0['nodes']} nodes, {s0['edges']} edges, {s0['repos']} repos")
    print(
        f"L1 deps: {s1['go']} Go repos ({s1['absent']} without go.mod, "
        f"{s1['errors']} fetch errors, {s1['skipped_host']} non-GitHub "
        f"skipped); {s1['modules']} modules, {s1['dep_edges']} "
        f"depends_on edges"
    )
    if "l1_refs" in result:
        sr = result["l1_refs"]
        print(
            f"L1 refs: branches [{', '.join(sr['branches'])}]; "
            f"{sr['ok']}/{sr['refs']} refs enriched ({sr['skipped']} "
            f"skipped: no go.mod/branch at ref, {sr['errors']} fetch "
            f"errors); {sr['dep_edges']} depends_on_ref edges, "
            f"{sr['modules_new']} ref-only modules"
        )
    if "l1_multi" in result:
        sm = result["l1_multi"]
        non_go = {e for e in graph._parse_ecosystems(args.ecosystems) if e not in ("go", "Go")}
        if args.no_universal:
            non_go -= set(UNIVERSAL_ECOSYSTEMS)
        graph._print_deps_multi_report(sm, non_go)
        print(f"L1 stats persisted -> {result['stats_path']}")
        if sm.get("rate_limited_incomplete"):
            print(
                "WARNING: L1 multi-ecosystem sweep stopped INCOMPLETE on "
                "a GitHub secondary rate-limit ban — "
                f"{sm.get('repos_ratelimited_skipped', 0)} repo(s) left "
                "unvisited; re-run `build` to resume via the cache",
                file=sys.stderr,
            )
        if sm.get("loud_fail"):
            print(
                "WARNING: L1 ecosystem(s) with manifests discovered "
                "but ZERO dependency edges extracted: "
                f"{', '.join(sm['loud_fail'])} — manifest coverage may "
                "be silently broken",
                file=sys.stderr,
            )
    return 0


BUILD = OpSpec(
    add_args=add_build_args,
    call=call_build,
    help="Build portfolio code graph (L0+L1)",
)


def add_freshness_args(ap) -> None:
    ap.add_argument("--spine", required=True)
    ap.add_argument("--max-age-days", type=int, default=30)


def call_freshness(engine, args) -> int:
    spine = Path(args.spine)
    if not spine.is_file():
        print(f"spine not found: {spine} — run /repo-graph first", file=sys.stderr)
        return 2
    fresh, reasons = graph.check_spine_freshness(
        spine, graph._default_inputs_dir(spine), args.max_age_days
    )
    print("FRESH" if fresh else "STALE: " + "; ".join(reasons))
    return 0 if fresh else 1


FRESHNESS = OpSpec(
    add_args=add_freshness_args,
    call=call_freshness,
    help="Check whether a repo-graph spine is fresh",
)


def add_interfaces_args(ap) -> None:
    ap.add_argument("--db", required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--jobs", type=int, default=6)


def call_interfaces(engine, args) -> int:
    con = graph.db_connect(Path(args.db))
    s2 = graph.build_interfaces(con, args.limit, args.jobs)
    print(
        f"L2 interfaces: {s2['ok']}/{s2['repos']} repos swept "
        f"({s2['clone_errors']} clone errors, {s2['timeouts']} "
        f"timeouts); {s2['crds']} CRDs, {s2['owns']} owns_crd, "
        f"{s2['requires']} requires_crd, {s2['intercepts']} "
        f"intercepts, {s2['rbac']} rbac_grants, "
        f"{s2['consumes']} consumes_group edges"
    )
    return 0


INTERFACES = OpSpec(
    add_args=add_interfaces_args,
    call=call_interfaces,
    help="Build L2 interface layer (CRDs, RBAC, intercepts)",
)


def add_symbols_args(ap) -> None:
    ap.add_argument("--db", required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--jobs", type=int, default=6)


def call_symbols(engine, args) -> int:
    if not graph._load_ts_langs():
        print(
            "tree-sitter unavailable — install the harness's "
            "optional 'graph' dependency group (pip install "
            "tree-sitter tree-sitter-{go,python,typescript,"
            "javascript})",
            file=sys.stderr,
        )
        return 1
    con = graph.db_connect(Path(args.db))
    s4 = graph.build_symbols(con, args.limit, args.jobs)
    print(
        f"L4 symbols: {s4['ok']}/{s4['repos']} repos swept "
        f"({s4['clone_errors']} clone/extract errors, "
        f"{s4['timeouts']} timeouts, {s4['truncated']} truncated at "
        f"{MAX_SYMBOL_FILES} files); {s4['symbols']} exported "
        f"symbols, {s4['import_edges']} imports_package edges"
    )
    return 0


SYMBOLS = OpSpec(
    add_args=add_symbols_args,
    call=call_symbols,
    help="Build L4 exported-symbols layer",
)


def add_artifacts_args(ap) -> None:
    ap.add_argument("--db", required=True)
    ap.add_argument(
        "--findings", required=True, help="Findings tree holding *-container-audit.json."
    )
    ap.add_argument(
        "--sbom-dir",
        help="Directory of CycloneDX SBOMs (*.cdx.json) named or stamped with the image digest.",
    )


def call_artifacts(engine, args) -> int:
    con = graph.db_connect(Path(args.db))
    s3 = graph.build_artifacts(
        con, Path(args.findings), Path(args.sbom_dir) if args.sbom_dir else None
    )
    print(
        f"L3 artifacts: {s3['reports']} container-audit report(s) → "
        f"{s3['images']} image(s), {s3['built_from']} built_from, "
        f"{s3['ships_package']} ships_package; {s3['sboms']} SBOM(s) "
        f"→ {s3['ships_module']} ships_module "
        f"({s3['sbom_unmatched']} SBOMs unmatched to an image)"
    )
    return 0


ARTIFACTS = OpSpec(
    add_args=add_artifacts_args,
    call=call_artifacts,
    help="Build L3 container-artifact layer from findings and SBOMs",
)


def add_stats_args(ap) -> None:
    ap.add_argument("--db")
    ap.add_argument("--out-dir", default=".")


def call_stats(engine, args) -> int:
    db = _resolve_db(engine, args.db)
    if db is None:
        return 2
    graph.write_stats(graph.db_connect(db), Path(args.out_dir))
    print(f"stats written to {args.out_dir}")
    return 0


STATS = OpSpec(
    add_args=add_stats_args,
    call=call_stats,
    help="Write portfolio graph stats markdown and summary JSON",
)


def add_query_args(ap) -> None:
    ap.add_argument("--db")
    ap.add_argument(
        "name",
        choices=[
            "blast-radius",
            "top-shared",
            "internal-coupling",
            "crd-consumers",
            "ships-module",
            "imports-package",
            "exports-of",
        ],
    )
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument(
        "--ecosystem",
        default="go",
        help="Ecosystem for blast-radius: the positional arg is "
        "resolved to a node id via dep_node_id (default "
        "'go' -> module:<path>; e.g. 'npm' -> pkg:npm/<name>).",
    )


def call_query(engine, args) -> int:
    db = _resolve_db(engine, args.db)
    if db is None:
        return 2
    try:
        out = graph.query(
            db,
            args.name,
            args.arg,
            limit=args.limit,
            ecosystem=args.ecosystem,
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    return 0


QUERY = OpSpec(
    add_args=add_query_args,
    call=call_query,
    help="Run a portfolio graph query (blast-radius, top-shared, …)",
)


OBSERVE = passthrough_op(
    "portfolio_observe", "Observe one repository at its forge; keep what it answered.", "main"
)

PLAN = passthrough_op("portfolio_onboard", "What onboard would register, writing nothing.", "plan")
ONBOARD = passthrough_op("portfolio_onboard", "Register a product's repositories.", "onboard")
OWNER_HINTS = passthrough_op("portfolio_onboard", "Who may own a repository.", "owner_hints")
IMPORT_OWNERS = passthrough_op(
    "portfolio_onboard", "Mirror the declared ownership source.", "import_owners"
)
POPULATION = passthrough_op(
    "portfolio_population", "What the registered repositories had assessed.", "main"
)
DEPENDENCIES = passthrough_op(
    "portfolio_dependencies", "The packages in a commit's manifest SBOM.", "dependencies"
)
DEPENDENTS = passthrough_op(
    "portfolio_dependencies", "The commits a package reaches.", "dependents"
)
