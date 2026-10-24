"""``traust corpus …`` — report population, findings DB, precedents, identity."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_engine._util import finding_identity as fi
from traust_engine.corpus import findings_db, precedent
from traust_engine.corpus import resolver as corpus_resolver
from traust_engine.locations import FINDINGS_DB_REL, FP_PRECEDENT_CACHE_REL

from traust.cli.groups._registry import OpSpec
from traust.context import (
    add_ledger_binding_args,
    analysis_results_dir,
    bind_ledger,
    progress_tracker_dir,
)


def _corpus_cfg(engine, config_path: Path | None):
    if config_path is not None:
        return corpus_resolver.load_config(config_path)
    return engine.corpus.config()


def _analysis_results(engine, arg: str | None) -> Path:
    if arg:
        return Path(arg)
    return analysis_results_dir(engine)


def _print_resolution_summary(res) -> None:
    agg = corpus_resolver.aggregates(res)
    hdr = (
        f"{'tree':<22} {'ownership':<12} {'reports':>7} {'unique':>7} "
        f"{'branch':>7} {'md-only':>7} {'ledger':>7}"
    )
    print(hdr + "\n" + "-" * len(hdr))
    for tree, t in sorted(agg["trees"].items()):
        print(
            f"{tree:<22} {t['ownership']:<12} {t['reports']:>7} "
            f"{t['unique_base_slugs']:>7} {t['branch_reaudits']:>7} "
            f"{t['reports_md_only']:>7} {t['with_findings_current']:>7}"
        )
    d = agg["duplication"]
    print(
        f"\nsymlink aliases: {d['symlink_aliases']} file / "
        f"{d['dir_symlink_aliases']} dir -> "
        f"{d['symlink_canonical_targets']} canonical | branch re-audits: "
        f"{d['branch_reaudit_reports']} | cross-tree slugs: "
        f"{d['cross_tree_slugs']}"
    )
    for w in res.warnings:
        print(f"WARNING: {w}", file=sys.stderr)


# ---------------------------------------------------------------------------
# findings-db
# ---------------------------------------------------------------------------


def add_findings_db_args(ap) -> None:
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="default: <results-root>/graph/findings.db",
    )
    ap.add_argument("--trees", nargs="*", default=None)
    ap.add_argument(
        "--config",
        type=Path,
        default=None,
        help="corpus-config.yaml override (tests)",
    )


def call_findings_db(engine, args) -> int:
    if args.results_root is None and args.config is None:
        counts, out = engine.corpus.build_findings_db(out=args.out, trees=args.trees)
    else:
        results = (
            args.results_root.resolve()
            if args.results_root is not None
            else analysis_results_dir(engine)
        )
        out = args.out or (results / FINDINGS_DB_REL)
        cfg = _corpus_cfg(engine, args.config)
        counts = findings_db.build(
            results,
            out,
            trees=args.trees,
            cfg=cfg,
            progress_tracker=progress_tracker_dir(engine),
        )
    print(f"wrote {out}")
    print("  " + ", ".join(f"{k}: {v:,}" for k, v in counts.items()))
    return 0


FINDINGS_DB = OpSpec(
    add_args=add_findings_db_args,
    call=call_findings_db,
    help="build the SQLite findings projection",
)


# ---------------------------------------------------------------------------
# precedent (build | match)
# ---------------------------------------------------------------------------


def add_precedent_args(ap) -> None:
    sub = ap.add_subparsers(dest="precedent_cmd", required=True)

    b = sub.add_parser("build", help="rebuild the cache from scratch")
    b.add_argument("--analysis-results", default=None)
    b.add_argument(
        "--config",
        type=Path,
        default=None,
        help="corpus-config.yaml (default: harness config)",
    )
    b.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output path (default: <analysis-results>/graph/fp-precedent-cache.json)",
    )
    b.add_argument(
        "--taxonomy",
        type=Path,
        default=None,
        help="fp-persistence-analysis.json for the phase2-rule join",
    )

    m = sub.add_parser("match", help="annotate findings with precedents")
    m.add_argument("--cache", type=Path, required=True)
    m.add_argument(
        "--findings",
        type=Path,
        required=True,
        help="JSON: a findings list, or an object with a findings[] array",
    )
    m.add_argument("--json-out", type=Path, default=None)


def call_precedent(engine, args) -> int:
    if args.precedent_cmd == "build":
        if args.analysis_results is None and args.config is None:
            cache, out = engine.corpus.build_fp_precedent_cache(
                taxonomy_path=args.taxonomy,
                out=args.out,
            )
        else:
            analysis_results = _analysis_results(engine, args.analysis_results)
            cfg = _corpus_cfg(engine, args.config)
            cache = precedent.build_cache(analysis_results, cfg, taxonomy_path=args.taxonomy)
            out = args.out or (analysis_results / FP_PRECEDENT_CACHE_REL)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
        md = cache["metadata"]
        pop = md["population"]
        print(
            f"wrote {out}: {md['entries']} component entr"
            f"{'y' if md['entries'] == 1 else 'ies'} — "
            f"{pop['human_countersigned']} human-countersigned + "
            f"{pop['machine_refuted_sound']} machine-refuted-sound "
            f"precedent(s) across {md['layers_scanned']} layer(s); "
            f"excluded: {pop['excluded_unsound']} unsound, "
            f"{pop['excluded_contested']} contested, "
            f"{pop['excluded_stale_disposition']} stale-disposition"
        )
        if md["entries"] == 0:
            print("cache is EMPTY — consumers no-op.")
        return 0

    if not args.cache.is_file():
        result = {"cache": str(args.cache), "matches": []}
    else:
        try:
            cache = json.loads(args.cache.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read cache: {e}", file=sys.stderr)
            return 2
        try:
            doc = json.loads(args.findings.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read findings: {e}", file=sys.stderr)
            return 2
        findings = doc if isinstance(doc, list) else (doc.get("findings") or [])
        result = {
            "cache": str(args.cache),
            "matches": engine.corpus.match_findings(cache, findings),
        }
    text = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(text, encoding="utf-8")
        print(f"wrote {args.json_out}: {len(result['matches'])} match(es)")
    else:
        print(text, end="")
    return 0


PRECEDENT = OpSpec(
    add_args=add_precedent_args,
    call=call_precedent,
    help="shared-component FP-precedent cache (build | match)",
)


# ---------------------------------------------------------------------------
# summary / resolve (corpus resolver)
# ---------------------------------------------------------------------------


def _add_resolver_common_args(ap) -> None:
    ap.add_argument("--analysis-results", default=None)
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument("--trees", default=None, help="comma-separated subset of trees")


def add_summary_args(ap) -> None:
    _add_resolver_common_args(ap)


def call_summary(engine, args) -> int:
    cfg = _corpus_cfg(engine, args.config)
    trees = args.trees.split(",") if args.trees else None
    res = corpus_resolver.resolve(
        _analysis_results(engine, args.analysis_results),
        cfg,
        trees=trees,
        with_repo_urls=False,
    )
    _print_resolution_summary(res)
    return 0


SUMMARY = OpSpec(
    add_args=add_summary_args,
    call=call_summary,
    help="print per-tree corpus population table",
)


def add_resolve_args(ap) -> None:
    _add_resolver_common_args(ap)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--with-repo-urls",
        action="store_true",
        help="read metadata.repository from every audit JSON (slower)",
    )


def call_resolve(engine, args) -> int:
    cfg = _corpus_cfg(engine, args.config)
    trees = args.trees.split(",") if args.trees else None
    res = corpus_resolver.resolve(
        _analysis_results(engine, args.analysis_results),
        cfg,
        trees=trees,
        with_repo_urls=args.with_repo_urls,
    )
    _print_resolution_summary(res)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(corpus_resolver.build_manifest(res, cfg), indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote {args.out}")
    return 0


RESOLVE = OpSpec(
    add_args=add_resolve_args,
    call=call_resolve,
    help="resolve corpus and emit a manifest (on-demand)",
)


# ---------------------------------------------------------------------------
# finding-identity (fingerprint | backfill | rebaseline)
# ---------------------------------------------------------------------------


def add_finding_identity_args(ap) -> None:
    sub = ap.add_subparsers(dest="identity_cmd", required=True)

    p1 = sub.add_parser("fingerprint", help="print (or --write) fingerprints for one report")
    p1.add_argument("audit", type=Path)
    p1.add_argument("--write", action="store_true")
    p1.add_argument(
        "--allow-identity-move",
        action="store_true",
        help=(
            "permit re-stamping to CHANGE an existing fingerprint. Ledger events are keyed "
            "on these values, so a move orphans that history -- only with a plan for the "
            "orphaned events."
        ),
    )

    p4 = sub.add_parser(
        "attribute",
        help="attribute existing fingerprints to the recipe that minted them",
    )
    p4.add_argument("root", type=Path)
    p4.add_argument(
        "--write",
        action="store_true",
        help="stamp fingerprint_algo where attribution succeeded. Writes the "
        "MARKER only, never the hash, so no identity moves.",
    )

    p5 = sub.add_parser(
        "stamp-missing",
        help="fingerprint findings that have none; never re-stamps",
    )
    p5.add_argument("root", type=Path)
    p5.add_argument("--write", action="store_true")

    p2 = sub.add_parser(
        "backfill",
        help="annotate every *-security-audit.json under a tree",
    )
    p2.add_argument("root", type=Path)
    p2.add_argument("--dry-run", action="store_true")
    p2.add_argument(
        "--allow-identity-move",
        action="store_true",
        help=(
            "permit re-stamping to CHANGE an existing fingerprint. Ledger events are keyed "
            "on these values, so a move orphans that history -- only with a plan for the "
            "orphaned events."
        ),
    )

    p3 = sub.add_parser(
        "rebaseline",
        help="correlate an old report's findings to a new one",
    )
    p3.add_argument("old_audit", type=Path)
    p3.add_argument("new_audit", type=Path)
    p3.add_argument("layer", type=Path)
    p3.add_argument("--dry-run", action="store_true")
    add_ledger_binding_args(p3)
    p3.add_argument(
        "--no-review-queue",
        action="store_true",
        help="batch mode: record proposals without enqueueing needs_review",
    )


def call_finding_identity(engine, args) -> int:
    if args.identity_cmd == "fingerprint":
        return fi.run_fingerprint(
            args.audit,
            write=args.write,
            allow_identity_move=args.allow_identity_move,
        )

    if args.identity_cmd == "stamp-missing":
        return fi.run_stamp_missing(args.root, write=args.write)

    if args.identity_cmd == "attribute":
        return fi.run_attribute(args.root, write=args.write)

    if args.identity_cmd == "backfill":
        return fi.run_backfill(
            args.root,
            dry_run=args.dry_run,
            allow_identity_move=args.allow_identity_move,
        )

    bind_ledger(engine, args)
    ledger_svc = engine.ledger.service(data_dir=args.layer.parent)
    r = fi.rebaseline(
        args.old_audit,
        args.new_audit,
        args.layer,
        dry_run=args.dry_run,
        queue_reviews=not args.no_review_queue,
        ledger_service=ledger_svc,
    )
    by_tier: dict[str, int] = {}
    for m in r["mapped"].values():
        by_tier[m["matched_by"]] = by_tier.get(m["matched_by"], 0) + 1
    print(
        f"mapped {len(r['mapped'])} "
        f"({', '.join(f'{k}: {v}' for k, v in by_tier.items()) or '—'})"
        f" | unmatched old: {len(r['unmatched_old'])}"
        f" | new-only: {len(r['unmatched_new'])}"
        f" | reviews queued: {r['queued_reviews']}"
        f" | claim pins migrated: {len(r['migrated_claims'])}"
        f"{' [dry-run]' if args.dry_run else ''}"
    )
    for oid in r["unmatched_old"]:
        print(f"  unmatched: {oid}")
    return 0


FINDING_IDENTITY = OpSpec(
    add_args=add_finding_identity_args,
    call=call_finding_identity,
    help="finding fingerprints and rebaseline (fingerprint | backfill | rebaseline)",
)
