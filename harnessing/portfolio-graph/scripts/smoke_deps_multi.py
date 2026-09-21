#!/usr/bin/env python3
"""Offline completeness/smoke checker for the multi-ecosystem portfolio-graph
dependency layer (L1). Its whole job is to catch SILENT under-coverage after a
backfill: a broken parser, a missed fetch, or a Go blast-radius regression.

Checks (each prints a PASS/FAIL/SKIP line; the CLI exits non-zero if any FAIL):

  1 PRESENCE      Every ecosystem present in `depends_on` edges has >=1 pkg
                  node and >=1 edge; every REQUESTED ecosystem with 0 edges is
                  a loud FAIL (the silent-gap tripwire) — this is the presence
                  check the universal docker/actions/helm surfaces are held to.
  2 COVERAGE      Language-gated ecosystems only. repos_with_edges / DENOM >=
                  --floor per requested ecosystem. DENOM is the builder's
                  persisted `repos_with_manifest` (manifest-based, authoritative
                  — repos where a manifest of that ecosystem was actually
                  discovered in the git tree) when deps-multi-stats.json is
                  present next to the db; otherwise it falls back to the
                  gh-language-cache count (labelled "language-based (overcounts)"
                  because a trace of a language is not a dependency repo).
                  Both ratios are reported when both are available. SKIP (never
                  FAIL) when the denominator is 0. Universal surfaces are
                  presence-only and carry NO coverage floor.
  3 GO NO-REGRESS q_blast_radius of the pinned --go-modules exactly equals a
                  snapshot captured on the pre-backfill db; mismatch prints the
                  added/removed repos. A missing snapshot in check mode is a
                  loud FAIL telling the operator to run --make-snapshot first.
  4 COLLISION     module:<name> and pkg:<eco>/<name> occupy distinct id spaces;
                  a blast-radius on one id must not surface the other's
                  dependents. Reports how many shared names were checked.
  5 SUMMARY       Per-ecosystem {repos_with_manifest, repos_with_edges,
                  authoritative ratio, pkg_nodes, dep_edges, basis} + overall
                  PASS/FAIL; universal surfaces are marked presence-only.

stdlib + build_portfolio_graph / manifest_parsers only. No network.

Exit codes: 0 = all checks PASS (or --make-snapshot wrote the snapshot and
exited); 1 = one or more checks FAIL; 2 = usage / db-missing.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from traust_engine.portfolio import graph as G
from traust_engine.portfolio import parsers as MP

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

DEFAULT_DB = None
DEFAULT_LANG_CACHE = G.DEFAULT_LANG_CACHE
# The builder's 9-ecosystem universe: 6 language-gated package ecosystems plus
# the 3 universal path-discovered surfaces (docker/actions/helm). Aligned with
# build_portfolio_graph.ALL_ECOSYSTEMS so a default smoke run covers everything
# a default `deps-multi --ecosystems all` produced.
DEFAULT_ECOSYSTEMS = ",".join(G.ALL_ECOSYSTEMS)
LANGUAGE_GATED = set(G.LANGUAGE_GATED_ECOSYSTEMS)
UNIVERSAL = set(G.UNIVERSAL_ECOSYSTEMS)
# The Go no-regression baseline is derived FROM the corpus graph (--make-snapshot
# reads the db), so it is corpus data, not a test fixture: one entry per repo
# naming what this deployment actually runs. It lives beside the db it came from.
# Order: explicit flag > env > corpus default.
_DEFAULT_SNAPSHOT_REL = Path("graph/inputs/go-blast-radius-snapshot.json")
DEFAULT_SNAPSHOT = os.environ.get("GO_BLAST_RADIUS_SNAPSHOT")
DEFAULT_GO_MODULES = "golang.org/x/net,google.golang.org/grpc,github.com/sirupsen/logrus"
SHORTFALL_CAP = 25


# --------------------------------------------------------------- graph helpers
def repo_key_map(con) -> dict:
    """repo node id -> 'org/name' (the lang-cache key) for github repos."""
    out = {}
    for rid, attrs in con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'"):
        a = json.loads(attrs or "{}")
        org, name = a.get("org"), a.get("name")
        if org and name:
            out[rid] = f"{org}/{name}"
    return out


def pkg_node_count(con, eco: str) -> int:
    if eco in ("Go", "go"):
        return con.execute("SELECT COUNT(*) FROM nodes WHERE kind='module'").fetchone()[0]
    return con.execute("SELECT COUNT(*) FROM nodes WHERE id LIKE ?", (f"pkg:{eco}/%",)).fetchone()[
        0
    ]


def eco_edge_counts(con) -> dict:
    """{ecosystem: depends_on-edge count}, Go = ecosystem attr absent."""
    return {
        eco: c
        for eco, c in con.execute(
            "SELECT COALESCE(json_extract(attrs,'$.ecosystem'),'Go') eco, "
            "COUNT(*) FROM edges WHERE rel='depends_on' GROUP BY eco"
        )
    }


def repos_with_edges(con, eco: str, repo_ids: set) -> set:
    rows = con.execute(
        "SELECT DISTINCT src FROM edges WHERE rel='depends_on' "
        "AND json_extract(attrs,'$.ecosystem')=?",
        (eco,),
    )
    return {r[0] for r in rows} & repo_ids


def blast_repos(con, node_id: str) -> set:
    return {r["repo"] for r in G.q_blast_radius(con, node_id)["requiring_repos"]}


def direct_dependents(con, node_id: str) -> set:
    return {
        r[0]
        for r in con.execute(
            "SELECT DISTINCT src FROM edges WHERE rel='depends_on' AND dst=?", (node_id,)
        )
    }


def go_blast_sorted(con, module: str) -> list:
    return sorted(blast_repos(con, f"module:{module}"))


def load_deps_multi_stats(db_path, stats_override=None):
    """Return (stats_dict, path) for the builder's persisted per-ecosystem
    stats. Default location is deps-multi-stats.json next to the db (the same
    convention build_portfolio_graph writes to); --stats overrides. Returns
    (None, path) when the file is absent or unreadable so the caller can fall
    back to the language-cache denominator and label it as an overcount."""
    p = (
        Path(stats_override)
        if stats_override
        else Path(db_path).resolve().parent / "deps-multi-stats.json"
    )
    if not p.is_file():
        return None, p
    try:
        return json.loads(p.read_text()), p
    except (OSError, json.JSONDecodeError):
        return None, p


# ------------------------------------------------------------------- checks
def check_presence(con, requested, fails, log):
    edge_counts = eco_edge_counts(con)
    present = [e for e in edge_counts if edge_counts[e] > 0]
    for eco in sorted(present):
        pkgs = pkg_node_count(con, eco)
        ok = pkgs >= 1 and edge_counts[eco] >= 1
        log(ok, f"PRESENCE {eco}: {edge_counts[eco]} edges, {pkgs} pkg nodes")
        if not ok:
            fails.append(f"presence:{eco}")
    for eco in requested:
        if edge_counts.get(eco, 0) == 0:
            log(
                False,
                f"PRESENCE {eco}: 0 depends_on edges — requested "
                f"ecosystem produced NOTHING (silent-gap tripwire)",
            )
            fails.append(f"presence-gap:{eco}")


def check_coverage(con, requested, lang_cache, floor, repo_keys, stats, fails, log):
    """Coverage floor for LANGUAGE-GATED ecosystems only. The authoritative
    denominator is the builder's persisted `repos_with_manifest` (repos where
    a manifest of that ecosystem was actually discovered in the git tree); the
    gh-language-cache count is used only when the stats file is absent, and is
    labelled an overcount. Universal surfaces (docker/actions/helm) are
    reported presence-only and never carry a floor."""
    key_to_id = {v: k for k, v in repo_keys.items()}
    repo_ids = set(repo_keys)
    edge_counts = eco_edge_counts(con)
    summary = {}
    for eco in requested:
        rwe = repos_with_edges(con, eco, repo_ids)
        row = {
            "repos_with_edges": len(rwe),
            "pkg_nodes": pkg_node_count(con, eco),
            "dep_edges": edge_counts.get(eco, 0),
            "universal": eco in UNIVERSAL,
            "repos_with_manifest": None,
            "repos_with_lang": None,
            "ratio": None,
            "basis": None,
        }
        summary[eco] = row

        # authoritative manifest-based denominator, if the builder persisted it
        manifest_denom = None
        eco_stats = stats.get(eco) if isinstance(stats, dict) else None
        if isinstance(eco_stats, dict):
            manifest_denom = eco_stats.get("repos_with_manifest")
            row["repos_with_manifest"] = manifest_denom

        if eco in UNIVERSAL:
            # path-discovered surface: presence-only, no language floor.
            row["basis"] = "presence-only"
            log(
                None,
                f"COVERAGE {eco}: SKIP — universal surface "
                f"(presence-only, no language floor); {len(rwe)} repos "
                f"w/ edges, {row['pkg_nodes']} pkg nodes "
                f"(checked by PRESENCE)",
            )
            continue

        # language-based denominator (overcounts) — only meaningful for the
        # language-gated ecosystems.
        eco_langs = {lang for lang, e in MP.LANGUAGE_ECOSYSTEMS.items() if e == eco}
        rwl = {
            key_to_id[repo]
            for repo, langs in lang_cache.items()
            if repo in key_to_id and (set(langs) & eco_langs)
        }
        row["repos_with_lang"] = len(rwl)

        if manifest_denom is not None:
            denom, basis = manifest_denom, "manifest-based (authoritative)"
            row["basis"] = "manifest"
        else:
            denom, basis = len(rwl), "language-based (overcounts)"
            row["basis"] = "language"

        if not denom:
            log(None, f"COVERAGE {eco}: SKIP — denominator 0 [{basis}] (nothing to cover)")
            # still surface the other denominator for context if present
            if manifest_denom is not None and rwl:
                print(f"    language-based (overcounts): {len(rwe)}/{len(rwl)}")
            continue
        ratio = len(rwe) / denom
        row["ratio"] = round(ratio, 3)
        ok = ratio >= floor
        log(
            ok,
            f"COVERAGE {eco}: {len(rwe)}/{denom} repos = {ratio:.0%} (floor {floor:.0%}) [{basis}]",
        )
        # report BOTH denominators when both are available
        if manifest_denom is not None and len(rwl):
            print(
                f"    also language-based (overcounts): "
                f"{len(rwe)}/{len(rwl)} = {len(rwe) / len(rwl):.0%}"
            )
        if not ok:
            fails.append(f"coverage:{eco}")
            if manifest_denom is None:
                # fallback path: we know the repo ids, so name the shortfall.
                shortfall = sorted(f"{repo_keys[r]}" for r in (rwl - rwe))
                shown = shortfall[:SHORTFALL_CAP]
                print(
                    f"    shortfall ({len(shortfall)} repos with {eco} "
                    f"language but no {eco} edge):",
                    file=sys.stderr,
                )
                for repo in shown:
                    print(f"      - {repo}", file=sys.stderr)
                if len(shortfall) > len(shown):
                    print(f"      … +{len(shortfall) - len(shown)} more", file=sys.stderr)
            else:
                # authoritative path: stats carries counts, not the id list.
                print(
                    f"    shortfall: {denom - len(rwe)} of {denom} repos "
                    f"with a discovered {eco} manifest have no {eco} edge "
                    f"(rebuild with `deps-multi --ecosystems {eco}` to "
                    f"enumerate)",
                    file=sys.stderr,
                )
    return summary


def check_go_regression(con, go_modules, snapshot_path, fails, log):
    snap = Path(snapshot_path)
    if not snap.is_file():
        log(
            False,
            f"GO NO-REGRESS: snapshot missing at {snapshot_path} — "
            f"run this tool with --make-snapshot on the PRE-BACKFILL "
            f"db to capture the baseline, then re-run in check mode",
        )
        fails.append("go-snapshot-missing")
        return
    try:
        baseline = json.loads(snap.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log(False, f"GO NO-REGRESS: snapshot unreadable ({exc})")
        fails.append("go-snapshot-unreadable")
        return
    for mod in go_modules:
        current = go_blast_sorted(con, mod)
        if mod not in baseline:
            log(
                False,
                f"GO NO-REGRESS {mod}: not in snapshot — re-run "
                f"--make-snapshot with matching --go-modules",
            )
            fails.append(f"go-regress-missing:{mod}")
            continue
        expected = sorted(baseline[mod])
        if current == expected:
            log(True, f"GO NO-REGRESS {mod}: {len(current)} repos, unchanged")
            continue
        added = sorted(set(current) - set(expected))
        removed = sorted(set(expected) - set(current))
        log(False, f"GO NO-REGRESS {mod}: blast radius CHANGED (+{len(added)} / -{len(removed)})")
        for r in added:
            print(f"      + {r}", file=sys.stderr)
        for r in removed:
            print(f"      - {r}", file=sys.stderr)
        fails.append(f"go-regress:{mod}")


def check_collision(con, fails, log):
    module_names = {
        mid[len("module:") :] for (mid,) in con.execute("SELECT id FROM nodes WHERE kind='module'")
    }
    pkg_by_name: dict = {}
    for (pid,) in con.execute("SELECT id FROM nodes WHERE id LIKE 'pkg:%'"):
        eco, _, name = pid[len("pkg:") :].partition("/")
        if name:
            pkg_by_name.setdefault(name, []).append((eco, pid))
    shared = sorted(module_names & set(pkg_by_name))
    leaks = 0
    for name in shared:
        go_set = blast_repos(con, f"module:{name}")
        go_direct = direct_dependents(con, f"module:{name}")
        if go_set != go_direct:  # a join bug pulled extra/fewer repos
            leaks += 1
            fails.append(f"collision:module:{name}")
            continue
        for _eco, pid in pkg_by_name[name]:
            pkg_set = blast_repos(con, pid)
            pkg_direct = direct_dependents(con, pid)
            # leakage = a repo surfaced for one id that has no real edge to it
            if pkg_set != pkg_direct:
                leaks += 1
                fails.append(f"collision:{pid}")
    ok = leaks == 0
    log(
        ok,
        f"COLLISION: {len(shared)} shared name(s) checked "
        f"(module:<n> vs pkg:<eco>/<n>), {leaks} leak(s) — id spaces "
        f"{'isolated' if ok else 'LEAKING'}",
    )


# --------------------------------------------------------------------- driver
def _logger():
    def log(ok, msg):
        tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"[{tag}] {msg}")

    return log


def make_snapshot(con, go_modules, snapshot_path) -> int:
    snap = {mod: go_blast_sorted(con, mod) for mod in go_modules}
    out = Path(snapshot_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n")
    print(f"wrote Go blast-radius snapshot for {len(go_modules)} module(s) -> {snapshot_path}")
    for mod in go_modules:
        print(f"  {mod}: {len(snap[mod])} repos")
    return 0


_BASIS_LABEL = {
    "manifest": "manifest (authoritative)",
    "language": "language (overcounts)",
    "presence-only": "presence-only",
}


def print_summary(summary, fails):
    print("\n=== SUMMARY (per requested ecosystem) ===")
    print(
        f"{'ecosystem':10} {'repos_manifest':>14} {'repos_edge':>10} "
        f"{'ratio':>8} {'pkg_nodes':>10} {'dep_edges':>10}  basis"
    )
    for eco in sorted(summary):
        s = summary[eco]
        rwm = "-" if s.get("repos_with_manifest") is None else str(s["repos_with_manifest"])
        if s.get("universal"):
            ratio = "presence"
        elif s["ratio"] is None:
            ratio = "n/a"
        else:
            ratio = f"{s['ratio']:.0%}"
        basis = _BASIS_LABEL.get(s.get("basis"), s.get("basis") or "-")
        print(
            f"{eco:10} {rwm:>14} {s['repos_with_edges']:>10} "
            f"{ratio:>8} {s['pkg_nodes']:>10} {s['dep_edges']:>10}  {basis}"
        )
    verdict = "PASS" if not fails else "FAIL"
    print(
        f"\nOVERALL: {verdict}"
        + ("" if not fails else f" — {len(fails)} check(s) failed: " + ", ".join(fails))
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Offline smoke/completeness checker for the "
        "multi-ecosystem portfolio-graph L1 dependency layer."
    )
    add_config_home_arg(p)
    p.add_argument("--db", default=None)
    p.add_argument("--lang-cache", default=DEFAULT_LANG_CACHE)
    p.add_argument(
        "--stats",
        help="Override the builder's persisted deps-multi stats "
        "file (default: deps-multi-stats.json next to --db). "
        "When present its repos_with_manifest is the "
        "authoritative coverage denominator.",
    )
    p.add_argument(
        "--ecosystems", default=DEFAULT_ECOSYSTEMS, help="comma list of requested non-Go ecosystems"
    )
    p.add_argument(
        "--floor", type=float, default=0.5, help="minimum repos_with_edges/repos_with_lang ratio"
    )
    p.add_argument("--snapshot", default=None)
    p.add_argument(
        "--make-snapshot",
        action="store_true",
        help="capture the Go blast-radius snapshot and exit 0",
    )
    p.add_argument(
        "--go-modules",
        default=DEFAULT_GO_MODULES,
        help="comma list of Go module paths to snapshot/check",
    )
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    engine = load_engine(args.config_home)
    requested = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    go_modules = [m.strip() for m in args.go_modules.split(",") if m.strip()]
    db = Path(args.db) if args.db else engine.portfolio.portfolio_graph_db()
    snapshot = (
        Path(args.snapshot)
        if args.snapshot
        else analysis_results_dir(engine) / _DEFAULT_SNAPSHOT_REL
    )
    if DEFAULT_SNAPSHOT and args.snapshot is None:
        snapshot = Path(DEFAULT_SNAPSHOT)
    if not db.is_file():
        print(f"ERROR: graph db not found: {db}", file=sys.stderr)
        return 2
    con = sqlite3.connect(db)
    try:
        if args.make_snapshot:
            return make_snapshot(con, go_modules, snapshot)
        log = _logger()
        fails: list = []
        repo_keys = repo_key_map(con)
        lang_cache = G.load_language_cache(args.lang_cache)
        stats, stats_path = load_deps_multi_stats(args.db, args.stats)
        if stats is not None:
            print(f"coverage denominator: manifest-based (authoritative) from {stats_path}")
        else:
            print(
                f"coverage denominator: language-based (OVERCOUNTS) — "
                f"no deps-multi-stats.json at {stats_path}; run "
                f"`build_portfolio_graph.py deps-multi` to persist the "
                f"honest per-ecosystem repos_with_manifest",
                file=sys.stderr,
            )
        if not lang_cache and stats is None:
            print(
                f"WARNING: language cache empty/unreadable: "
                f"{args.lang_cache} — coverage checks will SKIP",
                file=sys.stderr,
            )
        check_presence(con, requested, fails, log)
        summary = check_coverage(
            con, requested, lang_cache, args.floor, repo_keys, stats, fails, log
        )
        check_go_regression(con, go_modules, snapshot, fails, log)
        check_collision(con, fails, log)
        print_summary(summary, fails)
        return 1 if fails else 0
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
