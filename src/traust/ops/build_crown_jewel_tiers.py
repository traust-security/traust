#!/usr/bin/env python3
"""Crown-jewel tier selection query — deep-fn plan Phase C (D1).

STATUS: DRAFT GENERATOR. Every artifact this script emits is stamped:

    DRAFT — tier list unsigned (deep-fn plan open question 2);
    Phase-C dispatch must not consume this until signed.

Consumer: progress-tracker/plans/deep-fn-technique-plan.md §3 Phase C —
the deep-profile dispatch (arm-D dual-pass + Phase-B lanes at expanded
caps) selects its targets from tier1/tier2 of this artifact ONCE the tier
list is signed off (open question 2: who signs, and whether external-BU /
upstream trees are in scope). Until then the artifact is review input for
the user only. There is no other consumer.

Composition (per the plan: "portfolio-graph fan-in × threat-register tags
× operator privilege", plus finding history as the empirical prior):

    score = 100 * sum(w_i * c_i for available sources)
                / sum(w_i for available sources)

  components (each normalized to [0, 1]):

    c_fanin    = log2(1 + fan_in) / log2(1 + max_fan_in_in_corpus)
                 fan_in = COUNT(DISTINCT dependent repos) over
                 portfolio-graph edges: repos whose `depends_on` edge
                 lands on a module this repo `declares`. Log-scaled
                 because fan-in is heavy-tailed (a handful of shared
                 libraries dominate); linear scaling would collapse
                 everything else to ~0.
    c_threat   = IMPACT_POINTS[max open-threat impact] / 5
                 over threat-register entries whose status is still open
                 (unmitigated or partially_mitigated). IMPACT_POINTS is
                 log2 of the register's own geometric impact weights
                 {low:1, medium:2, high:4, critical:8, existential:16},
                 +1 → {1..5}: preserves the register's ordering without
                 letting one existential threat outweigh everything else
                 quadratically.
    c_priv     = priv_tier / 3, where priv_tier is derived from the
                 operator-priv-profile static inventory (tiers 1-2 of
                 that skill; see _priv_tier() for the exact flag→tier
                 mapping). No profile → 0 (conservative: unknown
                 privilege earns no score, and the coverage gap is
                 reported — absence of a profile is NOT evidence of low
                 privilege).
    c_findings = log2(1 + 2*open_crit + open_high)
                 / log2(1 + corpus max of the same expression)
                 from findings.db v_open-equivalent filter at HEAD
                 (is_branch_audit=0). The 2x critical multiplier mirrors
                 the campaign convention that one critical outranks two
                 highs; log-scaled for the same heavy-tail reason as
                 fan-in.

  weights (DRAFT — part of what open question 2's sign-off must ratify):

    fanin 0.35, threat 0.25, priv 0.20, findings 0.20
    Fan-in leads because the plan names it first and blast radius is the
    crown-jewel property the §0.1 directive is about; threat-register
    impact is the curated risk signal; privilege and finding history are
    corroborating priors of equal draft weight.

  Missing-source degradation: if a whole source is absent/unreadable the
  run DOES NOT fail — the source's weight is dropped, the remaining
  weights are renormalized, and the gap is recorded in meta.gaps of the
  JSON and the DRAFT banner section of the Markdown.

Join key: lowercase repo base slug (the trailing path segment of the repo
name). The four sources key repos differently (graph node id, findings.db
base_slug, threat-model directory name, priv-profile filename stem); the
base slug is the only key they share. Same-slug collisions across orgs
are merged (max of each raw component) and the merged repo ids are listed
in the row.

Tier sizes: tier1 = --tier1-size (default 20 = the plan's go/no-go pilot
size, §3 Phase C acceptance). tier1+tier2 = 100 and watch = next 100:
the plan's §4 cost table sizes the Phase-C tier at "100-200 repos", so
the draft proposes the 100 lower bound as the tier and the 100→200
stretch as the watch list.

Usage:
    build_crown_jewel_tiers.py --out-dir <dir> [--tier1-size 20]
        [--results-root <analysis-results>]
            (default: configured analysis_results from $TRAUST_CONFIG_HOME/locations.yaml)
        [--graph-db PATH] [--findings-db PATH] [--threat-register PATH]

Defaults derived from --results-root and configured locations:
    graph db         <results-root>/graph/portfolio-graph.db
    findings db      <results-root>/graph/findings.db
    threat register  configured progress_tracker from $TRAUST_CONFIG_HOME/locations.yaml
                     (metrics/dashboards/threat-register/threat-register.json)
    priv profiles    <root>/**/*-priv-profile.json (scan-testing/, tmp/,
                     dot-dirs pruned — scratch copies are not evidence)

Emits <out-dir>/crown-jewel-tiers.{json,md}. Deterministic given the
inputs (stable sort: score desc, slug asc; no wall-clock beyond the
generated date). Requires: stdlib + sqlite3 only.
Exit 0 on success; 1 if NO source could be read; 2 on usage errors.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

DRAFT_MARKER = (
    "DRAFT — tier list unsigned (deep-fn plan open question 2); "
    "Phase-C dispatch must not consume this until signed"
)

# Draft component weights — see module docstring for rationale; these are
# part of what the open-question-2 sign-off must ratify.
WEIGHTS = {"fanin": 0.35, "threat": 0.25, "priv": 0.20, "findings": 0.20}

# log2 of the threat register's own geometric impact weights
# {low:1, medium:2, high:4, critical:8, existential:16}, +1 → 1..5.
IMPACT_POINTS = {"low": 1, "medium": 2, "high": 3, "critical": 4, "existential": 5}

# Register statuses that still count as open risk (its other statuses are
# mitigated / risk_accepted).
OPEN_THREAT_STATUSES = {"unmitigated", "partially_mitigated"}

# One critical outranks two highs — campaign convention (same multiplier
# the sla/exec views use when they collapse severities to one number).
CRIT_MULT = 2

# Plan §4 sizes the Phase-C tier at 100-200 repos: draft proposes the 100
# lower bound as tier1+tier2 and the 100→200 stretch as the watch list.
TIER_TOTAL = 100
WATCH_TOTAL = 200

# Directories never walked for priv profiles: scratch/experiment copies
# (scan-testing matrix reruns) and temp trees are not selection evidence.
PRUNE_DIRS = {"scan-testing", "tmp", "node_modules", "vendor"}


def _slug(name: str) -> str:
    """Join key: lowercase trailing path segment."""
    return name.rstrip("/").rsplit("/", 1)[-1].lower()


# ---------------------------------------------------------------- sources


def load_repo_universe(graph_db: Path):
    """Repo nodes + fan-in from portfolio-graph.db.

    Fan-in(repo R) = COUNT(DISTINCT dependent repo) over edges where a
    repo's `depends_on` lands on a module R `declares` (self excluded).
    Metadata (org/name/url/max_sev) comes from the node attrs — these are
    the repo-graph.json L0 spine fields, already ingested by
    build_portfolio_graph.py, so we read them here instead of re-parsing
    repo-graph.json.
    """
    con = sqlite3.connect(f"file:{graph_db}?mode=ro", uri=True)
    try:
        repos = {}
        for node_id, label, attrs_json in con.execute(
            "SELECT id, label, attrs FROM nodes WHERE kind='repo'"
        ):
            attrs = json.loads(attrs_json or "{}")
            name = attrs.get("name") or (label or node_id).rsplit("/", 1)[-1]
            slug = _slug(name)
            row = repos.setdefault(
                slug,
                {
                    "slug": slug,
                    "repo_ids": [],
                    "org": attrs.get("org"),
                    "name": name,
                    "url": attrs.get("url"),
                    "max_sev_graph": attrs.get("max_sev"),
                    "fanin": 0,
                },
            )
            row["repo_ids"].append(node_id)
        fanin_rows = con.execute(
            """
            SELECT dec.src AS owner, COUNT(DISTINCT dep.src) AS fan_in
            FROM edges dec
            JOIN edges dep
              ON dep.rel = 'depends_on' AND dep.dst = dec.dst
             AND dep.src <> dec.src
            JOIN nodes n ON n.id = dep.src AND n.kind = 'repo'
            WHERE dec.rel = 'declares'
            GROUP BY dec.src
            """
        ).fetchall()
        by_id = {}
        for row in repos.values():
            for rid in row["repo_ids"]:
                by_id[rid] = row
        for owner_id, fan_in in fanin_rows:
            row = by_id.get(owner_id)
            if row is not None:
                # same-slug collisions merge on max (see docstring)
                row["fanin"] = max(row["fanin"], fan_in)
        for row in repos.values():
            row["repo_ids"].sort()
        n_edges = con.execute("SELECT COUNT(*) FROM edges WHERE rel='depends_on'").fetchone()[0]
        return repos, {"repo_nodes": len(by_id), "depends_on_edges": n_edges}
    finally:
        con.close()


def load_threats(register_path: Path):
    """Per-slug open-threat rollup from the threat-register dashboard JSON.

    Keyed by the threat-model directory name (the register's model paths
    look like findings/<product>/<repo-dir>/<repo>-threat-model.md).
    """
    data = json.loads(register_path.read_text(encoding="utf-8"))
    threats = data.get("threats") or []
    per = {}
    for t in threats:
        if t.get("status") not in OPEN_THREAT_STATUSES:
            continue
        model = t.get("model") or ""
        repo_dir = model.rsplit("/", 2)[-2] if model.count("/") >= 2 else model
        slug = _slug(repo_dir)
        row = per.setdefault(slug, {"open_threats": 0, "max_impact": None, "max_points": 0})
        row["open_threats"] += 1
        pts = IMPACT_POINTS.get(t.get("impact"), 0)
        if pts > row["max_points"]:
            row["max_points"] = pts
            row["max_impact"] = t.get("impact")
    return per, {"threats_total": len(threats), "repos_with_open_threats": len(per)}


def _priv_tier(profile: dict) -> tuple[int, str]:
    """Map an operator-priv-profile static inventory to a 0-3 tier.

    3 cluster-privileged: privileged/host workloads, a shipped SCC that
      allows privileged containers, or RBAC that is escalation-complete
      (wildcard resources, escalate/bind/impersonate, or RBAC write).
    2 elevated: SCC `use` requests, secrets access, pods/exec, nodes
      access, wildcard verbs, or any cluster-scoped RBAC.
    1 namespaced: a profile exists and none of the above fire.
    (0 = no profile at all — assigned by the caller, reported as a gap.)
    """
    summary = profile.get("summary") or {}
    flags = profile.get("rbac_flags") or {}
    if (
        summary.get("privileged_or_host_workloads")
        or any(s.get("allowPrivilegedContainer") for s in profile.get("sccs_shipped") or [])
        or flags.get("wildcard_resources")
        or flags.get("escalate_bind_impersonate")
        or flags.get("rbac_write")
    ):
        return 3, "cluster-privileged"
    if (
        profile.get("scc_requests")
        or flags.get("wildcard_verbs")
        or flags.get("secrets_access")
        or flags.get("pods_exec")
        or flags.get("nodes_access")
        or summary.get("cluster_scoped_rules")
    ):
        return 2, "elevated"
    return 1, "namespaced"


def load_priv_profiles(results_root: Path):
    """Discover *-priv-profile.json under results_root and tier each repo.

    Scratch/tmp trees are pruned (PRUNE_DIRS). One profile per slug:
    paths under findings/ win over other trees; ties break on sorted path
    (deterministic).
    """
    candidates = {}
    for dirpath, dirnames, filenames in os.walk(results_root):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS and not d.startswith("."))
        for fn in sorted(filenames):
            if not fn.endswith("-priv-profile.json"):
                continue
            slug = _slug(fn[: -len("-priv-profile.json")])
            path = Path(dirpath) / fn
            rel = path.relative_to(results_root)
            rank = (0 if rel.parts and rel.parts[0] == "findings" else 1, str(rel))
            prev = candidates.get(slug)
            if prev is None or rank < prev[0]:
                candidates[slug] = (rank, path)
    per, parsed, unreadable = {}, 0, 0
    for slug, (_rank, path) in sorted(candidates.items()):
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            unreadable += 1
            continue
        parsed += 1
        tier, tier_label = _priv_tier(profile)
        per[slug] = {
            "priv_tier": tier,
            "priv_label": tier_label,
            "profile": str(path.relative_to(results_root)),
        }
    return per, {"profiles_parsed": parsed, "profiles_unreadable": unreadable}


def load_findings(findings_db: Path):
    """Open crit/high counts per base_slug at HEAD from findings.db.

    Filter mirrors the db's v_open view (resolution open/in_progress,
    validity not FP/withdrawn/refuted/hardening) restricted to
    is_branch_audit=0 — branch re-audits duplicate HEAD findings and
    would double-count.
    """
    con = sqlite3.connect(f"file:{findings_db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            """
            SELECT lower(r.base_slug),
                   SUM(CASE WHEN lower(f.severity)='critical' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN lower(f.severity)='high' THEN 1 ELSE 0 END)
            FROM findings f JOIN repos r USING (repo_key)
            WHERE r.is_branch_audit = 0
              AND COALESCE(f.resolution, 'open') IN ('open', 'in_progress')
              AND COALESCE(f.validity, 'confirmed')
                  NOT IN ('false_positive', 'withdrawn', 'refuted', 'hardening')
            GROUP BY lower(r.base_slug)
            """
        ).fetchall()
        own_rows = con.execute(
            """
            SELECT lower(base_slug), ownership, COUNT(*) AS n
            FROM repos GROUP BY lower(base_slug), ownership
            ORDER BY lower(base_slug), n DESC, ownership
            """
        ).fetchall()
        ownership = {}
        for slug, own, _n in own_rows:
            ownership.setdefault(slug, own)  # first row per slug = modal
        per = {
            slug: {"open_critical": crit or 0, "open_high": high or 0} for slug, crit, high in rows
        }
        n_findings = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        return (
            per,
            ownership,
            {
                "findings_rows": n_findings,
                "slugs_with_open_crit_high": sum(
                    1 for v in per.values() if v["open_critical"] or v["open_high"]
                ),
            },
        )
    finally:
        con.close()


# ---------------------------------------------------------------- scoring


def _lognorm(value: float, corpus_max: float) -> float:
    """log2(1+x)/log2(1+max) — 0 when the corpus max is 0."""
    if corpus_max <= 0:
        return 0.0
    return math.log2(1 + value) / math.log2(1 + corpus_max)


def score_rows(universe, threats, privs, findings, available):
    weights = {k: WEIGHTS[k] for k in available}
    wsum = sum(weights.values())
    max_fanin = max((r["fanin"] for r in universe.values()), default=0)
    max_load = max(
        (CRIT_MULT * f["open_critical"] + f["open_high"] for f in findings.values()),
        default=0,
    )
    rows = []
    for slug, base in universe.items():
        th = threats.get(slug)
        pv = privs.get(slug)
        fd = findings.get(slug)
        comp = {}
        if "fanin" in weights:
            comp["fanin"] = {
                "raw": base["fanin"],
                "normalized": round(_lognorm(base["fanin"], max_fanin), 4),
            }
        if "threat" in weights:
            comp["threat"] = {
                "open_threats": th["open_threats"] if th else 0,
                "max_open_impact": th["max_impact"] if th else None,
                "normalized": round((th["max_points"] / 5) if th else 0.0, 4),
            }
        if "priv" in weights:
            comp["priv"] = {
                "tier": pv["priv_tier"] if pv else 0,
                "label": pv["priv_label"] if pv else "no-profile",
                "normalized": round((pv["priv_tier"] / 3) if pv else 0.0, 4),
            }
        if "findings" in weights:
            load = (CRIT_MULT * fd["open_critical"] + fd["open_high"]) if fd else 0
            comp["findings"] = {
                "open_critical": fd["open_critical"] if fd else 0,
                "open_high": fd["open_high"] if fd else 0,
                "normalized": round(_lognorm(load, max_load), 4),
            }
        score = 100 * sum(weights[k] * comp[k]["normalized"] for k in weights) / wsum
        rows.append({**base, "components": comp, "score": round(score, 2)})
    rows.sort(key=lambda r: (-r["score"], r["slug"]))
    for rank, row in enumerate(rows, 1):
        row["rank"] = rank
    return rows, {k: round(v / wsum, 4) for k, v in weights.items()}


# ---------------------------------------------------------------- emitters


def _md_table(rows, ownership):
    head = (
        "| # | repo | score | fan-in | open threats (max impact) | priv tier "
        "| open C/H | ownership |\n|---|---|---|---|---|---|---|---|"
    )
    lines = [head]
    for r in rows:
        c = r["components"]
        fan = c.get("fanin", {}).get("raw", "—")
        th = c.get("threat", {})
        pv = c.get("priv", {})
        fd = c.get("findings", {})
        lines.append(
            "| {rank} | {name} | {score} | {fan} | {nth} ({imp}) | {tier} ({lbl}) "
            "| {crit}/{high} | {own} |".format(
                rank=r["rank"],
                name=r["name"],
                score=r["score"],
                fan=fan,
                nth=th.get("open_threats", "—"),
                imp=th.get("max_open_impact") or "none",
                tier=pv.get("tier", "—"),
                lbl=pv.get("label", "n/a"),
                crit=fd.get("open_critical", "—"),
                high=fd.get("open_high", "—"),
                own=ownership.get(r["slug"], "unknown"),
            )
        )
    return lines


def emit(out_dir: Path, rows, ownership, sources, gaps, weights, tier1_size):
    scored = [r for r in rows if r["score"] > 0]
    tier1 = scored[:tier1_size]
    tier2 = scored[tier1_size:TIER_TOTAL]
    watch = scored[TIER_TOTAL:WATCH_TOTAL]

    def strip(r):
        return {
            k: r[k]
            for k in ("rank", "slug", "name", "org", "url", "repo_ids", "score", "components")
        } | {"ownership": ownership.get(r["slug"], "unknown")}

    payload = {
        "meta": {
            "status": DRAFT_MARKER,
            "generated": date.today().isoformat(),
            "generator": "traust.ops.build_crown_jewel_tiers",
            "consumer": (
                "deep-fn-technique-plan.md §3 Phase C deep-profile dispatch — "
                "GATED on sign-off (open question 2); until signed this is "
                "user-review input only"
            ),
            "formula": (
                "score = 100 * sum(w*c)/sum(w); c_fanin=log2-normalized "
                "dependent-repo count; c_threat=max open-threat impact points/5; "
                "c_priv=priv tier/3; c_findings=log2-normalized "
                f"({CRIT_MULT}*crit+high) open at HEAD. See script docstring."
            ),
            "weights_effective": weights,
            "sources": sources,
            "gaps": gaps,
            "tier_sizing": {
                "tier1": tier1_size,
                "tier1_plus_tier2": TIER_TOTAL,
                "watch_through_rank": WATCH_TOTAL,
                "basis": "plan §4 Phase-C tier = 100-200 repos; tier1 default = "
                "20-repo go/no-go pilot (§3 Phase C acceptance)",
            },
            "scored_repos": len(scored),
            "universe_repos": len(rows),
        },
        "tiers": {
            "tier1": [strip(r) for r in tier1],
            "tier2": [strip(r) for r in tier2],
            "watch": [strip(r) for r in watch],
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "crown-jewel-tiers.json").write_text(
        json.dumps(payload, indent=1) + "\n", encoding="utf-8"
    )

    L = [
        "# Crown-jewel tiers (Phase C selection query)",
        "",
        f"> **{DRAFT_MARKER}**",
        "",
        f"Generated {payload['meta']['generated']} by "
        "`python3 -m traust.ops.build_crown_jewel_tiers`. "
        f"{len(scored)} of {len(rows)} portfolio repos scored > 0.",
        "",
        "**Formula:** " + payload["meta"]["formula"],
        "",
        "**Effective weights:** " + ", ".join(f"{k}={v}" for k, v in weights.items()),
        "",
        "## Sources",
        "",
    ]
    for name, info in sources.items():
        L.append(
            f"- **{name}**: `{info['path']}` — "
            + ", ".join(f"{k}={v}" for k, v in info.items() if k != "path")
        )
    if gaps:
        L += ["", "## Gaps (formula degraded)", ""]
        L += [f"- {g}" for g in gaps]
    L += ["", f"## Tier 1 (top {len(tier1)} — go/no-go pilot set)", ""]
    L += _md_table(tier1, ownership)
    L += ["", f"## Tier 2 (ranks {tier1_size + 1}-{TIER_TOTAL})", ""]
    L += _md_table(tier2, ownership)
    L += ["", f"## Watch (ranks {TIER_TOTAL + 1}-{WATCH_TOTAL})", ""]
    L += _md_table(watch, ownership)
    L += ["", f"> **{DRAFT_MARKER}**", ""]
    (out_dir / "crown-jewel-tiers.md").write_text("\n".join(L), encoding="utf-8")
    return payload


# -------------------------------------------------------------------- main


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None, help="analysis-results root")
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument(
        "--tier1-size",
        type=int,
        default=20,
        help="tier-1 size (default 20 = plan's go/no-go pilot size)",
    )
    ap.add_argument(
        "--graph-db", type=Path, default=None, help="override <root>/graph/portfolio-graph.db"
    )
    ap.add_argument(
        "--findings-db", type=Path, default=None, help="override <root>/graph/findings.db"
    )
    ap.add_argument(
        "--threat-register",
        type=Path,
        default=None,
        help="override <progress-tracker>/metrics/dashboards/threat-register/threat-register.json",
    )
    args = ap.parse_args(argv)
    if args.tier1_size < 1:
        ap.error("--tier1-size must be >= 1")

    engine = load_engine(args.config_home)
    root = resolve_results_root(args)
    tracker = progress_tracker_dir(engine)
    graph_db = args.graph_db or root / "graph" / "portfolio-graph.db"
    findings_db = args.findings_db or root / "graph" / "findings.db"
    register = args.threat_register or (
        tracker / "metrics" / "dashboards" / "threat-register" / "threat-register.json"
    )

    sources, gaps = {}, []

    # Fan-in universe is mandatory: without the graph there is no repo
    # population to rank.
    if not graph_db.is_file():
        print(f"FATAL: portfolio graph db not found: {graph_db}", file=sys.stderr)
        return 1
    universe, ginfo = load_repo_universe(graph_db)
    sources["portfolio_graph"] = {"path": str(graph_db), **ginfo, "repos": len(universe)}
    available = ["fanin"]

    threats = {}
    if register.is_file():
        try:
            threats, tinfo = load_threats(register)
            sources["threat_register"] = {"path": str(register), **tinfo}
            available.append("threat")
        except (json.JSONDecodeError, OSError) as exc:
            gaps.append(
                f"threat register unreadable ({register}: {exc}) — "
                "threat component dropped, weights renormalized"
            )
    else:
        gaps.append(
            f"threat register not found ({register}) — threat component "
            "dropped, weights renormalized"
        )

    privs, pinfo = load_priv_profiles(root)
    if privs:
        sources["priv_profiles"] = {
            "path": f"{root}/**/*-priv-profile.json",
            **pinfo,
            "repos_tiered": len(privs),
        }
        available.append("priv")
    else:
        gaps.append(
            "no *-priv-profile.json found under results root — privilege "
            "component dropped, weights renormalized"
        )

    findings = {}
    ownership = {}
    if findings_db.is_file():
        try:
            findings, ownership, finfo = load_findings(findings_db)
            sources["findings_db"] = {"path": str(findings_db), **finfo}
            available.append("findings")
        except sqlite3.Error as exc:
            gaps.append(
                f"findings.db unreadable ({findings_db}: {exc}) — "
                "findings component dropped, weights renormalized"
            )
    else:
        gaps.append(
            f"findings.db not found ({findings_db}) — findings component "
            "dropped, weights renormalized"
        )

    rows, weights = score_rows(universe, threats, privs, findings, available)
    payload = emit(args.out_dir, rows, ownership, sources, gaps, weights, args.tier1_size)
    print(
        f"crown-jewel-tiers.{{json,md}} → {args.out_dir}  "
        f"(tier1={len(payload['tiers']['tier1'])}, "
        f"tier2={len(payload['tiers']['tier2'])}, "
        f"watch={len(payload['tiers']['watch'])}; "
        f"gaps={len(gaps)})"
    )
    print(f"STATUS: {DRAFT_MARKER}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
