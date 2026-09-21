#!/usr/bin/env python3
"""Financial report — spend, per-business-unit cost, and unit economics
over time.

The harness already measures spend (docs/model-routing.md); what it had
no way to answer was the questions a budget owner actually asks: what
did this cost, which business unit did it land on, is it going up, and
what did a finding cost us. This builds that view from the pieces that
already exist and adds the one dimension that was missing — BU.

FOUR SECTIONS
  1. Period cost        per-lane, from the Phase-0 attribution rows
                        (`spend-attribution:*` in the metrics ledger)
  2. Business unit      NEW. Spend is not tagged with a BU anywhere, so
                        it is bridged: a session's transcript reveals
                        which findings tree it touched, and findings.db
                        maps that to `business_unit`. Coverage is
                        ALWAYS reported — see BRIDGE below.
  3. Unit economics     $/finding, $/repo, $/KLoC against findings.db
  4. Trend              month-over-month, from the ledger's history

THE BU BRIDGE, AND WHY ITS COVERAGE IS PRINTED EVERY TIME. Two signals
were measured 2026-08-06:
  - declared `model-spend:<skill>` rows carry a real `repo`, but they
    are sparse: only **9.4%** of attributed dollars fall in a
    (date, skill) bucket that has any declared run.
  - transcript findings-tree paths (`analysis-results/<tree>/<product>/
    <repo>/`) appear in **75%** of sessions — far wider.
So the primary signal is the transcript path, corroborated by declared
rows where they exist. Everything else lands in `bu-unknown`, which is
never hidden. A BU table that silently covered a tenth of the money
would be worse than no BU table.

TOKENS ARE THE FACT; DOLLARS ARE A DERIVED VIEW. Cost is recomputed
from each row's stored token counts at CURRENT registry rates, not read
from the `cost_usd` frozen in when the row was appended. Measured
2026-08-06: the registry carried `claude-opus-5` at $15/$75 — the stale
Opus 4.1-era rate, 3x the published $5/$25 — which roughly doubled a
month's reported total. Rows written under a bad rate would otherwise
report it forever; deriving at read time means fixing a rate fixes
history too.

TWO ACCURACY LIMITS, STATED IN EVERY REPORT
  - **Prices are list-price estimates**, never invoiced actuals, and a
    rate can be wrong (see above). Any model with no registry price is
    NAMED in the report rather than counted as $0.
  - **--invoice is the reconciliation seam.** Supply real billing
    (CSV: `period,amount_usd[,note]`) and the report shows estimate vs
    invoice variance instead of implying the estimate is truth.

Usage:
    python3 scripts/build_financial_report.py                  # this month
    python3 scripts/build_financial_report.py --month 2026-07
    python3 scripts/build_financial_report.py --months 6       # trend
    python3 scripts/build_financial_report.py --by-bu
    python3 scripts/build_financial_report.py --invoice bills.csv
    python3 scripts/build_financial_report.py --json
"""

from __future__ import annotations

import argparse
import collections
import csv
import datetime
import json
import re
import sqlite3
from pathlib import Path

from traust_engine import HarnessEngine
from traust_engine.metrics import attribute_spend as asp
from traust_engine.metrics import collect_spend as css
from traust_engine.metrics import history as metrics_history

from traust.context import (
    add_config_home_arg,
    findings_db,
    load_engine,
    workspace_dir,
)
from traust.paths import HARNESS_ROOT, config_path

ATTRIBUTION_PREFIX = "spend-attribution:"
UNATTRIBUTED = "unattributed"
BU_UNKNOWN = "bu-unknown"

# analysis-results/<tree>/<product>/<repo>/... — the campaign layout.
_TREE_PATH_RX = re.compile(
    r"analysis-results/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)"
    r"(?:/([A-Za-z0-9._-]+))?"
)
# Directory names that are bookkeeping, not a product.
_NOT_A_PRODUCT = {"_manifest", "graph", "impact", "isolation", "pqc", "artifacts", ".triage-state"}


# ---------------------------------------------------------------------------
# business-unit resolution
# ---------------------------------------------------------------------------


def bu_maps(db_path: Path) -> dict:
    """-> {product: bu, slug: bu, tree: bu}. findings.db already carries
    `business_unit` per repo (sourced from $TRAUST_CONFIG_HOME/corpus-config.yaml via
    /corpus-intake), so this is a lookup, not a new taxonomy."""
    maps = {"product": {}, "slug": {}, "tree": {}}
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = con.execute(
            "SELECT product, base_slug, tree, business_unit FROM repos "
            "WHERE business_unit IS NOT NULL"
        ).fetchall()
        con.close()
    except sqlite3.Error:
        return maps
    for product, slug, tree, bu in rows:
        if product:
            maps["product"].setdefault(product, bu)
        if slug:
            maps["slug"].setdefault(slug, bu)
        if tree:
            maps["tree"].setdefault(tree, bu)
    return maps


def detect_bu(rec: dict, maps: dict) -> str | None:
    """Strongest BU signal in one transcript record: a findings-tree
    path resolved through findings.db. Tries product, then repo slug,
    then the tree itself (coarsest but still a real BU)."""
    raw = json.dumps(rec)
    if "analysis-results/" not in raw:
        return None
    best = None
    for m in _TREE_PATH_RX.finditer(raw):
        tree, product, repo = m.group(1), m.group(2), m.group(3)
        if product in _NOT_A_PRODUCT:
            continue
        for key, table in ((product, "product"), (repo, "slug"), (product, "slug")):
            if key and key in maps[table]:
                best = maps[table][key]
                break
        else:
            if tree in maps["tree"]:
                best = maps["tree"][tree]
            continue
        # a product/slug hit is stronger than a tree hit; keep scanning
        # so the LAST (most recent) signal in the record wins
    return best


def collect_bu(dirs: list[Path], maps: dict, month: str | None, valid_skills: set[str]) -> dict:
    """-> {date: {bu: {skill: {model: agg}}}}. Walks each session in
    order tracking BOTH the active skill and the active BU, the same
    running-attribution model Phase 0 uses for skills alone."""
    agg: dict = collections.defaultdict(
        lambda: collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(
                    lambda: {k: 0 for k in asp.TOKEN_KEYS} | {"messages": 0}
                )
            )
        )
    )
    for d in dirs:
        for f in sorted(d.glob("*.jsonl")):
            skill, bu = asp.UNATTRIBUTED, BU_UNKNOWN
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    interesting = (
                        '"usage"' in line
                        or "analysis-results/" in line
                        or any(t in line for t in asp._INTERESTING)
                    )
                    if not interesting:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    s = asp.detect_skill(rec, valid_skills)
                    if s:
                        skill = s
                    b = detect_bu(rec, maps)
                    if b:
                        bu = b
                    msg = rec.get("message") or {}
                    usage, model = msg.get("usage"), msg.get("model")
                    if not usage or not model or model.startswith("<"):
                        continue
                    ts = (rec.get("timestamp") or "")[:10]
                    if not ts or (month and not ts.startswith(month)):
                        continue
                    a = agg[ts][bu][skill][model]
                    for k in asp.TOKEN_KEYS:
                        a[k] += usage.get(k) or 0
                    a["messages"] += 1
    return agg


def cost_of(agg_leaf: dict, model: str, reg, engine: HarnessEngine | None = None) -> float | None:
    try:
        if engine is not None:
            return engine.models.cost_usd(
                model,
                agg_leaf["input_tokens"],
                agg_leaf["output_tokens"],
                agg_leaf["cache_read_input_tokens"],
                agg_leaf["cache_creation_input_tokens"],
            )
        from traust_engine.registry import models as model_registry

        return model_registry.cost_usd(
            reg,
            model,
            agg_leaf["input_tokens"],
            agg_leaf["output_tokens"],
            agg_leaf["cache_read_input_tokens"],
            agg_leaf["cache_creation_input_tokens"],
        )
    except Exception:
        return None


def bu_costs(agg: dict, reg, engine: HarnessEngine | None = None) -> tuple[dict, set]:
    """-> ({bu: usd}, unpriced_models)."""
    out: dict = collections.defaultdict(float)
    unpriced: set = set()
    for _date, bus in agg.items():
        for bu, skills in bus.items():
            for _skill, models in skills.items():
                for model, leaf in models.items():
                    usd = cost_of(leaf, model, reg, engine=engine)
                    if usd is None:
                        unpriced.add(model)
                        continue
                    out[bu] += usd
    return dict(out), unpriced


# ---------------------------------------------------------------------------
# ledger-backed period + trend (Phase 0 rows)
# ---------------------------------------------------------------------------


def ledger_series(
    ws: Path, reprice: bool = True, reg=None, engine: HarnessEngine | None = None
) -> tuple[dict, dict]:
    """-> ({month: {skill: usd}}, reprice_stats).

    TOKENS ARE THE FACT; DOLLARS ARE A DERIVED VIEW. By default this
    recomputes cost from each row's stored token counts at the CURRENT
    registry rates rather than trusting the `cost_usd` frozen into the
    row when it was appended.

    That distinction is not academic. Measured 2026-08-06: the registry
    carried `claude-opus-5` at $15/$75 — the stale Opus 4.1-era rate,
    3x the published $5/$25 — and that one wrong number roughly
    doubled a month's reported total. Rows written under the bad rate
    would have gone on reporting the bad number forever. Deriving at
    read time means correcting a rate fixes history in the same commit.

    Pass reprice=False to see what the rows literally recorded — useful
    for diagnosing a rate change, never for reporting."""
    from traust_engine.registry import models as model_registry

    if reprice and reg is None and engine is None:
        raise ValueError("reg or engine is required when reprice=True")
    out: dict = collections.defaultdict(lambda: collections.defaultdict(float))
    stats = {"rows": 0, "repriced": 0, "unpriced": set(), "stored_usd": 0.0, "derived_usd": 0.0}
    rows = engine.metrics.rows() if engine is not None else metrics_history.rows()
    for r in rows:
        if not str(r.get("source") or "").startswith(ATTRIBUTION_PREFIX):
            continue
        m = r.get("metrics") or {}
        date = str(m.get("date") or "")
        if len(date) < 7:
            continue
        stored = m.get("cost_usd")
        usd = stored
        if reprice and m.get("model"):
            try:
                if engine is not None:
                    derived = engine.models.cost_usd(
                        m["model"],
                        int(m.get("tokens_in") or 0),
                        int(m.get("tokens_out") or 0),
                        int(m.get("cache_read") or 0),
                        int(m.get("cache_creation") or 0),
                    )
                else:
                    derived = model_registry.cost_usd(
                        reg,
                        m["model"],
                        int(m.get("tokens_in") or 0),
                        int(m.get("tokens_out") or 0),
                        int(m.get("cache_read") or 0),
                        int(m.get("cache_creation") or 0),
                    )
            except Exception:
                derived = None
            if derived is None:
                stats["unpriced"].add(m["model"])
            else:
                usd, stats["repriced"] = derived, stats["repriced"] + 1
        if usd is None:
            continue
        stats["rows"] += 1
        stats["stored_usd"] += float(stored or 0)
        stats["derived_usd"] += float(usd)
        out[date[:7]][str(m.get("skill") or "?")] += float(usd)
    stats["unpriced"] = sorted(stats["unpriced"])
    stats["drift_usd"] = round(stats["derived_usd"] - stats["stored_usd"], 2)
    return {k: dict(v) for k, v in out.items()}, stats


def lane_split(month_row: dict) -> tuple[float, float]:
    """-> (lane_usd, unattributed_usd)."""
    lane = sum(v for k, v in month_row.items() if k != UNATTRIBUTED)
    return round(lane, 2), round(month_row.get(UNATTRIBUTED, 0.0), 2)


# ---------------------------------------------------------------------------
# unit economics
# ---------------------------------------------------------------------------


def campaign_counts(db_path: Path) -> dict:
    """Denominators for unit economics. Deliberately narrow: repos with
    a preferred HEAD report, and findings that are not false positives.
    /census remains the denominator authority for anything published —
    these are cost-per ratios, not coverage claims."""
    out = {"repos": 0, "findings": 0, "crit_high": 0}
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return out
    try:
        # `preferred` is a STRING enum in findings.db ('audit_json' /
        # 'findings_current'), NOT a boolean — an earlier `preferred=1`
        # here silently counted 0 repos and produced "cost per repo:
        # n/a" against a fully populated corpus.
        out["repos"] = (
            con.execute(
                "SELECT COUNT(DISTINCT repo_url) FROM repos "
                "WHERE preferred = 'audit_json' AND repo_url IS NOT NULL"
            ).fetchone()[0]
            or 0
        )
        cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
        sev = "severity" if "severity" in cols else None
        out["findings"] = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] or 0
        if sev:
            out["crit_high"] = (
                con.execute(
                    f"SELECT COUNT(*) FROM findings WHERE lower({sev}) IN ('critical','high')"
                ).fetchone()[0]
                or 0
            )
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return out


def unit_economics(total_usd: float, counts: dict) -> dict:
    def per(n):
        return round(total_usd / n, 2) if n else None

    return {
        "usd_per_repo": per(counts["repos"]),
        "usd_per_finding": per(counts["findings"]),
        "usd_per_crit_high": per(counts["crit_high"]),
        "denominators": counts,
    }


# ---------------------------------------------------------------------------
# invoice reconciliation seam
# ---------------------------------------------------------------------------


def load_invoices(path: Path) -> dict:
    """CSV `period,amount_usd[,note]` -> {period: {amount, note}}.
    The seam exists so estimates can be checked against reality; until
    it is supplied every figure in this report is an estimate."""
    out: dict = {}
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                period = (row.get("period") or "").strip()
                try:
                    amt = float((row.get("amount_usd") or "").strip())
                except ValueError:
                    continue
                if period:
                    out[period] = {"amount_usd": amt, "note": (row.get("note") or "").strip()}
    except OSError:
        return {}
    return out


_UNVERIFIED_RX = re.compile(r"^\s*([A-Za-z0-9._-]+):\s*\{[^}]*\}\s*#.*unverified", re.M | re.I)


def unverified_models(registry_path: Path | None = None) -> list:
    """Models priced off a rate nobody has confirmed. The registry marks
    these in a trailing COMMENT, not a field (e.g. claude-opus-5: "NOT on
    the published rate card — price unverified"), so this reads the raw
    text. They carry the bulk of campaign spend, which is exactly why
    the caveat is not academic and is printed in every report."""
    path = registry_path or config_path("model-registry.yaml")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return sorted({m.group(1) for m in _UNVERIFIED_RX.finditer(text)})


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _usd(v) -> str:
    return f"${v:,.2f}" if isinstance(v, (int, float)) else "n/a"


def render(report: dict) -> list[str]:
    L = [
        f"# Financial report — {report['period_label']}",
        "",
        f"_Generated {report['generated']} · harness {report['harness_version']}._",
        "",
    ]

    # The caveat leads. A reader who quotes one number should have seen
    # this first, not found it in a footnote.
    cav = report["caveats"]
    L += ["> **These are list-price estimates, not invoiced actuals.**"]
    if cav["unverified_models"]:
        L += [
            f"> The rate for "
            f"{', '.join('`' + m + '`' for m in cav['unverified_models'])}"
            f" is **unverified** (not on the published rate card) and "
            f"these models carry most campaign spend."
        ]
    if report.get("invoice"):
        inv = report["invoice"]
        L += [
            f"> Invoice reconciliation: estimate {_usd(inv['estimate'])} "
            f"vs invoiced {_usd(inv['invoiced'])} — variance "
            f"{_usd(inv['variance'])} ({inv['variance_pct']})."
        ]
    else:
        L += [
            "> No invoice supplied (`--invoice`), so nothing here has "
            "been checked against real billing."
        ]
    L += [""]

    p = report["period"]
    L += [
        "## Period cost",
        "",
        f"**Harness lanes {_usd(p['lane_usd'])}** · unattributed "
        f"{_usd(p['unattributed_usd'])} · total {_usd(p['total_usd'])}",
        "",
        "_`unattributed` is workstation sessions that never invoked a "
        "skill. A scanning budget should be judged against the lane "
        "subtotal._",
        "",
        "| Lane | Cost |",
        "|---|---:|",
    ]
    for skill, usd in sorted(p["by_lane"].items(), key=lambda kv: -kv[1])[:15]:
        L.append(f"| {skill} | {_usd(usd)} |")
    L += [""]

    if report.get("by_bu"):
        b = report["by_bu"]
        L += [
            "## By business unit",
            "",
            f"_Bridged: spend carries no BU tag, so it is resolved from "
            f"the findings tree each session touched "
            f"(findings.db `business_unit`). **Coverage "
            f"{b['coverage_pct']}** of period cost — the remainder is "
            f"`{BU_UNKNOWN}` and is shown, never redistributed._",
            "",
            "_This table and *Period cost* partition the **same** "
            "total along different axes, so their rows will not line "
            "up: a session can touch a BU's findings tree without "
            "invoking a skill (BU known, lane `unattributed`), or run "
            "a skill against no tree (lane known, BU unknown). Do not "
            "read a BU figure as a lane figure._",
            "",
            "| Business unit | Cost | Share |",
            "|---|---:|---:|",
        ]
        tot = b["total_usd"] or 1
        for bu, usd in sorted(b["by_bu"].items(), key=lambda kv: -kv[1]):
            L.append(f"| {bu} | {_usd(usd)} | {usd / tot * 100:.1f}% |")
        L += [""]
        if b["unpriced_models"]:
            L += [
                f"⚠ unpriced model(s) excluded from the BU split: "
                f"{', '.join(sorted(b['unpriced_models']))}",
                "",
            ]

    ue = report["unit_economics"]
    d = ue["denominators"]
    L += [
        "## Unit economics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Cost per repo | {_usd(ue['usd_per_repo'])} |",
        f"| Cost per finding | {_usd(ue['usd_per_finding'])} |",
        f"| Cost per critical/high | {_usd(ue['usd_per_crit_high'])} |",
        "",
        f"_Denominators: {d['repos']:,} repos (preferred HEAD reports), "
        f"{d['findings']:,} findings, {d['crit_high']:,} critical/high. "
        f"These are cost ratios against the period's lane spend — "
        f"`/census` remains the denominator authority for any published "
        f"coverage claim, and much of the corpus was audited in earlier "
        f"periods, so a single month's cost over an all-time count "
        f"understates true unit cost._",
        "",
    ]

    t = report["trend"]
    if t:
        L += [
            "## Trend",
            "",
            "| Month | Lane | Unattributed | Total | Δ lane |",
            "|---|---:|---:|---:|---:|",
        ]
        # Newest first, but Δ must compare each month to the OLDER one
        # (the row BELOW it). Carrying `prev` forward while iterating
        # downward inverts the sign — a month would read as an increase
        # against a month that had not happened yet.
        months = sorted(t, reverse=True)
        for i, month in enumerate(months):
            row = t[month]
            older = months[i + 1] if i + 1 < len(months) else None
            delta = "—" if older is None else f"{row['lane'] - t[older]['lane']:+,.2f}"
            L.append(
                f"| {month} | {_usd(row['lane'])} | "
                f"{_usd(row['unattributed'])} | {_usd(row['total'])} | "
                f"{delta} |"
            )
        L += [
            "",
            "_Δ compares to the month below it. Lane share swings "
            "with campaign activity — judge a budget on several "
            "months, never one._",
            "",
        ]
    return L


def build_report(
    ws: Path,
    month: str | None,
    months: int,
    want_bu: bool,
    invoice_path: Path | None,
    db_path: Path,
    reg,
    engine: HarnessEngine | None = None,
) -> dict:
    series, reprice = ledger_series(ws, reg=reg, engine=engine)
    month = month or datetime.date.today().strftime("%Y-%m")
    row = series.get(month, {})
    lane, unatt = lane_split(row)

    trend = {}
    for m in sorted(series, reverse=True)[: max(months, 1)]:
        ln, un = lane_split(series[m])
        trend[m] = {"lane": ln, "unattributed": un, "total": round(ln + un, 2)}

    report = {
        "artifact": "financial-report",
        "generated": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "?",
        "period_label": month,
        "period": {
            "month": month,
            "lane_usd": lane,
            "unattributed_usd": unatt,
            "total_usd": round(lane + unatt, 2),
            "by_lane": {k: round(v, 2) for k, v in row.items() if k != UNATTRIBUTED},
        },
        "unit_economics": unit_economics(lane, campaign_counts(db_path)),
        "trend": trend,
        "caveats": {
            "prices_are_list_estimates": True,
            "repriced_from_tokens": True,
            "repriced_rows": reprice["repriced"],
            "reprice_drift_usd": reprice["drift_usd"],
            "unpriced_models": reprice["unpriced"],
            "unverified_models": unverified_models(),
            "invoice_supplied": bool(invoice_path),
        },
    }

    if want_bu:
        maps = bu_maps(db_path)
        dirs = (
            engine.metrics.session_project_dirs(ws)
            if engine is not None
            else css.workspace_slugs(ws)
        )
        agg = collect_bu(dirs, maps, month, asp.known_skills())
        costs, unpriced = bu_costs(agg, reg, engine=engine)
        total = sum(costs.values())
        known = total - costs.get(BU_UNKNOWN, 0.0)
        report["by_bu"] = {
            "by_bu": {k: round(v, 2) for k, v in costs.items()},
            "total_usd": round(total, 2),
            "resolved_usd": round(known, 2),
            "coverage_pct": (f"{known / total * 100:.1f}%" if total else "n/a"),
            "unpriced_models": sorted(unpriced),
        }

    if invoice_path:
        inv = load_invoices(invoice_path)
        got = inv.get(month)
        if got:
            est = report["period"]["total_usd"]
            var = round(got["amount_usd"] - est, 2)
            report["invoice"] = {
                "estimate": est,
                "invoiced": got["amount_usd"],
                "variance": var,
                "variance_pct": (f"{var / est * 100:+.1f}%" if est else "n/a"),
                "note": got.get("note", ""),
            }
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="workspace root (default: configured workspace)",
    )
    ap.add_argument("--month", default=None, help="YYYY-MM (default: current)")
    ap.add_argument("--months", type=int, default=6, help="how many months of trend to show")
    ap.add_argument(
        "--by-bu", action="store_true", help="add the business-unit split (walks transcripts)"
    )
    ap.add_argument(
        "--invoice",
        type=Path,
        default=None,
        help="CSV period,amount_usd[,note] — reconcile estimates against real billing",
    )
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None, help="write Markdown here (default: stdout)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    args.workspace = args.workspace or workspace_dir(engine)
    args.db = args.db or findings_db(engine)
    reg = engine.models.registry()
    report = build_report(
        args.workspace,
        args.month,
        args.months,
        args.by_bu,
        args.invoice,
        args.db,
        reg,
        engine=engine,
    )
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
        return 0
    body = "\n".join(render(report))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
