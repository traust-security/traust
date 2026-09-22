#!/usr/bin/env python3
"""Staleness & drift checker across derived artifacts and paired sources.

Everything downstream of a source can silently age: pull-through caches
(EPSS/KEV), the findings-DB projection, the graphs derived from
the inputs inventory, pinned registries (ADR, and the IaC declaration source when
Phase 2 lands), and dated policy provenance. This checker makes that
visible on a cadence: one deterministic pass, one report in
progress-tracker (metrics/drift/drift-report.{json,md}).

It ROUTES ATTENTION, NEVER CONCLUDES (candidate-generator doctrine):
each item gets a status and the exact refresh command; deciding to
rebuild, advance a pin, or file a finding stays with the human/skill
that runs it.

Statuses:
  fresh       within threshold
  stale       source moved or age exceeded — refresh command included
  drift       two sources disagree on the same fact (e.g. unregistered
              output trees vs corpus config)
  review_due  dated provenance past its review window (policy values)
  pending     checked artifact does not exist yet (e.g. adr-registry
              before compliance Phase 2c) — listed so the gap is visible
  unavailable checker could not determine (reason given)

Usage:
    python3 -m traust.cli.check_drift [--workspace <dir>]
        [--out-dir <dir>] [--fail-on stale|drift]
"""

from __future__ import annotations

import argparse
import datetime
import importlib
import importlib.util
import json
import os
import subprocess
import tempfile
import sys
from pathlib import Path

from traust_contracts.paths import schema_dir
from traust_engine.corpus.resolver import split_ref

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    inputs_dir,
    load_engine,
    progress_tracker_dir,
    workspace_dir,
)
from traust.paths import HARNESS_ROOT, optional_config_path, skill_dir

try:
    import yaml
except ImportError:
    yaml = None

# Resolved once per main() run so CHECKS honor split locations.yaml
# (analysis_results / progress_tracker not nested under workspace).
_run_ar: Path | None = None
_run_pt: Path | None = None


def _ar(ws: Path) -> Path:
    return _run_ar if _run_ar is not None else ws / "analysis-results"


def _pt(ws: Path) -> Path:
    return _run_pt if _run_pt is not None else ws / "progress-tracker"


def _module_file(module: str) -> Path | None:
    try:
        spec = importlib.util.find_spec(module)
        if spec and spec.origin:
            return Path(spec.origin)
    except (ImportError, ModuleNotFoundError, ValueError):
        pass
    return None


# The refresh job is daily, so a week-wide window let a dead job hide for
# six days. 48h = one missed run plus slack: the row is the dead-timer
# backstop for the job, and a backstop looser than the cadence it guards
# is why a 38-day-stale EPSS/KEV cache went unreported (2026-08-25).
FEED_STALE_HOURS = 48
# Per-feed overrides. product-definitions refetches at 24h (upstream's own
# guidance to consumers) but is VPN-only and pull-through, so it only
# refreshes when a VPN-connected consumer runs. 168h keeps a fortnight of
# off-VPN work from turning the row red while still surfacing a cache
# nobody has touched in a week — the 720h it carried alongside the old
# 30-day TTL would have hidden 29 days of contact drift.
FEED_STALE_HOURS_BY_NAME = {"product-definitions": 24 * 7}
LIVENESS_STALE_DAYS = 14
PROVENANCE_REVIEW_DAYS = 180
# Checkov releases several times a week (patch churn); version lag is
# meaningless, age is not — the bundled policies age with the pin.
CHECKOV_PIN_MAX_AGE_DAYS = 90
# External deterministic scanners are PATH-invoked and unpinned by
# design; a lagging install means aging detection content (gitleaks
# detectors, grype matchers, opengrep engine, osv ecosystems). Grace
# window keeps normal release churn quiet: stale only when a newer
# release has existed this long and the local install still lags.
EXTERNAL_TOOL_LAG_GRACE_DAYS = 14
# The external-tools rows watch the BINARY; this watches the DATA behind
# it. grype ships its matchers separately from the binary, so a current
# grype can carry a months-old vulnerability DB and the version row stays
# green while every scan silently misses recent CVEs. Measured 2026-08-25:
# grype 0.117.0 == latest (row fresh) while its DB was built 2026-07-30
# and self-reported `Status: invalid`. 5 days is grype's OWN max-allowed
# age — past it the DB invalidates itself — so this is the tool's policy,
# not a number we picked.
GRYPE_DB_MAX_AGE_DAYS = 5
# Bounded schema sample: the write-time gate in pqc_facts.py means new
# files cannot violate, so a small newest-first sample is enough to
# catch a schema/corpus divergence without a multi-minute full sweep.
PQC_FACTS_SCHEMA_SAMPLE = 25
# Generated dashboards refresh on demand, not on a schedule — this
# backstop caught the scoreboard sitting 6 days / 88 harness versions
# stale (0.85.0 -> 0.173.x, 2026-07-24). Spend actuals are expected
# roughly daily; 4 days tolerates a long weekend.
SCOREBOARD_STALE_DAYS = 7
SPEND_DASHBOARD_STALE_DAYS = 4
# Dependency-exposure reads the portfolio graph's dependency layer, whose
# heavyweight rebuild is a human decision (the `portfolio-graph` drift row
# triggers it); 14 days tolerates that cadence before the exposure view
# is flagged as serving stale blast-radius/vuln numbers.
DEP_EXPOSURE_STALE_DAYS = 14
# Per-builder dashboard freshness. The aggregate scoreboard row cannot stand in for
# these: refresh_dashboards runs consumer stages continue-on-error, so ONE builder can
# die while the scoreboard stays fresh and the row stays green. Measured 2026-08-20 —
# build_rbac_tenancy_rollup was dead from 2026-08-13 (two fatal errors from the
# package restructure) and nothing flagged it, because rbac-tenancy had no row.
# 7d, matching the documented weekly target and SCOREBOARD_STALE_DAYS. A looser
# threshold defeats the purpose: rbac-tenancy died 7 days after its last good build,
# so a 14d window would have called it fresh for another week.
BUILDER_STALE_DAYS = 7
# stage name (refresh_dashboards.build_stages) -> output dir under metrics/dashboards.
# Stages absent here are reported as uncovered rather than skipped: a builder with no
# freshness signal is exactly the case this check exists for.
BUILDER_OUTPUT_DIRS = {
    "census": "census",
    "trends": "trends",
    "insecure-patterns": "insecure-patterns",
    "rbac-tenancy": "rbac-tenancy",
    "sla": "sla",
    "compliance": "compliance",
    "attack-coverage": "attack-coverage",
}
# The continuous-operations router is a daily loop; 3 days tolerates a
# weekend before the worklist (and every lane consuming it) goes loud.
RESCAN_WORKLIST_STALE_DAYS = 3
# The rule-mining lane runs weekly; the row is the post-wave trigger —
# a large audit/triage wave appends ledger events well ahead of the
# next scheduled run, and confirmations older than a week that no rule
# has seen are exactly the drift the lane exists to close.
RULE_MINING_LAG_DAYS = 7
# Anti-Go-bias tripwire (language-coverage check): a programming language
# that becomes DOMINANT in at least this many repos yet maps to no
# dependency-graph ecosystem — and is not an explicit no-deps language —
# means the portfolio graph is silently under-covering a NEW language
# (same philosophy as the docs-product-map FUTURE-version check).
LANGUAGE_COVERAGE_THRESHOLD = 10
# Languages that legitimately have NO package-dependency ecosystem to
# graph, so an uncovered-language flag on them would be noise. EXTEND THIS
# (with a one-line reason) rather than lowering the threshold when a new
# no-deps language crosses the bar — shells, markup/templating/query
# languages, and IaC/policy surfaces owned by other lanes live here.
NO_DEPS_LANGUAGE_ALLOWLIST = frozenset(
    {
        "Shell",
        "YAML",
        "Markdown",
        "Dockerfile",  # covered via the universal 'docker' surface
        "HCL",
        "Terraform",  # IaC — owned by /cloud-config-audit (Checkov)
        "Go Template",
        "Jsonnet",
        "Starlark",
        "Makefile",
        "HTML",
        "CSS",
        "SCSS",
        "Text",
        "Gherkin",
        "PLpgSQL",
        "Jinja",
        "Mustache",
        "Smarty",
        "Open Policy Agent",  # Rego policy — no package graph
        "JSON",
    }
)
# Languages whose dependency graph IS built, but by a dedicated non-
# manifest_parsers lane rather than a LANGUAGE_ECOSYSTEMS manifest mapping.
# Go's module graph is the portfolio-graph L1 layer (go.mod fetch in
# build_portfolio_graph.py), so Go is covered even though it is absent from
# LANGUAGE_ECOSYSTEMS — without this the dominant portfolio language would
# flag on every run, inverting the whole point of the tripwire.
GRAPHED_NON_MANIFEST_LANGUAGES = frozenset({"Go"})
# Languages with a SYMBOL-TIER reachability engine wired (the rung above
# ecosystem coverage: can a dependency finding here ever reach
# `affected`?). Values are the engine + its soundness, for the row text.
# WIRING A NEW ENGINE MEANS ADDING ITS LANGUAGE HERE — the
# reachability-coverage tripwire reads this as the coverage claim, and an
# un-updated map keeps reporting drift (loud) rather than silently
# marking a language covered.
REACHABILITY_ENGINES = {
    "Go": "govulncheck symbol mode (sound both directions)",
    "Java": "joern javasrc2cpg call sites (promotion-only)",
    "C": "joern c2cpg call sites (promotion-only)",
    "C++": "joern c2cpg call sites (promotion-only)",
}
# Dominant-repo count at which an absent reachability engine is worth
# flagging. Higher than LANGUAGE_COVERAGE_THRESHOLD on purpose: wiring a
# reachability engine costs a validated pilot, so the bar to call its
# absence drift is portfolio mass, not presence.
REACHABILITY_COVERAGE_THRESHOLD = 50
# Dated watch register for the un-mechanizable revisit triggers (OSV
# call-graph data, an Apache-licensed engine maturing) — see
# check_reachability_coverage leg 2.
REACHABILITY_WATCH_REL = "progress-tracker/configs/reachability-watch.yaml"
# The portfolio language cache (loc-dashboard / build_portfolio_graph
# language harvest): one JSON object per line,
# {"repo": "org/name", "languages": {"Go": <bytes>, ...}}.
LANG_CACHE_REL = (
    "analysis-results/findings/_manifest/portfolio-lang/gh-languages-cache-merged.jsonl"
)
# The gh-languages cache is NOT refetched on a cadence, so the language-
# coverage tripwire above can run on stale data and miss a genuinely new
# language/ecosystem entering the portfolio. It is a slow-moving signal
# (portfolio language mix shifts over months), so a generous 30-day window
# stays quiet through normal churn while still catching a cache that has
# gone unrefreshed long enough to blind the coverage backstop.
LANGUAGE_CACHE_MAX_AGE_DAYS = 30


def _now():
    return datetime.datetime.now(datetime.UTC)


def _age_days(dt: datetime.datetime) -> float:
    return (_now() - dt).total_seconds() / 86400


def _parse_iso(s: str) -> datetime.datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s.strip(), fmt).replace(tzinfo=datetime.UTC)
        except (ValueError, AttributeError):
            continue
    return None


def _mtime(p: Path) -> datetime.datetime | None:
    try:
        return datetime.datetime.fromtimestamp(p.stat().st_mtime, tz=datetime.UTC)
    except OSError:
        return None


def _git_head_date(repo: Path) -> datetime.datetime | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%cI"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
        return datetime.datetime.fromisoformat(out).astimezone(datetime.UTC)
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def item(name, status, detail, refresh=None):
    d = {"item": name, "status": status, "detail": detail}
    if refresh:
        d["refresh"] = refresh
    return d


# --------------------------------------------------------------------------
# checks — each returns a list of report items
# --------------------------------------------------------------------------


def watched_feeds() -> list[tuple]:
    """(name, optional) for every feed fetch_feeds.py knows about.

    Driven from fetch_feeds.FEEDS rather than a literal list here: a
    hardcoded ("epss", "kev") is how a newly added feed goes silently
    unmonitored, which is the one failure a staleness checker must not
    have. Falls back to the known-public pair if fetch_feeds cannot be
    imported, so this check degrades instead of vanishing.
    """
    try:
        mod = importlib.import_module("traust.cli.fetch_feeds")
        return [(n, bool(s.get("internal"))) for n, s in mod.FEEDS.items()]
    except Exception:
        return [("epss", False), ("kev", False)]


def _feed_row_prefix(name: str) -> str:
    """`feeds:` for a security source, `registry:` for a reference one.

    Derived from membership in config/feeds.yaml rather than hardcoded, so
    the row name follows the CATEGORY instead of the fetch mechanism.
    `product-definitions` is fetched by fetch_feeds but is Red Hat Product
    Security's product/ownership registry — zero vulnerability data — and
    calling its row `feeds:product-definitions` kept re-merging two
    categories the registry exists to separate. A source that cannot be
    classified (unreadable registry) reports as a feed: the conservative
    side, since under-reporting a security source is the worse error.
    """
    try:
        from traust.registry import feeds_config as fc

        return "feeds" if name in fc.cached_sources() else "registry"
    except Exception:
        return "feeds"


def check_feeds(engine) -> list[dict]:
    # Resolve through the registry so the checker and fetch_feeds can
    # never disagree about where the cache lives. They did once: with
    # FEEDS_CACHE_DIR unset the fetcher wrote one tree while every
    # consumer read another, and the corpus copy sat 38 days stale while
    # a refresh reported success (measured 2026-08-25).
    from traust.context import workspace_dir
    from traust.registry.feeds_config import feeds_cache_dir

    cache = feeds_cache_dir(engine=engine)
    meta_p = cache / "feeds-meta.json"
    if not meta_p.is_file():
        ws = workspace_dir(engine)
        legacy = _ar(ws) / "feeds" / "feeds-meta.json"
        if legacy.is_file():  # one-release compatibility read
            meta_p = legacy
    if not meta_p.is_file():
        return [
            item(
                "feeds:epss+kev",
                "pending",
                "no feeds cache yet",
                "python3 -m traust.cli.fetch_feeds",
            )
        ]
    try:
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [item("feeds:meta", "unavailable", "feeds-meta unparseable")]
    out = []
    for feed, optional in watched_feeds():
        threshold = FEED_STALE_HOURS_BY_NAME.get(feed, FEED_STALE_HOURS)
        # internal feeds are excluded from `--feed all`, so name them
        refresh = (
            "python3 -m traust.cli.fetch_feeds --feed " + feed
            if optional
            else "python3 -m traust.cli.fetch_feeds"
        )
        row = f"{_feed_row_prefix(feed)}:{feed}"
        t = _parse_iso((meta.get(feed) or {}).get("retrieved_at", ""))
        if t is None:
            # An optional (VPN-only) feed nobody has fetched is a normal
            # state, not a broken one — pending, not unavailable.
            out.append(
                item(
                    row,
                    "pending" if optional else "unavailable",
                    "never fetched (optional, VPN-only)" if optional else "no retrieval timestamp",
                    refresh if optional else None,
                )
            )
            continue
        hours = _age_days(t) * 24
        status = "fresh" if hours <= threshold else "stale"
        out.append(
            item(
                row,
                status,
                f"retrieved {t.date().isoformat()} ({hours:.0f}h ago; threshold {threshold}h)",
                refresh if status != "fresh" else None,
            )
        )
    return out


def check_findings_db(ws: Path) -> list[dict]:
    db = _ar(ws) / "graph" / "findings.db"
    if not db.is_file():
        return [
            item(
                "findings.db",
                "pending",
                "projection not built",
                "python3 -m traust.cli corpus findings-db",
            )
        ]
    try:
        import sqlite3

        con = sqlite3.connect(db)
        row = con.execute("SELECT value FROM meta WHERE key='built_at'").fetchone()
        con.close()
        built = _parse_iso(row[0]) if row else None
    except Exception as e:
        return [item("findings.db", "unavailable", f"cannot read meta: {e}")]
    if built is None:
        return [item("findings.db", "unavailable", "no built_at stamp")]
    newest, newest_p = None, None
    root = _ar(ws) / "findings"
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(
                ("-findings-layer.json", "-findings-current.json", "-security-audit.json")
            ):
                p = Path(dirpath) / fn
                try:
                    mt = p.stat().st_mtime
                except OSError:
                    continue
                if newest is None or mt > newest:
                    newest, newest_p = mt, p
    if newest is None:
        return [item("findings.db", "unavailable", "no ledger/report files found")]
    newest_dt = datetime.datetime.fromtimestamp(newest, tz=datetime.UTC)
    if newest_dt > built:
        return [
            item(
                "findings.db",
                "stale",
                f"built {built.isoformat()} but ledgers changed since "
                f"(newest: {newest_p.name} @ {newest_dt.isoformat()})",
                "python3 -m traust.cli corpus findings-db",
            )
        ]
    # Generator-newer-than-artifact: the schema/views are baked into the
    # .db at build time, so a code change to the builder leaves existing
    # artifacts serving the OLD definitions while the data looks fresh —
    # measured 2026-07-31: the v_open enum fix (v0.235.2) shipped while
    # the production projection kept hiding 751 in-progress findings
    # until a manual rebuild. mtime is checkout-time on fresh clones,
    # which at worst prompts one harmless rebuild.
    builder = _module_file("traust_engine.corpus.findings_db")
    if builder is None:
        builder_mt = None
    else:
        try:
            builder_mt = datetime.datetime.fromtimestamp(builder.stat().st_mtime, tz=datetime.UTC)
        except OSError:
            builder_mt = None
    if builder_mt is not None and builder_mt > built:
        return [
            item(
                "findings.db",
                "stale",
                f"built {built.isoformat()} but build_findings_db.py changed "
                f"since ({builder_mt.isoformat()}) — the projection may carry "
                "outdated schema/views",
                "python3 -m traust.cli corpus findings-db",
            )
        ]
    return [
        item(
            "findings.db", "fresh", f"built {built.isoformat()}, no ledger or builder changes since"
        )
    ]


def check_fp_precedent_cache(ws: Path) -> list[dict]:
    """FP-precedent cache vs the disposition ledgers it projects: new
    countersign/triage/validation events after the cache was built mean
    /triage and the audit Precision Gate are routing on stale precedent
    (error-correction plan §6, Phase 4)."""
    cache_p = _ar(ws) / "graph" / "fp-precedent-cache.json"
    if not cache_p.is_file():
        return [
            item(
                "fp-precedent-cache",
                "pending",
                "projection not built",
                "python3 -m traust.cli corpus precedent build",
            )
        ]
    try:
        stamp = (json.loads(cache_p.read_text(encoding="utf-8")).get("metadata") or {}).get(
            "generated", ""
        )
    except (OSError, json.JSONDecodeError):
        stamp = ""
    built = _parse_iso(stamp)
    if built is None and stamp:
        # the builder stamps isoformat with a +00:00 offset, not Z
        try:
            built = datetime.datetime.fromisoformat(stamp).astimezone(datetime.UTC)
        except ValueError:
            built = None
    if built is None:
        return [item("fp-precedent-cache", "unavailable", "no metadata.generated stamp")]
    newest, newest_p = None, None
    root = _ar(ws) / "findings"
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith("-findings-layer.json"):
                p = Path(dirpath) / fn
                try:
                    mt = p.stat().st_mtime
                except OSError:
                    continue
                if newest is None or mt > newest:
                    newest, newest_p = mt, p
    if newest is None:
        return [item("fp-precedent-cache", "unavailable", "no disposition ledgers found")]
    newest_dt = datetime.datetime.fromtimestamp(newest, tz=datetime.UTC)
    if newest_dt > built:
        return [
            item(
                "fp-precedent-cache",
                "stale",
                f"built {built.isoformat()} but ledgers changed since "
                f"(newest: {newest_p.name} @ {newest_dt.isoformat()}) — "
                f"new adjudications are not yet citeable precedent",
                "python3 -m traust.cli corpus precedent build",
            )
        ]
    return [
        item("fp-precedent-cache", "fresh", f"built {built.isoformat()}, no ledger changes since")
    ]


def _newest_by_suffix(
    root: Path, suffixes: tuple[str, ...]
) -> tuple[datetime.datetime | None, Path | None]:
    """(mtime, path) of the newest file under root matching any suffix —
    the freshness idiom the findings-db and fp-precedent-cache rows use."""
    newest, newest_p = None, None
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(suffixes):
                p = Path(dirpath) / fn
                try:
                    mt = p.stat().st_mtime
                except OSError:
                    continue
                if newest is None or mt > newest:
                    newest, newest_p = mt, p
    if newest is None:
        return None, None
    return datetime.datetime.fromtimestamp(newest, tz=datetime.UTC), newest_p


def check_rule_mining(ws: Path) -> list[dict]:
    """Rule-mining artifact vs the disposition ledgers it mines: new
    confirmed/resolved events after the last mine mean the rule-pack
    backlog, precision picture, and TP corpus are running on stale
    ground truth. Weekly-lane grace (RULE_MINING_LAG_DAYS): ledger
    churn inside the week is normal; the row goes loud only when
    ledger changes are more than a week newer than the artifact — the
    post-wave trigger for traust_engine.sweep.rule_lane."""
    refresh = "python3 -m traust.cli sweep rule-lane"
    art = _pt(ws) / "metrics" / "rule-mining" / "rule-mining.json"
    if not art.is_file():
        return [item("rule-mining", "pending", "rule-mining artifact not built yet", refresh)]
    built = _mtime(art)
    if built is None:
        return [item("rule-mining", "unavailable", "artifact mtime unreadable")]
    newest_dt, newest_p = _newest_by_suffix(_ar(ws), ("-findings-layer.json",))
    if newest_dt is None:
        return [
            item(
                "rule-mining", "unavailable", "no disposition ledgers found under analysis-results"
            )
        ]
    lag_days = (newest_dt - built).total_seconds() / 86400
    if lag_days > RULE_MINING_LAG_DAYS:
        return [
            item(
                "rule-mining",
                "stale",
                f"mined {built.date().isoformat()} but ledgers changed "
                f"through {newest_dt.date().isoformat()} "
                f"({lag_days:.0f}d newer; threshold {RULE_MINING_LAG_DAYS}d; "
                f"newest: {newest_p.name}) — new confirmations are not yet "
                f"rule-mining fuel",
                refresh,
            )
        ]
    if lag_days > 0:
        return [
            item(
                "rule-mining",
                "fresh",
                f"mined {built.date().isoformat()}; ledger changes "
                f"since are {lag_days:.1f}d newer (inside the "
                f"{RULE_MINING_LAG_DAYS}d weekly-lane window)",
            )
        ]
    return [
        item("rule-mining", "fresh", f"mined {built.date().isoformat()}, no ledger changes since")
    ]


def _inputs_root(ws: Path) -> Path:
    """The inputs inventory: ``locations.inputs`` when a config home resolves,
    else ``<ws>/inputs`` (the same default ``inputs_dir`` uses)."""
    fallback = ws / "inputs"
    try:
        configured = inputs_dir(load_engine())
    except SystemExit:
        return fallback
    except Exception:
        return fallback
    # The configured inventory is authoritative only for the workspace it
    # belongs to; a caller passing a different workspace (tests build one in
    # tmp_path) gets that workspace's own inputs/ tree.
    try:
        configured.resolve().relative_to(ws.resolve())
    except ValueError:
        return fallback
    return configured


def check_graphs(ws: Path) -> list[dict]:
    out = []
    inputs = _inputs_root(ws)
    inputs_head = _git_head_date(inputs)
    for name, path, stamp_getter in (
        (
            "repo-graph",
            ws / "analysis-results/graph/repo-graph.json",
            lambda p: _parse_iso((json.loads(p.read_text(encoding="utf-8"))).get("generated", "")),
        ),
        ("portfolio-graph", ws / "analysis-results/graph/portfolio-graph.db", _mtime),
    ):
        if not path.is_file():
            out.append(item(name, "pending", "artifact absent"))
            continue
        try:
            stamp = stamp_getter(path)
        except (json.JSONDecodeError, OSError):
            stamp = None
        if stamp is None:
            out.append(
                item(
                    name,
                    "unavailable",
                    "no usable timestamp (metadata gap — consider stamping source SHA at build)",
                )
            )
            continue
        if inputs_head is None:
            out.append(item(name, "unavailable", "inputs inventory not readable"))
            continue
        # repo-graph's `generated` stamp is date-only — compare at day
        # granularity or every same-day inputs commit false-positives
        if name == "repo-graph":
            is_stale = inputs_head.date() > stamp.date()
        else:
            is_stale = inputs_head > stamp
        if is_stale:
            out.append(
                item(
                    name,
                    "stale",
                    f"built {stamp.date().isoformat()} but "
                    f"inputs inventory HEAD moved "
                    f"{inputs_head.date().isoformat()} — inventory/ownership "
                    f"may have changed",
                    f"rebuild {name} from inputs (see its skill)",
                )
            )
        else:
            out.append(
                item(name, "fresh", f"built {stamp.date().isoformat()}, inputs unchanged since")
            )
    return out


def check_impact_artifacts(ws: Path) -> list[dict]:
    """Impact-analysis artifacts vs the portfolio graph they were derived
    from: an artifact older than the current graph build may misstate the
    blast radius (repos added/removed, dependency edges changed). Advisory
    data also moves, but that staleness is unbounded by design — the graph
    comparison is the deterministic pair we can check."""
    out = []
    impact_dir = ws / "analysis-results/impact"
    if not impact_dir.is_dir():
        return out  # nothing produced yet — not even pending
    db = ws / "analysis-results/graph/portfolio-graph.db"
    db_stamp = _mtime(db) if db.is_file() else None
    for art in sorted(impact_dir.glob("*-impact-analysis.json")):
        name = f"impact:{art.stem.removesuffix('-impact-analysis')}"
        stamp = _mtime(art)
        if db_stamp is None:
            out.append(item(name, "unavailable", "portfolio-graph.db absent"))
        elif stamp is not None and db_stamp > stamp:
            out.append(
                item(
                    name,
                    "stale",
                    f"artifact from {stamp.date().isoformat()} predates the "
                    f"portfolio-graph build {db_stamp.date().isoformat()} — "
                    f"blast radius may have shifted",
                    "re-run /impact-analysis for this CVE",
                )
            )
        else:
            out.append(item(name, "fresh", "artifact newer than the graph it queries"))
    return out


def check_validation_benchmark(ws: Path) -> list[dict]:
    """P7 hybrid cadence, monthly leg: the validation benchmark scorecard
    must be younger than 35 days; the release-cut leg is
    traust_engine.sweep.benchmark check-trigger in the release flow."""
    card = ws / "analysis-results/scan-testing/validation-benchmark/scorecard.json"
    if not card.is_file():
        return [
            item(
                "validation-benchmark",
                "pending",
                "no benchmark run recorded yet (plan P7)",
                "run python3 -m traust.cli sweep benchmark plan",
            )
        ]
    stamp = _mtime(card)
    import datetime as _dt

    age = (_dt.datetime.now(_dt.UTC) - stamp).days if stamp else None
    if age is not None and age > 35:
        return [
            item(
                "validation-benchmark",
                "stale",
                f"last scored {age} days ago (monthly cadence)",
                "schedule a benchmark run on a disposable cluster",
            )
        ]
    return [
        item(
            "validation-benchmark",
            "fresh",
            f"scored {age} day(s) ago" if age is not None else "scored",
        )
    ]


def check_repo_liveness(ws: Path) -> list[dict]:
    p = _pt(ws) / "metrics" / "repo-liveness.json"
    mt = _mtime(p)
    if mt is None:
        return [
            item(
                "repo-liveness",
                "pending",
                "artifact absent",
                "python3 -m traust.cli.check_repo_liveness (census Step 2b)",
            )
        ]
    days = _age_days(mt)
    status = "fresh" if days <= LIVENESS_STALE_DAYS else "stale"
    return [
        item(
            "repo-liveness",
            status,
            f"{days:.0f}d old (threshold {LIVENESS_STALE_DAYS}d)",
            "census Step 2b" if status != "fresh" else None,
        )
    ]


def _manifest_parsers_mod():
    """Load manifest_parsers — authority on GitHub language → ecosystem."""
    return importlib.import_module("traust_engine.portfolio.parsers")


def _progress_tracker_for_checks(ws: Path, engine) -> Path:
    """Config progress-tracker when ws is the configured workspace; else ws tree."""
    if ws.resolve() == workspace_dir(engine).resolve():
        return progress_tracker_dir(engine)
    return ws / "progress-tracker"


def _analysis_results_for_checks(ws: Path, engine) -> Path:
    """Config analysis-results when ws is the configured workspace; else ws tree."""
    if ws.resolve() == workspace_dir(engine).resolve():
        return analysis_results_dir(engine)
    return ws / "analysis-results"


def check_corpus_registration(ws: Path, engine) -> list[dict]:
    """Unregistered output trees = drift between disk and corpus config."""
    try:
        res = engine.corpus.resolve_under(_analysis_results_for_checks(ws, engine))
    except Exception as e:
        return [item("corpus-registration", "unavailable", str(e)[:160])]
    if not res.warnings:
        return [item("corpus-registration", "fresh", "all output trees registered")]
    return [
        item(
            "corpus-registration",
            "drift",
            f"{len(res.warnings)} corpus warning(s): " + "; ".join(res.warnings[:5]),
            "/corpus-intake to register or retire trees",
        )
    ]


def check_ref_provenance(ws: Path, engine) -> list[dict]:
    """Slug-derived ref vs declared metadata.ref (branch-awareness
    Phase 4,; plan: progress-tracker/plans/
    branch-awareness-plan.md). corpus.py resolves ref identity —
    declared `metadata.ref` preferred, legacy `__release-X.Y` slug
    fallback. A report carrying BOTH must agree: a disagreement means
    the file was moved/renamed under a stale slug, or the writer
    stamped the wrong checkout. Reported symmetrically — the checker
    never picks a winner."""
    try:
        res = engine.corpus.resolve_under(_analysis_results_for_checks(ws, engine))
    except Exception as e:
        return [item("ref-provenance", "unavailable", str(e)[:160])]
    declared = [r for r in res.records if r.ref_source == "metadata"]
    disagreements = []
    for r in declared:
        slug_ref = split_ref(r.base)[1] or split_ref(r.repo_dir)[1]
        if slug_ref and slug_ref != r.ref:
            loc = "/".join(p for p in (r.tree, r.product, r.repo_dir) if p)
            disagreements.append(
                f"{loc}/{r.base}: slug says {slug_ref!r}, metadata.ref says {r.ref!r}"
            )
    if disagreements:
        return [
            item(
                "ref-provenance",
                "drift",
                f"{len(disagreements)} report(s) whose slug-derived ref and "
                f"declared metadata.ref disagree: " + "; ".join(disagreements[:3]),
                "inspect each report — stale slug after a move/rename vs a "
                "wrong-checkout stamp; correcting either is a human "
                "decision",
            )
        ]
    return [
        item(
            "ref-provenance",
            "fresh",
            f"no slug/declared ref disagreement ({len(declared)} report(s) declare metadata.ref)",
        )
    ]


def check_adr_registry(ws: Path) -> list[dict]:
    reg_p = _pt(ws) / "configs" / "compliance" / "adr-registry.yaml"
    if not reg_p.is_file():
        return [item("adr-registry", "pending", "not built yet (compliance Phase 2c)")]
    if yaml is None:
        return [item("adr-registry", "unavailable", "PyYAML missing")]
    reg = yaml.safe_load(reg_p.read_text(encoding="utf-8")) or {}
    out = []
    for r in reg.get("registers") or []:
        name, url, pin = r.get("name"), r.get("repo"), r.get("pin")
        if not str(url).startswith("https://"):
            out.append(
                item(
                    f"adr-registry:{name}", "unavailable", f"non-https registry url refused: {url}"
                )
            )
            continue
        try:
            head = subprocess.run(
                ["git", "ls-remote", "--", url, "HEAD"],
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
            ).stdout.split()[0]
        except (subprocess.SubprocessError, OSError, IndexError):
            out.append(item(f"adr-registry:{name}", "unavailable", f"cannot reach {url}"))
            continue
        if pin and head and not head.startswith(pin):
            out.append(
                item(
                    f"adr-registry:{name}",
                    "stale",
                    f"pinned {pin[:12]} but upstream HEAD {head[:12]} — "
                    "decisions may have been added/amended/superseded",
                    "review upstream changes, then advance the pin (deliberate config change)",
                )
            )
        else:
            out.append(
                item(f"adr-registry:{name}", "fresh", f"pin matches upstream HEAD ({head[:12]})")
            )
    return out or [item("adr-registry", "unavailable", "registry has no registers")]


def check_checkov_pin(ws: Path) -> list[dict]:
    """Pinned Checkov vs PyPI. The ~1000 bundled policies ship INSIDE
    the release, so an aging pin means aging cloud-config policies —
    that is the drift this check makes visible. Checkov ships several
    patch releases a week, so the signal is the AGE of the pinned
    release, not version lag."""
    runner = skill_dir("cloud-config-audit") / "run_checkov.py"
    if not runner.is_file():
        return [item("checkov-pin", "pending", "cloud-config-audit runner not in tree")]
    import re

    m = re.search(r'PINNED_CHECKOV_VERSION\s*=\s*"([^"]+)"', runner.read_text(encoding="utf-8"))
    if not m:
        return [
            item(
                "checkov-pin",
                "unavailable",
                "cannot parse PINNED_CHECKOV_VERSION from run_checkov.py",
            )
        ]
    pinned = m.group(1)
    try:
        import urllib.request

        with urllib.request.urlopen("https://pypi.org/pypi/checkov/json", timeout=30) as resp:
            data = json.load(resp)
    except Exception as e:  # offline runs stay loud, never crash
        return [item("checkov-pin", "unavailable", f"cannot reach PyPI ({type(e).__name__})")]
    latest = data.get("info", {}).get("version", "")
    uploads = data.get("releases", {}).get(pinned) or []
    uploaded = (
        _parse_iso((uploads[0].get("upload_time_iso_8601") or "")[:19] + "Z") if uploads else None
    )
    refresh = (
        "review release notes; bump PINNED_CHECKOV_VERSION in "
        "harnessing/3-audit/cloud-config-audit/scripts/run_checkov.py; update "
        "the docs/external-dependencies.md verified date; "
        "re-baseline one known IaC tree before a sweep "
        "(deliberate config change)"
    )
    if pinned == latest:
        return [item("checkov-pin", "fresh", f"pinned {pinned} == latest PyPI release")]
    if uploaded is None:
        return [
            item(
                "checkov-pin", "unavailable", f"pinned {pinned} not found on PyPI (latest {latest})"
            )
        ]
    age = _age_days(uploaded)
    if age > CHECKOV_PIN_MAX_AGE_DAYS:
        return [
            item(
                "checkov-pin",
                "stale",
                f"pinned {pinned} released {age:.0f}d ago "
                f"(threshold {CHECKOV_PIN_MAX_AGE_DAYS}d; latest "
                f"{latest}) — the bundled policies age with the "
                "pin",
                refresh,
            )
        ]
    return [
        item(
            "checkov-pin",
            "fresh",
            f"pinned {pinned} is {age:.0f}d old (threshold "
            f"{CHECKOV_PIN_MAX_AGE_DAYS}d; latest {latest})",
        )
    ]


def check_yara_rules_pin(ws: Path) -> list[dict]:
    """Pinned ReversingLabs YARA rules SHA vs upstream `develop` HEAD.
    The malware-family pack ages FASTER than the yara engine (whose floor
    the external-tools `yara` row watches) — a frozen pin stops matching
    NEW families, so a mismatch is the drift this makes visible. Rolling
    `develop` branch with no releases (~monthly cadence), so the signal is
    SHA divergence, modeled on the adr-registry pin check."""
    runner = _module_file("traust_engine.adapters.yara")
    if runner is None or not runner.is_file():
        return [item("yara-rules-pin", "pending", "run_yara module not in tree")]
    import re

    text = runner.read_text(encoding="utf-8")
    m_sha = re.search(r'RL_RULES_SHA\s*=\s*"([0-9a-f]{40})"', text)
    m_repo = re.search(r'RL_RULES_REPO\s*=\s*"(https://[^"]+)"', text)
    if not (m_sha and m_repo):
        return [
            item(
                "yara-rules-pin",
                "unavailable",
                "cannot parse RL_RULES_SHA/RL_RULES_REPO from traust_engine.adapters.yara",
            )
        ]
    pin, url = m_sha.group(1), m_repo.group(1)
    try:
        head = subprocess.run(
            ["git", "ls-remote", "--", url, "develop"],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
        ).stdout.split()[0]
    except (subprocess.SubprocessError, OSError, IndexError):
        return [item("yara-rules-pin", "unavailable", f"cannot reach {url}")]
    refresh = (
        "review upstream changes, then bump RL_RULES_SHA in "
        "traust_engine.adapters.yara and the "
        "docs/external-dependencies.md "
        "verified date (deliberate config change — never "
        "auto-advanced)"
    )
    if head and head != pin:
        return [
            item(
                "yara-rules-pin",
                "stale",
                f"pinned {pin[:12]} but upstream develop HEAD "
                f"{head[:12]} — new malware-family rules may have "
                "landed that scans won't match",
                refresh,
            )
        ]
    return [item("yara-rules-pin", "fresh", f"pin matches upstream develop HEAD ({pin[:12]})")]


def check_argus_rules_pin(ws: Path) -> list[dict]:
    """Pinned argus-observe-rules SHA vs upstream `main` HEAD.

    An OPT-IN crypto/PQC supplement, not the default pack — so a stale
    pin costs coverage on a lane nobody is forced to run, not silent
    scan degradation. It is watched anyway for the same reason the YARA
    pack is: an unmoving pin on a rolling branch is invisible staleness,
    and this pack's whole value is new crypto/PQC detections landing
    upstream. Advancing the pin is a deliberate config change — the
    rules are uncalibrated against our ledger, so a bump should be
    reviewed, never auto-advanced."""
    runner = _module_file("traust_engine.adapters.opengrep")
    if runner is None or not runner.is_file():
        return [item("argus-rules-pin", "pending", "run_opengrep module not in tree")]
    import re as _re

    text = runner.read_text(encoding="utf-8")
    m_sha = _re.search(r'ARGUS_RULES_SHA\s*=\s*"([0-9a-f]{40})"', text)
    m_repo = _re.search(r'ARGUS_RULES_REPO\s*=\s*"(https://[^"]+)"', text)
    if not (m_sha and m_repo):
        return [
            item(
                "argus-rules-pin",
                "unavailable",
                "cannot parse ARGUS_RULES_SHA/ARGUS_RULES_REPO from "
                "traust_engine.adapters.opengrep",
            )
        ]
    pin, url = m_sha.group(1), m_repo.group(1)
    try:
        head = subprocess.run(
            ["git", "ls-remote", "--", url, "main"],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
        ).stdout.split()[0]
    except (subprocess.SubprocessError, OSError, IndexError):
        return [item("argus-rules-pin", "unavailable", f"cannot reach {url}")]
    refresh = (
        "review upstream changes, then bump ARGUS_RULES_SHA in "
        "traust_engine.adapters.opengrep and the "
        "docs/external-dependencies.md verified date (deliberate "
        "config change on an uncalibrated pack — never "
        "auto-advanced)"
    )
    if head and head != pin:
        return [
            item(
                "argus-rules-pin",
                "stale",
                f"pinned {pin[:12]} but upstream main HEAD "
                f"{head[:12]} — new crypto/PQC rules may have landed "
                "that the opt-in supplement won't match",
                refresh,
            )
        ]
    return [item("argus-rules-pin", "fresh", f"pin matches upstream main HEAD ({pin[:12]})")]


# Held in LOCKSTEP with build_rescan_worklist.py's
# THREAT_MODEL_QUARTERLY_DAYS: that lane drains the pool on a quarterly
# cadence, and this row is the dead-timer that fires only if the lane
# stops draining. Two different numbers would mean either a row that
# can never go stale or one that is permanently stale.
THREAT_MODEL_STALE_DAYS = 92


def check_threat_model_staleness(ws: Path) -> list[dict]:
    """Backstop for the threat-model re-model cadence (shipped
    2026-08-05, progress-tracker/plans/threat-model-cadence-plan.md).
    Three router lanes now refresh models — a `/threat-model pr` stamp
    on diff rows (Phase 1, report-only), a `threat-model-review` row on
    major/minor releases (Phase 2), and a `threat-model-quarterly`
    calendar pool (Phase 3) — so a model older than the quarterly
    threshold means the LANE is not draining, not merely that time
    passed. Before those lanes existed this row was the only signal at
    all; it now plays the dead-timer role docs-semantic-sweep plays for
    behavioral doc claims.

    Staleness = the model's provenance `date:` (section 7 — the
    authoritative as-of stamp; models also record the code SHA they were
    built against as `target: <url> @ <sha>`, so no schema change is
    needed to measure this). Routes attention only — never re-models
    (that has agent cost and is an operator decision)."""
    import re as _re

    root = _ar(ws)
    if not root.is_dir():
        return [item("threat-model", "unavailable", "analysis-results not checked out")]
    models = sorted(root.rglob("*-threat-model.md"))
    if not models:
        return [item("threat-model", "pending", "no threat models emitted yet")]
    date_rx = _re.compile(r"^-?\s*date:\s*(\d{4}-\d{2}-\d{2})", _re.MULTILINE)
    now = datetime.datetime.now(datetime.UTC)
    dated = undated = 0
    stale: list[tuple[int, str]] = []
    for m in models:
        try:
            text = m.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        prov = text.split("## 7. Provenance", 1)
        dm = date_rx.search(prov[1] if len(prov) > 1 else text)
        d = _parse_iso(dm.group(1) + "T00:00:00Z") if dm else None
        if d is None:
            undated += 1
            continue
        dated += 1
        age = (now - d).days
        if age > THREAT_MODEL_STALE_DAYS:
            stale.append((age, m.name.replace("-threat-model.md", "")))
    refresh = (
        "the threat-model-quarterly lane is not draining — run "
        "python3 -m traust.cli.build_rescan_worklist, "
        "then python3 harnessing/2-threat-model/threat-model/scripts/"
        "emit_drain_tranche.py, and dispatch the "
        "threat-model rows (/threat-model review --auto); cadence "
        "plan: progress-tracker/plans/threat-model-cadence-plan.md"
    )
    if stale:
        stale.sort(reverse=True)
        worst = ", ".join(f"{n} ({a}d)" for a, n in stale[:3])
        return [
            item(
                "threat-model",
                "stale",
                f"{len(stale)} of {dated} dated model(s) exceed the "
                f"{THREAT_MODEL_STALE_DAYS}d quarterly cadence; "
                f"oldest: {worst}" + (f"; {undated} undated" if undated else ""),
                refresh,
            )
        ]
    return [
        item(
            "threat-model",
            "fresh",
            f"{dated} model(s), none older than "
            f"{THREAT_MODEL_STALE_DAYS}d" + (f" ({undated} undated)" if undated else ""),
        )
    ]


# Roster and expected floors live in config/external-tools.yaml — the
# single source of truth shared with the orchestrator job-image build.
# Checkov/bicep/pqc-scan are deliberately absent from the manifest:
# hard-pinned in their runners and covered by their own drift rows.
EXTERNAL_TOOLS_MANIFEST = optional_config_path("external-tools.yaml")
EXTERNAL_TOOLS = None  # tests may inject a list; None = load manifest

_SEMVER_RE = r"(\d+)\.(\d+)\.(\d+)"

# Sentinel + marker for a tool that answers its version probe with an
# untagged build string instead of a release semver (see
# _installed_tool_version). Not a version — never fed to the comparison.
# Pattern kept as a string and compiled at use (module has no top-level
# `re` import; the version helpers import it locally).
_UNTAGGED = "untagged"
_UNTAGGED_BUILD_RE_SRC = r"\b(HEAD|SNAPSHOT|nightly|dev-build|dirty)\b"


# version_cmd is config-supplied argv handed to subprocess.run — without
# a binary allowlist, write access to config/external-tools.yaml is
# arbitrary code execution in every drift run (assessment 2026-07-31,
# rollup-F2). Only known scanner binaries may be probed, only with
# flag-style args (no interpreters, no -c payloads, no paths).
_VERSION_CMD_BINARIES = frozenset(
    {
        "opengrep",
        "gitleaks",
        "syft",
        "grype",
        "osv-scanner",
        "cosign",
        "skopeo",
        "govulncheck",
        "pip-audit",
        "checkov",
        "trivy",
        "semgrep",
        "kube-linter",
        "conftest",
        "hadolint",
        "tokei",
        "scc",
        "cloc",
        "yara",
        "joern",
        # `mewt` is a mutation engine that runs the TARGET's own test suite,
        # so it executes arbitrary code by design -- but only under its
        # campaign subcommands. It is safe here for the same reason `go` is:
        # _vet_version_cmd admits only flag-shaped args or the literal
        # "version", so `mewt --version` passes and `mewt run <path>` cannot
        # be spelled from the manifest at all.
        "mewt",
        # `go` is a toolchain driver, not a scanner, and is the most dangerous
        # entry here: `go run`/`go generate` execute arbitrary code. It is safe
        # ONLY because _vet_version_cmd restricts args to flag-shaped tokens or
        # the literal "version" -- `go version` passes, `go run x` does not. If
        # that arg vetting is ever loosened, remove this entry first.
        "go",
    }
)
_VERSION_ARG_RX = None  # compiled lazily below


def _vet_version_cmd(argv: list[str]) -> str | None:
    """Reason the version_cmd is unsafe to execute, or None if OK."""
    global _VERSION_ARG_RX
    if _VERSION_ARG_RX is None:
        import re as _re

        _VERSION_ARG_RX = _re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*$|^version$")
    head = argv[0]
    if "/" in head or head not in _VERSION_CMD_BINARIES:
        return (
            f"version_cmd binary {head!r} not in the drift-check allowlist (_VERSION_CMD_BINARIES)"
        )
    for a in argv[1:]:
        if not _VERSION_ARG_RX.match(a):
            return f"version_cmd arg {a!r} is not a plain version flag"
    return None


def _load_external_tools() -> tuple[list[dict] | None, str | None]:
    """Manifest entries as dicts, or (None, reason). Malformed entries
    fail the whole load loudly — a partially-read roster would report
    missing tools as covered."""
    if yaml is None:
        return None, "PyYAML missing"
    if EXTERNAL_TOOLS_MANIFEST is None or not EXTERNAL_TOOLS_MANIFEST.is_file():
        return None, "external-tools.yaml missing from $TRAUST_CONFIG_HOME"
    try:
        doc = yaml.safe_load(EXTERNAL_TOOLS_MANIFEST.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return None, f"manifest unparseable ({type(e).__name__})"
    tools = (doc or {}).get("tools")
    if not isinstance(tools, list) or not tools:
        return None, "manifest has no tools list"
    out = []
    for t in tools:
        name = t.get("name")
        argv = t.get("version_cmd")
        up = t.get("upstream") or {}
        if not (name and isinstance(argv, list) and argv):
            return None, (f"malformed entry {name or t!r}: need name and version_cmd")
        # upstream is OPTIONAL. Some tools can be floored but not compared:
        # Go tags releases goX.Y.Z, not vX.Y.Z, so a semver staleness check
        # would answer confidently and wrongly. A half-specified row is
        # better than an absent tool or a fabricated verdict -- but a row
        # with ONE of kind/ref is a typo, not a decision, so still refuse.
        if bool(up.get("kind")) != bool(up.get("ref")):
            return None, (f"malformed entry {name}: upstream needs both kind and ref, or neither")
        unsafe = _vet_version_cmd([str(a) for a in argv])
        if unsafe:
            return None, f"unsafe entry {name}: {unsafe}"
        out.append(
            {
                "name": name,
                "argv": [str(a) for a in argv],
                "kind": up.get("kind"),
                "ref": up.get("ref"),
                "version_re": t.get("version_regex") or _SEMVER_RE,
                "expected": t.get("expected"),
            }
        )
    return out, None


def _installed_tool_version(argv: list[str], version_re: str = _SEMVER_RE) -> str | None:
    """First semver token in the tool's version output (or the tool's
    anchored pattern where the bare-first-semver heuristic misfires),
    or None if the tool is absent/unparseable. Missing-vs-broken is
    distinguished by the caller via shutil.which.

    stdin is DEVNULL'd: some probed binaries are REPL launchers whose
    `--version` is not a recognized flag, so they fall through to an
    interactive prompt and read the parent's stdin (joern does exactly
    this). Inheriting stdin would let a version probe consume the drift
    run's input or stall to the timeout."""
    import re

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL
        )
    except (subprocess.SubprocessError, OSError):
        return None
    out = proc.stdout + proc.stderr
    m = re.search(version_re, out)
    if m:
        return ".".join(m.groups())
    # No semver, but the tool DID answer with a self-reported build
    # marker (joern's brew HEAD build banners `Version: HEAD+20260810`).
    # Distinguishing this from "output unparseable" matters: the roster
    # entry is correct and the tool works, only the freshness comparison
    # is impossible — same class as the unstamped `go install` v0.0.0
    # case, and a different operator action (reinstall a tagged release,
    # not fix the version_cmd).
    return _UNTAGGED if re.search(_UNTAGGED_BUILD_RE_SRC, out, re.I) else None


def _latest_upstream(kind: str, ref: str) -> tuple[str, datetime.datetime | None] | None:
    """(latest release version, published-at) from the tool's home
    registry, or None if unreachable/unparseable. GITHUB_TOKEN is used
    if present (header only, never argv)."""
    import re
    import urllib.request

    try:
        if kind == "github":
            req = urllib.request.Request(
                f"https://api.github.com/repos/{ref}/releases/latest",
                headers={
                    "Accept": "application/vnd.github+json",
                    **(
                        {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
                        if os.environ.get("GITHUB_TOKEN")
                        else {}
                    ),
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
            ver, when = data.get("tag_name", ""), data.get("published_at", "")
        elif kind == "pypi":
            with urllib.request.urlopen(f"https://pypi.org/pypi/{ref}/json", timeout=30) as resp:
                data = json.load(resp)
            ver = data.get("info", {}).get("version", "")
            uploads = data.get("releases", {}).get(ver) or []
            when = (uploads[0].get("upload_time_iso_8601") or "") if uploads else ""
        elif kind == "goproxy":
            with urllib.request.urlopen(
                f"https://proxy.golang.org/{ref}/@latest", timeout=30
            ) as resp:
                data = json.load(resp)
            ver, when = data.get("Version", ""), data.get("Time", "")
        else:
            return None
    except Exception:  # offline runs stay loud, never crash
        return None
    m = re.search(_SEMVER_RE, ver)
    if not m:
        return None
    return ".".join(m.groups()), _parse_iso((when or "")[:19] + "Z")


def check_external_tools(ws: Path) -> list[dict]:
    """Installed external deterministic scanners vs their latest
    upstream release. These tools are PATH-invoked and unpinned by
    design (user-supplied prerequisites, docs/external-dependencies.md)
    — nothing else notices when a workstation's gitleaks or grype falls
    behind and its detection content silently ages. Version-lag signal
    with a grace window (EXTERNAL_TOOL_LAG_GRACE_DAYS) so normal
    release churn stays quiet. Routes attention only: upgrading is a
    deliberate toolchain change, re-verify one known-good target before
    a sweep."""
    import shutil

    tools = EXTERNAL_TOOLS
    if tools is None:
        tools, err = _load_external_tools()
        if tools is None:
            return [
                item(
                    "external-tools",
                    "unavailable",
                    f"cannot load roster: {err}",
                    "fix config/external-tools.yaml — the external-tool rows are blind without it",
                )
            ]
    out = []
    for spec in tools:
        name, argv = spec["name"], spec["argv"]
        kind, ref = spec.get("kind"), spec.get("ref")
        version_re = spec["version_re"]
        expected = spec.get("expected")
        iname = f"external-tools:{name}"
        if not (kind and ref):
            installed = _installed_tool_version(argv, version_re) if shutil.which(argv[0]) else None
            out.append(
                item(
                    iname,
                    "info",
                    f"floor-tracked only (installed {installed or 'absent'}, "
                    f"manifest floor {expected}) — no upstream comparison is "
                    "declared for this tool, so freshness is not claimed",
                )
            )
            continue
        if shutil.which(argv[0]) is None:
            out.append(
                item(
                    iname,
                    "pending",
                    "not installed on PATH — install to track "
                    "freshness (prerequisite for the skills "
                    "that invoke it)",
                )
            )
            continue
        local = _installed_tool_version(argv, version_re)
        if local is None:
            out.append(item(iname, "unavailable", "installed but version output unparseable"))
            continue
        if local == "0.0.0":
            # unstamped `go install` builds self-report v0.0.0 — lag
            # is uncomputable, not zero
            out.append(
                item(
                    iname,
                    "unavailable",
                    "installed build self-reports v0.0.0 "
                    "(unstamped) — reinstall a tagged release "
                    "to track freshness",
                )
            )
            continue
        if local == _UNTAGGED:
            # answered, but with a build marker instead of a release
            # semver (joern's brew HEAD build). Roster coverage is
            # correct and `expected` still drives the job image; only
            # the installed-vs-upstream comparison is impossible here.
            out.append(
                item(
                    iname,
                    "unavailable",
                    "installed build self-reports an untagged/HEAD build, "
                    "not a release version — freshness lag is uncomputable "
                    f"on this install (manifest expects {expected})"
                    if expected
                    else "installed build self-reports an untagged/HEAD build, "
                    "not a release version — freshness lag is uncomputable",
                    f"install {name} from a tagged release (package-manager "
                    "HEAD/--HEAD builds cannot be version-compared); the "
                    "`expected` floor still governs the job image",
                )
            )
            continue
        lv = tuple(int(x) for x in local.split("."))
        if expected:
            try:
                ev = tuple(int(x) for x in str(expected).split("."))
            except ValueError:
                ev = None
            if ev and lv < ev:
                # installed reality disagrees with the declared config
                out.append(
                    item(
                        iname,
                        "drift",
                        f"installed {local} below the manifest's expected "
                        f"{expected} (config/external-tools.yaml) — this "
                        "environment is not what the job image / floor "
                        "declares",
                        f"upgrade {name} to >= {expected}, or revise "
                        "`expected` in config/external-tools.yaml "
                        "(deliberate config change)",
                    )
                )
                continue
        latest = _latest_upstream(kind, ref)
        if latest is None:
            out.append(
                item(
                    iname,
                    "unavailable",
                    f"installed {local}; cannot reach {kind} for the latest release",
                )
            )
            continue
        latest_ver, published = latest
        uv = tuple(int(x) for x in latest_ver.split("."))
        if lv >= uv:
            out.append(
                item(
                    iname,
                    "fresh",
                    f"installed {local} == latest {latest_ver}"
                    if lv == uv
                    else f"installed {local} ahead of latest release {latest_ver}",
                )
            )
            continue
        age = _age_days(published) if published else None
        if age is not None and age <= EXTERNAL_TOOL_LAG_GRACE_DAYS:
            out.append(
                item(
                    iname,
                    "fresh",
                    f"installed {local} < latest {latest_ver}, but the "
                    f"release is {age:.0f}d old (grace "
                    f"{EXTERNAL_TOOL_LAG_GRACE_DAYS}d)",
                )
            )
            continue
        out.append(
            item(
                iname,
                "stale",
                f"installed {local} but latest {latest_ver}"
                + (
                    f" (released {age:.0f}d ago; grace {EXTERNAL_TOOL_LAG_GRACE_DAYS}d)"
                    if age is not None
                    else " (release date unknown)"
                )
                + " — detection content ages with the install",
                f"review {name} release notes; upgrade via your package "
                "manager; re-run one known-good target before a sweep "
                "(deliberate toolchain change)",
            )
        )
    return out


def check_feed_sources(ws: Path) -> list[dict]:
    """Liveness of every registered security-data source that carries a probe.

    The cached tier gets freshness rows from `check_feeds`; the LIVE tier
    had nothing. That gap is not theoretical: `fetch_advisory.py csaf`
    requested `csaf/v2/advisories/<cve>.json` and returned 404 for every
    CVE ever passed to it — Red Hat keys CSAF advisories by RHSA, not by
    CVE — and nothing failed, because a hardcoded URL has no registry to
    inspect and no check to fail (measured 2026-08-25).

    Each probe is a known-good identifier declared in config/feeds.yaml.
    A definitive HTTP error means the registry and the service disagree
    about the endpoint's shape -> `drift`. A transport failure means we
    could not tell -> `unavailable`, never `drift`: an offline
    workstation must not report six broken sources. Status only; the
    response body is never read.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    try:
        from traust.registry import feeds_config as fc

        sources = fc.probeable_sources()
    except Exception as e:
        return [
            item(
                "feed-source",
                "unavailable",
                f"cannot load config/feeds.yaml: {e}",
                "fix config/feeds.yaml — every feed-source row is blind without it",
            )
        ]
    out = []
    for sid, spec in sorted(sources.items()):
        probe = spec["probe"]
        ident = probe.get("ident")
        expect = int(probe.get("expect_status", 200))
        data = None
        try:
            if ident == "none":
                url = spec["url"]
            elif spec.get("method") == "POST":
                url = spec["url_template"]
                data = json.dumps(
                    {"package": {"name": ident, "ecosystem": probe.get("ecosystem", "npm")}}
                ).encode()
            elif spec.get("doc_url_template"):
                low = str(ident).lower()
                url = spec["doc_url_template"].format(year=low.split("-")[1], ident_lower=low)
            else:
                url = fc.resolve_url(spec, ident)
        except (KeyError, IndexError, ValueError) as e:
            out.append(
                item(
                    f"feed-source:{sid}",
                    "drift",
                    f"probe url could not be built: {e}",
                    "fix this source's url template in config/feeds.yaml",
                )
            )
            continue
        host = urllib.parse.urlsplit(url).netloc
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "User-Agent": "traust check_drift",
                **({"Content-Type": "application/json"} if data else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            out.append(
                item(
                    f"feed-source:{sid}",
                    "drift",
                    f"{host} answered HTTP {e.code} for the declared probe "
                    f"({ident}) — the registry and the service disagree about "
                    f"this endpoint's shape",
                    "correct this source's url_template in config/feeds.yaml, then re-probe",
                )
            )
            continue
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            out.append(
                item(
                    f"feed-source:{sid}",
                    "unavailable",
                    f"could not reach {host} ({e}) — liveness undetermined, not a failed source",
                )
            )
            continue
        status = "fresh" if code == expect else "drift"
        out.append(
            item(
                f"feed-source:{sid}",
                status,
                f"{host} HTTP {code}" + ("" if status == "fresh" else f" (expected {expect})"),
                None if status == "fresh" else "reconcile config/feeds.yaml with the service",
            )
        )
    return out


def check_grype_db(ws: Path) -> list[dict]:
    """grype's vulnerability DB content age — NOT its binary version.

    `external-tools:grype` compares the installed binary against the
    latest release and says nothing about the matchers it ships with.
    Those update on Anchore's cadence, independently of the binary, so
    the version row can read fresh while every container and SBOM scan
    runs against months-old CVE data. That is a false-negative source
    the whole point of a drift row is to surface.

    grype self-invalidates a DB older than GRYPE_DB_MAX_AGE_DAYS, so
    `Status:` is authoritative when present and the built-date is the
    fallback. Routes attention only — `grype db update` is the fix and
    stays a human/job action, never something this checker performs.
    """
    import re
    import shutil

    if shutil.which("grype") is None:
        return [
            item(
                "grype-db",
                "pending",
                "grype not on PATH — DB freshness untracked "
                "(prerequisite for secure-container-audit and the "
                "secure-code-audit SBOM step)",
            )
        ]
    try:
        proc = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return [item("grype-db", "unavailable", f"`grype db status` did not complete ({e})")]
    out = proc.stdout + proc.stderr
    built = re.search(r"^Built:\s*(\S+)", out, re.M)
    status = re.search(r"^Status:\s*(\S+)", out, re.M)
    if not built:
        return [
            item(
                "grype-db",
                "unavailable",
                "could not parse a Built: date from `grype db "
                "status` — output shape may have changed",
            )
        ]
    try:
        ts = datetime.datetime.strptime(built.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.UTC
        )
    except ValueError:
        return [item("grype-db", "unavailable", f"unparseable Built: timestamp {built.group(1)!r}")]
    age = (datetime.datetime.now(datetime.UTC) - ts).days
    said = status.group(1).lower() if status else None
    refresh = (
        "grype db update — then re-run any container/SBOM scan "
        "whose findings must reflect current CVE data"
    )
    if said == "invalid" or age > GRYPE_DB_MAX_AGE_DAYS:
        return [
            item(
                "grype-db",
                "stale",
                f"DB built {ts:%Y-%m-%d} ({age}d ago; grype's own max age is "
                f"{GRYPE_DB_MAX_AGE_DAYS}d)"
                + (f"; grype reports Status: {said}" if said else "")
                + " — container/SBOM scans are matching against aged CVE data",
                refresh,
            )
        ]
    return [
        item(
            "grype-db",
            "fresh",
            f"DB built {ts:%Y-%m-%d} ({age}d ago; threshold "
            f"{GRYPE_DB_MAX_AGE_DAYS}d)" + (f", Status: {said}" if said else ""),
        )
    ]


def check_pqc_facts_provenance(ws: Path) -> list[dict]:
    """Corpus *-pqc-facts.json stamps vs the current adapter/scanner
    pins, plus a bounded schema-conformance sample. The write-time gate
    in pqc_facts.py protects new writes only; this check makes the
    existing corpus's aging visible when ADAPTER_VERSION or the
    pqc-scan pin moves. Stale facts self-heal via re-scans."""
    adapter = skill_dir("pqc-readiness") / "scripts" / "pqc_facts.py"
    corpus = _ar(ws) / "pqc"
    if not adapter.is_file():
        return [item("pqc-facts-stamps", "pending", "pqc-readiness adapter not in tree")]
    if not corpus.is_dir():
        return [item("pqc-facts-stamps", "pending", "no pqc corpus under analysis-results/pqc")]
    import re

    src = adapter.read_text(encoding="utf-8")
    # \s crosses newlines: tolerates ADAPTER_VERSION = (\n "x.y.z" ...)
    m_ver = re.search(r'ADAPTER_VERSION\s*=\s*\(?\s*"([^"]+)"', src)
    m_commit = re.search(r'PQC_SCAN_COMMIT\s*=\s*\(?\s*"([^"]+)"', src)
    if not m_ver:
        return [
            item(
                "pqc-facts-stamps", "unavailable", "cannot parse ADAPTER_VERSION from pqc_facts.py"
            )
        ]
    cur_ver = m_ver.group(1)
    cur_commit = m_commit.group(1) if m_commit else None

    files = sorted(corpus.glob("*/*-pqc-facts.json"))
    if not files:
        return [item("pqc-facts-stamps", "pending", "pqc corpus present but holds no facts files")]

    out = []
    # stamps live in the envelope head (artifact/repository/stamps
    # precede facts[]), so a bounded head-read keeps this O(corpus)
    # cheap instead of parsing ~400k facts.
    ver_counts: dict[str, int] = {}
    commit_stale = 0
    unreadable = 0
    for p in files:
        try:
            with Path.open(p, encoding="utf-8") as fh:
                head = fh.read(4096)
        except OSError:
            unreadable += 1
            continue
        mv = re.search(r'"adapter_version":\s*"([^"]+)"', head)
        v = mv.group(1) if mv else "unstamped"
        ver_counts[v] = ver_counts.get(v, 0) + 1
        if cur_commit:
            mc = re.search(r'"pqc_scan_commit":\s*"([^"]+)"', head)
            if mc and mc.group(1) != cur_commit:
                commit_stale += 1
    stale = sum(n for v, n in ver_counts.items() if v != cur_ver)
    hist = ", ".join(f"{v}×{n}" for v, n in sorted(ver_counts.items(), reverse=True))
    detail = (
        f"{len(files)} facts files; adapter now {cur_ver}; "
        f"stamps: {hist}"
        + (f"; {commit_stale} predate scanner pin {cur_commit[:8]}" if commit_stale else "")
        + (f"; {unreadable} unreadable" if unreadable else "")
    )
    if stale or commit_stale or unreadable:
        out.append(
            item(
                "pqc-facts-stamps",
                "stale",
                detail,
                "re-run /pqc-readiness Layer 1 on the stale repos — facts "
                "are deterministic per repo SHA, so re-scans self-heal "
                "the stamps",
            )
        )
    else:
        out.append(item("pqc-facts-stamps", "fresh", detail))

    pqc_schema_path = schema_dir() / "pqc-facts.schema.json"
    if not pqc_schema_path.is_file():
        out.append(
            item(
                "pqc-facts-schema", "pending", "contracts/schemas/pqc-facts.schema.json not in tree"
            )
        )
        return out
    try:
        import jsonschema
    except ImportError:
        out.append(item("pqc-facts-schema", "unavailable", "jsonschema not installed"))
        return out
    validator = jsonschema.Draft202012Validator(
        json.loads(pqc_schema_path.read_text(encoding="utf-8"))
    )
    sample = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[:PQC_FACTS_SCHEMA_SAMPLE]
    bad = []
    for p in sample:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            bad.append(p.parent.name)
            continue
        if next(validator.iter_errors(doc), None) is not None:
            bad.append(p.parent.name)
    if bad:
        out.append(
            item(
                "pqc-facts-schema",
                "drift",
                f"{len(bad)}/{len(sample)} sampled facts files violate "
                f"contracts/schemas/pqc-facts.schema.json (e.g. {', '.join(bad[:3])})",
                "harnessing/3-audit/pqc-readiness/scripts/pqc_facts.py "
                "--validate-facts <file> per offender; if the "
                "schema itself changed, sweep the whole corpus before "
                "consumers (/patch pqc ingest, L2 prepass) trip on it",
            )
        )
    else:
        out.append(
            item(
                "pqc-facts-schema",
                "fresh",
                f"newest {len(sample)}/{len(files)} facts files conform "
                "(bounded sample; write-time gate covers new files)",
            )
        )
    return out


# Graph repo-node $.pqc coverage vs the pqc corpus that feeds it. The
# backfeed (scan_pqc_dependencies.py) stamps `$.pqc` onto each repo node;
# a portfolio-graph rebuild that re-upserted repo nodes from the spine
# used to clobber that whole attrs blob and drop `$.pqc` (3142 repos ->
# 41 after one rebuild), which zeroed the per-product PQC reports
# (build_pqc_product_reports.py requires json_extract(attrs,'$.pqc') IS
# NOT NULL). This row is the drift backstop for that clobber; the
# structural fix is build_portfolio_graph.ENRICHMENT_ATTR_KEYS. Ratio, not
# exact match, because normal per-repo re-scan churn moves the count a
# little.
PQC_BACKFEED_MIN_RATIO = 0.5


def check_pqc_backfeed(ws: Path) -> list[dict]:
    """Graph PQC enrichment vs the pqc corpus. Compares the count of
    portfolio-graph repo nodes carrying `$.pqc` against the expected
    corpus size (pqc-backfeed-summary.json:repos_with_pqc_attrs, else the
    *-pqc-facts.json corpus count) and flags `drift` when the graph is
    below PQC_BACKFEED_MIN_RATIO of it — the clobber signature. Read-only;
    pending/skip when the graph db or corpus is absent, never crashes."""
    refresh = (
        "python3 harnessing/3-audit/pqc-readiness/scripts/scan_pqc_dependencies.py "
        "(re-run the pqc backfeed to re-stamp graph repo nodes)"
    )
    db = _ar(ws) / "graph" / "portfolio-graph.db"
    if not db.is_file():
        return [item("pqc-backfeed", "pending", "portfolio-graph.db not built yet", refresh)]
    expected = None
    summary_p = _ar(ws) / "graph" / "pqc-backfeed-summary.json"
    if summary_p.is_file():
        try:
            expected = int(
                json.loads(summary_p.read_text(encoding="utf-8")).get("repos_with_pqc_attrs")
            )
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            expected = None
    if not expected:
        corpus = _ar(ws) / "pqc"
        if corpus.is_dir():
            expected = len(list(corpus.glob("*/*-pqc-facts.json")))
    if not expected:
        return [
            item(
                "pqc-backfeed",
                "pending",
                "no pqc-backfeed summary or facts corpus to compare against",
                refresh,
            )
        ]
    try:
        import sqlite3

        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        n = con.execute(
            "SELECT COUNT(*) FROM nodes WHERE kind='repo' "
            "AND json_extract(attrs,'$.pqc') IS NOT NULL"
        ).fetchone()[0]
        con.close()
    except Exception as e:
        return [
            item("pqc-backfeed", "unavailable", f"cannot read portfolio-graph.db: {str(e)[:120]}")
        ]
    if n < expected * PQC_BACKFEED_MIN_RATIO:
        return [
            item(
                "pqc-backfeed",
                "drift",
                f"graph PQC enrichment stale/clobbered ({n} of {expected} "
                f"repos) — re-run scan_pqc_dependencies backfeed",
                refresh,
            )
        ]
    return [
        item(
            "pqc-backfeed",
            "fresh",
            f"{n} of {expected} corpus repos carry $.pqc in the graph "
            f"(threshold {PQC_BACKFEED_MIN_RATIO:.0%})",
        )
    ]


def check_framework_upstream(ws: Path) -> list[dict]:
    """Upstream-content drift for the vendored framework spine: the
    provenance file pins the usnistgov/oscal-content commit the
    derivations came from; a moved upstream HEAD means NIST may have
    revised the catalog/baselines — review before re-deriving (a moved
    HEAD is often unrelated content, so this is stale-for-review, not
    auto-refresh)."""
    prov_p = ws / "progress-tracker/configs/compliance" / "provenance.json"
    if not prov_p.is_file():
        return [item("framework-spine:upstream", "pending", "no compliance provenance yet")]
    try:
        prov = json.loads(prov_p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [item("framework-spine:upstream", "unavailable", "provenance.json unparseable")]
    pinned = prov.get("upstream_head")
    url = prov.get("upstream")
    if not pinned or not url:
        return [
            item(
                "framework-spine:upstream", "unavailable", "provenance lacks upstream/upstream_head"
            )
        ]
    try:
        head = subprocess.run(
            ["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, timeout=60
        ).stdout.split()[0]
    except (subprocess.SubprocessError, OSError, IndexError):
        return [item("framework-spine:upstream", "unavailable", f"cannot reach {url}")]
    if not head.startswith(pinned):
        return [
            item(
                "framework-spine:upstream",
                "stale",
                f"derived at {pinned[:12]} but oscal-content HEAD is "
                f"{head[:12]} — check whether the SP800-53 rev5 files "
                "changed before re-deriving",
                "review upstream diff; if the rev5 files moved, re-derive "
                "per configs/compliance/README.md and update provenance",
            )
        ]
    return [
        item(
            "framework-spine:upstream",
            "fresh",
            f"upstream HEAD matches the derivation pin ({head[:12]})",
        )
    ]


def check_policy_provenance(ws: Path) -> list[dict]:
    out = []
    comp = ws / "progress-tracker/configs/compliance"
    targets = [
        (
            "sla-policy",
            ws / "progress-tracker/configs/sla-policy.yaml",
            lambda d: (d.get("source") or {}).get("retrieved"),
        ),
        ("compliance-spine", comp / "provenance.json", lambda d: d.get("retrieved")),
        ("org-parameters", comp / "org-parameters.yaml", lambda d: d.get("declared_on")),
        # harness-authored framework catalogs: ids-only files whose
        # `reviewed` date is the last check against the living
        # framework (PCI SSC revisions, TSC updates, EUR-Lex
        # consolidations have no machine feed — the review window IS
        # the staleness mechanism)
        ("catalog-pci-dss", comp / "catalog-pci-dss-v4.yaml", lambda d: d.get("reviewed")),
        ("catalog-soc2-tsc", comp / "catalog-soc2-tsc.yaml", lambda d: d.get("reviewed")),
        ("catalog-gdpr", comp / "catalog-gdpr-technical.yaml", lambda d: d.get("reviewed")),
    ]
    for name, path, getter in targets:
        if not path.is_file():
            out.append(item(f"provenance:{name}", "pending", "config absent"))
            continue
        try:
            doc = (
                json.loads(path.read_text(encoding="utf-8"))
                if path.suffix == ".json"
                else (yaml.safe_load(path.read_text(encoding="utf-8")) if yaml else None)
            )
        except Exception:
            doc = None
        d = _parse_iso(getter(doc) or "") if doc else None
        if d is None:
            out.append(item(f"provenance:{name}", "unavailable", "no retrieval/declaration date"))
            continue
        days = _age_days(d)
        status = "fresh" if days <= PROVENANCE_REVIEW_DAYS else "review_due"
        out.append(
            item(
                f"provenance:{name}",
                status,
                f"dated {d.date().isoformat()} ({days:.0f}d ago; review "
                f"window {PROVENANCE_REVIEW_DAYS}d)",
                "re-verify values at the source and update the date"
                if status == "review_due"
                else None,
            )
        )
    return out


_GENERATED_RE = None  # compiled lazily in _generated_stamp


def _generated_stamp(path: Path) -> datetime.datetime | None:
    """Parse the `**Generated:** YYYY-MM-DD` header of a dashboard."""
    global _GENERATED_RE
    if _GENERATED_RE is None:
        import re

        _GENERATED_RE = re.compile(r"\*\*Generated:\*\*\s*(\d{4}-\d{2}-\d{2})")
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return None
    m = _GENERATED_RE.search(head)
    return _parse_iso(m.group(1)) if m else None


def check_docs_semantic_sweep(ws: Path) -> list[dict]:
    """Quarterly semantic docs sweep (check-harness-docs SKILL, 'Quarterly
    semantic sweep'): the mechanical doc gates catch counts/links/flags,
    not behavioral claims — those are bounded by a periodic reviewer sweep
    whose report lands at
    progress-tracker/gap-assessments/docs-verification-*.md (relocated
    from metrics/ 2026-07-31 — a review report, not a metric; the
    legacy glob is kept so an un-migrated checkout still reads its
    sweep clock). The 2026-07-25 baseline sweep found ~60 discrepancies
    that had accumulated over ~150 releases; a 92-day cadence bounds
    that class."""
    reports = sorted(
        list((_pt(ws) / "gap-assessments").glob("docs-verification-*.md"))
        + list((_pt(ws) / "metrics").glob("docs-verification-*.md")),
        key=lambda p: p.name,
    )
    refresh = (
        "run the quarterly semantic sweep per the check-harness-docs "
        "SKILL ('Quarterly semantic sweep' section)"
    )
    if not reports:
        return [
            item(
                "docs-semantic-sweep",
                "pending",
                "no docs-verification report recorded yet",
                refresh,
            )
        ]
    latest = reports[-1]
    stamp = _mtime(latest)
    age = (datetime.datetime.now(datetime.UTC) - stamp).days if stamp else None
    if age is not None and age > 92:
        return [
            item(
                "docs-semantic-sweep",
                "stale",
                f"last sweep {latest.name} is {age} days old (quarterly cadence)",
                refresh,
            )
        ]
    return [
        item(
            "docs-semantic-sweep",
            "fresh",
            f"last sweep {latest.name}" + (f", {age} day(s) ago" if age is not None else ""),
        )
    ]


def check_rescan_worklist(ws: Path) -> list[dict]:
    """Continuous-scanning router output (docs/continuous-operations.md):
    the rescan worklist is the daily routing decision every scan lane
    consumes — a missing or aged artifact means the fleet is drifting
    unrouted, so both read as stale, not pending."""
    refresh = "python3 -m traust.cli.build_rescan_worklist"
    p = _ar(ws) / "findings" / "_manifest" / "rescan-worklist.json"
    if not p.is_file():
        return [
            item(
                "rescan-worklist",
                "stale",
                "no rescan worklist generated yet (daily router loop not running)",
                refresh,
            )
        ]
    try:
        stamp = _parse_iso(json.loads(p.read_text(encoding="utf-8")).get("generated_at", ""))
    except (OSError, json.JSONDecodeError):
        return [item("rescan-worklist", "unavailable", "rescan-worklist.json unparseable")]
    if stamp is None:
        return [item("rescan-worklist", "unavailable", "no generated_at stamp")]
    days = _age_days(stamp)
    if days > RESCAN_WORKLIST_STALE_DAYS:
        return [
            item(
                "rescan-worklist",
                "stale",
                f"generated {stamp.date().isoformat()} "
                f"({days:.0f}d ago; threshold "
                f"{RESCAN_WORKLIST_STALE_DAYS}d)",
                refresh,
            )
        ]
    return [
        item(
            "rescan-worklist",
            "fresh",
            f"generated {stamp.date().isoformat()} "
            f"({days:.1f}d ago; threshold "
            f"{RESCAN_WORKLIST_STALE_DAYS}d)",
        )
    ]


def _root_file_row(out: list[dict], metrics: Path, name: str, fname: str) -> None:
    """Freshness row for a builder that writes one file at the dashboards root."""
    path = metrics / "dashboards" / fname
    refresh = f"python3 -m traust.cli.refresh_dashboards --only {name}"
    mt = _mtime(path) if path.is_file() else None
    if mt is None:
        out.append(item(f"dashboards:{name}", "pending", "no output built yet", refresh))
        return
    days = _age_days(mt)
    fresh = days <= BUILDER_STALE_DAYS
    out.append(
        item(
            f"dashboards:{name}",
            "fresh" if fresh else "stale",
            f"newest output {mt.date().isoformat()} ({days:.0f}d ago; "
            f"threshold {BUILDER_STALE_DAYS}d)",
            None if fresh else refresh,
        )
    )


def _check_each_builder(metrics: Path) -> list[dict]:
    """One freshness row per dashboard builder, keyed off the canonical stage list.

    Derived from refresh_dashboards.build_stages rather than a second hand-kept list,
    so adding a builder adds its row. A stage with no known output directory is
    reported `uncovered` instead of being dropped — silent under-coverage is how a
    dead builder went unnoticed for a week.
    """
    out = []
    try:
        from traust.cli.refresh_dashboards import build_stages

        stages = build_stages(Path("/nonexistent"), Path("/nonexistent"), "", False)
    except Exception as e:
        return [item("dashboards:builders", "unavailable", f"cannot read the stage list: {e}")]

    for name, tier, _argv in stages:
        if tier != "consumer" and name not in BUILDER_OUTPUT_DIRS:
            continue
        sub = BUILDER_OUTPUT_DIRS.get(name)
        if sub is None:
            continue  # covered by its own row above, or has no dashboard output
        d = metrics / "dashboards" / sub
        files = [f for f in d.glob("*") if f.is_file()] if d.is_dir() else []
        row = f"dashboards:{name}"
        refresh = f"python3 -m traust.cli.refresh_dashboards --only {name}"
        if not files:
            out.append(item(row, "pending", "no output built yet", refresh))
            continue
        newest = max((_mtime(f) for f in files if _mtime(f)), default=None)
        if newest is None:
            out.append(item(row, "unavailable", "mtime unreadable"))
            continue
        days = _age_days(newest)
        status = "fresh" if days <= BUILDER_STALE_DAYS else "stale"
        out.append(
            item(
                row,
                status,
                f"newest output {newest.date().isoformat()} ({days:.0f}d ago; "
                f"threshold {BUILDER_STALE_DAYS}d)",
                refresh if status == "stale" else None,
            )
        )

    # Two builders write a single file at the dashboards root rather than their own
    # directory. dashboards/fuzz/ exists but holds a July campaign summary, not this
    # builder's output — mapping validation-fuzz to it produced a false `stale` on the
    # rows' first run, which is its own kind of failure: a freshness signal nobody
    # believes is no better than none.
    root_file_rows = {
        "loc": "loc-dashboard.html",
        "validation-fuzz": "Live-validation-fuzz-dashboard.md",
    }
    for row_name, fname in root_file_rows.items():
        _root_file_row(out, metrics, row_name, fname)

    covered = set(BUILDER_OUTPUT_DIRS) | set(root_file_rows)
    consumers = {n for n, tier, _ in stages if tier == "consumer"}
    uncovered = sorted(
        consumers
        - covered
        - {
            "cve-feed",
            "cve-provenance",
            "spend",
            "dependency-exposure",
            "scoreboard",
            "exec-summary",
        }
    )
    if uncovered:
        out.append(
            item(
                "dashboards:builders-uncovered",
                "info",
                "no freshness signal for: "
                + ", ".join(uncovered)
                + " — add them to BUILDER_OUTPUT_DIRS or confirm they emit no dashboard",
            )
        )
    return out


def check_dashboard_staleness(ws: Path) -> list[dict]:
    """Generated dashboards refresh on demand — flag the ones that aged.

    Scoreboard + spend dashboard are rebuilt by a human/skill run, not a
    scheduler (folding them into a scheduled loop is deliberately
    deferred); this check is the backstop that makes a missed refresh
    visible instead of silently serving week-old headline numbers.
    """
    out = []
    metrics = _pt(ws) / "metrics"

    targets = [
        (
            "dashboards:harness-scoreboard",
            metrics / "traust-metrics.md",
            SCOREBOARD_STALE_DAYS,
            "python3 -m traust.cli.refresh_dashboards --only scoreboard  "
            "(full chain: drop --only; or /traust-metrics; "
            "builder: harnessing/traust-metrics/"
            "collect_harness_metrics.py)",
        ),
        (
            "dashboards:spend",
            metrics / "dashboards" / "spend" / "spend-dashboard.md",
            SPEND_DASHBOARD_STALE_DAYS,
            "python3 -m traust.cli.refresh_dashboards --only spend",
        ),
        (
            "dashboards:dependency-exposure",
            metrics / "dependency-exposure" / "dependency-exposure.md",
            DEP_EXPOSURE_STALE_DAYS,
            "python3 -m traust.cli.refresh_dashboards --only dependency-exposure",
        ),
    ]
    for name, path, threshold, refresh in targets:
        if not path.is_file():
            out.append(item(name, "pending", "dashboard not built yet", refresh))
            continue
        stamp = _generated_stamp(path) or _mtime(path)
        if stamp is None:
            out.append(item(name, "unavailable", "no Generated stamp and mtime unreadable"))
            continue
        days = _age_days(stamp)
        status = "fresh" if days <= threshold else "stale"
        out.append(
            item(
                name,
                status,
                f"generated {stamp.date().isoformat()} ({days:.0f}d ago; threshold {threshold}d)",
                refresh if status == "stale" else None,
            )
        )

    out.extend(_check_each_builder(metrics))

    # Second signal for spend: the newest session-actuals row. The
    # dashboard can be rebuilt without the ledger having been appended,
    # so a fresh Generated stamp can still hide stale actuals.
    spend_md = metrics / "dashboards" / "spend" / "spend-dashboard.md"
    if spend_md.is_file():
        newest = None
        try:
            for line in spend_md.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("| 2"):
                    d = _parse_iso(line.split("|")[1].strip())
                    if d and (newest is None or d > newest):
                        newest = d
        except OSError:
            newest = None
        if newest is None:
            out.append(
                item("dashboards:spend-actuals", "unavailable", "no dated actuals rows found")
            )
        else:
            days = _age_days(newest)
            status = "fresh" if days <= SPEND_DASHBOARD_STALE_DAYS else "stale"
            out.append(
                item(
                    "dashboards:spend-actuals",
                    status,
                    f"newest actuals row {newest.date().isoformat()} "
                    f"({days:.0f}d ago; threshold "
                    f"{SPEND_DASHBOARD_STALE_DAYS}d)",
                    "python3 -m traust.cli.refresh_dashboards "
                    "--only spend-actuals spend  (operator workstation; "
                    "builder: python3 -m traust.cli metrics collect-spend "
                    "--append)"
                    if status == "stale"
                    else None,
                )
            )
    return out


DOCS_MAP_STALE_DAYS = 30


def _docs_live_versions(product: str) -> list[str] | None:
    """Enumerate a product's documentation versions from its live
    docs.redhat.com landing page (stock curl — the CDN 403s other
    client shapes). None on any network failure — the caller reports
    check-skipped, never fabricates freshness."""
    import subprocess

    url = f"https://docs.redhat.com/en/documentation/{product}"
    try:
        proc = subprocess.run(
            ["curl", "-sSL", "--fail", "--max-time", "30", url],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    import re as _re

    vs = sorted(
        set(
            _re.findall(
                rf"documentation/{_re.escape(product)}/([0-9][0-9a-z.-]*|"
                rf'[0-9]-latest|latest|current)["/]',
                proc.stdout,
            )
        )
    )
    return vs or None


def check_docs_product_map(ws: Path) -> list[dict]:
    """Doc-variance lane: catches FUTURE documentation versions — the
    declared docs-product-map's enumerated versions vs each product's
    live landing page, plus map age. A new upstream version missing
    from the map is drift (variance tracking would silently not cover
    it); network failure is reported, never treated as fresh."""
    p = _inputs_root(ws) / "adhoc" / "docs-product-map.yaml"
    if not p.is_file():
        return [
            item(
                "docs-product-map",
                "pending",
                "map absent (doc-variance lane part 1)",
                "plans/doc-variance-plan.md",
            )
        ]
    try:
        import yaml as _yaml

        doc = _yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception as e:
        return [item("docs-product-map", "drift", f"map unreadable: {e}")]
    out = []
    fetched = str(doc.get("fetched_at") or "")
    try:
        age = (_now().date() - datetime.date.fromisoformat(fetched[:10])).days
        if age > DOCS_MAP_STALE_DAYS:
            out.append(
                item(
                    "docs-product-map",
                    "stale",
                    f"version enumeration {age}d old (threshold {DOCS_MAP_STALE_DAYS}d)",
                    "re-enumerate versions from the live landing pages",
                )
            )
    except ValueError:
        out.append(item("docs-product-map", "drift", f"unparseable fetched_at: {fetched!r}"))
    for slug, entry in sorted((doc.get("products") or {}).items()):
        declared = [str(v) for v in entry.get("versions") or []]
        live = _docs_live_versions(slug)
        if live is None:
            out.append(
                item(
                    f"docs-versions:{slug}",
                    "unavailable",
                    "live enumeration failed (network) — NOT treated as fresh",
                )
            )
            continue

        def _vkey(v):
            try:
                return tuple(int(x) for x in v.split("."))
            except ValueError:
                return None

        declared_keys = [k for k in (_vkey(v) for v in declared) if k]
        # FUTURE versions only: newer than the declared window's max.
        # Older-than-window versions are historical docs, deliberately
        # out of scope — flagging them would bury the real signal.
        newer = (
            [v for v in live if (k := _vkey(v)) and declared_keys and k > max(declared_keys)]
            if declared_keys
            else []
        )
        gone = [v for v in declared if v not in live]
        if newer:
            out.append(
                item(
                    f"docs-versions:{slug}",
                    "drift",
                    f"NEW doc version(s) beyond the declared window: "
                    f"{', '.join(newer)} — variance tracking is not "
                    f"covering them",
                    "update docs-product-map.yaml versions (+ "
                    "version_to_refs rule if the branch convention "
                    "differs)",
                )
            )
        if gone:
            out.append(
                item(
                    f"docs-versions:{slug}",
                    "drift",
                    f"declared version(s) no longer on the landing page: "
                    f"{', '.join(gone)} (retired docs?)",
                    "review the map row; mark records for those versions disposition=stale",
                )
            )
        if not newer and not gone:
            out.append(
                item(f"docs-versions:{slug}", "fresh", f"{len(declared)} version(s) match live")
            )
    return out


def check_dependency_pins(ws: Path) -> list[dict]:
    """Installed sibling-package versions vs the pins in pyproject.toml.

    This replaced `check_submodules` when the C8 restructure swapped the
    `contracts`/`traust-ledger` git submodules for pip dependencies. The
    FAILURE CLASS DID NOT GO AWAY — only its delivery mechanism did:

        submodules: working tree commit != superproject pin
                    -> "cannot import name 'stamp_and_sign'"
        pip deps  : installed version   != [tool.uv.sources] tag
                    -> "No module named 'traust_engine'"

    Both are "a dependency is not the version this tree expects", and both
    surface as import errors that name neither the dependency system nor the
    fix. The submodule form cost real time on 2026-08-13 (18 test modules
    died at collection after v0.267.0 bumped traust-ledger); the pip form was
    hit on 2026-08-14, when `traust_engine` was simply absent from the venv
    until `uv sync` ran. Skills invoke these modules, so an out-of-sync venv
    fails a scan rather than a test run.

    CI does not cover this: it builds its own venv with
    `uv pip install --require-hashes`, which guarantees the CI environment,
    not the operator workstation where every skill actually executes.

    Fails open — an unreadable pyproject or a missing importlib metadata
    entry reports `unavailable`, never a false `fresh`.
    """
    import re as _re

    pj = HARNESS_ROOT / "pyproject.toml"
    if not pj.is_file():
        return [item("dependency-pins", "unavailable", "pyproject.toml not found")]
    try:
        text = pj.read_text(encoding="utf-8")
    except OSError as e:
        return [
            item(
                "dependency-pins", "unavailable", f"cannot read pyproject.toml ({type(e).__name__})"
            )
        ]
    # [tool.uv.sources] entries pinned to a git tag are the sibling packages
    pins = _re.findall(
        r'^\s*([A-Za-z0-9_.-]+)\s*=\s*\{\s*git\s*=\s*"[^"]+"\s*,\s*'
        r'tag\s*=\s*"v?([0-9][^"]*)"\s*\}',
        text,
        _re.M,
    )
    if not pins:
        return [item("dependency-pins", "fresh", "no git-tag-pinned sibling packages declared")]
    try:
        import importlib.metadata as md
    except ImportError:  # pragma: no cover
        return [item("dependency-pins", "unavailable", "importlib.metadata unavailable")]
    fix = "uv sync"
    out = []
    for name, want in pins:
        iname = "dependency-pins:" + name
        try:
            got = md.version(name)
        except Exception:
            out.append(
                item(
                    iname,
                    "drift",
                    f"NOT INSTALLED — pyproject pins {name} v{want}, but it is "
                    f"absent from this environment; anything importing it fails "
                    f"with a ModuleNotFoundError that never mentions uv",
                    fix,
                )
            )
            continue
        if got == want:
            out.append(item(iname, "fresh", f"{name} v{got} matches the pin"))
        else:
            out.append(
                item(
                    iname,
                    "drift",
                    f"VERSION SKEW — {name} v{got} installed but pyproject pins "
                    f"v{want}; imports may resolve to a different API than this "
                    f"tree was written against",
                    fix,
                )
            )
    return out


def check_ledger_completeness(ws: Path) -> list[dict]:
    """Does the ledger actually cover the corpus? Nothing asked this before.

    Signature coverage is guarded (below) and the findings-db projection is guarded,
    but no check asserted that a ledger EXISTS for each audited repo, or that the
    identity fields it depends on are populated. So every gap had to be discovered by
    hand, one campaign at a time — a single sweep turned up audits with no layer,
    layers whose events had no fingerprint, findings with a degenerate identity,
    and colliding layer ids, none of which any check would ever have reported.

    Each invariant below is one of those, generalised. They are reported, never fixed
    here: drift-watch detects, migrations remediate.

    **Only `-security-audit.json` requires a layer.** A layer records dispositions on
    findings, so an artifact that asserts no findings needs none — threat models,
    privilege profiles, patch diffs, fuzz corpora and per-CVE evidence are all
    correctly ledger-free and are not flagged.
    """
    import collections

    findings = _ar(ws) / "findings"
    if not findings.is_dir():
        return [item("ledger:completeness", "unavailable", "no findings tree")]

    state = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
    special = {"_manifest", "_index", "_orgs"}
    no_layer: list[str] = []
    no_digest = 0
    no_claims = 0
    partial_claims = 0
    stems: collections.Counter = collections.Counter()
    layers = 0

    for dirpath, _dirnames, filenames in os.walk(findings):
        rel = os.path.relpath(dirpath, findings)
        parts = Path(rel).parts
        if set(parts) & state or (parts and parts[0] in special):
            continue
        # Per-AUDIT, not per-directory. Testing "does this directory contain any
        # layer" is a false negative wherever one directory holds two audits and one
        # layer — 12 audits / 99 findings hid behind exactly that, 2026-08-21.
        present = set(filenames)
        for f in filenames:
            if f.endswith("-findings-layer.json"):
                layers += 1
                stems[f[: -len(".json")]] += 1
                try:
                    meta = (
                        json.loads((Path(dirpath) / f).read_text(encoding="utf-8")).get("metadata")
                        or {}
                    )
                except (OSError, json.JSONDecodeError):
                    continue
                if not meta.get("audit_report_sha256"):
                    no_digest += 1
                rep = Path(dirpath) / (meta.get("audit_report") or "")
                if meta.get("audit_report") and rep.is_file():
                    try:
                        ids = {
                            x.get("id")
                            for x in (
                                json.loads(rep.read_text(encoding="utf-8")).get("findings") or []
                            )
                            if x.get("id")
                        }
                    except (OSError, json.JSONDecodeError):
                        ids = set()
                    ch = set(meta.get("claim_hashes") or {})
                    if ids and not ch:
                        no_claims += 1
                    elif ids - ch:
                        partial_claims += 1
            elif f.endswith("-security-audit.json"):
                base = f[: -len("-security-audit.json")]
                if f"{base}-findings-layer.json" not in present:
                    no_layer.append(str(Path(rel) / f))

    out = []
    # 1. an audited repo with no ledger cannot record a disposition at all
    if no_layer:
        out.append(
            item(
                "ledger:audits-without-a-layer",
                "stale",
                f"{len(no_layer)} security audits have no findings-layer beside them, so "
                f"their findings cannot be confirmed, refuted or resolved "
                f"(e.g. {no_layer[0]})",
                "create the layer via the owning skill, then re-run /track-findings",
            )
        )
    else:
        out.append(item("ledger:audits-without-a-layer", "fresh", "every audit has a layer"))

    # 2. without a digest a report cannot be verified once it leaves git (plan R1)
    out.append(
        item(
            "ledger:layers-without-a-report-digest",
            "stale" if no_digest else "fresh",
            f"{no_digest} of {layers} layers lack audit_report_sha256"
            if no_digest
            else f"all {layers} layers record a report digest",
            "re-emit the affected layers so each records its report digest "
            "(deployments carrying legacy layers have a one-shot backfill)"
            if no_digest
            else None,
        )
    )

    # 3. claim_hashes is the baseline's tamper-evidence, and it is inside the
    #    signature — a layer without it cannot detect a finding's claim being edited
    if no_claims or partial_claims:
        out.append(
            item(
                "ledger:incomplete-claim-hashes",
                "stale",
                f"{no_claims} layers record no claim_hashes and {partial_claims} cover only "
                f"some of their report's findings — those findings' claims are not "
                f"tamper-evident",
                "create the missing layers so every report's findings are "
                "claim-pinned and tamper-evident",
            )
        )
    else:
        out.append(
            item(
                "ledger:incomplete-claim-hashes",
                "fresh",
                "every layer's claim_hashes covers its report",
            )
        )

    # 4. a colliding layer id silently merges two repos' dispositions in the projection
    dupes = sum(c - 1 for c in stems.values() if c > 1)
    out.append(
        item(
            "ledger:colliding-layer-ids",
            "info" if dupes else "fresh",
            f"{dupes} layer files share a filename stem — EXPECTED and harmless since "
            f"traust-ledger 0.9.0 keys on the path hash. Informational, not a defect: it is "
            f"the tripwire that fires if anything reverts to stem-keying, which silently "
            f"merged 19.4% of projection rows"
            if dupes
            else f"{len(stems)} distinct layer stems, no collisions",
            None,
        )
    )
    return out


def check_finding_identity(ws: Path) -> list[dict]:
    """Is every finding in the corpus stamped, and does every stamp still reproduce?

    The identity gates are all in the PRODUCING session: the audit skill runs the
    stamp step, and `traust_engine.reporting.validate.check_finding_identity` errors
    on an absent or non-reproducing value. `analysis-results` itself has no hook and
    no CI, so an artifact written outside the skill path — a hand-edited report, a
    migration that re-serialised findings, an import from a non-harness producer —
    meets no gate on the way in. This row is that boundary check, after the fact.

    Three invariants, each a way identity fails silently:

    1. **unstamped** — a finding with no `fingerprint` is invisible to cross-scan
       continuation and to disposition carry-forward; it cannot be matched to its own
       history on the next re-audit.
    2. **non-reproducing** — a stamp the current recipe does not produce. Either it
       was not written by `traust_ledger.identity` (so it is not a cross-scan identity
       and must not be trusted as one), or the finding's identity inputs were edited
       under it, or it predates an `ALGO_VERSION` move whose re-stamp migration did
       not reach it. Report findings carry no `fingerprint_algo`, so these are
       indistinguishable here — which is why the remedy is to look, not to re-stamp
       reflexively: re-stamping CHANGES identity and orphans disposition history.
    3. **degenerate** — every location path canonicalizes to empty, so identity
       collapses to `(repo, "", cwe)` and distinct findings in one repo share it.
       `fingerprint(strict=True)` refuses these at stamp time, but the flip is gated
       on classifying the residue first (plan item 4b), so this row is that
       burndown's counter rather than a defect that appeared today.

    Cheap: one pass, ~3s over 8k reports, because the recipe is a sha256 over three
    canonicalized strings.
    """
    from traust_engine.ledger import canon_path, fingerprint

    findings = _ar(ws) / "findings"
    if not findings.is_dir():
        return [item("identity:corpus-sweep", "unavailable", "no findings tree")]

    state = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
    special = {"_manifest", "_index", "_orgs"}
    reports = total = 0
    unstamped: list[str] = []
    wrong: list[str] = []
    degenerate = 0
    unreadable = 0
    collisions = 0
    collision_examples: list[str] = []

    for dirpath, _dirnames, filenames in os.walk(findings):
        parts = list(Path(dirpath).relative_to(findings).parts)
        if set(parts) & state or (parts and parts[0] in special):
            continue
        for f in filenames:
            if not f.endswith("-security-audit.json"):
                continue
            try:
                doc = json.loads((Path(dirpath) / f).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                unreadable += 1
                continue
            reports += 1
            repo = (doc.get("metadata") or {}).get("repository")
            # Two findings in ONE report sharing an identity is a false MERGE, the
            # dual of the false splits above and invisible to them: both stamps
            # recompute perfectly, they just name the same thing.
            seen_here: dict[str, str] = {}
            for fnd in doc.get("findings") or []:
                total += 1
                stored = fnd.get("fingerprint")
                fid = fnd.get("id", "?")
                if not stored:
                    unstamped.append(f"{f}:{fid}")
                    continue
                usable_paths = [
                    c
                    for c in (canon_path(loc.get("path")) for loc in (fnd.get("locations") or []))
                    if c
                ]
                # Degenerate findings collide BY CONSTRUCTION and are already
                # counted one row up; counting them here too would report one
                # defect twice and inflate this number by 96.
                if not usable_paths:
                    degenerate += 1
                elif stored in seen_here:
                    collisions += 1
                    if len(collision_examples) < 3:
                        collision_examples.append(
                            f"{f}: {seen_here[stored][:40]} <-> {str(fnd.get('title', fid))[:40]}"
                        )
                else:
                    seen_here[stored] = str(fnd.get("title", fid))
                try:
                    if fingerprint(fnd, repo) != stored:
                        wrong.append(f"{f}:{fid}")
                except Exception:
                    wrong.append(f"{f}:{fid}")

    if not total:
        return [item("identity:corpus-sweep", "unavailable", "no audit findings found")]

    out = []
    out.append(
        item(
            "identity:unstamped-findings",
            "drift" if unstamped else "fresh",
            f"{len(unstamped)} of {total} findings across {reports} audit reports carry no "
            f"`fingerprint` — they cannot be matched to their own history on re-audit "
            f"(e.g. {unstamped[0]})"
            if unstamped
            else f"all {total} findings in {reports} audit reports are stamped",
            "python3 -m traust.cli corpus finding-identity backfill analysis-results/findings"
            if unstamped
            else None,
        )
    )

    out.append(
        item(
            "identity:non-reproducing-stamps",
            "drift" if wrong else "fresh",
            f"{len(wrong)} of {total} stamps do not reproduce under the current recipe "
            f"(e.g. {wrong[0]}) — not written by traust_ledger.identity, edited under, or "
            f"missed by an ALGO_VERSION re-stamp"
            if wrong
            else f"all {total} stamps reproduce under the installed recipe",
            "inspect before re-stamping: python3 -m traust.cli corpus finding-identity "
            "fingerprint <report.json> CHANGES identity and orphans disposition history"
            if wrong
            else None,
        )
    )

    out.append(
        item(
            "identity:degenerate-findings",
            "stale" if degenerate else "fresh",
            f"{degenerate} of {total} findings have no usable location, so their identity "
            f"collapses to (repo, '', cwe) and collides with every other such finding in "
            f"the same repo — the residue blocking the fingerprint(strict=True) flip"
            if degenerate
            else f"no degenerate identities in {total} findings — strict=True is flippable",
            "classify the degenerate identities, then repath them to the "
            "artifact that actually carries each finding"
            if degenerate
            else None,
        )
    )

    out.append(
        item(
            "identity:colliding-fingerprints",
            "info" if collisions else "fresh",
            f"{collisions} of {total} findings share an identity with ANOTHER finding in "
            f"the same report ({100 * collisions / total:.2f}%) — same file, same primary "
            f"CWE, different vulnerability, one name. Not a regression and not a burndown: "
            f"the recipe hashes repo+paths+CWE and nothing distinguishes two such findings. "
            f"Contained today because dispositions key on (layer, finding_ref) not identity "
            f"(D9) and rebaseline tier-1 refuses a non-unique candidate; it bites where "
            f"something DOES key on the fingerprint. e.g. {collision_examples[0]}"
            if collisions
            else f"no within-report identity collisions in {total} findings",
            None,
        )
    )

    if unreadable:
        out.append(
            item(
                "identity:unreadable-reports",
                "unavailable",
                f"{unreadable} audit report(s) could not be parsed and were not swept",
            )
        )
    return out


def _deployment_file(ws: Path, name: str) -> Path | None:
    """The operational config file the harness will read: $TRAUST_CONFIG_HOME
    (or its documented default) via config_path. ``ws`` no longer influences
    discovery — one variable, one answer."""
    del ws
    return optional_config_path(name)


def check_signature_coverage(ws: Path) -> list[dict]:
    """Merkle-root signature coverage across the disposition ledger.

    A signature over the root is what makes single-writer enforceable rather
    than aspirational: only the key-holder can produce a valid ledger state.
    Coverage reaching 100% was a deliberate campaign (ledger plan P3/P4), and
    nothing guards it — `verify_merkle_integrity` treats an ABSENT signature as
    clean (only an absent root or leaf_format 1 are errors), so coverage can
    regress silently.

    It already has, twice over, for the same reason: any edit to a layer changes
    the root, and `stamp_and_sign` correctly DROPS the now-invalid signature
    rather than leave one that no longer matches. When no key is configured —
    the normal state on a workstation, since the key lives in Vault and P8 has
    not delivered it to the writers — the layer is re-stamped and left unsigned.
    That is the right behaviour and it is invisible: the layer still validates.

    Walks with os.walk(followlinks=False): findings/_orgs/ is a symlink index,
    and a glob through it counts the same physical layer many times.

    Fails open — no corpus reports `pending`, never a false `fresh`.
    """
    corpus = _ar(ws)
    if not corpus.is_dir():
        return [item("ledger-signature-coverage", "pending", "no analysis-results checkout")]
    total = unsigned = rootless = invalid = corrupt = 0
    examples: list[str] = []
    bad_examples: list[str] = []
    corrupt_examples: list[str] = []
    # Verification is best-effort: without the public key we can still report
    # coverage, and saying so beats reporting a validity result we did not compute.
    pubkey = _deployment_file(ws, "ledger-signing-key.pub")
    verifier = None
    integrity_check = None
    if pubkey is not None and pubkey.is_file():
        try:
            from traust_ledger.api.integrity import (
                verify_merkle_integrity as integrity_check,
            )
            from traust_ledger.api.integrity import (
                verify_merkle_signature as verifier,
            )
        except ImportError:
            verifier = integrity_check = None
    for dirpath, dirnames, filenames in os.walk(corpus, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for fn in filenames:
            if not fn.endswith("-findings-layer.json"):
                continue
            fp = Path(dirpath) / fn
            try:
                meta = json.loads(fp.read_text(encoding="utf-8")).get("metadata") or {}
            except (OSError, json.JSONDecodeError):
                continue
            total += 1
            if not meta.get("merkle_root"):
                rootless += 1
                continue
            if not meta.get("merkle_root_signature"):
                unsigned += 1
                if len(examples) < 3:
                    examples.append(fn[: -len("-findings-layer.json")])
                continue
            # **Presence is not validity.** A signature that no longer matches its
            # payload reads as healthy to a presence check, and that is the one
            # failure mode nothing else detects: populating `artifact_digests`
            # changes the format-4 signed payload without moving the Merkle root, so
            # the old signature survives, invalid. D8 calls a present-but-invalid
            # signature indistinguishable from tampering — worse than an absent one.
            # ~17ms/layer measured, so the whole corpus verifies in ~2.5 minutes.
            if verifier is not None:
                try:
                    layer = json.loads(fp.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                # **Signature and integrity catch different tampering.** The
                # signature binds the *declared* root; editing an event leaves that
                # declaration alone, so the signature still verifies while the
                # recomputed root no longer matches. Checking only one of the two
                # calls a tampered layer clean — verified against a live round trip
                # 2026-09-02: an edited `rationale` produced
                # "metadata.merkle_root mismatch" from integrity and NOTHING from
                # the signature check. Both, or neither is worth running.
                if [f for f in verifier(layer, str(pubkey)) if f.severity.name == "ERROR"]:
                    invalid += 1
                    if len(bad_examples) < 3:
                        bad_examples.append(fn[: -len("-findings-layer.json")])
                elif integrity_check is not None and [
                    f for f in integrity_check(layer) if f.severity.name == "ERROR"
                ]:
                    corrupt += 1
                    if len(corrupt_examples) < 3:
                        corrupt_examples.append(fn[: -len("-findings-layer.json")])
    if not total:
        return [
            item(
                "ledger-signature-coverage",
                "pending",
                "no *-findings-layer.json under analysis-results",
            )
        ]
    verified_note = (
        ""
        if verifier is not None
        else " (validity NOT checked — no public key at "
        "<deployment config dir>/ledger-signing-key.pub)"
    )
    if not unsigned and not rootless and not invalid and not corrupt:
        return [
            item(
                "ledger-signature-coverage",
                "fresh",
                f"{total:,}/{total:,} layers rooted and signed"
                + (
                    ", signatures and Merkle roots verified"
                    if verifier is not None
                    else verified_note
                ),
            )
        ]
    bits = []
    if corrupt:
        bits.append(
            f"{corrupt} layer(s) whose MERKLE ROOT does not recompute "
            f"({', '.join(corrupt_examples)}{'…' if corrupt > 3 else ''}) — "
            f"event content edited under a still-valid signature"
        )
    if invalid:
        bits.append(
            f"{invalid} layer(s) with a signature that DOES NOT VERIFY "
            f"({', '.join(bad_examples)}{'…' if invalid > 3 else ''}) — "
            f"stale, not absent"
        )
    if unsigned:
        bits.append(
            f"{unsigned} layer(s) rooted but UNSIGNED "
            f"({', '.join(examples)}{'…' if unsigned > 3 else ''})"
        )
    if rootless:
        bits.append(f"{rootless} layer(s) with no merkle_root")
    return [
        item(
            "ledger-signature-coverage",
            "drift",
            f"{'; '.join(bits)} of {total:,} — an edited layer loses its signature "
            f"when no key is configured, and absent-signature is not a validation "
            f"error, so this regresses silently",
            "re-run the signing pass (ledger sign <layer> --key ...)",
        )
    ]


_EXPORT_PROBE = r"""
import importlib, json, sys
pkg, root, mods = sys.argv[1], sys.argv[2], sys.argv[3:]
out = {}
top = importlib.import_module(pkg)
if not (getattr(top, "__file__", "") or "").startswith(root):
    print(json.dumps({"__wrong_source__": getattr(top, "__file__", "")})); raise SystemExit(0)
for mod in mods:
    try:
        m = importlib.import_module(f"{pkg}.{mod}")
    except ModuleNotFoundError as e:
        out[mod] = {"missing": e.name or ""}; continue
    except Exception as e:  # noqa: BLE001 — reported, not swallowed
        out[mod] = {"error": type(e).__name__}; continue
    names = getattr(m, "__all__", None)
    if names is None:
        names = [n for n in dir(m) if not n.startswith("_")
                 and getattr(getattr(m, n, None), "__module__", "").startswith(pkg)]
    out[mod] = {"names": sorted(names)}
print(json.dumps(out))
"""


def _probe_exports(pkg_root: Path, pkg: str, mods: list[str]) -> dict | None:
    """Public names per documented module, imported from the checkout.

    Runs a fresh interpreter with the checkout's ``src/`` first on the path so
    the audit sees the code the README sits beside — never the (possibly
    older) installed pin, and never modules this process already imported.
    Returns None when the package would not import from the checkout at all.
    """
    pkg_root = pkg_root.resolve()
    src = str(pkg_root.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    try:
        r = subprocess.run(
            [sys.executable, "-c", _EXPORT_PROBE, pkg, str(pkg_root), *mods],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )
        data = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None
    if not isinstance(data, dict) or "__wrong_source__" in data:
        return None
    return data


def _module_path_exists(pkg_root: Path, parts: list[str]) -> bool:
    """True when `parts` names a public module or package under `pkg_root`.

    Walks the dotted path against the tree: every intermediate component must
    be a package (`<name>/__init__.py`), the leaf may be a module (`<name>.py`)
    or a package. Any `_`-prefixed component is private surface and resolves
    False — README text should not be pointing consumers at it.
    """
    if not parts or any(p.startswith("_") for p in parts):
        return False
    cur = pkg_root
    for comp in parts[:-1]:
        cur = cur / comp
        if not (cur / "__init__.py").is_file():
            return False
    leaf = cur / parts[-1]
    return (leaf.with_suffix(".py")).is_file() or (leaf / "__init__.py").is_file()


def check_sibling_readmes(ws: Path, siblings: dict | None = None) -> list[dict]:
    """Sibling-repo READMEs vs that repo's own pyproject and module surface.

    Same failure class as `check_dependency_pins` one level out: a *documented*
    claim that reality has moved past. Measured on traust-ledger 2026-08-17 — the
    README pinned `traust-contracts>=0.2,<0.3` / `v0.2.0` while its own
    pyproject pinned `>=0.3,<0.4` / `v0.3.0` (contracts was released at 0.4.0),
    told consumers to pin `traust-ledger v0.1.1` when the latest tag was v0.1.3,
    and cited a vectors path the contracts v0.3.0 `v1/` restructure had moved.
    It also described `traust_ledger.events` as three names when it exports eight
    — the five omitted ones being the newest work in the module.

    Why here and not a per-repo CI job: these repos run ruff + pytest, neither
    of which reads prose, and a bespoke docs job per sibling is machinery for
    one file each. Drift already exists to catch claims-vs-reality across the
    workspace and already owns the dependency-pin version of this check.

    KNOWN LIMIT, stated so nobody mistakes this for a gate: drift runs from the
    harness on the operator workstation. It does NOT block an MR in the sibling
    repo — it reports the drift on the drift cadence. A sibling that wants a
    hard gate needs one in its own CI.

    Fails open: a sibling that is not checked out, or an unreadable file,
    reports `unavailable`, never a false `fresh`.
    """
    import re as _re

    out: list[dict] = []
    # dist name -> (import name, checkout dir candidates). Sibling checkout is
    # `traust-ledger/` at the workspace root. The module surface is read from
    # the checkout, never listed here: a hardcoded module list is itself a
    # documented claim that reality moves past (it did — the ledger's
    # restructure into api/, client, config, handlers made the old
    # ["identity", "events", "writer", "integrity"] list flag every correct
    # README mention as "not a module", measured 2026-09-07).
    if siblings is None:
        siblings = {
            "traust-ledger": ("traust_ledger", ("traust-ledger",)),
        }
    for repo, (pkg, dirs) in siblings.items():
        iname = f"sibling-readme:{repo}"
        root = next((ws / d for d in dirs if (ws / d).is_dir()), ws / dirs[0])
        readme, pj = root / "README.md", root / "pyproject.toml"
        if not readme.is_file() or not pj.is_file():
            out.append(
                item(iname, "unavailable", f"{repo} not checked out at {root} — nothing to compare")
            )
            continue
        pkg_root = root / "src" / pkg
        if not pkg_root.is_dir():
            out.append(
                item(
                    iname,
                    "unavailable",
                    f"{repo} has no src/{pkg}/ package tree at {root} — "
                    f"cannot resolve its module surface",
                )
            )
            continue
        try:
            rtext, ptext = readme.read_text(), pj.read_text()
        except OSError as e:
            out.append(item(iname, "unavailable", f"cannot read {repo} docs ({type(e).__name__})"))
            continue

        problems: list[str] = []

        # 1. every dependency pin the pyproject declares must not be
        #    contradicted by a different pin for the same package in the README
        for name, spec in _re.findall(r'"([a-z0-9][a-z0-9-]+)(>=[^"]+)"', ptext):
            claimed = _re.findall(rf'"{_re.escape(name)}(>=[^"]+)"', rtext)
            stale = [c for c in claimed if c != spec]
            if stale:
                problems.append(f"README pins {name}{stale[0]} but pyproject pins {name}{spec}")
        for name, tag in _re.findall(
            r'^([a-z0-9][a-z0-9-]+) = \{ git = [^}]*tag = "([^"]+)"', ptext, _re.M
        ):
            claimed = _re.findall(
                rf'^{_re.escape(name)} = \{{ git = [^}}]*tag = "([^"]+)"', rtext, _re.M
            )
            stale = [c for c in claimed if c != tag]
            if stale:
                problems.append(f"README pins {name} tag {stale[0]} but pyproject pins {tag}")

        # 2. every `pkg.sub.module` the README names must exist in the checkout.
        #    Resolved against the tree, not an import: a private (`_`-prefixed)
        #    path is not public surface even though it imports, and a module
        #    that exists but fails to import is a different defect (step 3
        #    reports it as unavailable rather than hiding it here).
        mentioned = sorted(
            set(_re.findall(rf"\b{_re.escape(pkg)}((?:\.[a-z_][a-z0-9_]*)+)", rtext))
        )
        documented_mods: list[str] = []
        for dotted in mentioned:
            parts = dotted.lstrip(".").split(".")
            if not _module_path_exists(pkg_root, parts):
                problems.append(f"README names {pkg}{dotted}, which is not a module")
                continue
            documented_mods.append(".".join(parts))

        # 3. every public name a module EXPORTS should appear in the README.
        #    Deliberately this direction and not the reverse: checking that every
        #    backticked identifier exists flags prose ("algo_version") and
        #    declared future work ("a ServiceBackend arrives with..."), and a
        #    check that cries wolf gets ignored. Under-documentation is the
        #    failure that actually happened — traust_ledger.events exported eight
        #    names while the README listed three, and the five omitted ones were
        #    the newest work in the module.
        #    Scope: the modules the README itself documents (step 2's survivors).
        #    Every public module in the tree would be the stricter rule, but the
        #    ledger's src/ also holds service wiring (handlers, service, cli)
        #    whose exports are not consumer surface, and a check that lists
        #    those cries wolf.
        undocumented: list[str] = []
        unimportable: list[str] = []
        # Audit the CHECKOUT's modules, not whatever version of the sibling
        # this venv happens to have installed: the README sits beside the
        # source it describes, and the installed pin can lag it by releases
        # (measured 2026-09-07 — the venv held traust-ledger 0.20.0 while the
        # checkout was 0.20.2, so a fixed README kept reporting as drift).
        # A subprocess with the checkout's src/ first on the path is the only
        # way to get a clean import that the in-process module cache cannot
        # shadow.
        exports = _probe_exports(pkg_root, pkg, documented_mods)
        if exports is None:
            problems.append(
                "export audit could not run against the checkout "
                f"(src/{pkg} did not import in a subprocess)"
            )
        else:
            for mod in documented_mods:
                info = exports.get(mod, {})
                if "missing" in info:
                    missing = info["missing"]
                    if missing == pkg or missing.startswith(pkg + "."):
                        unimportable.append(f"{pkg}.{mod} (references {missing})")
                    continue
                if "error" in info:
                    unimportable.append(f"{pkg}.{mod} ({info['error']})")
                    continue
                for sym in info.get("names", []):
                    if f"`{sym}`" not in rtext:
                        undocumented.append(f"{pkg}.{mod}.{sym}")
        if undocumented:
            problems.append(
                f"{len(undocumented)} exported name(s) absent from the README: "
                f"{', '.join(undocumented[:6])}"
            )
        if unimportable:
            problems.append(
                f"{len(unimportable)} README-named module(s) exist but do not "
                f"import in this venv: {', '.join(unimportable[:4])}"
            )

        fix = f"update {repo}/README.md to match its pyproject and module surface"
        if problems:
            out.append(item(iname, "drift", "; ".join(problems[:4]), fix))
        else:
            out.append(
                item(
                    iname,
                    "fresh",
                    f"{repo} README agrees with its pyproject pins and module surface",
                )
            )
    return out


def _language_mass(cache_p: Path) -> tuple[dict[str, int], dict[str, int], int, int]:
    """(dominant, present, repos, malformed) from the portfolio language
    cache. `dominant` counts the repos each language leads by bytes;
    `present` counts repos it appears in at all. Shared by the
    language-coverage and reachability-coverage tripwires so the two can
    never disagree about the portfolio's language mass."""
    dominant: dict[str, int] = {}
    present: dict[str, int] = {}
    repos = 0
    malformed = 0
    for line in cache_p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            langs = json.loads(line).get("languages") or {}
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(langs, dict) or not langs:
            continue
        repos += 1
        for lang in langs:
            present[lang] = present.get(lang, 0) + 1
        top = max(langs.items(), key=lambda kv: kv[1] or 0)[0]
        dominant[top] = dominant.get(top, 0) + 1
    return dominant, present, repos, malformed


def check_reachability_coverage(ws: Path) -> list[dict]:
    """Portfolio language mass vs SYMBOL-TIER REACHABILITY coverage, plus
    the review clock on the reachability watch register.

    Sibling of the language-coverage tripwire, one rung up the evidence
    ladder: that check asks whether a language's *dependency graph* is
    built at all; this one asks whether a language whose graph exists can
    ever reach `affected`. Without a reachability engine every dependency
    hit in that language ceilings at `likely_affected` on manifest
    evidence ("a pin is never reachability", docs/reachability.md), so a
    high-mass uncovered language is a standing precision gap, not a
    neutral absence.

    Two legs:

    1. Any language dominant in >= REACHABILITY_COVERAGE_THRESHOLD repos
       with no entry in REACHABILITY_ENGINES and no no-deps allowlist
       excuse = **drift**, reported with its repo mass so the priority
       ordering is visible rather than assumed.
    2. The watch register's `reviewed` date against its cadence. The
       W3 revisit triggers ("does OSV carry call-graph data yet", "has an
       Apache-licensed reachability engine matured") have no machine
       feed, so — like the compliance catalogs' `reviewed` keys — the
       review window IS the staleness mechanism.

    Routes attention only: wiring an engine is a deliberate pilot with a
    ground-truth corpus (docs/reachability.md "Validation records").
    """
    out = []
    cache_p = ws / LANG_CACHE_REL
    if not cache_p.is_file():
        out.append(
            item(
                "reachability-coverage",
                "pending",
                f"no portfolio language cache yet ({LANG_CACHE_REL})",
                "build the language cache (loc-dashboard / build_portfolio_graph language harvest)",
            )
        )
    else:
        dominant, present, repos, malformed = _language_mass(cache_p)
        flagged = [
            (lang, n)
            for lang, n in sorted(dominant.items(), key=lambda kv: (-kv[1], kv[0]))
            if n >= REACHABILITY_COVERAGE_THRESHOLD
            and lang not in REACHABILITY_ENGINES
            and lang not in NO_DEPS_LANGUAGE_ALLOWLIST
        ]
        for lang, n in flagged:
            out.append(
                item(
                    "reachability-coverage:" + lang,
                    "drift",
                    f"{lang} is dominant in {n} repos (present in "
                    f"{present.get(lang, n)}) but has NO symbol-tier "
                    f"reachability engine — every dependency finding in it "
                    f"ceilings at `likely_affected` on manifest evidence, "
                    f"and no finding can reach `affected`. Covered today: "
                    + ", ".join(sorted(REACHABILITY_ENGINES))
                    + f" (threshold {REACHABILITY_COVERAGE_THRESHOLD} repos)",
                    "wire an engine behind a facts-only wrapper validated "
                    "against a ground-truth corpus (the Java/C pattern, "
                    "docs/reachability.md), or record the deliberate "
                    "non-coverage decision in " + REACHABILITY_WATCH_REL,
                )
            )
        if not flagged:
            out.append(
                item(
                    "reachability-coverage",
                    "fresh",
                    f"every language dominant in >= "
                    f"{REACHABILITY_COVERAGE_THRESHOLD} of {repos} repos has "
                    f"a symbol-tier reachability engine or a no-deps excuse"
                    + (f"; {malformed} malformed cache line(s) skipped" if malformed else ""),
                )
            )

    # Leg 2 — the watch register's review clock.
    reg_p = ws / REACHABILITY_WATCH_REL
    refresh = (
        "re-check the watch conditions in "
        + REACHABILITY_WATCH_REL
        + " and bump its `reviewed` date (or act on a trigger "
        "that has fired)"
    )
    if not reg_p.is_file():
        out.append(
            item(
                "reachability-watch:review",
                "pending",
                f"no watch register at {REACHABILITY_WATCH_REL}",
                refresh,
            )
        )
        return out
    if yaml is None:
        out.append(
            item(
                "reachability-watch:review",
                "unavailable",
                "PyYAML missing — cannot read the watch register",
            )
        )
        return out
    try:
        reg = yaml.safe_load(reg_p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        out.append(
            item(
                "reachability-watch:review", "unavailable", f"{REACHABILITY_WATCH_REL} unparseable"
            )
        )
        return out
    reviewed = reg.get("reviewed")
    cadence = reg.get("review_cadence_days") or 92
    # unquoted YAML dates load as datetime.date — str() normalizes both
    # that and a quoted "YYYY-MM-DD" into what _parse_iso accepts
    stamp = _parse_iso(str(reviewed)) if reviewed else None
    if stamp is None:
        out.append(
            item(
                "reachability-watch:review",
                "unavailable",
                "register has no parseable `reviewed` date",
                refresh,
            )
        )
        return out
    age = _age_days(stamp)
    n_watch = len(reg.get("watch") or [])
    if age > cadence:
        out.append(
            item(
                "reachability-watch:review",
                "stale",
                f"{n_watch} watch condition(s) last reviewed {reviewed} "
                f"({age:.0f}d ago, cadence {cadence}d)",
                refresh,
            )
        )
    else:
        out.append(
            item(
                "reachability-watch:review",
                "fresh",
                f"{n_watch} watch condition(s) reviewed {reviewed} "
                f"({age:.0f}d ago, cadence {cadence}d)",
            )
        )
    return out


def check_language_coverage(ws: Path) -> list[dict]:
    """Portfolio language composition vs dependency-graph ecosystem
    coverage — the anti-Go-bias tripwire.

    Two signals, same philosophy as the docs-product-map FUTURE-version
    check (detect NEW things current coverage does not handle):

    1. Any GitHub language that is DOMINANT (max bytes) in at least
       LANGUAGE_COVERAGE_THRESHOLD repos but maps to NEITHER a covered
       ecosystem (manifest_parsers.LANGUAGE_ECOSYSTEMS / the universal
       docker/actions/helm surfaces / the GRAPHED_NON_MANIFEST_LANGUAGES
       carve-out for Go's go.mod L1 lane) NOR the
       NO_DEPS_LANGUAGE_ALLOWLIST is
       a new language the portfolio graph is silently under-covering
       (e.g. Swift/Elixir/PHP/Kotlin/Scala if uncovered). Flagged `drift`.

    2. If the graph builder has persisted deps-multi-stats.json, one
       informational row per ecosystem (repos_with_manifest, dep_edges),
       and `drift` for any ecosystem whose manifests WERE discovered
       (repos_with_manifest > 0) but produced zero dep_edges — a
       silently-broken extraction lane / coverage regression (mirrors the
       builder's own `loud_fail` definition).

    Routes attention only: mapping a new ecosystem or extending the
    allowlist is a deliberate human/config decision.
    """
    out = []
    cache_p = ws / LANG_CACHE_REL
    if not cache_p.is_file():
        out.append(
            item(
                "language-coverage",
                "pending",
                f"no portfolio language cache yet ({LANG_CACHE_REL})",
                "build the language cache (loc-dashboard / build_portfolio_graph language harvest)",
            )
        )
    else:
        try:
            mp = _manifest_parsers_mod()
            lang_eco = dict(mp.LANGUAGE_ECOSYSTEMS)
            universal = set(mp.UNIVERSAL_ECOSYSTEMS)
        except Exception as e:
            return [
                item(
                    "language-coverage",
                    "unavailable",
                    f"cannot load manifest_parsers: {str(e)[:120]}",
                )
            ]
        dominant, present, repos, malformed = _language_mass(cache_p)
        flagged = []
        for lang, n in sorted(dominant.items(), key=lambda kv: (-kv[1], kv[0])):
            if n < LANGUAGE_COVERAGE_THRESHOLD:
                continue
            if (
                lang in lang_eco
                or lang in universal
                or lang in GRAPHED_NON_MANIFEST_LANGUAGES
                or lang in NO_DEPS_LANGUAGE_ALLOWLIST
            ):
                continue
            flagged.append((lang, n))
        for lang, n in flagged:
            out.append(
                item(
                    "language-coverage:" + lang,
                    "drift",
                    f"Language {lang} is dominant in {n} repos but has no "
                    f"dependency-graph ecosystem coverage and is not on the "
                    f"no-deps allowlist — portfolio graph may be under-"
                    f"covering it (present in {present.get(lang, n)} repos "
                    f"total; threshold {LANGUAGE_COVERAGE_THRESHOLD})",
                    "add a manifest_parsers.LANGUAGE_ECOSYSTEMS mapping + "
                    "parser for this language, or add it to "
                    "check_drift.NO_DEPS_LANGUAGE_ALLOWLIST with a reason "
                    "(deliberate coverage decision)",
                )
            )
        if not flagged:
            out.append(
                item(
                    "language-coverage",
                    "fresh",
                    f"{len(dominant)} dominant language(s) across {repos} "
                    f"repos; every language dominant in >= "
                    f"{LANGUAGE_COVERAGE_THRESHOLD} repos is ecosystem-covered "
                    f"or allowlisted"
                    + (f"; {malformed} malformed cache line(s) skipped" if malformed else ""),
                )
            )

    # Per-ecosystem coverage-regression tripwire (if the builder persisted
    # deps-multi-stats.json next to portfolio-graph.db).
    stats_p = _ar(ws) / "graph" / "deps-multi-stats.json"
    if stats_p.is_file():
        try:
            stats = json.loads(stats_p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            out.append(
                item(
                    "language-coverage:ecosystems",
                    "unavailable",
                    "deps-multi-stats.json unparseable",
                )
            )
            return out
        for eco, s in sorted(stats.items()):
            # Per-ecosystem rows are dicts carrying repos_with_manifest;
            # global scalars (repos_tree_ok, loud_fail, ...) are skipped.
            if not isinstance(s, dict) or "repos_with_manifest" not in s:
                continue
            rwm = s.get("repos_with_manifest") or 0
            edges = s.get("dep_edges") or 0
            iname = "language-coverage:eco:" + eco
            if rwm > 0 and edges == 0:
                out.append(
                    item(
                        iname,
                        "drift",
                        f"ecosystem {eco}: {rwm} repos_with_manifest but 0 "
                        f"dep_edges — the extraction lane produced nothing "
                        f"(silently-broken surface / coverage regression)",
                        "re-run build_portfolio_graph deps-multi for this "
                        "ecosystem and inspect its parser — a discovered "
                        "manifest yielding no edges is a broken lane",
                    )
                )
            else:
                out.append(
                    item(
                        iname,
                        "fresh",
                        f"ecosystem {eco}: {rwm} repos_with_manifest, {edges} dep_edges",
                    )
                )
    return out


def check_language_cache_freshness(ws: Path) -> list[dict]:
    """Staleness backstop for the gh-languages cache that check_language_
    coverage reads. That cache is not refetched on cadence, so a stale cache
    lets the coverage tripwire run on old data and miss a genuinely new
    language/ecosystem entering the portfolio. Flags `drift` when the cache
    file is MISSING or older than LANGUAGE_CACHE_MAX_AGE_DAYS; /loc-dashboard
    (with fetch) refreshes it. Routes attention only."""
    cache_p = ws / LANG_CACHE_REL
    refresh = "/loc-dashboard (with fetch) refreshes the gh-languages cache"
    mt = _mtime(cache_p)
    if mt is None:
        return [
            item(
                "language-cache-freshness",
                "drift",
                f"portfolio language cache missing ({LANG_CACHE_REL}) — the "
                f"language-coverage tripwire has no data to run on",
                refresh,
            )
        ]
    days = _age_days(mt)
    status = "fresh" if days <= LANGUAGE_CACHE_MAX_AGE_DAYS else "drift"
    return [
        item(
            "language-cache-freshness",
            status,
            f"{LANG_CACHE_REL} is {days:.0f}d old (threshold "
            f"{LANGUAGE_CACHE_MAX_AGE_DAYS}d) — a stale cache lets the "
            f"language-coverage check miss a new language/ecosystem",
            refresh if status != "fresh" else None,
        )
    ]


# --------------------------------------------------------------------------
# agent plugins — installed Claude Code plugins vs their marketplace entry
# --------------------------------------------------------------------------
# config/external-tools.yaml describes a BINARY: a `version_cmd` to run and a
# GitHub release to compare against. An agent plugin has neither, so adopting
# one leaves a dependency nothing watches — the shape of the sigstore
# retroactive intake. This row closes that, modelled on check_adr_registry:
# a recorded local state compared against the upstream source of truth, with
# no auto-advance.
#
# Roster lives in $TRAUST_CONFIG_HOME/agent-plugins.yaml so the deployment
# decides which plugins it depends on; absent file = nothing watched, which
# is the default for an adopter using no plugins.
AGENT_PLUGINS_MANIFEST = optional_config_path("agent-plugins.yaml")

_PLUGIN_STATE = Path.home() / ".claude" / "plugins" / "installed_plugins.json"


def _installed_plugin(state: dict, name: str, marketplace: str) -> dict | None:
    """The newest install record for `name@marketplace`, or None."""
    records = (state.get("plugins") or {}).get(f"{name}@{marketplace}") or []
    return max(records, key=lambda r: r.get("lastUpdated") or "", default=None)


def check_agent_plugins(ws: Path) -> list[dict]:
    """Installed agent plugins vs the version their marketplace publishes.

    Reports only; advancing a plugin is a deliberate human action, per the
    standing constraint that no check may auto-advance a pin.
    """
    if AGENT_PLUGINS_MANIFEST is None or not AGENT_PLUGINS_MANIFEST.is_file():
        return []
    if yaml is None:
        return [item("agent-plugins", "unavailable", "PyYAML missing")]
    roster = yaml.safe_load(AGENT_PLUGINS_MANIFEST.read_text(encoding="utf-8")) or {}
    entries = roster.get("plugins") or []
    if not entries:
        return []

    # Roster validation first: a malformed repo URL is a config error and must
    # be reported even on a machine with no plugins installed, where the state
    # read below legitimately fails.
    out: list[dict] = []
    checkable = []
    for e in entries:
        url = str(e.get("repo") or "")
        if not url.startswith("https://"):
            out.append(
                item(
                    f"agent-plugins:{e.get('name')}",
                    "unavailable",
                    f"non-https plugin repo refused: {url}",
                )
            )
            continue
        checkable.append(e)
    if not checkable:
        return out

    try:
        state = json.loads(_PLUGIN_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out + [
            item(
                "agent-plugins",
                "unavailable",
                f"cannot read {_PLUGIN_STATE} — plugins are a per-workstation "
                "install, so this row is silent on a headless runner",
            )
        ]

    for e in checkable:
        name = e.get("name")
        marketplace = e.get("marketplace")
        url = str(e.get("repo") or "")
        row = f"agent-plugins:{name}"

        installed = _installed_plugin(state, name, marketplace)
        if installed is None:
            out.append(
                item(
                    row,
                    "pending",
                    f"declared in agent-plugins.yaml but not installed",
                    f"/plugin marketplace add {marketplace} && /plugin install {name}",
                )
            )
            continue

        have = installed.get("version")
        sha = (installed.get("gitCommitSha") or "")[:12]
        want, err = _marketplace_version(url, name)
        if err:
            out.append(item(row, "unavailable", err))
            continue

        if want and have and want != have:
            out.append(
                item(
                    row,
                    "stale",
                    f"installed {have} (sha {sha or 'unknown'}) but the marketplace "
                    f"publishes {want} — upstream may have changed the skill's "
                    f"behaviour or its licence terms",
                    f"/plugin update {name}, then re-check its row in "
                    f"docs/external-dependencies.md",
                )
            )
        else:
            out.append(item(row, "fresh", f"{have} matches the marketplace (sha {sha or 'n/a'})"))
    return out


def _marketplace_version(url: str, name: str) -> tuple[str | None, str | None]:
    """(version, error) for `name` in the marketplace manifest at `url`.

    Reads the manifest from a shallow clone rather than a raw-content URL so
    the row works for any git host, and so the https gate above is the only
    network policy decision.
    """
    with tempfile.TemporaryDirectory() as tmp:
        try:
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", "--", url, tmp + "/m"],
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"},
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return None, f"cannot reach {url} ({type(exc).__name__})"
        if proc.returncode != 0:
            return None, f"cannot clone {url}"
        manifest = Path(tmp) / "m" / ".claude-plugin" / "marketplace.json"
        if not manifest.is_file():
            return None, f"{url} has no .claude-plugin/marketplace.json"
        try:
            doc = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None, f"unreadable marketplace.json at {url}"
        return _plugin_version_from_manifest(doc, name, url)


def _plugin_version_from_manifest(doc: dict, name: str, url: str) -> tuple[str | None, str | None]:
    """The version `name` is published at in a marketplace manifest document."""
    for plugin in doc.get("plugins") or []:
        if plugin.get("name") == name:
            return plugin.get("version"), None
    return None, f"{name} is not listed in {url}'s marketplace.json"



CHECKS = (
    check_findings_db,
    check_ledger_completeness,
    check_fp_precedent_cache,
    check_rule_mining,
    check_graphs,
    check_validation_benchmark,
    check_impact_artifacts,
    check_repo_liveness,
    check_adr_registry,
    check_checkov_pin,
    check_yara_rules_pin,
    check_argus_rules_pin,
    check_external_tools,
    check_agent_plugins,
    check_feed_sources,
    check_grype_db,
    check_pqc_facts_provenance,
    check_pqc_backfeed,
    check_framework_upstream,
    check_policy_provenance,
    check_docs_semantic_sweep,
    check_threat_model_staleness,
    check_rescan_worklist,
    check_dashboard_staleness,
    check_docs_product_map,
    check_language_coverage,
    check_reachability_coverage,
    check_dependency_pins,
    check_sibling_readmes,
    check_signature_coverage,
    check_finding_identity,
    check_language_cache_freshness,
)

ENGINE_CHECKS = (check_corpus_registration, check_ref_provenance)


def harness_version():
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (OSError, subprocess.SubprocessError):
        return None


def render_md(report: dict) -> str:
    # `info` belongs here even though it is not an actionable status: two checks
    # emit it (dashboards:builders-uncovered since 0.307.0, ledger:colliding-layer-ids
    # since 0.313.0) and its absence made this renderer raise ValueError on the very
    # corpus those rows describe — the markdown half of the report has not been
    # written since. A status vocabulary split across two literals is the bug; the
    # sort key now tolerates an unknown one instead of aborting the report.
    order = ("drift", "stale", "review_due", "unavailable", "pending", "info", "fresh")
    icon = {
        "fresh": "✓",
        "stale": "⚠",
        "drift": "✗",
        "review_due": "⏰",
        "pending": "…",
        "unavailable": "?",
        "info": "·",
    }
    L = [
        "# Staleness & Drift Report",
        "",
        f"_Generated {report['metadata']['generated_at']} · harness "
        f"{report['metadata']['harness_version']}. Deterministic "
        f"checker — routes attention, never concludes; refresh "
        f"commands are suggestions, rebuild decisions stay human._",
        "",
        "| | Item | Status | Detail |",
        "|---|---|---|---|",
    ]
    items = sorted(
        report["items"],
        key=lambda i: order.index(i["status"]) if i["status"] in order else len(order),
    )
    for i in items:
        L.append(
            f"| {icon.get(i['status'], '·')} | {i['item']} | {i['status']} | {i['detail'][:160]} |"
        )
    L.append("")
    stale = [i for i in items if i["status"] in ("stale", "drift", "review_due")]
    if stale:
        L.append("## Refresh queue")
        L.append("")
        for i in stale:
            if i.get("refresh"):
                L.append(f"- **{i['item']}** → `{i['refresh']}`")
        L.append("")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="workspace root (default: configured workspace)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="report output dir (default: <progress-tracker>/metrics/drift)",
    )
    ap.add_argument(
        "--fail-on",
        choices=("stale", "drift"),
        default=None,
        help="nonzero exit when items at/above this class exist (drift > stale)",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    ws = (args.workspace or workspace_dir(engine)).resolve()
    global _run_ar, _run_pt
    _run_ar = _analysis_results_for_checks(ws, engine)
    _run_pt = _progress_tracker_for_checks(ws, engine)
    items = []
    try:
        try:
            items.extend(check_feeds(engine))
        except Exception as e:
            items.append(item("check_feeds", "unavailable", f"checker error: {e}"))
        for chk in CHECKS:
            try:
                items.extend(chk(ws))
            except Exception as e:
                items.append(
                    item(
                        chk.__name__,
                        "unavailable",  # kills the run
                        f"checker error: {e}",
                    )
                )
        for chk in ENGINE_CHECKS:
            try:
                items.extend(chk(ws, engine))
            except Exception as e:
                items.append(item(chk.__name__, "unavailable", f"checker error: {e}"))
    finally:
        _run_ar = _run_pt = None
    counts = {}
    for i in items:
        counts[i["status"]] = counts.get(i["status"], 0) + 1
    report = {
        "metadata": {
            "artifact": "staleness-drift-report",
            "role": (
                "deterministic freshness/agreement checker — routes attention, never concludes"
            ),
            "harness_version": harness_version(),
            "workspace": str(ws),
            "generated_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "summary": counts,
        "items": items,
    }
    if args.out_dir:
        out_dir = args.out_dir.resolve()
    elif args.workspace is not None:
        out_dir = (_pt(ws) / "metrics" / "drift").resolve()
    else:
        out_dir = (progress_tracker_dir(engine) / "metrics" / "drift").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "drift-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "drift-report.md").write_text(render_md(report), encoding="utf-8")
    print(f"wrote {out_dir}/drift-report.{{json,md}}")
    print("  " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    if args.fail_on:
        bad = {"stale": ("stale", "drift"), "drift": ("drift",)}[args.fail_on]
        if any(i["status"] in bad for i in items):
            return 1
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "drift", *sys.argv[1:]]))
