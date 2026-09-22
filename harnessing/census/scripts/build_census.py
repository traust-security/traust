#!/usr/bin/env python3
"""Census — population, duplication vectors, and distinct vulnerabilities.

The deterministic denominator authority for every other dashboard. Built
on traust.cli.groups.corpus (discovery / identity / ownership) plus a full pass
over every report's preferred layer (findings-current when present, else
the audit JSON), it answers three questions no single dashboard answers:

1. POPULATION — what exists, per tree and ownership cut: reports, unique
   repo slugs, md-only parse gaps, disposition-ledger coverage,
   unregistered-tree drift warnings.

2. DUPLICATION — the five vectors that inflate naive counts, quantified
   fresh each run: symlink aliases (incl. ledgers attached to aliased
   reports), branch re-audits (and how many of their findings are
   fingerprint-confirmations of a HEAD finding vs branch-only), layered
   artifact restatement (audit/triage/findings-current), cross-tree slug
   overlap, and duplicate report basenames.

3. DISTINCT VULNERABILITIES — the Lens 2 headline: unique finding
   fingerprints at HEAD, disposition-adjusted (false positives dropped,
   hardening reported separately), with severity taken as the max across
   occurrences. Reported per ownership cut; the executive view is the
   owned cut with the upstream cut as an adjacent line, never folded in.

Outputs (to progress-tracker/metrics/dashboards/census/):
    census.json  census.md  census.html

Each run appends a snapshot to the central metrics ledger
(traust_engine.metrics.history, source "census").

CLI:
    python3 harnessing/census/scripts/build_census.py \\
        [--workspace-root WS] [--out-dir DIR] [--summary] [--skip-ledger]
"""

from __future__ import annotations

import argparse
import collections
import html as html_mod
import json
import sys
import time
from datetime import UTC, datetime, timezone  # noqa: F401  (strptime in main)
from pathlib import Path

from traust_engine._util.script_loader import load_script
from traust_engine.corpus import report_store
from traust_engine.metrics import history as metrics_history

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)
from traust.paths import HARNESS_ROOT

HARNESS = HARNESS_ROOT


def _load_script(name: str):
    return load_script(name, HARNESS)


corpus = _load_script("corpus")
finding_identity = _load_script("finding_identity")

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITIES = ("critical", "high", "medium", "low", "informational")


# ---------------------------------------------------------------------------
# finding classification
# ---------------------------------------------------------------------------


def classify(finding: dict, layered: bool) -> tuple[str, str]:
    """-> (validity, resolution). findings-current carries an explicit
    disposition; a plain audit finding is a claim (open by definition)."""
    if layered:
        disp = finding.get("disposition") or {}
        return (disp.get("validity") or "not_verified", disp.get("resolution") or "open")
    vs = finding.get("validation_status")
    if vs in ("false_positive", "hardening"):
        return vs, "open"
    return "not_verified", "open"


def fp_key(finding: dict, repo_url: str | None) -> str:
    return finding.get("fingerprint") or finding_identity.fingerprint(finding, repo_url)


# ---------------------------------------------------------------------------
# the census pass
# ---------------------------------------------------------------------------


def _preferred_report(rec, store, results):
    """The report a census row counts from, fetched through the store.

    Reads used to be `Path(rec.findings_current or rec.audit_json).read_text()`.
    Going through `report_store` is the point of §4.4.0 step 2: the census stops
    caring whether that artifact is a file beside the layer or an object in a
    bucket. `to_ref` accepts either an absolute path (what records hand out today)
    or a ref, so this works on both sides of step 2b.
    """
    layered = rec.preferred == "findings_current"
    path = rec.findings_current if layered else rec.audit_json
    if not path:
        return layered, None, None
    ref = report_store.to_ref(path, results)
    return layered, ref, store.get_json(ref)


def run_census(analysis_results: Path, cfg, engine=None, use_engine_resolve: bool = False) -> dict:
    t0 = time.monotonic()
    if use_engine_resolve and engine is not None:
        res = engine.corpus.load_resolution()
    else:
        res = report_store.load_resolution(analysis_results, cfg)
    store = report_store.ReportStore(report_store.LocalBackend(analysis_results))
    agg = corpus.aggregates(res)

    cuts: dict[str, dict] = {}  # ownership -> metrics
    head_fps_by_tree: dict[str, set] = collections.defaultdict(set)
    branch_records = []
    parse_errors: list[str] = []
    base_paths = collections.defaultdict(set)  # basename -> report dirs

    def cut(ownership: str) -> dict:
        return cuts.setdefault(
            ownership,
            {
                "reports": 0,
                "head_reports": 0,
                "md_only": 0,
                "with_ledger": 0,
                "head_findings": 0,
                "fp_dropped": 0,
                "hardening": {},  # fp -> sev
                "distinct": {},  # fp -> {"sev","open"}
            },
        )

    # Declared-layer IaC audits (report_kind == "cloud-config") are a
    # different unit (hardening-class posture, no live observation) and
    # NEVER blend into the code-audit cuts or the distinct-vulnerability
    # headline — they get their own labeled block.
    cloud = {
        "reports": 0,
        "with_ledger": 0,
        "findings": 0,
        "suppressed": 0,
        "by_severity": collections.Counter(),
    }

    # Container-image audits (report_kind == "container-audit") are a
    # digest-keyed artifact snapshot, not a source-code unit, and their
    # findings are often the shipped manifestation of code findings the
    # headline already counts (source_findings cross-links) — so like
    # cloud-config they NEVER blend into the code-audit cuts or the
    # distinct-vulnerability headline; they get their own labeled block.
    container = {
        "reports": 0,
        "with_ledger": 0,
        "findings": 0,
        "fp_dropped": 0,
        "by_severity": collections.Counter(),
    }

    for rec in res.records:
        if rec.report_kind == "container-audit":
            container["reports"] += 1
            if rec.findings_current:
                container["with_ledger"] += 1
            try:
                layered, _ref, rep = _preferred_report(rec, store, analysis_results)
            except (OSError, ValueError, json.JSONDecodeError) as e:
                parse_errors.append(f"{rec.audit_json or rec.findings_current}: {e}")
                continue
            if rep is None:
                continue
            for f in rep.get("findings") or []:
                validity, _ = classify(f, layered)
                if validity == "false_positive":
                    container["fp_dropped"] += 1
                    continue
                container["findings"] += 1
                sev = str(f.get("severity") or "informational").lower()
                container["by_severity"][sev] += 1
            continue
        if rec.report_kind == "cloud-config":
            cloud["reports"] += 1
            if rec.findings_current:
                cloud["with_ledger"] += 1
            try:
                layered, _ref, rep = _preferred_report(rec, store, analysis_results)
            except (OSError, ValueError, json.JSONDecodeError) as e:
                parse_errors.append(f"{rec.audit_json or rec.findings_current}: {e}")
                continue
            if rep is None:
                continue
            for f in rep.get("findings") or []:
                validity, _ = classify(f, layered)
                if validity == "false_positive" or f.get("status") == "suppressed":
                    cloud["suppressed"] += 1
                    continue
                cloud["findings"] += 1
                sev = str(f.get("severity") or "informational").lower()
                cloud["by_severity"][sev] += 1
            continue
        c = cut(rec.ownership)
        c["reports"] += 1
        base_paths[rec.base].add(rec.tree + "/" + (rec.product or "") + "/" + rec.repo_dir)
        if rec.findings_current:
            c["with_ledger"] += 1
        if rec.is_branch_audit:
            branch_records.append(rec)
            continue
        c["head_reports"] += 1
        if rec.findings_current:
            c["head_with_ledger"] = c.get("head_with_ledger", 0) + 1
        if rec.is_md_only and not rec.findings_current:
            c["md_only"] += 1
            continue

        try:
            layered, _ref, rep = _preferred_report(rec, store, analysis_results)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            parse_errors.append(f"{rec.audit_json or rec.findings_current}: {e}")
            continue
        if rep is None:
            continue
        repo_url = (rep.get("metadata") or {}).get("repository")

        for f in rep.get("findings") or []:
            validity, resolution = classify(f, layered)
            if validity == "false_positive":
                c["fp_dropped"] += 1
                continue
            key = fp_key(f, repo_url)
            sev = str(f.get("severity") or "informational").lower()
            if validity == "hardening":
                prev = c["hardening"].get(key)
                if prev is None or SEV_RANK.get(sev, 0) > SEV_RANK.get(prev, 0):
                    c["hardening"][key] = sev
                continue
            head_fps_by_tree[rec.tree].add(key)
            c["head_findings"] += 1
            entry = c["distinct"].setdefault(key, {"sev": sev, "open": False})
            if SEV_RANK.get(sev, 0) > SEV_RANK.get(entry["sev"], 0):
                entry["sev"] = sev
            if resolution not in ("resolved", "risk_accepted"):
                entry["open"] = True

    # branch pass — confirmations of HEAD findings vs branch-only findings
    branch = {
        "reports": len(branch_records),
        "findings": 0,
        "confirmations": 0,
        "branch_only_fps": set(),
        "parse_errors": 0,
    }
    for rec in branch_records:
        try:
            layered, _ref, rep = _preferred_report(rec, store, analysis_results)
        except (OSError, ValueError, json.JSONDecodeError):
            branch["parse_errors"] += 1
            continue
        if rep is None:
            continue
        repo_url = (rep.get("metadata") or {}).get("repository")
        for f in rep.get("findings") or []:
            validity, _ = classify(f, layered)
            # hardening skipped like FP so "confirmations" means confirmed
            # VULNERABILITIES — same semantics as the executive summary
            if validity in ("false_positive", "hardening"):
                continue
            branch["findings"] += 1
            key = fp_key(f, repo_url)
            if key in head_fps_by_tree[rec.tree]:
                branch["confirmations"] += 1
            else:
                branch["branch_only_fps"].add(key)

    # roll distinct maps into serialisable summaries
    for c in cuts.values():
        sev_dist = collections.Counter(v["sev"] for v in c["distinct"].values())
        open_dist = collections.Counter(v["sev"] for v in c["distinct"].values() if v["open"])
        c["distinct_vulnerabilities"] = len(c["distinct"])
        c["distinct_open"] = sum(v["open"] for v in c["distinct"].values())
        c["distinct_by_severity"] = {s: sev_dist.get(s, 0) for s in SEVERITIES}
        c["open_by_severity"] = {s: open_dist.get(s, 0) for s in SEVERITIES}
        c["hardening_distinct"] = len(c["hardening"])
        c.setdefault("head_with_ledger", 0)
        c["head_ledger_coverage_pct"] = (
            round(100.0 * c["head_with_ledger"] / c["head_reports"], 1)
            if c["head_reports"]
            else 0.0
        )
        del c["distinct"], c["hardening"]

    dup_basenames = {b: sorted(ps) for b, ps in base_paths.items() if len(ps) > 1}
    file_aliases = [
        a
        for a in res.aliases
        if a["kind"] == "file" and a["link"].endswith(corpus.AUDIT_JSON_SUFFIX)
    ]
    alias_ledgers = sum(
        1
        for a in file_aliases
        if Path(a["link"][: -len(corpus.AUDIT_JSON_SUFFIX)] + "-findings-current.json").is_file()
    )

    duplication = {
        "v1_symlink_aliases": {
            "file_aliases": agg["duplication"]["symlink_aliases"],
            "dir_aliases": agg["duplication"]["dir_symlink_aliases"],
            "canonical_targets": agg["duplication"]["symlink_canonical_targets"],
            "ledgers_attached_to_aliases": alias_ledgers,
        },
        "v2_branch_reaudits": {
            "reports": branch["reports"],
            "findings": branch["findings"],
            "head_confirmations": branch["confirmations"],
            "branch_only_distinct": len(branch["branch_only_fps"]),
            "parse_errors": branch["parse_errors"],
        },
        "v3_layered_artifacts": {
            "with_triage": sum(bool(r.triage_json) for r in res.records),
            "with_findings_current": sum(bool(r.findings_current) for r in res.records),
            "naive_all_json_multicount": sum(
                1 + bool(r.triage_json) + bool(r.findings_current) for r in res.records
            ),
            "reports": len(res.records),
        },
        "v4_cross_tree_overlap": {
            "slugs": agg["duplication"]["cross_tree_slugs"],
            "examples": agg["duplication"]["cross_tree_examples"],
        },
        "v5_duplicate_basenames": {
            "basenames": len(dup_basenames),
            "excess_copies": sum(len(p) - 1 for p in dup_basenames.values()),
        },
    }

    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "harness_version": corpus.harness_version(),
        "analysis_results": str(analysis_results),
        "population": {"trees": agg["trees"], "totals": agg["totals"]},
        "ownership_cuts": cuts,
        "cloud_config": {
            "reports": cloud["reports"],
            "with_ledger": cloud["with_ledger"],
            "findings": cloud["findings"],
            "suppressed": cloud["suppressed"],
            "by_severity": {s: cloud["by_severity"].get(s, 0) for s in SEVERITIES},
        },
        "container_audit": {
            "reports": container["reports"],
            "with_ledger": container["with_ledger"],
            "findings": container["findings"],
            "fp_dropped": container["fp_dropped"],
            "by_severity": {s: container["by_severity"].get(s, 0) for s in SEVERITIES},
        },
        "duplication": duplication,
        "warnings": res.warnings,
        "parse_errors": parse_errors[:50],
        "parse_error_count": len(parse_errors),
        "runtime_seconds": round(time.monotonic() - t0, 1),
        "_resolution": res,  # stripped before JSON write
    }


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------


def _sev_line(dist: dict) -> str:
    return " / ".join(str(dist.get(s, 0)) for s in SEVERITIES)


def render_md(cen: dict, cfg: dict, trend: str = "") -> str:
    owned = cen["ownership_cuts"].get("owned", {})
    upstream = cen["ownership_cuts"].get("upstream", {})
    ext = cen["ownership_cuts"].get("external-bu", {})
    dup = cen["duplication"]
    lines = [
        "# Corpus Census",
        "",
        f"_Generated {cen['generated']} · harness {cen['harness_version']} "
        f"· deterministic (`build_census.py`) · runtime "
        f"{cen['runtime_seconds']}s_",
        "",
    ]
    if trend:
        lines += [trend, ""]
    lines += [
        "## Executive view — Hybrid Platforms (owned)",
        "",
        f"**Distinct vulnerabilities: {owned.get('distinct_vulnerabilities', 0):,} "
        f"({owned.get('distinct_open', 0):,} open)** — unique finding "
        f"fingerprints at HEAD across `findings/`, disposition-adjusted, "
        f"false positives excluded, hardening separate "
        f"({owned.get('hardening_distinct', 0):,} distinct hardening gaps).",
        "",
        f"- Open by severity (C/H/M/L/I): **{_sev_line(owned.get('open_by_severity', {}))}**",
        f"- All distinct by severity (C/H/M/L/I): "
        f"{_sev_line(owned.get('distinct_by_severity', {}))}",
        f"- Upstream supply-chain exposure (adjacent, `oss-findings/`, "
        f"never folded in): "
        f"{upstream.get('distinct_vulnerabilities', 0):,} distinct "
        f"({upstream.get('distinct_open', 0):,} open; C/H/M/L/I "
        f"{_sev_line(upstream.get('open_by_severity', {}))})",
        f"- External-BU scan work (Lens 1 only, excluded from HP risk): "
        f"{ext.get('reports', 0):,} reports",
        f"- Cloud-config declared-layer IaC audits (`cloud-config/`, "
        f"hardening-class posture, never folded into the "
        f"distinct-vulnerability headline): "
        f"{cen.get('cloud_config', {}).get('reports', 0):,} reports, "
        f"{cen.get('cloud_config', {}).get('findings', 0):,} findings "
        f"(C/H/M/L/I "
        f"{_sev_line(cen.get('cloud_config', {}).get('by_severity', {}))})",
        f"- Container-image audits (`*-container-audit.json`, "
        f"digest-keyed artifact snapshots, never folded into the "
        f"distinct-vulnerability headline — image findings often "
        f"manifest code findings already counted): "
        f"{cen.get('container_audit', {}).get('reports', 0):,} reports, "
        f"{cen.get('container_audit', {}).get('findings', 0):,} findings "
        f"(C/H/M/L/I "
        f"{_sev_line(cen.get('container_audit', {}).get('by_severity', {}))})",
        f"- **Disposition-ledger coverage (owned, HEAD): "
        f"{owned.get('head_with_ledger', 0):,}/"
        f"{owned.get('head_reports', 0):,} "
        f"({owned.get('head_ledger_coverage_pct', 0)}%)** — the population "
        f"remediation tracking applies to; blended coverage figures "
        f"elsewhere also count branch re-audits (never dispositioned by "
        f"design) and non-owned trees.",
        "",
        "## Population by tree",
        "",
        "| Tree | Ownership | Reports | Unique slugs | Branch re-audits | md-only | Ledgers |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for tree, t in sorted(cen["population"]["trees"].items()):
        lines.append(
            f"| `{tree}/` | {t['ownership']} ({t['business_unit']}) "
            f"| {t['reports']:,} | {t['unique_base_slugs']:,} "
            f"| {t['branch_reaudits']:,} | {t['reports_md_only']} "
            f"| {t['with_findings_current']:,} |"
        )
    reg = [
        (n, e)
        for n, e in cfg.engagements.items()
        if not (Path(cen["analysis_results"]) / e.tree).is_dir()
    ]
    for _name, eng in reg:
        lines.append(
            f"| `{eng.tree}/` | {eng.ownership} "
            f"({eng.business_unit}) | registered, no output "
            f"| — | — | — | — |"
        )
    refs = cen["population"]["totals"].get("refs") or {}
    if refs:
        lines += [
            "",
            "### Per-ref breakdown",
            "",
            "_Reports carrying a ref — legacy slug refs and declared "
            "`metadata.ref` alike (branch-awareness Phase 1); "
            "HEAD reports without a ref are not listed. Additive "
            "metadata: no other census number is derived from this "
            "table._",
            "",
            "| Ref | Reports |",
            "|---|---:|",
        ]
        for ref, n in sorted(refs.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| `{ref}` | {n:,} |")
    v1, v2 = dup["v1_symlink_aliases"], dup["v2_branch_reaudits"]
    v3, v4 = dup["v3_layered_artifacts"], dup["v4_cross_tree_overlap"]
    v5 = dup["v5_duplicate_basenames"]
    lines += [
        "",
        "## Duplication vectors",
        "",
        f"1. **Symlink aliases** — {v1['file_aliases']} file + "
        f"{v1['dir_aliases']} dir aliases → {v1['canonical_targets']} "
        f"canonical reports; {v1['ledgers_attached_to_aliases']} disposition "
        f"ledgers sit next to aliased reports (never counted as reports).",
        f"2. **Branch re-audits** — {v2['reports']:,} reports restating "
        f"{v2['findings']:,} findings; {v2['head_confirmations']:,} are "
        f"fingerprint-confirmations of a HEAD finding (Lens 1 coverage, "
        f"not new exposure); {v2['branch_only_distinct']:,} distinct "
        f"branch-only findings have no tier-1 HEAD match (upper bound — "
        f"strict fingerprint matching misses re-classified/moved findings; "
        f"the rebaseline ladder will tighten this).",
        f"3. **Layered artifacts** — {v3['with_triage']:,} triage + "
        f"{v3['with_findings_current']:,} findings-current restatements: a "
        f"naive all-JSON glob would count {v3['naive_all_json_multicount']:,} "
        f"artifacts for {v3['reports']:,} reports.",
        f"4. **Cross-tree overlap** — {v4['slugs']} repo slugs appear in "
        f"more than one tree (dedupe by canonical URL before portfolio "
        f"sums).",
        f"5. **Duplicate basenames** — {v5['basenames']} report basenames "
        f"exist at multiple real paths ({v5['excess_copies']} excess "
        f"copies).",
        "",
        "## Parse gaps & drift",
        "",
        f"- md-only audit reports (invisible to JSON consumers): "
        f"{cen['population']['totals']['md_only']}",
        f"- JSON parse errors this run: {cen['parse_error_count']}",
    ]
    lv = cen.get("repo_liveness")
    if lv:
        c = lv["counts"]
        non_active = sum(v for k, v in c.items() if k != "active")
        lines += [
            "",
            "## Repo liveness (population metadata)",
            "",
            f"_As of {lv['generated']} "
            f"(`progress-tracker/metrics/repo-liveness.json`)._ "
            f"{c.get('active', 0):,} active · "
            f"{c.get('archived', 0):,} archived · "
            f"{c.get('moved', 0) + c.get('moved-archived', 0):,} moved · "
            f"{c.get('missing', 0):,} missing · "
            f"{c.get('unknown', 0):,} unknown (non-GitHub host) — "
            f"{non_active:,} repos cannot (or may not) act on findings "
            f"through normal ownership. Archived-but-shipping components "
            f"are a distinct risk segment, not burndown residue.",
        ]
    for w in cen["warnings"]:
        lines.append(f"- ⚠ {w}")
    lines += [
        "",
        "---",
        "",
        corpus.render_population_block(
            cen["_resolution"],
            tool="census",
            unit="reports; distinct vulnerabilities = unique finding fingerprints at HEAD",
            filters="false positives dropped; hardening separate; "
            "branch re-audits reported as confirmations",
            denominator="corpus-config.yaml tree walk (findings.db `repos`)",
        ),
    ]
    return "\n".join(lines) + "\n"


def render_html(cen: dict) -> str:
    esc = lambda s: html_mod.escape(str(s))  # noqa: E731
    owned = cen["ownership_cuts"].get("owned", {})
    upstream = cen["ownership_cuts"].get("upstream", {})
    dup = cen["duplication"]

    def card(lbl, val, sub=""):
        return (
            f'<div class="card"><div class="lbl">{esc(lbl)}</div>'
            f'<div class="val">{esc(val)}</div>'
            f'<div class="sub">{esc(sub)}</div></div>'
        )

    sev_chips = "".join(
        f'<span class="sev sev-{s}">{owned.get("open_by_severity", {}).get(s, 0)}</span>'
        for s in SEVERITIES
    )
    tree_rows = "".join(
        f"<tr><td><code>{esc(t)}/</code></td><td>{esc(m['ownership'])}</td>"
        f"<td>{esc(m['business_unit'])}</td>"
        f"<td class='num'>{m['reports']:,}</td>"
        f"<td class='num'>{m['unique_base_slugs']:,}</td>"
        f"<td class='num'>{m['branch_reaudits']:,}</td>"
        f"<td class='num'>{m['reports_md_only']}</td>"
        f"<td class='num'>{m['with_findings_current']:,}</td></tr>"
        for t, m in sorted(cen["population"]["trees"].items())
    )
    ref_totals = cen["population"]["totals"].get("refs") or {}
    ref_rows = "".join(
        f"<tr><td><code>{esc(ref)}</code></td><td class='num'>{n:,}</td></tr>"
        for ref, n in sorted(ref_totals.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    v1, v2 = dup["v1_symlink_aliases"], dup["v2_branch_reaudits"]
    v3, v4 = dup["v3_layered_artifacts"], dup["v4_cross_tree_overlap"]
    v5 = dup["v5_duplicate_basenames"]
    dup_rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{esc(v)}</td></tr>"
        for k, v in [
            (
                "Symlink aliases",
                f"{v1['file_aliases']} file + {v1['dir_aliases']} dir → "
                f"{v1['canonical_targets']} canonicals; "
                f"{v1['ledgers_attached_to_aliases']} alias-attached ledgers",
            ),
            (
                "Branch re-audits",
                f"{v2['reports']:,} reports / {v2['findings']:,} findings; "
                f"{v2['head_confirmations']:,} HEAD confirmations; "
                f"{v2['branch_only_distinct']:,} branch-only distinct",
            ),
            (
                "Layered artifacts",
                f"{v3['with_triage']:,} triage + {v3['with_findings_current']:,} "
                f"findings-current; naive glob = "
                f"{v3['naive_all_json_multicount']:,} artifacts for "
                f"{v3['reports']:,} reports",
            ),
            ("Cross-tree overlap", f"{v4['slugs']} slugs in >1 tree"),
            (
                "Duplicate basenames",
                f"{v5['basenames']} basenames / {v5['excess_copies']} excess copies",
            ),
        ]
    )
    warn_html = "".join(f'<div class="warn">⚠ {esc(w)}</div>' for w in cen["warnings"])

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Corpus Census</title>
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--border:#30363d;
--panel:#161b22;--accent:#58a6ff}}
*{{box-sizing:border-box}}
body{{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}}
h1{{margin:0 0 4px;font-size:22px}}
.sub,.card .sub{{color:var(--muted);font-size:12px}}
.hdr{{color:var(--muted);margin-bottom:20px;font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
gap:12px;margin-bottom:20px}}
.card{{background:var(--panel);border:1px solid var(--border);
border-radius:8px;padding:14px}}
.card .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.5px}}
.card .val{{font-size:24px;font-weight:600;margin-top:4px}}
.panel{{background:var(--panel);border:1px solid var(--border);
border-radius:8px;padding:16px;margin-bottom:20px}}
h2{{margin:0 0 12px;font-size:15px;color:var(--muted);
text-transform:uppercase;letter-spacing:.5px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px 12px;color:var(--muted);font-size:11px;
text-transform:uppercase;letter-spacing:.5px;
border-bottom:1px solid var(--border)}}
td{{padding:8px 12px;border-bottom:1px solid var(--border);
vertical-align:top}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.sev{{display:inline-block;min-width:26px;text-align:center;padding:2px 6px;
border-radius:3px;font-size:11px;font-weight:600;margin-right:3px}}
.sev-critical{{background:#da3633aa;color:#fff}}
.sev-high{{background:#e8590caa;color:#fff}}
.sev-medium{{background:#bf8700aa;color:#fff}}
.sev-low{{background:#1f6febaa;color:#fff}}
.sev-informational{{background:#30363d;color:var(--muted)}}
.warn{{color:#e9c46a;font-size:13px;padding:4px 0}}
</style></head><body>
<h1>Corpus Census</h1>
<div class="hdr">Generated {esc(cen["generated"])} · harness
{esc(cen["harness_version"])} · deterministic · runtime
{esc(cen["runtime_seconds"])}s</div>
<div class="cards">
{
        card(
            "Distinct vulnerabilities (owned)",
            f"{owned.get('distinct_vulnerabilities', 0):,}",
            f"{owned.get('distinct_open', 0):,} open · findings/ at HEAD, disposition-adjusted",
        )
    }
{
        card(
            "Upstream exposure (adjacent)",
            f"{upstream.get('distinct_vulnerabilities', 0):,}",
            f"{upstream.get('distinct_open', 0):,} open · oss-findings/, never folded in",
        )
    }
{
        card(
            "Reports",
            f"{cen['population']['totals']['reports']:,}",
            f"{cen['population']['totals']['unique_base_slugs']:,} unique repo slugs",
        )
    }
{
        card(
            "Branch re-audits",
            f"{cen['population']['totals']['branch_reaudits']:,}",
            f"{dup['v2_branch_reaudits']['head_confirmations']:,} HEAD confirmations",
        )
    }
{
        card(
            "Hardening (owned, distinct)",
            f"{owned.get('hardening_distinct', 0):,}",
            "tracked separately",
        )
    }
{card("md-only parse gaps", cen["population"]["totals"]["md_only"], "invisible to JSON consumers")}
{
        card(
            "Non-active repos",
            f"{sum(v for k, v in (cen.get('repo_liveness') or {}).get('counts', {}).items() if k != 'active'):,}"
            if cen.get("repo_liveness")
            else "—",
            "archived/moved/missing/unknown — liveness artifact "
            + str((cen.get("repo_liveness") or {}).get("generated", "absent")),
        )
    }
</div>
<div class="panel"><h2>Owned open by severity</h2>{sev_chips}</div>
<div class="panel"><h2>Population by tree</h2>
<table><tr><th>Tree</th><th>Ownership</th><th>Business unit</th>
<th>Reports</th><th>Unique slugs</th><th>Branch</th><th>md-only</th>
<th>Ledgers</th></tr>{tree_rows}</table></div>
{
        f'<div class="panel"><h2>Per-ref breakdown</h2>'
        f"<table><tr><th>Ref</th><th>Reports</th></tr>{ref_rows}</table></div>"
        if ref_rows
        else ""
    }
<div class="panel"><h2>Duplication vectors</h2>
<table>{dup_rows}</table></div>
{f'<div class="panel"><h2>Drift warnings</h2>{warn_html}</div>' if cen["warnings"] else ""}
</body></html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results root (default: config / $AUDIT_RESULTS_ROOT)",
    )
    ap.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="deprecated; use --results-root / config instead",
    )
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument(
        "--skip-ledger", action="store_true", help="do not append to the central metrics ledger"
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    if args.workspace_root:
        print("warning: --workspace-root is deprecated; use --results-root", file=sys.stderr)
    analysis_results = resolve_results_root(args)
    if not analysis_results.is_dir():
        sys.exit(
            f"error: {analysis_results} not found — pass "
            f"--results-root or configure analysis_results"
        )
    pt = progress_tracker_dir(engine)
    out_dir = args.out_dir or pt / "metrics" / "dashboards" / "census"
    out_dir.mkdir(parents=True, exist_ok=True)

    cfg = corpus.load_config(args.config) if args.config else engine.corpus.config()
    cen = run_census(analysis_results, cfg, engine=engine, use_engine_resolve=True)
    res = cen.pop("_resolution")

    # Repo liveness (Phase 7): population metadata from the collector's
    # artifact — consumers read the file, never re-query GitHub.
    liveness_path = pt / "metrics" / "repo-liveness.json"
    cen["repo_liveness"] = None
    try:
        lv = json.loads(liveness_path.read_text(encoding="utf-8"))
        cen["repo_liveness"] = {"generated": lv.get("generated"), "counts": lv.get("counts") or {}}
        gen = datetime.strptime(lv.get("generated", "1970-01-01"), "%Y-%m-%d").replace(tzinfo=UTC)
        if (datetime.now(UTC) - gen).days > 7:
            cen["warnings"].append(
                f"repo-liveness artifact is stale ({lv.get('generated')}) "
                f"— rerun harnessing/census/scripts/check_repo_liveness.py (census Step 2b)"
            )
    except (OSError, json.JSONDecodeError, ValueError):
        cen["warnings"].append(
            "repo-liveness.json missing/unreadable — downstream consumers "
            "are reading no liveness status; run scripts/"
            "check_repo_liveness.py (census Step 2b)"
        )

    trend = ""
    owned = cen["ownership_cuts"].get("owned", {})
    metrics = {
        "reports": cen["population"]["totals"]["reports"],
        "unique_slugs": cen["population"]["totals"]["unique_base_slugs"],
        "distinct_vulns_owned": owned.get("distinct_vulnerabilities", 0),
        "distinct_open_owned": owned.get("distinct_open", 0),
        "branch_reaudits": cen["population"]["totals"]["branch_reaudits"],
        "symlink_aliases": cen["duplication"]["v1_symlink_aliases"]["file_aliases"],
        "md_only": cen["population"]["totals"]["md_only"],
        "cross_tree_slugs": cen["duplication"]["v4_cross_tree_overlap"]["slugs"],
    }
    if not args.skip_ledger:
        try:
            prev = engine.metrics.previous("census")
            trend = metrics_history.trend_line(metrics, prev, list(metrics)) or ""
            engine.metrics.append_if_changed("census", metrics, hv=cen["harness_version"])
        except Exception as e:  # ledger failure never blocks the census
            print(f"metrics-ledger append skipped: {e}", file=sys.stderr)

    cen_for_json = dict(cen)
    (out_dir / "census.json").write_text(
        json.dumps(cen_for_json, indent=2) + "\n", encoding="utf-8"
    )
    cen["_resolution"] = res
    (out_dir / "census.md").write_text(render_md(cen, cfg, trend), encoding="utf-8")
    (out_dir / "census.html").write_text(render_html(cen), encoding="utf-8")
    # corpus-manifest.json retired 2026-08-20. It was a 13.6 MB write-only
    # artifact — committed on every dashboard refresh, and measurably read by
    # nothing: every dashboard, this one included, resolves the population
    # in-process via corpus.resolve(). Its fields already live in
    # findings.db `repos`, which additionally carries repo_key, repo_url, ref
    # and audit_date, and now the six artifact refs the manifest uniquely had.
    # Query the projection instead of parsing a JSON blob.

    print(
        f"census: {metrics['reports']:,} reports, "
        f"{metrics['distinct_vulns_owned']:,} distinct owned vulns "
        f"({metrics['distinct_open_owned']:,} open), "
        f"{metrics['branch_reaudits']:,} branch re-audits, "
        f"{cen['parse_error_count']} parse errors, "
        f"{cen['runtime_seconds']}s"
    )
    for w in cen["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    print(f"wrote {out_dir}/census.{{json,md,html}}")
    if args.summary:
        print("\n" + render_md(cen, cfg, trend))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
