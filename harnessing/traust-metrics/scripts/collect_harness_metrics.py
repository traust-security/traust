#!/usr/bin/env python3
"""Collect Traust campaign metrics from derived artifacts.

Reads only files the pipeline already produces (executive summary,
validation dashboard, threat register, progress-tracker control files)
plus the harness repo's own tree/git metadata, and renders one Markdown
scoreboard. Never authors a number itself: every value is parsed from a
generated artifact or counted from the tree, and every row cites its
source. Missing sources degrade to "—" and are flagged in the data-
freshness table rather than failing the run.

A `<!-- MANUAL:BEGIN -->` … `<!-- MANUAL:END -->` block in an existing
output file is preserved verbatim across regenerations, so hand-written
talking points (cost comparisons, quotes, roadmap asks) survive updates.

Usage:
    python3 collect_harness_metrics.py [--workspace-root DIR] [--out FILE]
"""

import argparse
import contextlib
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)
from traust.paths import HARNESS_ROOT

SOURCE = "traust-metrics"

MANUAL_BEGIN = "<!-- MANUAL:BEGIN -->"
MANUAL_END = "<!-- MANUAL:END -->"

# No default placeholder is emitted. If a hand-added MANUAL block exists in
# the previous file it is preserved verbatim; otherwise the section is absent.
MANUAL_DEFAULT = ""


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def num(s):
    """'1,234' -> 1234 (int)."""  # estate-data-ok: illustrative, not a measurement
    return int(s.replace(",", ""))


def fmt(n):
    return f"{n:,}" if isinstance(n, int) else ("—" if n is None else str(n))


def search(pattern, text):
    if text is None:
        return None
    m = re.search(pattern, text)
    return m.groups() if m else None


def git(harness, *args):
    try:
        out = subprocess.run(
            ["git", "-C", str(harness), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
        return out
    except (subprocess.SubprocessError, OSError):
        return None


def count_lines(paths):
    total = 0
    for p in paths:
        with contextlib.suppress(OSError):
            total += p.read_text(encoding="utf-8", errors="replace").count("\n")
    return total


def collect(ws, results, tracker, harness):
    m = {}  # metric name -> value (int/str/None)
    sources = {}  # source label -> (path, generated-date or None, found?)

    dash = tracker / "metrics" / "dashboards"

    def dashboard(*rel):
        """Dashboard artifact path: metrics/dashboards home, falling back to
        the legacy analysis-results location."""
        new = dash.joinpath(*rel)
        old = results.joinpath(*rel)
        return new if new.exists() or not old.exists() else old

    # Preferred: the machine sidecar the builder emits alongside the md
    # (Executive-summary-findings.metrics.json, 2026-07-31). The prose
    # regexes below are a FALLBACK for pre-sidecar snapshots only —
    # they couple to sentence wording and blank silently on rewording
    # (docs-verification 2026-07-31, wiring c3).
    _SIDECAR_KEYS = (
        "repos_audited",
        "unique_repos",
        "findings_total",
        "sev_critical",
        "sev_high",
        "sev_medium",
        "sev_low",
        "sev_informational",
        "unique_critical",
        "unique_high",
        "repos_with_critical",
        "repos_with_high",
        "credential_findings",
        "dispositioned_repos",
        "resolved_findings",
        "hardening_backlog",
    )
    p_side = dashboard("Executive-summary-findings.metrics.json")
    try:
        side = json.loads(p_side.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        side = None
    p = dashboard("Executive-summary-findings.md")
    if side:
        sources["Executive summary"] = (p_side, (side.get("generated") or "")[:10] or None, True)
        for k in _SIDECAR_KEYS:
            if side.get(k) is not None:
                m[k] = side[k]
    else:
        t = read(p)
        g = search(r"\*\*Generated:\*\*\s*([0-9-]+)", t)
        sources["Executive summary"] = (p, g and g[0], t is not None)
        if g := search(
            r"([\d,]+) reports across ([\d,]+) unique repositories, ([\d,]+) findings total", t
        ):
            m["repos_audited"], m["unique_repos"], m["findings_total"] = (
                num(g[0]),
                num(g[1]),
                num(g[2]),
            )
        elif g := search(r"([\d,]+) repositories audited, ([\d,]+) findings total", t):
            m["repos_audited"], m["findings_total"] = num(g[0]), num(g[1])
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            if g := search(rf"\|\s*\*\*{sev}\*\*\s*\|\s*([\d,]+)\s*\|", t):
                m[f"sev_{sev.lower()}"] = num(g[0])
        if g := search(r"\*\*([\d,]+) unique Critical\*\* and \*\*([\d,]+) unique High\*\*", t):
            m["unique_critical"], m["unique_high"] = num(g[0]), num(g[1])
        if g := search(r"≥1 Critical:\*\*\s*([\d,]+)\s*·\s*\*\*with ≥1 High:\*\*\s*([\d,]+)", t):
            m["repos_with_critical"], m["repos_with_high"] = num(g[0]), num(g[1])
        if g := search(
            r"\*\*([\d,]+) unique\*\* findings \(([\d,]+) total occurrences\) flagged as hard-coded",
            t,
        ):
            m["credential_findings"] = num(g[0])
        if g := search(r"([\d,]+) of ([\d,]+) repositories carry a findings disposition ledger", t):
            m["dispositioned_repos"] = num(g[0])
        if g := search(r"\*\*([\d,]+) resolved\*\*", t):
            m["resolved_findings"] = num(g[0])
        if g := search(r"([\d,]+) hardening findings", t):
            m["hardening_backlog"] = num(g[0])

    # --- Corpus census (denominator authority; the Lens 2 source) -----------
    p = dashboard("census", "census.json")
    try:
        cen = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        cen = None
    sources["Corpus census"] = (p, cen and (cen.get("generated") or "")[:10], cen is not None)
    if cen:
        cuts = cen.get("ownership_cuts") or {}
        owned = cuts.get("owned") or {}
        up = cuts.get("upstream") or {}
        m["distinct_vulns_owned"] = owned.get("distinct_vulnerabilities")
        m["distinct_open_owned"] = owned.get("distinct_open")
        obs = owned.get("open_by_severity") or {}
        m["distinct_open_critical"] = obs.get("critical")
        m["distinct_open_high"] = obs.get("high")
        m["hardening_distinct_owned"] = owned.get("hardening_distinct")
        m["distinct_vulns_upstream"] = up.get("distinct_vulnerabilities")
        m["distinct_open_upstream"] = up.get("distinct_open")
        m["external_bu_reports"] = (cuts.get("external-bu") or {}).get("reports")
        m["owned_head_ledgered"] = owned.get("head_with_ledger")
        m["owned_head_reports"] = owned.get("head_reports")
        m["owned_head_ledger_pct"] = owned.get("head_ledger_coverage_pct")
        dup = cen.get("duplication") or {}
        v2 = dup.get("v2_branch_reaudits") or {}
        m["branch_confirmations"] = v2.get("head_confirmations")
        m["branch_reaudit_reports"] = v2.get("reports")
        m["unique_repo_slugs"] = ((cen.get("population") or {}).get("totals") or {}).get(
            "unique_base_slugs"
        )

    # --- Insecure patterns (the Lens 3 source) -------------------------------
    p = dashboard("insecure-patterns", "insecure-patterns.json")
    try:
        ip = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        ip = None
    _gen = ((ip or {}).get("metadata") or {}).get("generated") or ""
    sources["Insecure patterns"] = (p, _gen[:10] or None, ip is not None)
    if ip and ip.get("patterns"):
        pats = ip["patterns"]
        m["patterns_catalogued"] = len(pats)
        m["top_pattern"] = f"{pats[0].get('cwe')} — {pats[0].get('name')}"
        m["top_pattern_repos"] = pats[0].get("repo_count")

    # --- Detection-recall benchmark (harness QA; capability C1) -------------
    p = dashboard("benchmark", "benchmark.json")
    try:
        bm = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        bm = None
    sources["Recall benchmark"] = (p, bm and (bm.get("generated") or "")[:10], bm is not None)
    if bm:
        m["recall_strict"] = (bm.get("overall") or {}).get("recall")
        m["recall_targets"] = bm.get("targets_scored")
        m["recall_expected"] = (bm.get("overall") or {}).get("expected")
        m["recall_stability"] = (bm.get("stability") or {}).get("mean_jaccard")
        m["injection_pass_rate"] = (bm.get("injection_canaries") or {}).get("pass_rate")
        m["injection_canaries"] = (bm.get("injection_canaries") or {}).get("total")
        m["recall_auditor_version"] = ", ".join(bm.get("auditor_versions") or []) or bm.get(
            "harness_version"
        )

    # --- Findings trends (ledger replay) ------------------------------------
    p = dashboard("trends", "findings-trends.json")
    try:
        tr = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        tr = None
    sources["Findings trends"] = (p, tr and tr.get("generated_at", "")[:10], tr is not None)
    if tr:
        cov = tr.get("coverage") or {}
        if cov.get("audited_repos"):
            m["ledger_covered_repos"] = cov.get("covered_repos")
            m["ledger_coverage_pct"] = f"{100 * cov['covered_repos'] / cov['audited_repos']:.1f}"
        if tr.get("buckets"):
            b = tr["buckets"][-1]
            m["open_ledger_view"] = b.get("open")
            m["mean_cvss_open"] = b.get("mean_cvss_open")
            ow = b.get("owasp_open") or {}
            if ow:
                m["owasp_risk_critical"] = ow.get("critical", 0)
                m["owasp_risk_high"] = ow.get("high", 0)
                m["owasp_risk_medium"] = ow.get("medium", 0)
                m["owasp_risk_low"] = ow.get("low", 0) + ow.get("note", 0)
            m["owasp_risk_high_plus_pct"] = b.get("owasp_high_plus_pct")

    # --- Live validation & fuzz dashboard ----------------------------------
    p = dashboard("Live-validation-fuzz-dashboard.md")
    t = read(p)
    g = search(r"\*\*Generated:\*\*\s*([0-9-]+)", t)
    sources["Validation & fuzz dashboard"] = (p, g and g[0], t is not None)
    if g := search(
        r"\*\*([\d,]+) findings confirmed exploitable\*\*[^(]*\(([\d,]+) claimed-Critical, ([\d,]+) claimed-High\)",
        t,
    ):
        m["confirmed_exploitable"] = num(g[0])
        m["confirmed_critical"], m["confirmed_high"] = num(g[1]), num(g[2])
    if g := search(r"\*\*([\d,]+) refuted\*\*", t):
        m["refuted"] = num(g[0])
    if g := search(r"([\d,]+) of ([\d,]+) finding-checks attempted \(([\d.]+)% coverage\)", t):
        m["checks_attempted"], m["checks_total"] = num(g[0]), num(g[1])
        m["validation_coverage_pct"] = g[2]
    if g := search(r"([\d,]+) of ([\d,]+) mapped attack chains have ≥1 confirmed step", t):
        m["chains_confirmed"], m["chains_total"] = num(g[0]), num(g[1])
    if g := search(r"`validations/` \(([\d,]+) live-validation reports\)", t):
        m["validation_reports"] = num(g[0])

    # --- Fuzz campaign sidecar (machine-readable; md scrape is fallback) ----
    fj = None
    for cand in (
        dash / "fuzz" / "FUZZ-CAMPAIGN-SUMMARY.json",
        results / "FUZZ-CAMPAIGN-SUMMARY.json",
    ):
        try:
            fj = json.loads(cand.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sources["Fuzz campaign sidecar"] = (cand, fj.get("generated"), True)
        break
    if fj and fj.get("totals"):
        ft = fj["totals"]
        m["fuzz_targets"] = ft.get("targets")
        m["fuzz_fuzzers"] = ft.get("fuzz_functions")
        m["fuzz_bugs"] = ft.get("bugs")
        m["fuzz_advisories"] = ft.get("advisories")
    elif g := search(
        r"([\d,]+) targets · ([\d,]+) fuzzers · ≥?([\d,]+) confirmed bugs · ([\d,]+) portfolio advisories",
        t,
    ):
        m["fuzz_targets"], m["fuzz_fuzzers"] = num(g[0]), num(g[1])
        m["fuzz_bugs"], m["fuzz_advisories"] = num(g[2]), num(g[3])

    # --- Threat register -----------------------------------------------------
    p = dashboard("threat-register", "threat-register.md")
    t = read(p)
    g = search(
        r"Generated ([0-9-]+) from \*\*([\d,]+) threat models\*\* \(\*\*([\d,]+) threats\*\*, ([\d,]+) open\)",
        t,
    )
    sources["Threat register"] = (p, g and g[0], t is not None)
    if g:
        m["threat_models"], m["threats_total"], m["threats_open"] = num(g[1]), num(g[2]), num(g[3])

    # --- Progress tracker ----------------------------------------------------
    p = tracker / "tracking" / "opened-tickets.md"
    t = read(p)
    sources["Opened tickets"] = (p, None, t is not None)
    if g := search(r"\*\*([\d,]+) active tickets filed\*\* \(([\d,]+) findings covered\)", t):
        m["jira_tickets"], m["jira_findings_covered"] = num(g[0]), num(g[1])

    # (package-folder counting retired 2026-07-17 — a folder count informs
    # no decision; routing/adoption is better read from Jira tickets and
    # the disposition-ledger coverage rows)

    # --- Cloud-config (IaC declared-layer) lane -------------------------
    # Separate report kind, NEVER blended into code-audit counts
    # (traust.cli.groups.corpus doctrine). Source: findings.db projection.
    ccdb = results / "graph" / "findings.db"
    sources["Cloud-config lane (findings.db)"] = (ccdb, None, ccdb.is_file())
    if ccdb.is_file():
        try:
            import sqlite3

            con = sqlite3.connect(f"file:{ccdb}?mode=ro", uri=True)
            m["cc_reports"] = con.execute(
                "SELECT COUNT(*) FROM repos WHERE report_kind='cloud-config'"
            ).fetchone()[0]
            sev = dict(
                con.execute(
                    # current_finding is the contract's spine; report_kind
                    # rides it, so the lane needs no join to repos.
                    "SELECT severity, COUNT(*) FROM current_finding "
                    "WHERE report_kind='cloud-config' GROUP BY severity"
                ).fetchall()
            )
            m["cc_findings"] = sum(sev.values())
            m["cc_crit"] = sev.get("critical", 0)
            m["cc_high"] = sev.get("high", 0)
            m["cc_medium"] = sev.get("medium", 0)
            con.close()
        except Exception:
            pass

    # --- Harness tree & git ---------------------------------------------------
    sources["Harness repo"] = (harness, None, harness.is_dir())
    v = read(harness / "VERSION")
    sha = git(harness, "rev-parse", "--short", "HEAD")
    if v:
        m["harness_version"] = v.strip() + (f"-{sha}" if sha else "")
    c = git(harness, "rev-list", "--count", "HEAD")
    m["harness_commits"] = int(c) if c else None
    tags = git(harness, "tag")
    m["harness_releases"] = len(tags.splitlines()) if tags else None
    m["skills"] = len(list(harness.glob("harnessing/*/SKILL.md")))
    m["commands"] = len(list(harness.glob(".claude/commands/*.md")))

    py = [
        p for p in harness.rglob("*.py") if ".venv" not in p.parts and "__pycache__" not in p.parts
    ]
    m["python_loc"] = count_lines(py)
    prompts = list(harness.glob("harnessing/**/*.md")) + list(harness.glob(".claude/commands/*.md"))
    m["prompt_loc"] = count_lines(prompts)

    # Test count: prefer a live pytest collection; fall back to grepping.
    m["tests"] = None
    venv_py = harness / ".venv" / "bin" / "python"
    if venv_py.exists():
        try:
            out = subprocess.run(
                [str(venv_py), "-m", "pytest", "tests/", "--collect-only", "-q"],
                cwd=str(harness),
                capture_output=True,
                text=True,
                timeout=120,
            ).stdout
            if g := re.search(r"(\d+) tests collected", out):
                m["tests"] = int(g.group(1))
        except (subprocess.SubprocessError, OSError):
            pass
    if m["tests"] is None:
        m["tests"] = sum(read(p).count("def test_") for p in harness.glob("tests/*.py") if read(p))

    # --- Derived ratios --------------------------------------------------------
    if m.get("refuted") and m.get("checks_attempted"):
        m["refutation_rate_pct"] = f"{100 * m['refuted'] / m['checks_attempted']:.1f}"
    if m.get("findings_total") and m.get("repos_audited"):
        m["findings_per_repo"] = f"{m['findings_total'] / m['repos_audited']:.1f}"

    return m, sources


def render(m, sources, ws, manual_block):
    today = datetime.date.today().isoformat()

    def row(label, key, source, note=""):
        val = m.get(key)
        return f"| {label} | **{fmt(val)}** | {source}{' — ' + note if note else ''} |"

    lines = [
        "# Traust Metrics",
        "",
        f"**Generated:** {today} by `traust/harnessing/traust-metrics/scripts/collect_harness_metrics.py` "
        f"(harness {m.get('harness_version', '—')}). Do not hand-edit — rerun `/traust-metrics` instead (a hand-added MANUAL block, if present, is preserved).",
        "",
        "Every number is parsed from a pipeline artifact or counted from the tree; the",
        "Data freshness table at the bottom shows how current each source is. Rebuild a",
        "stale source first (`/census`, `/executive-summary-findings`,",
        "`/validation-fuzz-dashboard`, `/threat-register`), then rerun this skill.",
        "",
        "Metrics are organized by the **three-lens taxonomy**",
        "(progress-tracker/plans/metrics-improvement-plan.md): **Lens 2 —",
        "distinct exposure** is the canonical headline (what there is to fix);",
        "**Lens 1 — work performed** counts occurrences and throughput (the same",
        "defect shipped in N products counts N times — that is coverage, not",
        "double-counting); **Lens 3 — systemic patterns** ranks fleet-wide",
        "leverage. Never average numbers across lenses.",
        "",
        "## Lens 2 — Distinct exposure (canonical headline)",
        "",
        "_Scope: Hybrid Platforms–owned (`findings/` at HEAD) · unit: unique",
        "finding fingerprints · stage: disposition-adjusted, false positives",
        "excluded, hardening separate. Source: corpus census, the denominator",
        "authority._",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row(
            "Distinct vulnerabilities (owned)",
            "distinct_vulns_owned",
            "census",
            f"{fmt(m.get('distinct_open_owned'))} open",
        ),
        row("Open Critical (distinct)", "distinct_open_critical", "census"),
        row("Open High (distinct)", "distinct_open_high", "census"),
        row(
            "Hardening backlog (distinct, tracked separately)", "hardening_distinct_owned", "census"
        ),
        row(
            "Upstream supply-chain exposure (adjacent — never folded in)",
            "distinct_vulns_upstream",
            "census",
            f"{fmt(m.get('distinct_open_upstream'))} open",
        ),
        row(
            "Disposition-ledger coverage (owned, HEAD)",
            "owned_head_ledgered",
            "census",
            f"of {fmt(m.get('owned_head_reports'))} owned HEAD reports "
            f"({m.get('owned_head_ledger_pct', '—')}%) — blended figures "
            f"elsewhere also count branch re-audits and non-owned trees",
        ),
        row(
            "OWASP risk rating — High+Critical share of open (%)",
            "owasp_risk_high_plus_pct",
            "findings trends",
            "likelihood × impact per the OWASP Risk Rating Methodology "
            "(factors derived from each finding's CVSS 3.x vector); "
            "replaces the mean-CVSS and legacy CVSS-sum rows — see "
            "traust/docs/risk-rating-methodology.md",
        ),
        "",
        "## Lens 1 — Work performed (scale & coverage)",
        "",
        "_Scope: all trees and business units · unit: reports and finding",
        "occurrences._",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row(
            "Repositories/branches audited",
            "repos_audited",
            "executive summary",
            f"{fmt(m.get('unique_repo_slugs'))} unique repo slugs (census)",
        ),
        row("Findings produced (occurrences)", "findings_total", "executive summary"),
        row("Avg findings per repo", "findings_per_repo", "derived"),
        row(
            "Release-branch confirmations of HEAD findings",
            "branch_confirmations",
            "census",
            f"across {fmt(m.get('branch_reaudit_reports'))} branch re-audits — "
            f"coverage on shipped releases, not new exposure",
        ),
        row(
            "External-BU scan reports (excluded from HP risk numbers)",
            "external_bu_reports",
            "census",
        ),
        row("Threat models produced", "threat_models", "threat register"),
        row(
            "Threats catalogued (open)",
            "threats_open",
            "threat register",
            f"of {fmt(m.get('threats_total'))} total",
        ),
        row(
            "IaC cloud-config audits (declared layer)",
            "cc_reports",
            "findings.db (cloud-config kind)",
            "separate report kind — never blended into code-audit counts",
        ),
        row(
            "IaC findings (all dispositions)",
            "cc_findings",
            "findings.db (cloud-config kind)",
            f"{fmt(m.get('cc_crit'))} critical / "
            f"{fmt(m.get('cc_high'))} high / "
            f"{fmt(m.get('cc_medium'))} medium — hardening-class "
            "dominant; 2026-07-29 step-change = iac-baseline-sweep-"
            "phase0 (81 targets), not a risk event",
        ),
        "",
        "### Findings & impact (occurrences across products)",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row(
            "Critical findings",
            "sev_critical",
            "executive summary",
            f"{fmt(m.get('unique_critical'))} unique",
        ),
        row(
            "High findings", "sev_high", "executive summary", f"{fmt(m.get('unique_high'))} unique"
        ),
        row("Repos with ≥1 Critical", "repos_with_critical", "executive summary"),
        row("Repos with ≥1 High", "repos_with_high", "executive summary"),
        row("Committed-credential findings (unique)", "credential_findings", "executive summary"),
        "",
        "## Lens 3 — Systemic patterns (fleet leverage)",
        "",
        "_Scope: `findings/` source-code findings bucketed by primary CWE._",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Recurring patterns catalogued", "patterns_catalogued", "insecure-patterns"),
        row(
            "Top pattern",
            "top_pattern",
            "insecure-patterns",
            f"in {fmt(m.get('top_pattern_repos'))} repos",
        ),
        "",
        "## Lens 1 — Empirical validation — why the numbers can be trusted",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row(
            "Findings confirmed exploitable in live environments",
            "confirmed_exploitable",
            "validation dashboard",
            f"{fmt(m.get('confirmed_critical'))} claimed-Critical / {fmt(m.get('confirmed_high'))} claimed-High",
        ),
        row("False positives refuted & removed", "refuted", "validation dashboard"),
        row("Refutation rate among attempted checks (%)", "refutation_rate_pct", "derived"),
        row("Live-validation reports produced", "validation_reports", "validation dashboard"),
        row(
            "Finding-checks attempted",
            "checks_attempted",
            "validation dashboard",
            f"of {fmt(m.get('checks_total'))} ({m.get('validation_coverage_pct', '—')}% coverage)",
        ),
        row(
            "Attack chains with ≥1 confirmed step",
            "chains_confirmed",
            "validation dashboard",
            f"of {fmt(m.get('chains_total'))} mapped",
        ),
        row(
            "Fuzz targets / fuzzers written",
            "fuzz_targets",
            "fuzz sidecar",
            f"{fmt(m.get('fuzz_fuzzers'))} fuzzers",
        ),
        row(
            "Fuzz-confirmed bugs",
            "fuzz_bugs",
            "fuzz sidecar",
            f"{fmt(m.get('fuzz_advisories'))} portfolio advisories",
        ),
        "",
        "## Lens 1 — Delivery & adoption",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row(
            "Jira defects filed",
            "jira_tickets",
            "progress-tracker",
            f"{fmt(m.get('jira_findings_covered'))} findings covered",
        ),
        "",
        "## Platform maturity & reliability",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Harness version", "harness_version", "VERSION + git"),
        row(
            "Commits / releases",
            "harness_commits",
            "git",
            f"{fmt(m.get('harness_releases'))} tagged releases",
        ),
        row("Active skills", "skills", "harness tree", f"{fmt(m.get('commands'))} slash commands"),
        row("Python lines of code", "python_loc", "harness tree"),
        row("Engineered prompt content (lines)", "prompt_loc", "harness tree"),
        row("Regression tests", "tests", "pytest"),
        row(
            "Detection recall (strict, ground-truth benchmark)",
            "recall_strict",
            "recall benchmark",
            f"{fmt(m.get('recall_expected'))} expected findings across "
            f"{fmt(m.get('recall_targets'))} targets; auditor "
            f"{m.get('recall_auditor_version', '—')}",
        ),
        row(
            "Auditor stability (duplicate-run fingerprint Jaccard)",
            "recall_stability",
            "recall benchmark",
        ),
        row(
            "Prompt-injection canary pass rate",
            "injection_pass_rate",
            "recall benchmark",
            f"{fmt(m.get('injection_canaries'))} canaries — pass = seeded "
            f"finding detected AND injected instructions not obeyed",
        ),
        "",
        *([manual_block, ""] if manual_block else []),
        "## Data freshness",
        "",
        "| Source | Path | Generated | Status |",
        "|---|---|---|---|",
    ]
    for label, (path, date, found) in sources.items():
        try:
            rel = path.relative_to(ws)
        except ValueError:
            rel = path
        status = "ok" if found else "**MISSING — rebuild**"
        lines.append(f"| {label} | `{rel}` | {date or '—'} | {status} |")
    lines.append("")
    return "\n".join(lines)


HISTORY_KEYS = [
    # (metric key, human label) — the improvement series rendered over time.
    ("repos_audited", "Reports (repos/branches audited)"),
    ("unique_repos", "Unique repositories"),
    ("findings_total", "Findings (as counted that day)"),
    ("sev_critical", "Critical"),
    ("sev_high", "High"),
    ("unique_critical", "Unique Critical"),
    ("unique_high", "Unique High"),
    ("repos_with_critical", "Repos with >=1 Critical"),
    ("repos_with_high", "Repos with >=1 High"),
    ("credential_findings", "Credential findings (unique)"),
    ("hardening_backlog", "Hardening backlog"),
    ("dispositioned_repos", "Repos with disposition ledger"),
    ("ledger_coverage_pct", "Ledger coverage %"),
    ("resolved_findings", "Findings resolved"),
    ("open_ledger_view", "Open findings (ledger replay)"),
    ("recall_strict", "Detection recall (strict)"),
    ("recall_stability", "Auditor stability (Jaccard)"),
    ("injection_pass_rate", "Injection canary pass rate"),
    ("owasp_risk_critical", "OWASP risk rating: Critical (open)"),
    ("owasp_risk_high", "OWASP risk rating: High (open)"),
    ("owasp_risk_medium", "OWASP risk rating: Medium (open)"),
    ("owasp_risk_low", "OWASP risk rating: Low/Note (open)"),
    ("owasp_risk_high_plus_pct", "OWASP High+Critical share of open (%)"),
    ("confirmed_exploitable", "Confirmed exploitable (live)"),
    ("refuted", "False positives refuted (live)"),
    ("validation_reports", "Live-validation reports"),
    ("threat_models", "Threat models"),
    ("threats_open", "Open threats"),
    ("jira_tickets", "Jira defects filed"),
]


def history_path(engine):
    from traust_engine.locations import METRICS_HISTORY_REL, progress_tracker_dir

    return progress_tracker_dir(engine.ctx.locations) / METRICS_HISTORY_REL


def append_history(m, engine, note):
    """Append one immutable, hash-chained snapshot row via the shared
    ledger. NEVER rewrite prior rows — the ledger exists so as-reported
    numbers survive methodology changes (counting-policy shifts, late
    event ingestion) that rewrite every replayed/regenerated view."""
    return engine.metrics.append(
        SOURCE,
        {k: m.get(k) for k, _ in HISTORY_KEYS if m.get(k) is not None},
        note=note,
        hv=m.get("harness_version"),
    )


def render_history(tracker, engine, max_cols=8):
    """Render metrics/metrics-history.md from the JSONL ledger."""
    rows = [r for r in engine.metrics.rows() if r.get("source") == SOURCE]
    if not rows:
        return None
    shown = rows[-max_cols:]
    out = ["# Metrics Over Time — Hybrid Platforms Security", ""]
    out.append(
        f"Append-only hash-chained snapshot ledger (`metrics/metrics-history.jsonl`, "
        f"{len(rows)} snapshots; last {len(shown)} shown). Each column is "
        f"an as-reported data point — earlier numbers are never revised, "
        f"so counting-policy changes appear as explained steps, not "
        f"silent rewrites. Maintained by `/traust-metrics`."
    )
    out.append("")
    hdr = ["Metric"] + [r["snapshot_at"][:10] for r in shown]
    out.append("| " + " | ".join(hdr) + " |")
    out.append("|" + "---|" * len(hdr))
    for key, label in HISTORY_KEYS:
        vals = [r["metrics"].get(key) for r in shown]
        if all(v is None for v in vals):
            continue
        cells = [fmt(v) if isinstance(v, int) else (str(v) if v is not None else "—") for v in vals]
        out.append(f"| {label} | " + " | ".join(cells) + " |")
    out.append(
        "| _harness_ | " + " | ".join(str(r.get("harness_version") or "—") for r in shown) + " |"
    )
    notes = [(r["snapshot_at"][:10], r.get("note")) for r in shown if r.get("note")]
    if notes:
        out += ["", "## Snapshot notes", ""]
        out += [f"- **{d}** — {n}" for d, n in notes]
    md = "\n".join(out) + "\n"
    outp = tracker / "metrics" / "metrics-history.md"
    outp.write_text(md, encoding="utf-8")
    return outp


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (default: $AUDIT_RESULTS_ROOT or locations.yaml)",
    )
    ap.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="Parent workspace holding the sibling repos (default: configured workspace)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output file (default: <progress-tracker>/metrics/traust-metrics.md)",
    )
    ap.add_argument(
        "--note",
        default="",
        help="One-line context recorded with this snapshot in the "
        "metrics-history ledger (e.g. 'post ledger-backfill').",
    )
    ap.add_argument(
        "--no-history",
        action="store_true",
        help="Skip appending to tracking/metrics-history.jsonl.",
    )
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    ws = (args.workspace_root or workspace_dir(engine)).resolve()
    results = resolve_results_root(args)
    tracker = progress_tracker_dir(engine)
    harness = HARNESS_ROOT
    out = args.out or tracker / "metrics" / "traust-metrics.md"

    manual_block = MANUAL_DEFAULT
    prev = read(out)
    if prev and MANUAL_BEGIN in prev and MANUAL_END in prev:
        manual_block = prev[prev.index(MANUAL_BEGIN) : prev.index(MANUAL_END) + len(MANUAL_END)]

    metrics, sources = collect(ws, results, tracker, harness)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(metrics, sources, ws, manual_block), encoding="utf-8")

    if not args.no_history:
        row = append_history(metrics, engine, args.note)
        hist = render_history(tracker, engine)
        print(f"appended snapshot to {history_path(engine)} (row_sha {row['row_sha'][:12]}…)")
        if hist:
            print(f"wrote {hist}")
        for outp in engine.metrics.render():
            print(f"wrote {outp}")

    missing = [label for label, (_, _, found) in sources.items() if not found]
    print(f"wrote {out}")
    if missing:
        print(f"WARNING: missing sources: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
