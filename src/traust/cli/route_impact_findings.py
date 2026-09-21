#!/usr/bin/env python3
"""Route /impact-analysis `affected` classifications into the findings
ledger — the dependency-vulnerability filing leg (wiring-plan lever 1c).

Before harness 0.197.0 an impact artifact's `affected` repos reached
only findings.db's `impact` table (queryable analysis) — never the
findings pipeline: no baseline entry, no ledger event, no owner, no SLA
clock, no Jira. A newly disclosed dependency CVE therefore stayed
unaccountable until the repo's next full audit. Per the operator
directive of 2026-07-28, reachable dependency vulnerabilities become
first-class ledger findings the day the advisory lands, via the
direct-entry convention route_regressions.py established (v0.196.0):
findings enter the baseline and ledger at birth as
`validation_status: not_verified`, with /triage adjudicating
downstream — no triage precondition.

For each `affected` repo in the artifact (plus `likely_affected` with
--include-likely) this tool:

  1. Resolves the repo's baseline audit + disposition layer from
     findings.db (`repos` table, HEAD code-audit row; freshest
     audit_date wins on duplicate URLs — same query discipline as
     build_rescan_worklist.py).
  2. Dedupes: if any baseline finding already carries this CVE for this
     module (source_findings back-reference, or a live K07-style claim
     naming both), the repo is skipped — daily re-runs are no-ops.
  3. Mints a campaign ID at the baseline's pinned sha
     (`{SLUG}-{SHA7}-{NNN}`, numbering continuing where the baseline's
     findings at that sha leave off) and appends a dependency finding:
     `origin: "impact-analysis"`, `category: "supply-chain"`,
     severity from --severity (take it from the advisory; this tool
     never invents one), the artifact's reachability evidence block
     transcribed into the description, location = the dependency
     manifest, fingerprint via traust_engine.ledger, summaries
     kept validator-consistent.
  4. Pins the claim hash (add-only) and appends one ledger birth event
     (`source.type: impact_report` — machine-static class 3, actor
     `impact-analysis`, the artifact as evidence_ref, canonical
     event_id dedupe).
  5. Rebuilds the cumulative `*-findings-current.{json,md}` so owner
     routing, the SLA view, team reports, and every UI reading the
     ledger see the finding immediately.

Routes and records only — the affectedness judgment was authored by
/impact-analysis (evidence ladder: symbol > symbol-usage > binary >
manifest); triage/validation adjudicate downstream like any claimed
finding (docs/findings-routing.md).

Usage (from the workspace root):
    python3 traust/scripts/route_impact_findings.py \
        analysis-results/impact/<cve>-impact-analysis.json \
        --severity high \
        [--db analysis-results/graph/findings.db] [--include-likely] \
        [--limit N] [--recorded-at ISO8601] [--no-rebuild] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.corpus.resolver import normalize_repo_url
from traust_engine.ledger import (
    findings_from_events,
    fingerprint,
)

from traust.cli.route_regressions import (
    CAMPAIGN_ID_RE,
    _load,
    harness_version,
    next_sequence,
    rebuild_cumulative,
    stable_ref,
)
from traust.context import (
    add_config_home_arg,
    findings_db,
    load_engine,
)
from traust.lib.event_time import recorded_at_arg

SHA_RX = re.compile(r"\b([0-9a-f]{7,40})\b")
SLUG_RX = re.compile(r"^[A-Z][A-Z0-9_]{0,23}$")

_REPOS_SQL = """
SELECT repo_url, report_path FROM repos
WHERE report_kind = 'code-audit' AND is_branch_audit = 0
ORDER BY audit_date DESC
"""

# Manifest filename to cite as the finding location. Priority order at
# the call site (build_finding -> cited_manifest): (1) a real manifest
# path carried in the per-repo impact evidence; (2) the `manifest`
# provenance attr on the portfolio-graph dependency edge (Wave-3); (3)
# this heuristic. The heuristic itself prefers the advisory ecosystem
# (metadata.ecosystem) over a guess from the module coordinate; the
# description carries the module either way.
_MANIFEST_BY_ECOSYSTEM = {
    "go": "go.mod",
    "npm": "package.json",
    "pypi": "requirements.txt",
    "maven": "pom.xml",
    "cargo": "Cargo.toml",
    "ruby": "Gemfile",
    "nuget": "*.csproj",
    "docker": "Dockerfile",
    "actions": ".github/workflows/",
    "helm": "Chart.yaml",
}

# Fallback when the ecosystem is unknown (old/synthetic artifacts): guess
# from the module coordinate's shape. A domain-prefixed import path is
# Go; a Maven `group:artifact` coordinate has a colon; a scoped or bare
# single token is npm-shaped. A bare unknown never silently cites go.mod
# unless it actually looks like a Go import path.
_MANIFEST_BY_HINT = (
    (
        re.compile(
            r"^(github\.com|golang\.org|google\.golang\.org|k8s\.io|"
            r"sigs\.k8s\.io|gopkg\.in)/"
        ),
        "go.mod",
    ),
    (re.compile(r":"), "pom.xml"),
    (re.compile(r"^[^/@:]+\.[^/@:]+/"), "go.mod"),
    (re.compile(r"^(@|[a-z0-9._-]+$)"), "package.json"),
)


def _dep_node_id(module: str, ecosystem: str | None) -> str:
    """Graph node id for a dependency coordinate: Go lives in the
    `module:` id space, every other ecosystem in `pkg:<eco>/<name>`
    (build_portfolio_graph.dep_node_id convention)."""
    if not ecosystem or ecosystem == "go":
        return f"module:{module}"
    return f"pkg:{ecosystem}/{module}"


def manifest_from_graph(graph_db, repo_id: str, module: str, ecosystem: str | None) -> str | None:
    """Priority 2: the real source-manifest path off the portfolio-graph
    dependency edge (the Wave-3 `manifest` provenance attr). Returns the
    first path (sorted) or None on any absence — never raises, so a
    missing/locked/legacy graph db just falls through to the heuristic."""
    if not repo_id or graph_db is None:
        return None
    try:
        gp = Path(graph_db)
    except TypeError:
        return None
    if not gp.is_file():
        return None
    dsts = [_dep_node_id(module, ecosystem)]
    if ecosystem and ecosystem != "go":
        # tolerate an ecosystem-mislabelled edge: also try the Go node
        dsts.append(f"module:{module}")
    try:
        con = sqlite3.connect(f"file:{gp}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        for dst in dsts:
            rows = con.execute(
                "SELECT attrs FROM edges WHERE src = ? "
                "AND rel IN ('depends_on', 'imports_package') "
                "AND dst = ?",
                (repo_id, dst),
            ).fetchall()
            for (attrs,) in rows:
                try:
                    paths = (json.loads(attrs or "{}") or {}).get("manifest")
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(paths, list) and paths:
                    return sorted(str(p) for p in paths)[0]
    except sqlite3.Error:
        return None
    finally:
        con.close()
    return None


def repo_url_from_id(repo_id: str) -> str | None:
    """Graph repo ids are `repo:<host>/<path>` (run_impact_analysis
    convention — small shared copy)."""
    if repo_id.startswith("repo:"):
        return f"https://{repo_id[5:]}"
    return None


def manifest_for_module(module: str, ecosystem: str | None = None) -> str:
    """Priority-3 heuristic cited location. Prefer the advisory
    ecosystem when known; otherwise guess from the coordinate shape."""
    if ecosystem:
        m = _MANIFEST_BY_ECOSYSTEM.get(ecosystem.lower())
        if m:
            return m
    for rx, manifest in _MANIFEST_BY_HINT:
        if rx.search(module):
            return manifest
    # bare unknown, not obviously Go: a generic single-token coordinate
    # is npm-shaped more often than Go — never silently cite go.mod here
    return "package.json"


def cited_manifest(module: str, ecosystem: str | None, repo_entry: dict, graph_db) -> str:
    """Resolve the finding's cited location by provenance priority:
    (1) a real manifest path in the per-repo impact evidence;
    (2) the portfolio-graph edge's `manifest` provenance attr;
    (3) the ecosystem/coordinate heuristic."""
    ev = repo_entry.get("evidence") or {}
    p = ev.get("manifest_path")
    if isinstance(p, str) and p.strip():
        return p.strip()
    g = manifest_from_graph(graph_db, repo_entry.get("repo") or "", module, ecosystem)
    if g:
        return g
    return manifest_for_module(module, ecosystem)


def slug_for(audit: dict, repo_url: str) -> str:
    """Reuse the baseline's existing campaign-ID slug; derive from the
    repo name only for baselines with no campaign IDs yet."""
    for f in audit.get("findings", []):
        m = CAMPAIGN_ID_RE.match(str(f.get("id", "")))
        if m:
            return m.group(1)
    name = (repo_url or "repo").rstrip("/").rsplit("/", 1)[-1]
    slug = re.sub(r"[^A-Z0-9_]", "_", name.upper())[:24].strip("_") or "REPO"
    if not SLUG_RX.match(slug):
        slug = "R" + slug[:23]
    return slug


def baseline_sha7(audit: dict) -> str | None:
    m = SHA_RX.search(str((audit.get("metadata") or {}).get("commit") or ""))
    return m.group(1)[:7] if m else None


def already_filed(audit: dict, cve: str, module: str, layer: dict | None = None) -> str | None:
    """Existing finding id when this CVE+module is already claimed for
    the repo (any origin: an audit-filed K07 counts as coverage).

    Scans the baseline AND, when a layer is supplied, its event-carried
    findings (plan B2). Since this router no longer appends to the baseline
    (gate A15), its own prior filings live only on events — so ignoring the
    layer would re-file the same CVE+module on every run.
    """
    candidates = list(audit.get("findings", []))
    if layer is not None:
        candidates += list(findings_from_events(layer.get("events")).values())
    for f in candidates:
        srcs = " ".join(str(s) for s in f.get("source_findings", []))
        text = f"{f.get('title', '')} {f.get('description', '')} {srcs}"
        if cve in text and module in text:
            return str(f.get("id"))
    return None


def build_finding(
    new_id: str,
    artifact: dict,
    repo_entry: dict,
    severity: str,
    artifact_ref: str,
    repo_url: str | None,
    graph_db=None,
) -> dict:
    cve = artifact["cve"]
    module = artifact["module"]
    ecosystem = artifact.get("ecosystem")
    fixed = artifact.get("fixed_version") or "a fixed version"
    ev = repo_entry.get("evidence") or {}
    finding = {
        "id": new_id,
        "title": f"Vulnerable dependency: {module} ({cve})",
        "severity": severity,
        "cwes": ["CWE-1395"],
        "locations": [
            {
                "path": cited_manifest(module, ecosystem, repo_entry, graph_db),
                "description": (
                    f"dependency manifest pinning {module} "
                    f"{repo_entry.get('version') or ''}".strip()
                ),
            }
        ],
        "description": (
            f"{cve} affects {module} "
            f"(vulnerable range: {artifact.get('vulnerable_range') or 'see advisory'}; "
            f"pinned version: {repo_entry.get('version') or 'unknown'}). "
            f"/impact-analysis classified this repository "
            f"'{repo_entry.get('classification')}' with evidence level "
            f"'{ev.get('evidence_level', 'unknown')}' "
            f"(evidence: {json.dumps(ev, sort_keys=True)}). "
            f"Affected capability: "
            f"{artifact.get('feature_description') or 'see advisory'}."
        ),
        "remediation": f"Upgrade {module} to {fixed} or later.",
        "category": "supply-chain",
        "validation_status": "not_verified",
        "origin": "impact-analysis",
        "source_findings": [cve, artifact_ref],
        # Typed supply-chain provenance (contracts >=0.4.2). The same facts
        # were previously ONLY in the description prose and positionally in
        # source_findings, which made every routed finding unqueryable by
        # advisory or module without parsing English. Two consumers need it
        # structured: object storage, where `impact_artifact` may not resolve
        # by relative path so the finding must stand alone; and consumers that
        # build their own database from the artifacts rather than reading the
        # harness's local SQLite projection.
        "dependency": {
            k: v
            for k, v in {
                "advisory": cve,
                "module": module,
                "ecosystem": ecosystem,
                "vulnerable_range": artifact.get("vulnerable_range"),
                "fixed_version": artifact.get("fixed_version"),
                "installed_version": repo_entry.get("version"),
                "evidence_level": ev.get("evidence_level"),
                "classification": repo_entry.get("classification"),
                "impact_artifact": artifact_ref,
            }.items()
            if v
        },
    }
    finding["fingerprint"] = fingerprint(finding, repo_url)
    return finding


def build_event(
    new_id: str,
    artifact: dict,
    repo_entry: dict,
    artifact_ref: str,
    occurred_at: str,
    recorded_at: str,
    hv: str,
) -> dict:
    rationale = (
        f"{artifact['cve']} in {artifact['module']}: /impact-analysis "
        f"classified this repo '{repo_entry.get('classification')}' "
        f"(evidence level "
        f"{(repo_entry.get('evidence') or {}).get('evidence_level', 'unknown')}). "
        f"Routed as campaign finding {new_id} via the direct-entry "
        f"convention — validation_status: not_verified, resolution open; "
        f"triage/validation adjudicate downstream (operator directive "
        f"2026-07-28: dependency vulnerabilities become accountable "
        f"findings the day the advisory lands)."
    )
    return {
        "finding_ref": new_id,
        "recorded_at": recorded_at,
        "occurred_at": occurred_at,
        "source": {
            "type": "impact_report",
            "ref": artifact_ref,
            "actor": {"kind": "machine", "identity": "impact-analysis"},
        },
        "disposition": {"resolution": "open"},
        "rationale": rationale,
        "evidence_refs": [artifact_ref],
        "harness_version": hv,
    }


def resolve_baselines(db_path: Path) -> dict[str, Path]:
    """normalized repo_url -> freshest HEAD *-security-audit.json.

    findings.db's report_path is the repo's PREFERRED representation,
    which for md-only/converter repos is the derived
    *-findings-current.json — NEVER a filing target (the 2026-07-28
    bootstrap mutated 35 derived files through exactly this hole; they
    are regenerate-only). Only a real baseline audit JSON qualifies:
    a findings-current path is swapped for its sibling audit when one
    exists on disk, otherwise the repo resolves to nothing and the
    route loop reports it as `no-audit-json`."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(_REPOS_SQL).fetchall()
    finally:
        con.close()
    out: dict[str, Path] = {}
    for url, report_path in rows:
        n = normalize_repo_url(url)
        if not n or n in out or not report_path:
            continue
        path = Path(report_path)
        if path.name.endswith("-findings-current.json"):
            sibling = path.with_name(
                path.name.replace("-findings-current.json", "-security-audit.json")
            )
            path = sibling if sibling.is_file() else None
        elif not path.name.endswith("-security-audit.json"):
            path = None
        out[n] = path
    return out


def route_artifact(
    artifact_path: Path,
    db_path: Path,
    severity: str,
    include_likely: bool,
    limit: int | None,
    recorded_at: str | None,
    no_rebuild: bool,
    dry_run: bool,
    graph_db=None,
    *,
    engine,
) -> dict:
    raw = _load(artifact_path, "impact artifact")
    # run_impact_analysis.py nests the advisory fields under metadata;
    # accept top-level too (older/synthetic artifacts)
    meta = raw.get("metadata") or {}
    artifact = {
        "cve": meta.get("cve") or raw.get("cve"),
        "module": meta.get("module") or raw.get("module"),
        "ecosystem": meta.get("ecosystem") or raw.get("ecosystem"),
        "vulnerable_range": (meta.get("vulnerable_range") or raw.get("vulnerable_range")),
        "fixed_version": (meta.get("fixed_version") or raw.get("fixed_version")),
        "feature_description": (meta.get("feature_description") or raw.get("feature_description")),
        "generated_at": (meta.get("generated_at") or raw.get("generated_at")),
        "repos": raw.get("repos", []),
    }
    for key in ("cve", "module"):
        if not artifact.get(key):
            sys.exit(f"error: impact artifact missing '{key}'")
    artifact_ref = stable_ref(artifact_path)
    hv = f"{harness_version()}"
    recorded = recorded_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    occurred = artifact.get("generated_at") or recorded

    wanted = {"affected"} | ({"likely_affected"} if include_likely else set())
    targets = [r for r in artifact.get("repos", []) if r.get("classification") in wanted]
    if limit is not None:
        targets = targets[:limit]

    baselines = resolve_baselines(db_path)
    stats = {
        "targets": len(targets),
        "routed": 0,
        "already_filed": 0,
        "no_baseline": 0,
        "no_sha": 0,
        "rows": [],
    }

    for entry in targets:
        url = normalize_repo_url(repo_url_from_id(entry.get("repo", "")) or entry.get("repo", ""))
        if url and url in baselines and baselines[url] is None:
            # repo is audited but md-only: no baseline audit JSON to
            # append to — filing waits for the anchor-re-establishment
            # full audit (same self-heal class as no-pinned-sha)
            stats["no_audit_json"] = stats.get("no_audit_json", 0) + 1
            stats["rows"].append({"repo": entry.get("repo"), "status": "no-audit-json"})
            continue
        audit_path = baselines.get(url) if url else None
        if audit_path is None or not audit_path.is_file():
            stats["no_baseline"] += 1
            stats["rows"].append({"repo": entry.get("repo"), "status": "no-baseline"})
            continue
        # hard invariant: filings only ever append to a baseline audit
        assert audit_path.name.endswith("-security-audit.json"), audit_path
        audit = _load(audit_path, "baseline audit")

        # B3 — the layer is loaded UP FRONT now, because both the dedupe check
        # and id minting must see this router's own prior filings, which live on
        # events rather than in the baseline (gate A15: only the three
        # secure*audit skills may write a baseline).
        layer_path = audit_path.with_name(
            audit_path.name.replace("-security-audit.json", "-findings-layer.json")
        )
        shell = {
            "metadata": {
                "audit_report": audit_path.name,
                "repository": url or "https://unknown.invalid/",
                "created": recorded,
                "harness_version": hv,
            },
            "events": [],
            "needs_review": [],
        }
        if re.match(r"^[0-9a-f]{7,40}$", str((audit.get("metadata") or {}).get("commit") or "")):
            shell["metadata"]["audit_commit"] = str(audit["metadata"]["commit"])
        ledger = engine.ledger.service(data_dir=layer_path.parent)
        layer = ledger.ensure_layer_file(layer_path, shell=shell)

        existing = already_filed(audit, artifact["cve"], artifact["module"], layer)
        if existing:
            stats["already_filed"] += 1
            stats["rows"].append(
                {"repo": entry.get("repo"), "status": "already-filed", "finding": existing}
            )
            continue
        sha7 = baseline_sha7(audit)
        if not sha7:
            stats["no_sha"] += 1
            stats["rows"].append({"repo": entry.get("repo"), "status": "no-pinned-sha"})
            continue
        slug = slug_for(audit, url or "")
        new_id = f"{slug}-{sha7}-{next_sequence(audit, slug, sha7, layer):03d}"
        finding = build_finding(new_id, artifact, entry, severity, artifact_ref, url, graph_db)
        event = build_event(new_id, artifact, entry, artifact_ref, occurred, recorded, hv)
        # B3 — the claim rides on the event instead of being appended to the
        # baseline. build_cumulative unions it back in at replay (v0.283.0), so
        # the finding is just as visible while the baseline stays the fixed
        # claim set only the secure*audit skills may write.
        event["finding"] = finding

        if dry_run:
            stats["routed"] += 1
            stats["rows"].append(
                {"repo": entry.get("repo"), "status": "would-route", "finding": new_id}
            )
            continue

        # B3 — the baseline is NOT written. The claim rides on the event
        # (above); build_cumulative unions event-carried claims at replay.
        # RESOLVED by LedgerService.submit_events: report-reference stamping
        # (plan §4.4.0), Merkle finalization, signing, and stale-root
        # handling (previously left broken with --no-rebuild) are all internal
        # to the service now — every submit finalizes atomically.
        ledger.submit_events(layer_path, [event], report_path=audit_path)

        if not no_rebuild:
            rebuild_cumulative(audit_path, layer_path)
        stats["routed"] += 1
        stats["rows"].append({"repo": entry.get("repo"), "status": "routed", "finding": new_id})
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("artifact", type=Path, help="<cve>-impact-analysis.json from /impact-analysis")
    ap.add_argument(
        "--severity",
        required=True,
        choices=["critical", "high", "medium", "low", "info"],
        help="severity from the advisory (CVSS/vendor) — this tool never invents one",
    )
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument(
        "--graph-db",
        type=Path,
        default=None,
        help="portfolio graph db read for the `manifest` "
        "provenance attr on dependency edges (priority-2 "
        "cited location); absent = heuristic fallback",
    )
    ap.add_argument(
        "--include-likely",
        action="store_true",
        help="also file likely_affected repos (default: affected only)",
    )
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--recorded-at", type=recorded_at_arg, default=None)
    ap.add_argument("--no-rebuild", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    db = args.db or findings_db(engine)
    graph_db = args.graph_db or engine.portfolio.portfolio_graph_db()

    stats = route_artifact(
        args.artifact,
        db,
        args.severity,
        args.include_likely,
        args.limit,
        args.recorded_at,
        args.no_rebuild,
        args.dry_run,
        graph_db,
        engine=engine,
    )
    print(json.dumps(stats, indent=1))
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["route", "impact-findings", *sys.argv[1:]]))
