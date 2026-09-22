#!/usr/bin/env python3
"""Deterministic compliance-assessment runner (Phase 3).

The mechanical half of /compliance-check: loads the schema-gated policy
data (mapping registry, org-parameters, catalogs), expands the
framework selection (one, comma-list, or `all` — with per-framework
declared-input preconditions: a framework missing its required input is
SKIPPED WITH A NAMED REASON, never run degraded), materializes
findings-db views for the target's repos, evaluates every deterministic
check through the single assertion engine, writes the content-addressed
evidence bundle, assembles the assessment artifact with full provenance
stamps (registry hash, ODP hash, snapshot id, collector versions), and
runs the citation gate.

What it does NOT do: judge evidence_review controls (the agent's job,
afterwards, under the SKILL's rules) or narrate anything. Deterministic
controls leave here with code-computed verdicts (verdict_source=check);
evidence_review and organizational controls leave as not_assessed with
machine-readable reasons.

OSCAL export (--oscal): assessment-results for the 800-53-spine
frameworks with CONTENT-DERIVED uuid5 identifiers (determinism
amendment 6) — rerunning over identical inputs yields an identical
document.

Usage:
    python3 scripts/run_compliance_check.py \
        --frameworks all --target-kind product --repos org/a org/b \
        [--collector cloud_inventory=/path/snapshot.json]
        [--collector scan_k8s_hardening=/path/khs.json]
        [--findings-db <db>] [--adr-index <json>]
        [--cde-boundary <ref>] [--personal-data-stores a,b]
        [--trust-categories security,availability]
        [--out-dir <dir>] [--oscal]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    findings_db,
    load_engine,
    progress_tracker_dir,
)
from traust.paths import HARNESS_ROOT

try:
    import yaml
except ImportError:
    yaml = None

from traust_engine._util.script_loader import load_script


def _load(name: str):
    return load_script(name, HARNESS_ROOT)


ca = _load("compliance_assert")
vca = _load("validate_compliance_assessment")

ALL_FRAMEWORKS = (
    "nist-800-53-rev5",
    "fedramp-high",
    "fedramp-moderate",
    "pci-dss-v4",
    "soc2-tsc",
    "gdpr-technical",
)
# frameworks resolved against the 800-53 spine registry entries
SPINE_ALIASES = {"fedramp-high": "nist-800-53-rev5", "fedramp-moderate": "nist-800-53-rev5"}
SPINE_PROFILE = {
    "fedramp-high": "profile-800-53b-high.json",
    "fedramp-moderate": "profile-800-53b-moderate.json",
}

CAVEATS = {
    "soc2-tsc": (
        "point-in-time technical evidence; a SOC 2 Type 2 "
        "examination attests controls over a period — this is "
        "audit input, never an attestation"
    ),
    "fedramp-high": (
        "interim posture: assessed against the NIST "
        "800-53B High selections; FedRAMP-specific "
        "overlays pending an authoritative source"
    ),
    "fedramp-moderate": (
        "interim posture: assessed against the NIST "
        "800-53B Moderate selections; FedRAMP-specific "
        "overlays pending an authoritative source"
    ),
}

# dependency- and credential-class CWEs for the findings_db views
DEP_CWES = ("CWE-1035", "CWE-937", "CWE-1104", "CWE-1395")
CRED_CWES = ("CWE-798", "CWE-321", "CWE-259", "CWE-540")


def sha_file(path: Path) -> str:
    return ca.evidence_id(
        yaml.safe_load(path.read_text(encoding="utf-8"))
        if path.suffix in (".yaml", ".yml")
        else json.loads(path.read_text(encoding="utf-8"))
    )


def check_preconditions(fw: str, args) -> str | None:
    """Named skip reason, or None when the framework can run."""
    if fw == "pci-dss-v4" and not args.cde_boundary:
        return "skipped: no declared CDE boundary (--cde-boundary)"
    if fw == "gdpr-technical" and not args.personal_data_stores:
        return "skipped: no declared personal-data stores (--personal-data-stores)"
    if fw == "soc2-tsc" and not args.trust_categories:
        return "skipped: no declared trust-service categories (--trust-categories)"
    return None


def findings_db_views(db_path: Path, repos: list[str]) -> dict:
    """Pre-shaped views over the C9 projection for the target's repos
    (keeps the assertion DSL filter-free)."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    like = [f"%github.com/{r}" for r in repos] or ["%"]
    rows = []
    for pat in like:
        rows += con.execute(
            "SELECT f.finding_id, f.severity, f.primary_cwe, "
            "f.validity, f.repo_key FROM v_open f JOIN repos r "
            "USING (repo_key) WHERE COALESCE(r.repo_url,'') LIKE ?",
            (pat,),
        ).fetchall()
    con.close()

    def row(r):
        return {
            "id": r["finding_id"],
            "severity": r["severity"],
            "primary_cwe": r["primary_cwe"],
            "repo_key": r["repo_key"],
        }

    return {
        "open_critical_dependency_findings": sorted(
            (row(r) for r in rows if r["severity"] == "critical" and r["primary_cwe"] in DEP_CWES),
            key=lambda x: (x["repo_key"], x["id"]),
        ),
        "open_confirmed_hardcoded_credential_findings": sorted(
            (
                row(r)
                for r in rows
                if r["validity"] == "confirmed" and r["primary_cwe"] in CRED_CWES
            ),
            key=lambda x: (x["repo_key"], x["id"]),
        ),
    }


def write_bundle(evidence: list[dict], bundle_dir: Path):
    """Content-addressed bundle entries from evidence items' full
    values (the engine attaches `_value`; we write it and strip the
    key so the artifact stays schema-clean)."""
    _missing = object()
    for ev in evidence:
        v = ev.pop("_value", _missing)
        if v is _missing:
            continue  # null is a legitimate evidence value; only skip
            # items that never carried bundle material
        p = bundle_dir / f"{ev['sha256']}.json"
        if not p.exists():
            p.write_text(ca.canonical_json(v) + "\n", encoding="utf-8")


def evaluate_controls(
    registry: dict, frameworks: list[str], snapshots: dict, org_params, bundle_dir: Path
) -> list[dict]:
    checks = {c["id"]: c for c in registry["checks"]}
    results = []
    for ctl in registry["controls"]:
        spine_fw = ctl["framework"]
        for fw in frameworks:
            if SPINE_ALIASES.get(fw, fw) != spine_fw:
                continue
            base = {
                "framework": fw,
                "control_id": ctl["control_id"],
                "classification": ctl["classification"],
            }
            if ctl["classification"] == "organizational":
                results.append(
                    {
                        **base,
                        "verdict": "not_assessed",
                        "verdict_source": "check",
                        "reason": "organizational — out of technical scope",
                    }
                )
                continue
            if ctl["classification"] == "evidence_review":
                results.append(
                    {
                        **base,
                        "verdict": "not_assessed",
                        "verdict_source": "check",
                        "reason": "evidence_review — awaiting "
                        f"artifact: "
                        f"{ctl.get('evidence_request', '')}",
                    }
                )
                continue
            # deterministic: every check must pass; first failure wins
            agg, evidence, reasons = "satisfied", [], []
            for cid in ctl["checks"]:
                chk = checks[cid]
                snap = snapshots.get(chk["collector"])
                if snap is None:
                    agg = "not_assessed"
                    reasons.append(f"collector unavailable: {chk['collector']}")
                    continue
                res = ca.evaluate_check(chk, snap, org_params)
                if res["verdict"] == "not_satisfied":
                    agg = "not_satisfied"
                    write_bundle(res["evidence"], bundle_dir)
                    evidence = res["evidence"]
                    base["check_id"] = cid
                    break
                if res["verdict"] in ("not_assessed", "not_applicable") and agg == "satisfied":
                    agg = res["verdict"]
                    reasons.append(res.get("reason", ""))
                if res["verdict"] == "satisfied" and not evidence:
                    write_bundle(res["evidence"], bundle_dir)
                    evidence = res["evidence"]
                    base.setdefault("check_id", cid)
            r = {**base, "verdict": agg, "verdict_source": "check"}
            if agg in ("satisfied", "not_satisfied"):
                r["evidence"] = evidence
            else:
                r["reason"] = "; ".join(x for x in reasons if x) or "undetermined"
            results.append(r)
    return results


def coverage_blocks(results: list[dict]) -> dict:
    from collections import Counter

    cov = {}
    for r in results:
        c = cov.setdefault(r["framework"], Counter())
        c["total_in_scope"] += 1
        c[r["classification"]] += 1
        c[r["verdict"]] += 1
    keys = (
        "total_in_scope",
        "deterministic",
        "evidence_review",
        "organizational",
        "satisfied",
        "not_satisfied",
        "not_applicable",
        "not_assessed",
    )
    return {fw: {k: c.get(k, 0) for k in keys} for fw, c in cov.items()}


def export_oscal(doc: dict, out: Path):
    """Minimal OSCAL assessment-results with content-derived uuids."""
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

    def u5(*parts):
        return str(uuid.uuid5(ns, "|".join(parts)))

    spine = [
        r
        for r in doc["results"]
        if SPINE_ALIASES.get(r["framework"], r["framework"]) == "nist-800-53-rev5"
    ]
    observations = [
        {
            "uuid": u5(
                r["framework"], r["control_id"], r["verdict"], doc["metadata"]["registry_hash"]
            ),
            "title": f"{r['framework']} {r['control_id']}",
            "description": r.get("reason") or r["verdict"],
            "methods": ["TEST" if r["classification"] == "deterministic" else "EXAMINE"],
            "props": [
                {"name": "verdict", "value": r["verdict"]},
                {"name": "classification", "value": r["classification"]},
            ],
        }
        for r in spine
    ]
    oscal = {
        "assessment-results": {
            "uuid": u5(
                "assessment",
                doc["metadata"]["registry_hash"],
                doc["metadata"].get("snapshot_id") or "",
                ",".join(sorted(f["id"] for f in doc["metadata"]["frameworks"])),
            ),
            "metadata": {
                "title": "Hybrid Platforms compliance assessment",
                "last-modified": doc["metadata"]["generated_at"],
                "version": doc["metadata"]["harness_version"] or "0",
                "oscal-version": "1.1.2",
            },
            "results": [
                {
                    "uuid": u5("result", doc["metadata"]["registry_hash"]),
                    "title": "automated technical assessment",
                    "description": doc["metadata"]["frameworks"][0].get("caveat", ""),
                    "start": doc["metadata"]["generated_at"],
                    "observations": observations,
                }
            ],
        }
    }
    out.write_text(json.dumps(oscal, indent=1) + "\n", encoding="utf-8")


def artifact_base(target_id: str, frameworks_arg: str) -> str:
    """Unique, self-identifying artifact name:
    <target>-<framework-selection>-compliance-assessment. The selection
    is the REQUESTED one ('all', one id, or 'a+b' for a list) so a
    SOC 2-only run and an all-frameworks run of the same target never
    overwrite each other, and a detached file still says what it is."""
    tid = re.sub(r"[^A-Za-z0-9._-]+", "-", target_id).strip("-") or "unnamed"
    if frameworks_arg.strip() == "all":
        sel = "all"
    else:
        sel = "+".join(sorted(f.strip() for f in frameworks_arg.split(",") if f.strip()))
    return f"{tid}-{sel}-compliance-assessment"


def render_md(doc: dict) -> str:
    """Human-readable per-run report — coverage honesty leads, verdicts
    follow, everything the artifact states and nothing it doesn't."""
    m = doc["metadata"]
    t = m["target"]
    L = ["# Compliance Assessment", ""]
    A = L.append
    tid = t.get("environment") or t.get("product") or ",".join(t.get("repos") or []) or "(unnamed)"
    A(
        f"_Target **{tid}** ({t.get('kind')}) · {m['generated_at']} · "
        f"harness {m['harness_version']} · registry "
        f"{m['registry_hash'][:12]}…"
        + (f" · snapshot {t['snapshot_id'][:12]}…" if t.get("snapshot_id") else "")
        + "_"
    )
    A("")
    A("## Coverage (the honest headline — no blended percentage exists)")
    A("")
    A(
        "| Framework | In scope | Deterministic | Evidence review | "
        "Organizational | Satisfied | Not satisfied | N/A | Not assessed |"
    )
    A("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for fw, c in sorted((doc.get("coverage") or {}).items()):
        A(
            f"| {fw} | {c['total_in_scope']} | {c['deterministic']} | "
            f"{c['evidence_review']} | {c['organizational']} | "
            f"{c['satisfied']} | **{c['not_satisfied']}** | "
            f"{c['not_applicable']} | {c['not_assessed']} |"
        )
    for fw, reason in sorted((m.get("skipped_frameworks") or {}).items()):
        A(f"| {fw} | — | — | — | — | — | — | — | _{reason}_ |")
    A("")
    for f in m.get("frameworks") or []:
        if f.get("caveat"):
            A(f"> **{f['id']}:** {f['caveat']}")
    A("")
    ns = [r for r in doc.get("results") or [] if r.get("verdict") == "not_satisfied"]
    if ns:
        A("## Not satisfied")
        A("")
        for r in ns:
            A(f"### `{r['framework']}:{r['control_id']}` via `{r.get('check_id', '?')}`")
            A("")
            for ev in (r.get("evidence") or [])[:5]:
                A(f"- `{ev['sha256'][:12]}…` {ev['locator']}")
                if ev.get("excerpt"):
                    A(f"  - `{ev['excerpt'][:160]}`")
            more = len(r.get("evidence") or []) - 5
            if more > 0:
                A(f"- … {more} more evidence item(s) in the bundle")
            A("")
    A("## Not assessed / out of scope (transparency)")
    A("")
    reasons: dict[str, int] = {}
    for r in doc.get("results") or []:
        if r.get("verdict") in ("not_assessed", "not_applicable"):
            key = r.get("reason", "")[:80]
            reasons[key] = reasons.get(key, 0) + 1
    for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        A(f"- {n} × {reason}")
    A("")
    return "\n".join(L) + "\n"


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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--frameworks",
        required=True,
        help="framework id, comma list, 'all', or 'boundary' "
        "(= the frameworks the --boundary declares)",
    )
    ap.add_argument(
        "--target-kind", required=False, default=None, choices=("product", "environment", "both")
    )
    ap.add_argument(
        "--boundary",
        default=None,
        help="declared boundary id from the compliance scope "
        "registry (compliance-scope.yaml) — resolves the "
        "repo set, defaults frameworks and target-kind, "
        "and stamps scope provenance into the artifact",
    )
    ap.add_argument("--scope-registry", type=Path, default=None)
    ap.add_argument("--product", default=None)
    ap.add_argument("--repos", nargs="*", default=[])
    ap.add_argument("--environment", default=None)
    ap.add_argument("--collector", action="append", default=[], metavar="KIND=PATH")
    ap.add_argument("--registry", type=Path, default=None)
    ap.add_argument("--org-parameters", type=Path, default=None)
    ap.add_argument("--findings-db", type=Path, default=None)
    ap.add_argument("--adr-index", type=Path, default=None)
    ap.add_argument("--cde-boundary", default=None)
    ap.add_argument("--personal-data-stores", default=None)
    ap.add_argument("--trust-categories", default=None)
    ap.add_argument("--out-dir", type=Path, default=Path.cwd())
    ap.add_argument("--oscal", action="store_true")
    args = ap.parse_args(argv)
    engine = load_engine(args.config_home)
    configs = progress_tracker_dir(engine) / "configs" / "compliance"
    args.scope_registry = args.scope_registry or (configs / "compliance-scope.yaml")
    args.registry = args.registry or (configs / "compliance-mapping.yaml")
    args.org_parameters = args.org_parameters or (configs / "org-parameters.yaml")
    args.findings_db = args.findings_db or findings_db(engine)
    if yaml is None:
        sys.exit("PyYAML required")

    scope_res = None
    if args.boundary:
        # Phase 6: scope declared at boundary level, resolved
        # via the repo-graph product mapping. Fail-loud on any resolution
        # problem — a mis-scoped compliance run is worse than no run.
        from resolve_compliance_scope import ScopeError, load_scope
        from resolve_compliance_scope import resolve as resolve_scope

        try:
            scope_res = resolve_scope(load_scope(args.scope_registry), args.boundary)
        except ScopeError as e:
            sys.exit(f"--boundary: {e}")
        if args.repos:
            sys.exit(
                "--boundary and --repos are mutually exclusive: the "
                "registry is the scope authority for boundary runs"
            )
        args.repos = scope_res["repos"]
        if not args.product:
            args.product = scope_res.get("product") or args.boundary
        if args.target_kind is None:
            args.target_kind = "product"
        if args.frameworks == "boundary":
            args.frameworks = ",".join(scope_res["frameworks"])
    if args.target_kind is None:
        sys.exit("--target-kind required (or use --boundary)")

    registry = yaml.safe_load(args.registry.read_text(encoding="utf-8"))
    org_params = (
        yaml.safe_load(args.org_parameters.read_text(encoding="utf-8"))
        if args.org_parameters.is_file()
        else None
    )

    wanted = (
        list(ALL_FRAMEWORKS)
        if args.frameworks == "all"
        else [f.strip() for f in args.frameworks.split(",")]
    )
    unknown = [f for f in wanted if f not in ALL_FRAMEWORKS]
    if unknown:
        sys.exit(f"unknown framework(s): {', '.join(unknown)} (known: {', '.join(ALL_FRAMEWORKS)})")
    skipped, frameworks = {}, []
    for fw in wanted:
        reason = check_preconditions(fw, args)
        if reason:
            skipped[fw] = reason
        else:
            frameworks.append(fw)

    # environment-kind preconditions: FedRAMP/sovereignty need one
    if args.target_kind == "product":
        for fw in ("fedramp-high", "fedramp-moderate", "gdpr-technical"):
            if fw in frameworks:
                frameworks.remove(fw)
                skipped[fw] = "skipped: requires a deployed-environment target (product-only run)"

    snapshots = {}
    for spec in args.collector:
        kind, _, path = spec.partition("=")
        snapshots[kind] = json.loads(Path(path).read_text(encoding="utf-8"))
    if args.findings_db.is_file() and args.repos:
        snapshots["findings_db"] = findings_db_views(args.findings_db, args.repos)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = args.out_dir / "evidence"
    bundle_dir.mkdir(exist_ok=True)

    results = evaluate_controls(registry, frameworks, snapshots, org_params, bundle_dir)
    inv_meta = (snapshots.get("cloud_inventory") or {}).get("metadata") or {}
    target = {"kind": args.target_kind}
    if scope_res:
        target["scope"] = {
            "boundary": scope_res["boundary"],
            "resolves_via": scope_res["resolves_via"],
            "declared_by": scope_res["declared_by"],
            "declared_at": scope_res["declared_at"],
            "excluded": scope_res["excluded"],
            "draft": scope_res["draft"],
            # raw-bytes hash: the declaration AS WRITTEN is the provenance
            # unit (sha_file's canonical-JSON identity chokes on bare YAML
            # dates and would also mask whitespace edits to a signed doc)
            "registry_hash": hashlib.sha256(args.scope_registry.read_bytes()).hexdigest(),
        }
    if args.product:
        target["product"] = args.product
    if args.repos:
        target["repos"] = sorted(args.repos)
    if args.environment:
        target["environment"] = args.environment
    if inv_meta.get("snapshot_id"):
        target["snapshot_id"] = inv_meta["snapshot_id"]
    if args.cde_boundary:
        target["cde_boundary"] = args.cde_boundary
    if args.personal_data_stores:
        target["personal_data_stores"] = args.personal_data_stores.split(",")
    if args.trust_categories:
        target["trust_service_categories"] = args.trust_categories.split(",")

    doc = {
        "metadata": {
            "artifact": "compliance-assessment",
            "harness_version": harness_version() or "unknown",
            "target": target,
            "frameworks": [
                {
                    "id": fw,
                    **({"caveat": CAVEATS[fw]} if fw in CAVEATS else {}),
                    **({"profile": SPINE_PROFILE[fw]} if fw in SPINE_PROFILE else {}),
                }
                for fw in frameworks
            ],
            "skipped_frameworks": skipped,
            "registry_hash": sha_file(args.registry),
            "org_parameters_hash": (
                sha_file(args.org_parameters) if args.org_parameters.is_file() else None
            ),
            "collector_versions": {
                k: (v.get("metadata") or {}).get("collector", k) if isinstance(v, dict) else k
                for k, v in snapshots.items()
            },
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "coverage": coverage_blocks(results),
        "results": results,
    }
    tid = args.environment or args.product or ",".join(args.repos) or "unnamed"
    base = artifact_base(tid, args.frameworks)
    out = args.out_dir / f"{base}.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / f"{base}.md").write_text(render_md(doc), encoding="utf-8")

    adr_index = (
        json.loads(args.adr_index.read_text(encoding="utf-8"))
        if args.adr_index and args.adr_index.is_file()
        else None
    )
    failures = vca.validate(doc, bundle_dir, vca.SCHEMA, adr_index)
    print(f"wrote {out}")
    for fw, reason in skipped.items():
        print(f"  {fw}: {reason}")
    for fw, cov in doc["coverage"].items():
        print(
            f"  {fw}: {cov['satisfied']} satisfied / "
            f"{cov['not_satisfied']} not_satisfied / "
            f"{cov['not_assessed']} not_assessed "
            f"(of {cov['total_in_scope']})"
        )
    if failures:
        print(f"✗ citation gate: {len(failures)} failure(s)")
        for f in failures[:10]:
            print(f"  - {f}")
        return 1
    print("✓ citation gate passed")
    if args.oscal and frameworks:
        oscal_out = args.out_dir / f"{base}.oscal.json"
        export_oscal(doc, oscal_out)
        print(f"wrote {oscal_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
