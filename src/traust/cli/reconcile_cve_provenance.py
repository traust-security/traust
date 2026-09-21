#!/usr/bin/env python3
"""Reconcile audit findings against published Red Hat CVEs.

Answers "which CVE did our finding become?" from data instead of from
someone's memory, and stamps the answer into each layer's
`metadata.external_refs` (layer.schema.json, contracts >= 0.5.4).

WHY THIS EXISTS
    A 2026-08-20 first-discovery analysis found 59 Red Hat CVEs whose
    published text matches a finding we had already filed, a median 80
    days earlier. Nothing recorded that link: findings.db has no CVE
    column, and the escalation path (finding -> Bugzilla -> CVE) runs
    through systems we do not own. The one case the analysis could not
    see at all was a CVE filed by a team member working from harness
    findings, where the titles differ and the only record was in his
    head. This closes the machine-detectable part of that gap.

WHAT IT IS NOT
    Not a verdict. A stamp is provenance: it records that our finding
    corresponds to a published CVE and asserts nothing about validity,
    resolution or severity. It is written to layer METADATA, never to
    the audit baseline (gate A15) and never to the Merkle-signed event
    chain — the data is derived and recomputable, so signing it buys no
    integrity while making every re-run perturb a signed structure.

MATCHING
    Red Hat's `bugzilla_description` follows a "component: title"
    convention, giving two join keys. Components join to audited repo
    names; titles are compared with max(token-Jaccard, difflib ratio).

    >= AUTO_CONFIRM (0.75)   -> confirmed
    >= AUTO_PROBABLE (0.55)  -> confirmed when the CWEs overlap,
                                otherwise probable
    below                    -> no stamp

    CWE only ever PROMOTES. Measured on the 59: CWE corroborates 80% of
    true matches, but the disjoint 20% are the same issue filed under a
    sibling weakness (RH CWE-312 vs our CWE-522; RH CWE-863 vs our
    CWE-302/807). A hard CWE gate would drop 19% of true matches
    including CVE-2026-66792, the 9.9 — so it is a tiebreaker, not a
    filter.

    Only a CVE published AFTER our audit can be a first-discovery match;
    anything published earlier is something we read, not something we
    found.

CONFIDENCE, AND WHY BOTH BANDS ARE AUTO-STAMPED
    Across 53 matches adjudicated by hand at >= 0.55 there were zero
    false matches, and a wrong stamp mislabels a metric rather than
    closing a finding. Human review stays where state changes are
    decided (/countersign) and nowhere else. Only `confirmed` belongs in
    a headline number; `probable` is for triage.

NOT YET IMPLEMENTED
    The CNA/credit tier ("Red Hat assigned it and credited nobody
    external, so it is probably ours") needs cveawg.mitre.org data that
    the rh-cve feed does not carry. Left out rather than approximated.

Usage:
    python3 -m traust.cli.reconcile_cve_provenance
        [--results-root DIR] [--cache-dir DIR] [--apply]
        [--min-score F] [--report PATH]

Dry-run by default: prints what it would stamp and writes nothing.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import json
import re
import sys
from pathlib import Path

from traust_engine import HarnessEngine

from traust.cli.fetch_feeds import load_rh_cves
from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.registry.feeds_config import feeds_cache_dir

AUTO_CONFIRM = 0.75
AUTO_PROBABLE = 0.55

_STOP = {
    "the",
    "a",
    "an",
    "of",
    "to",
    "in",
    "on",
    "for",
    "and",
    "or",
    "with",
    "without",
    "via",
    "is",
    "are",
    "not",
    "no",
    "by",
    "from",
    "at",
    "as",
    "it",
    "its",
    "cve",
}
_REF_SUFFIX = re.compile(r"__release-[\w.\-]+$")


def _tokens(s: str) -> set[str]:
    return {
        w for w in re.findall(r"[a-z0-9_]+", (s or "").lower()) if len(w) > 2 and w not in _STOP
    }


def score_titles(cve_title: str, finding_title: str) -> float:
    """max(token-Jaccard, sequence ratio).

    Jaccard survives reordering and length differences; the sequence
    ratio rescues near-identical strings that tokenize apart (the CVE
    "no_auth" vs our "noauth" was a real 0.457 that should have been 1.0).
    """
    a, b = _tokens(cve_title), _tokens(finding_title)
    jac = len(a & b) / len(a | b) if a and b else 0.0
    seq = difflib.SequenceMatcher(
        None, (cve_title or "").lower(), (finding_title or "").lower()
    ).ratio()
    return max(jac, seq)


def _cwes(value) -> set[str]:
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    return set(re.findall(r"CWE-(\d+)", str(value or "")))


def classify(score: float, cve_cwe, finding_cwe) -> str | None:
    """Band a match. CWE promotes; it never blocks."""
    if score >= AUTO_CONFIRM:
        return "confirmed"
    if score >= AUTO_PROBABLE:
        return "confirmed" if (_cwes(cve_cwe) & _cwes(finding_cwe)) else "probable"
    return None


def audit_index(results_root: Path, engine: HarnessEngine) -> list[dict]:
    """Deduplicated code-audit reports via the shared corpus resolver.

    Never walk the tree by hand: findings/_orgs/ is a symlink index, and
    a naive glob double-counts through it — the measured inflation is
    roughly 2.7x.
    """
    results_root = results_root.resolve()
    res = engine.corpus.load_resolution(results_root=results_root)
    store = engine.corpus.report_store(results_root=results_root)
    recs = res.records if hasattr(res, "records") else res
    out = []
    for rec in recs:
        if rec.report_kind != "code-audit" or not rec.audit_json:
            continue
        p = Path(rec.audit_json)
        if not p.is_absolute():
            p = results_root / p
        try:
            doc = store.get_json(engine.corpus.to_ref(str(p), results_root=results_root))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        out.append(
            {
                "component": _REF_SUFFIX.sub("", (rec.base or "").lower()),
                "date": ((doc.get("metadata") or {}).get("date") or "")[:10],
                "layer": rec.findings_layer,
                "audit_json": str(p),
                "findings": [f for f in (doc.get("findings") or []) if f.get("title")],
            }
        )
    return out


def reconcile(reports: list[dict], cves: dict, min_score: float) -> list[dict]:
    by_component: dict[str, list[dict]] = {}
    for rep in reports:
        if rep["component"] and rep["date"]:
            by_component.setdefault(rep["component"], []).append(rep)

    matches = []
    for cve_id, cve in sorted(cves.items()):
        comp = (cve.get("component") or "").lower()
        if not comp or comp not in by_component:
            continue
        for rep in by_component[comp]:
            # Only a CVE published after our audit can be a first find.
            if not (cve["public_date"] > rep["date"]):
                continue
            best, best_f = 0.0, None
            for f in rep["findings"]:
                s = score_titles(cve["title"], f["title"])
                if s > best:
                    best, best_f = s, f
            if best_f is None or best < min_score:
                continue
            conf = classify(best, cve.get("cwe"), best_f.get("cwes"))
            if not conf:
                continue
            matches.append(
                {
                    "cve": cve_id,
                    "component": comp,
                    "public_date": cve["public_date"],
                    "audit_date": rep["date"],
                    "lead_days": (
                        datetime.date.fromisoformat(cve["public_date"])
                        - datetime.date.fromisoformat(rep["date"])
                    ).days,
                    "rh_severity": cve.get("severity"),
                    "score": round(best, 3),
                    "confidence": conf,
                    "finding_id": best_f.get("id"),
                    "finding_title": best_f.get("title"),
                    "cve_title": cve["title"],
                    "layer": rep["layer"],
                    "audit_json": rep["audit_json"],
                }
            )
    return matches


def stamp(matches: list[dict], results_root: Path, apply: bool) -> tuple[int, int]:
    """Write external_refs into each layer's metadata. Idempotent."""
    stamped_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_layer: dict[str, list[dict]] = {}
    for m in matches:
        if m["layer"]:
            by_layer.setdefault(str(m["layer"]), []).append(m)

    layers_written = refs_written = 0
    for layer_rel, group in sorted(by_layer.items()):
        p = Path(layer_rel)
        if not p.is_absolute():
            p = results_root / p
        if not p.is_file():
            continue
        try:
            original = p.read_text(encoding="utf-8")
            doc = json.loads(original)
        except (OSError, json.JSONDecodeError):
            continue
        # Preserve the file's own indentation. Re-serialising layers at a
        # different width turns a one-line stamp into a diff thousands of
        # lines long and buries the actual change.
        m = re.match(r"\{\n( +)\"", original)
        indent = len(m.group(1)) if m else 2
        meta = doc.setdefault("metadata", {})
        refs = dict(meta.get("external_refs") or {})
        changed = False
        for m in group:
            fid = m["finding_id"]
            if not fid:
                continue
            entry = {
                "system": "cve",
                "id": m["cve"],
                "url": f"https://access.redhat.com/security/cve/{m['cve']}",
                "confidence": m["confidence"],
                "matched_on": f"title-similarity:{m['score']}",
                "stamped_at": stamped_at,
            }
            existing = [r for r in refs.get(fid, []) if r.get("id") != m["cve"]]
            prior = next((r for r in refs.get(fid, []) if r.get("id") == m["cve"]), None)
            # Re-running must be a no-op when nothing but the clock moved.
            if prior and all(prior.get(k) == entry[k] for k in ("confidence", "matched_on")):
                continue
            refs[fid] = [*existing, entry]
            changed = True
            refs_written += 1
        if changed:
            layers_written += 1
            if apply:
                meta["external_refs"] = refs
                p.write_text(json.dumps(doc, indent=indent) + "\n", encoding="utf-8")
    return layers_written, refs_written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--apply", action="store_true", help="write the stamps (default is a dry run)")
    ap.add_argument("--min-score", type=float, default=AUTO_PROBABLE)
    ap.add_argument("--report", type=Path, help="write the full match list as JSON")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = args.results_root or analysis_results_dir(engine)
    cache_dir = args.cache_dir or feeds_cache_dir(engine=engine)

    try:
        cves = load_rh_cves(cache_dir)
    except (OSError, json.JSONDecodeError) as e:
        print(f"rh-cve feed unreadable ({e}); run fetch_feeds.py --feed rh-cve", file=sys.stderr)
        return 1
    reports = audit_index(results_root, engine)
    matches = reconcile(reports, cves, args.min_score)

    conf = [m for m in matches if m["confidence"] == "confirmed"]
    prob = [m for m in matches if m["confidence"] == "probable"]
    # Report DISTINCT CVEs, not rows. One component is audited on many
    # release branches, so a single CVE legitimately stamps many layers
    # (console: 11). Counting rows would inflate the headline ~2x.
    n_cve = len({m["cve"] for m in matches})
    n_conf = len({m["cve"] for m in conf})
    n_prob = len({m["cve"] for m in prob}) - len(
        {m["cve"] for m in prob} & {m["cve"] for m in conf}
    )
    print(f"feed: {len(cves)} CVEs | corpus: {len(reports)} code audits")
    print(f"distinct CVEs matched: {n_cve}  (confirmed {n_conf}, probable-only {n_prob})")
    print(
        f"  across {len(matches)} report(s) — a component audited on N "
        f"release branches matches N times"
    )
    if conf:
        leads = sorted(m["lead_days"] for m in conf)
        print(
            f"lead days (confirmed): min {leads[0]} / "
            f"median {leads[len(leads) // 2]} / max {leads[-1]}"
        )

    layers, refs = stamp(matches, results_root, args.apply)
    verb = "stamped" if args.apply else "would stamp"
    print(
        f"{verb} {refs} ref(s) across {layers} layer(s)"
        + ("" if args.apply else "  [dry run — pass --apply]")
    )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {
                    "generated": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "distinct_cves": n_cve,
                    "distinct_confirmed": n_conf,
                    "distinct_probable_only": n_prob,
                    "match_rows": len(matches),
                    "matches": matches,
                },
                indent=1,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["feeds", "reconcile-cve-provenance", *sys.argv[1:]]))
