#!/usr/bin/env python3
"""Build the full-sweep worklist for /verify-remediation.

Deterministic shortlist builder: walks every canonical audit report under
the findings tree and decides which repositories are WORTH re-verifying,
so the expensive LLM re-audit runs only where a fix can possibly exist.

Per repo it records:
  - pinned audit SHA (parsed from metadata.commit) vs live HEAD
    (`git ls-remote`) — a repo whose HEAD still equals the audited SHA
    cannot have fixed anything and is skipped;
  - ledger remediation signals — disposition events claiming
    fix_in_progress / resolved / partially_resolved in the sibling
    `*-findings-layer.json`;
  - severity profile of the audit findings;
  - whether a `*-remediation-verification.json` already exists
    (skipped unless --force → natural resumability).

Tiers (verify in this order):
  T1  ledger remediation signal (someone claims work happened)
  T2  HEAD drifted + ≥1 critical finding
  T3  HEAD drifted + ≥1 high finding
  T4  HEAD drifted, everything else
Skipped (listed, not queued): unchanged HEAD, already verified,
covered elsewhere (a sibling product filing of the same repo already has
a verification report pinning the current HEAD — fan-out territory, not
a fresh run; without this the sweep's own fan-out ledger events re-queue
siblings as T1 forever), unreachable remote, no parseable repo/SHA.

This script only routes — it never authors a verification verdict.

Usage:
    python3 build_verify_sweep.py [--results-root DIR] [--roots DIR...]
        [--include-branches] [--no-network] [--force]
        [--max-workers N] [--out FILE]
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path

from traust_engine.corpus.resolver import normalize_repo_url

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

SHA_RX = re.compile(r"\b([0-9a-f]{7,40})\b")
TIERS = ("T1", "T2", "T3", "T4")


def parse_pinned_sha(commit_field: str | None) -> str | None:
    """metadata.commit is sometimes prose ('edb306fe… (main HEAD, …)');
    take the first hex run that looks like a SHA."""
    if not commit_field:
        return None
    m = SHA_RX.search(commit_field)
    return m.group(1) if m else None


ANALYZED_ROW_RX = re.compile(r"(ref analyzed|analyzed commit|analyzed ref|head commit)", re.I)
REQUESTED_RX = re.compile(r"requested", re.I)


def md_fallback_sha(audit_json_path: Path) -> str | None:
    """Converter-era audits (md_to_json ≤0.4.2) drop metadata.commit from
    the JSON — the analyzed SHA survives only in the sibling markdown's
    header table. Scan the md for an 'analyzed' row and take its SHA.
    Rows mentioning a *requested* ref are skipped: when the requested ref
    was unfetchable the audit fell back to another ref, and pinning the
    requested SHA would mis-classify drift (observed live: a repo queued
    as unknown-drift whose HEAD equalled the analyzed fallback SHA)."""
    md = audit_json_path.with_name(audit_json_path.name.removesuffix(".json") + ".md")
    try:
        text = md.read_text(encoding="utf-8", errors="ignore")[:8000]
    except OSError:
        return None
    for line in text.splitlines():
        if ANALYZED_ROW_RX.search(line) and not REQUESTED_RX.search(line):
            m = SHA_RX.search(line)
            if m:
                return m.group(1)
    return None


def sev_counts(report: dict) -> collections.Counter:
    c = collections.Counter()
    for f in report.get("findings") or []:
        s = (f.get("severity") or "").lower()
        if s:
            c[s] += 1
    return c


def ledger_remediation_events(layer_path: Path) -> int:
    """Count disposition events that claim remediation activity."""
    try:
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    n = 0
    for ev in layer.get("events") or []:
        res = (ev.get("disposition") or {}).get("resolution") or ""
        if res in ("fix_in_progress", "resolved", "partially_resolved"):
            n += 1
    return n


def ls_remote_head(url: str, timeout: int = 25) -> str | None:
    # url originates in report metadata (attacker-influenced per the
    # threat model); https-only + GIT_ALLOW_PROTOCOL blocks the
    # ext::/--upload-pack RCE class (audit A2, plan P0.1)
    if not re.match(r"^https://[^\s'\"]+$", url or ""):
        return None
    try:
        out = subprocess.run(
            ["git", "ls-remote", "--", url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ALLOW_PROTOCOL": "https",
                "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            },
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return out.stdout.split()[0]
    except (subprocess.SubprocessError, OSError):
        return None


def discover(roots: list[Path], include_branches: bool) -> list[dict]:
    entries = []
    seen: set[Path] = set()
    for root in roots:
        for aj in sorted(root.rglob("*security-audit.json")):
            if aj.is_symlink() or "_manifest" in aj.parts:
                continue
            real = aj.resolve()
            if real in seen:
                continue
            seen.add(real)
            base = aj.name.removesuffix("-security-audit.json")
            if "__" in base and not include_branches:
                continue  # release-branch report; HEAD sweep covers the repo
            try:
                report = json.loads(aj.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            meta = report.get("metadata") or {}
            counts = sev_counts(report)
            verification = aj.parent / f"{base}-remediation-verification.json"
            layer = aj.parent / f"{base}-findings-layer.json"
            verified_patched = None
            if verification.exists():
                try:
                    vmeta = (
                        json.loads(verification.read_text(encoding="utf-8")).get("metadata") or {}
                    )
                    verified_patched = parse_pinned_sha(vmeta.get("patched_commit"))
                except (OSError, json.JSONDecodeError):
                    pass
            entries.append(
                {
                    "report": str(aj),
                    "repo_dir": str(aj.parent),
                    "base": base,
                    # normalize-or-skip: a non-normalizable repository field
                    # must NEVER fall through raw to git (audit A2, plan
                    # P0.1). Dry run 2026-07-24: two reports affected
                    # (one scheme-less repo; self-heals on re-audit).
                    "repository": normalize_repo_url(meta.get("repository")),
                    "pinned_sha": (parse_pinned_sha(meta.get("commit")) or md_fallback_sha(aj)),
                    "findings": sum(counts.values()),
                    "criticals": counts.get("critical", 0),
                    "highs": counts.get("high", 0),
                    "ledger_signal_events": (
                        ledger_remediation_events(layer) if layer.exists() else 0
                    ),
                    "verification_exists": verification.exists(),
                    "verified_patched_sha": verified_patched,
                }
            )
    return entries


def classify(e: dict) -> str:
    """Queue tier or skip reason for one discovered entry."""
    if e["verification_exists"]:
        return "skip:already_verified"
    if not e["repository"]:
        return "skip:no_repo_url"
    if e["head_sha"] is None and e["network"]:
        return "skip:unreachable"
    drifted = (
        e["head_sha"] is not None
        and e["pinned_sha"] is not None
        and not e["head_sha"].startswith(e["pinned_sha"])
        and not e["pinned_sha"].startswith(e["head_sha"])
    )
    unknown_drift = e["head_sha"] is None or e["pinned_sha"] is None
    if e["ledger_signal_events"] > 0:
        return "T1"
    if not drifted and not unknown_drift:
        return "skip:head_unchanged"
    if e["criticals"] > 0:
        return "T2"
    if e["highs"] > 0:
        return "T3"
    return "T4"


def covered_shas_by_url(entries: list[dict]) -> dict[str, set[str]]:
    """URL → patched SHAs of every existing verification report for that
    repo across ALL product filing dirs. A queued sibling whose live HEAD
    matches one of these is already adjudicated — verifying it again would
    re-do hours-old work, and the sweep's own ledger fan-out events would
    otherwise re-queue it as T1 forever (the treadmill feedback loop)."""
    by_url: dict[str, set[str]] = {}
    for e in entries:
        if e["repository"] and e.get("verified_patched_sha"):
            by_url.setdefault(e["repository"], set()).add(e["verified_patched_sha"])
    return by_url


def render_md(doc: dict) -> str:
    s = doc["summary"]
    lines = [
        "# /verify-remediation full-sweep worklist",
        "",
        f"Generated {doc['metadata']['generated_at']} · "
        f"{s['reports_scanned']:,} canonical reports scanned · "
        f"network {'ON' if doc['metadata']['network'] else 'OFF'}",
        "",
        "| Tier | Meaning | Repos | Criticals | Highs |",
        "|---|---|---:|---:|---:|",
    ]
    tier_names = {
        "T1": "ledger remediation signal",
        "T2": "HEAD drifted, ≥1 critical",
        "T3": "HEAD drifted, ≥1 high",
        "T4": "HEAD drifted, other",
    }
    for t in TIERS:
        rows = [e for e in doc["worklist"] if e["tier"] == t]
        lines.append(
            f"| {t} | {tier_names[t]} | {len(rows):,} "
            f"| {sum(e['criticals'] for e in rows):,} "
            f"| {sum(e['highs'] for e in rows):,} |"
        )
    non_active = [
        e
        for e in doc["worklist"]
        if not str(e.get("repo_status", "")).startswith(("active", "unknown"))
    ]
    lines += [
        "",
        f"Skipped: {s['skipped']['head_unchanged']:,} unchanged HEAD · "
        f"{s['skipped']['already_verified']:,} already verified · "
        f"{s['skipped'].get('covered_elsewhere', 0):,} covered by a "
        f"same-repo verification at the current HEAD · "
        f"{s['skipped']['unreachable']:,} unreachable · "
        f"{s['skipped']['no_repo_url']:,} no repo URL "
        f"(per-report skip reasons: `skipped[]` in the JSON)",
        "",
        f"Repo liveness: {len(non_active)} queued repo(s) are "
        f"non-active (archived/moved/missing) — verify with the "
        f"distinct archived-component disposition, not eternal "
        f"`unresolved`."
        if non_active
        else "Repo liveness: all queued repos active (or artifact absent).",
        "",
        "## Queue (tier, then criticals desc)",
        "",
        "| Tier | Repo dir | Repository | Pinned | HEAD | Crit | High | Ledger events |",
        "|---|---|---|---|---|---:|---:|---:|",
    ]
    for e in doc["worklist"]:
        lines.append(
            f"| {e['tier']} | `{e['repo_dir']}` | {e['repository']} "
            f"| `{(e['pinned_sha'] or '?')[:9]}` | `{(e['head_sha'] or '?')[:9]}` "
            f"| {e['criticals']} | {e['highs']} | {e['ledger_signal_events']} |"
        )
    lines.append("")
    return "\n".join(lines)


def load_liveness(tracker_dir: Path) -> dict[str, str]:
    """URL → status from the census-owned repo-liveness artifact
    (progress-tracker metrics). Empty when absent — annotation degrades
    to 'unknown', it never blocks the sweep."""
    artifact = tracker_dir / "metrics" / "repo-liveness.json"
    if not artifact.is_file():
        return {}
    try:
        repos = json.loads(artifact.read_text()).get("repos", {})
    except (OSError, json.JSONDecodeError):
        return {}
    return {url: e.get("status", "unknown") for url, e in repos.items()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results dir (default: sibling of the harness)",
    )
    ap.add_argument(
        "--roots",
        nargs="*",
        type=Path,
        default=None,
        help="findings trees to scan (default: <results-root>/findings)",
    )
    ap.add_argument(
        "--include-branches", action="store_true", help="also queue release-branch (__…) reports"
    )
    ap.add_argument(
        "--no-network",
        action="store_true",
        help="skip git ls-remote — drift becomes 'unknown', so every "
        "unverified repo with a URL is queued",
    )
    ap.add_argument(
        "--force", action="store_true", help="queue repos even when a verification report exists"
    )
    ap.add_argument("--max-workers", type=int, default=16)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output JSON (default: <results-root>/findings/_manifest/"
        "verify-sweep-worklist.json; .md written beside it)",
    )
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    results_root = resolve_results_root(args)
    roots = args.roots or [results_root / "findings"]
    out = args.out or (results_root / "findings" / "_manifest" / "verify-sweep-worklist.json")

    entries = discover(roots, args.include_branches)
    print(f"[+] scanned {len(entries)} canonical reports", file=sys.stderr)
    if args.force:
        for e in entries:
            e["verification_exists"] = False

    network = not args.no_network
    urls = sorted(
        {e["repository"] for e in entries if e["repository"] and not e["verification_exists"]}
    )
    heads: dict[str, str | None] = {}
    if network and urls:
        print(
            f"[+] ls-remote over {len(urls)} unique repos ({args.max_workers} workers) …",
            file=sys.stderr,
        )
        with concurrent.futures.ThreadPoolExecutor(args.max_workers) as ex:
            for url, head in zip(urls, ex.map(ls_remote_head, urls), strict=False):
                heads[url] = head

    liveness = load_liveness(progress_tracker_dir(engine))
    covered = covered_shas_by_url(entries)
    for e in entries:
        e["network"] = network
        e["head_sha"] = heads.get(e["repository"]) if network else None
        tier = classify(e)
        e["tier"] = tier if tier in TIERS else None
        e["skip_reason"] = None if tier in TIERS else tier.removeprefix("skip:")
        # Same-URL covered@HEAD: a sibling filing of a repo whose canonical
        # verification already pins the current HEAD needs fan-out at most,
        # never a fresh run (--force still queues it).
        if (
            e["tier"]
            and not args.force
            and e["head_sha"]
            and any(
                e["head_sha"].startswith(sha) or sha.startswith(e["head_sha"])
                for sha in covered.get(e["repository"] or "", ())
            )
        ):
            e["tier"] = None
            e["skip_reason"] = "covered_elsewhere"
        e.pop("network")
        e.pop("verified_patched_sha", None)  # internal to the covered check
        # Phase 7 (metrics-improvement plan): liveness annotates, never
        # skips — archived-but-shipping findings need a distinct
        # disposition, not silent eternal re-verification.
        e["repo_status"] = (
            liveness.get(e["repository"] or "", "unknown: not in liveness artifact")
            if liveness
            else "unknown: no liveness artifact"
        )

    worklist = sorted(
        (e for e in entries if e["tier"]),
        key=lambda e: (TIERS.index(e["tier"]), -e["criticals"], -e["highs"]),
    )
    # One verification per repository: when the same repo has canonical
    # reports under several products, keep the highest-priority entry and
    # record the siblings so their trees can share the verification result.
    by_url: dict[str, dict] = {}
    deduped = []
    for e in worklist:
        prev = by_url.get(e["repository"])
        if prev is None:
            by_url[e["repository"]] = e
            e["duplicate_report_dirs"] = []
            deduped.append(e)
        else:
            prev["duplicate_report_dirs"].append(e["repo_dir"])
    worklist = deduped
    skipped = collections.Counter(e["skip_reason"] for e in entries if e["skip_reason"])
    # Per-report skip rows so "why does this folder have no verification
    # report?" is answerable from the artifact, not by re-running discovery.
    skipped_reports = sorted(
        (
            {
                "report": e["report"],
                "repo_dir": e["repo_dir"],
                "repository": e["repository"],
                "skip_reason": e["skip_reason"],
            }
            for e in entries
            if e["skip_reason"]
        ),
        key=lambda r: (r["skip_reason"], r["repo_dir"]),
    )

    doc = {
        "metadata": {
            "artifact": "verify-remediation-sweep-worklist",
            "role": (
                "deterministic shortlist for /verify-remediation full-sweep "
                "— routes only, never authors a verification verdict"
            ),
            "generated_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "network": network,
            "roots": [str(r) for r in roots],
        },
        "summary": {
            "reports_scanned": len(entries),
            "queued": len(worklist),
            "by_tier": {t: sum(1 for e in worklist if e["tier"] == t) for t in TIERS},
            "skipped": {
                k: skipped.get(k, 0)
                for k in (
                    "head_unchanged",
                    "already_verified",
                    "covered_elsewhere",
                    "unreachable",
                    "no_repo_url",
                )
            },
        },
        "worklist": worklist,
        "skipped": skipped_reports,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    out.with_suffix(".md").write_text(render_md(doc), encoding="utf-8")

    print(f"[+] wrote {out} (+ .md)", file=sys.stderr)
    print(
        f"[+] queued {len(worklist)}: "
        + ", ".join(f"{t}={doc['summary']['by_tier'][t]}" for t in TIERS)
        + f" | skipped: {dict(skipped)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
