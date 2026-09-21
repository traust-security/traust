#!/usr/bin/env python3
"""
Build ``analysis-results/remediations/_manifest/remediation-manifest.csv``.

One row per **candidate finding** to remediate. A finding is a candidate
when it has ``verdict == true_positive`` in its ``*-triage.json``. Rows are
enriched with:

  * the upstream repo URL + audited commit (from ``triage_context.repo``)
  * the private fork URL + fix-branch name (from ``fork_map``)
  * the live-validation verdict (from the most recent
    ``analysis-results/validations/<slug>*/...-validation.json``)
  * any Jira key mentioned in ``progress-tracker/opened-tickets.md``
  * the audit-report ``remediation`` text and CWEs

Filters:
  --product <name>     Only this logical product / triage directory name.
  --confirmed-only     Only findings whose live-validation verdict is
                       ``confirmed`` (recommended for the pilot).
  --min-confidence N   Drop findings with triage confidence < N.
  --severity S[,S…]    Only these severities (default: critical,high,medium).

Existing rows are merged on ``rem_id`` so campaign state (status, fix_commit,
pr_url, …) survives a rebuild — same pattern as build_validation_manifest.py.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)

HERE = Path(__file__).resolve().parent

import fork_map  # noqa: E402
from traust_engine.escaping import csv_cell  # noqa: E402


@dataclass
class _ManifestPaths:
    workspace: Path
    analysis: Path
    findings: Path
    validations: Path
    rem_dir: Path
    manifest: Path
    tickets: Path


_paths: _ManifestPaths | None = None


def _resolve_paths(args) -> _ManifestPaths:
    global _paths
    engine = load_engine(args.config_home)
    workspace = workspace_dir(engine)
    analysis = resolve_results_root(args)
    _paths = _ManifestPaths(
        workspace=workspace,
        analysis=analysis,
        findings=analysis / "findings",
        validations=analysis / "validations",
        rem_dir=analysis / "remediations",
        manifest=analysis / "remediations" / "_manifest" / "remediation-manifest.csv",
        tickets=progress_tracker_dir(engine) / "tracking" / "opened-tickets.md",
    )
    fork_map.configure_paths(analysis)
    return _paths


COLUMNS = [
    "rem_id",  # <repo>.<finding_id>  (stable join key)
    "logical_product",
    "repo_name",
    "upstream_url",
    "audited_commit",
    "fork_url",
    "fix_branch",
    "finding_id",  # triage id (fNNN)
    "audit_finding_id",  # source audit id (FIND-NNN) parsed from triage 'source'
    "title",
    "severity",
    "confidence",
    "cwes",
    "file",
    "line",
    "remediation_hint",
    "validation_verdict",
    "validation_report",
    "jira_key",
    "triage_path",
    "audit_path",
    # mutable campaign state — preserved across rebuilds
    "status",
    "fix_commit",
    "pr_url",
    "started",
    "completed",
    "report_path",
]

DEFAULT_SEVERITIES = {"critical", "high", "medium"}

REPO_RE = re.compile(
    r"^(?:https?://)?(?:github\.com/|gitlab[^/]*/)?"
    r"(?P<org>[^/@\s]+)/(?P<repo>[^/@\s]+?)(?:\.git)?@(?P<sha>[0-9a-fA-F]{7,40}|HEAD)$"
)
SOURCE_RE = re.compile(r"#(?P<id>[A-Za-z0-9._-]+)$")
# finding ids are report-derived and become path components in
# report_path — must never carry separators or dot-runs (audit B1, plan
# P0.2). Dry run 2026-07-24: zero corpus ids rejected.
FID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# ---------------------------------------------------------------------------
# loaders
# ---------------------------------------------------------------------------
def load_existing(paths: _ManifestPaths) -> dict[str, dict]:
    if not paths.manifest.is_file():
        return {}
    with paths.manifest.open(newline="", encoding="utf-8") as f:
        return {r["rem_id"]: r for r in csv.DictReader(f)}


def load_jira_index(paths: _ManifestPaths) -> dict[str, str]:
    """Map repo-name → first Jira key mentioned in opened-tickets.md."""
    out: dict[str, str] = {}
    if not paths.tickets.is_file():
        # warn, never swallow: a missing tickets file means every manifest
        # row silently loses its jira_key column otherwise
        print(
            f"[manifest] WARN: {paths.tickets} not found — manifest rows will carry no Jira keys",
            file=sys.stderr,
        )
        return out
    txt = paths.tickets.read_text(encoding="utf-8")
    # rows look like: | n | KEY-123 | FIND-001 | org/repo | … |
    for m in re.finditer(r"\|\s*\d+\s*\|\s*([A-Z][A-Z0-9]+-\d+)\s*\|[^|]*\|\s*([^|]+?)\s*\|", txt):
        key, repo = m.group(1), m.group(2).strip()
        repo_name = repo.split("/")[-1]
        out.setdefault(repo_name, key)
    return out


def find_triage_files(paths: _ManifestPaths, product: str | None) -> list[Path]:
    roots = [
        paths.findings,
        paths.analysis / "ecoengg-findings",
        paths.analysis / "oss-findings",
        paths.analysis / "OpenStack-k8s-ops",
    ]
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*-triage.json"):
            if p.is_symlink():
                continue
            if product and product not in p.parts and product not in p.name:
                continue
            out.append(p)
    return sorted(out)


def latest_validation(paths: _ManifestPaths, slug: str) -> Path | None:
    """Return the most recent <slug>-validation.json under validations/<slug>*."""
    cands: list[Path] = []
    for d in paths.validations.glob(f"{slug}*"):
        if not d.is_dir() or d.name == "_manifest":
            continue
        cands.extend(d.glob("*-validation.json"))
    if not cands:
        return None

    # Prefer .vNNN suffixed dirs (later versions); fall back to mtime.
    def key(p: Path):
        m = re.search(r"\.v(\d+)", p.parent.name)
        return (int(m.group(1)) if m else -1, p.stat().st_mtime)

    return sorted(cands, key=key)[-1]


def load_validation_verdicts(vpath: Path) -> dict[str, str]:
    """finding_id (audit or triage) → verdict."""
    out: dict[str, str] = {}
    try:
        d = json.loads(vpath.read_text(encoding="utf-8"))
    except Exception:
        return out
    for f in d.get("validated_findings", d.get("findings", [])):
        verdict = str(f.get("verdict", "")).lower()
        for k in ("source_id", "finding_id", "id", "finding_ref"):
            if v := f.get(k):
                out[str(v)] = verdict
                # also index the bare id after a '#'
                if "#" in str(v):
                    out[str(v).split("#")[-1]] = verdict
        # title fallback for validations that dropped IDs
        if t := f.get("title"):
            out.setdefault(_norm_title(t), verdict)
    return out


def _norm_title(t: str) -> str:
    return re.sub(r"\W+", "", t).lower()[:80]


def load_audit_remediation(audit_path: Path) -> dict[str, dict]:
    """audit FIND-id → {remediation, cwes, severity}."""
    out: dict[str, dict] = {}
    if not audit_path.is_file():
        return out
    try:
        d = json.loads(audit_path.read_text(encoding="utf-8"))
    except Exception:
        return out
    for f in d.get("findings", []):
        out[str(f.get("id", ""))] = {
            "remediation": f.get("remediation", ""),
            "cwes": f.get("cwes", []),
            "severity": str(f.get("severity", "")).lower(),
        }
    return out


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def build_rows(args, paths: _ManifestPaths) -> list[dict]:
    prev = load_existing(paths)
    jira = load_jira_index(paths)
    rows: list[dict] = []
    sev_filter = set(args.severity)

    for tpath in find_triage_files(paths, args.product):
        try:
            triage = json.loads(tpath.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"WARN: cannot parse {tpath}: {e}", file=sys.stderr)
            continue
        ctx = triage.get("triage_context", {})
        repo_spec = ctx.get("repo", "")
        m = REPO_RE.match(repo_spec)
        if not m:
            continue
        org, repo, sha = m["org"], m["repo"], m["sha"]
        upstream = f"https://github.com/{org}/{repo}"
        try:
            fork = fork_map.resolve(upstream)
        except KeyError:
            fork = None

        # logical product = first dir under FINDINGS root, else repo name
        try:
            rel = tpath.relative_to(paths.findings)
            logical = rel.parts[0]
        except ValueError:
            logical = repo

        audit_path = tpath.with_name(tpath.name.replace("-triage.json", "-security-audit.json"))
        audit_idx = load_audit_remediation(audit_path)

        vpath = latest_validation(paths, logical)
        verdicts = load_validation_verdicts(vpath) if vpath else {}

        for f in triage.get("findings", []):
            if f.get("verdict") != "true_positive":
                continue
            sev = str(f.get("severity", "")).lower()
            if sev not in sev_filter:
                continue
            conf = f.get("confidence")
            if args.min_confidence and conf is not None and float(conf) < args.min_confidence:
                continue

            fid = str(f.get("id", ""))
            if not FID_RE.fullmatch(fid) or ".." in fid:
                print(f"skip: unsafe finding id {fid!r} in {tpath}", file=sys.stderr)
                continue
            src = f.get("source", "")
            audit_id = SOURCE_RE.search(src).group("id") if SOURCE_RE.search(src) else ""
            ai = audit_idx.get(audit_id, {})

            # validation verdict lookup — try several keys then title
            vverdict = ""
            for k in (audit_id, fid, src, f.get("title", "")):
                if k and (vv := verdicts.get(k) or verdicts.get(_norm_title(k))):
                    vverdict = vv
                    break
            if args.confirmed_only and vverdict != "confirmed":
                continue

            rem_id = f"{repo}.{fid}"
            cwes = ai.get("cwes") or []
            row = {
                "rem_id": rem_id,
                "logical_product": logical,
                "repo_name": repo,
                "upstream_url": upstream,
                "audited_commit": sha,
                "fork_url": fork.fork_url if fork else "",
                "fix_branch": fork.fix_branch(fid, _slug(f.get("title", ""))) if fork else "",
                "finding_id": fid,
                "audit_finding_id": audit_id,
                "title": f.get("title", ""),
                "severity": sev,
                "confidence": conf if conf is not None else "",
                "cwes": ";".join(cwes),
                "file": f.get("file", ""),
                "line": f.get("line", ""),
                "remediation_hint": _one_line(ai.get("remediation", "")),
                "validation_verdict": vverdict or "not_validated",
                "validation_report": str(vpath.relative_to(paths.workspace)) if vpath else "",
                "jira_key": jira.get(repo, ""),
                "triage_path": str(tpath.relative_to(paths.workspace)),
                "audit_path": (
                    str(audit_path.relative_to(paths.workspace)) if audit_path.is_file() else ""
                ),
                "status": "candidate",
                "fix_commit": "",
                "pr_url": "",
                "started": "",
                "completed": "",
                "report_path": (
                    f"analysis-results/remediations/{logical}/{repo}/{rem_id}-remediation.json"
                ),
            }
            if old := prev.get(rem_id):
                for k in ("status", "fix_commit", "pr_url", "started", "completed"):
                    if old.get(k):
                        row[k] = old[k]
            rows.append(row)

    # Stable order: validation-confirmed first, then severity, then confidence.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(
        key=lambda r: (
            0 if r["validation_verdict"] == "confirmed" else 1,
            sev_rank.get(r["severity"], 9),
            -float(r["confidence"] or 0),
            r["rem_id"],
        )
    )
    return rows


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40]


def _one_line(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()[:300]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--product", help="Limit to one logical product / directory name")
    ap.add_argument(
        "--confirmed-only",
        action="store_true",
        help="Only findings with live-validation verdict 'confirmed'",
    )
    ap.add_argument("--min-confidence", type=float, default=0.0)
    ap.add_argument(
        "--severity",
        default="critical,high,medium",
        type=lambda s: [x.strip().lower() for x in s.split(",")],
    )
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    paths = _resolve_paths(args)
    out = Path(args.out) if args.out else paths.manifest

    rows = build_rows(args, paths)
    out.parent.mkdir(parents=True, exist_ok=True)
    with Path.open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        # finding titles are quoted from audited repos; a leading =/@/+
        # is a live formula the moment the manifest opens in Sheets
        # (CWE-1236; escaping library, assessment root-cause 4)
        w.writerows(
            [{k: csv_cell(v) if isinstance(v, str) else v for k, v in r.items()} for r in rows]
        )

    by_v = {}
    for r in rows:
        by_v[r["validation_verdict"]] = by_v.get(r["validation_verdict"], 0) + 1
    print(f"wrote {out.relative_to(paths.workspace)}: {len(rows)} candidate(s)")
    for v, n in sorted(by_v.items()):
        print(f"  {v:>15}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
