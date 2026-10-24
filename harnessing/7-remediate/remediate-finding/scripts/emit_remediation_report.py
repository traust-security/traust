#!/usr/bin/env python3
"""
Assemble a ``*-remediation.json`` report from a prepared worktree.

Inputs:
  --prepared FILE        the work item, as `traust remediation prepare` printed it (required)
  --worktree DIR         git worktree containing the fix branch (required)
  --product SLUG         metadata.logical_product: the product this fix ships in (required)
  --out FILE             write JSON here (required); the diff goes beside it
  --checks FILE          JSON array of check objects (from run_checks.sh)
  --strategy S           patch.strategy enum value
  --rationale TEXT       patch.rationale (>= 50 chars)
  --behaviour TEXT       patch.behaviour_change
  --residual TEXT        patch.residual_risk
  --tests-added T[,T…]   regression tests added
  --status S             override summary.status (default derived from checks)

The script computes the diff, diffstat, files_changed and fix_commit, and
populates source_findings[] from the work item's findings (traust-core has no
door that assembles a worktree's diff). Validate with
``traust reporting validate --schema remediation.schema.json``, then record it
with ``traust remediation record``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Harness root: the directory holding VERSION, walked rather than counted.
# This was `HERE.parents[1]`, which resolved to `harnessing/` and so pointed one
# level too shallow — the C8 script-placement migration moved this file
# into scripts/ and the count was never updated.
HARNESS = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())
VERSION_FILE = HARNESS / "VERSION"


def sh(cwd: Path, *cmd: str) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def sh_ok(cwd: Path, *cmd: str) -> str:
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return r.stdout.strip()


def harness_version() -> str:
    ver = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.is_file() else "0.0.0"
    sha = sh_ok(HARNESS, "git", "rev-parse", "--short", "HEAD")
    return f"{ver}-{sha}" if sha else ver


def _lines(loc: dict) -> str:
    return f"{loc['line_start']}-{loc['line_end'] or loc['line_start']}"


def build_source_findings(prepared: dict) -> list[dict]:
    out = []
    for item in prepared["items"]:
        view = item["finding"]
        locations = [
            {"path": loc["path"], "lines": _lines(loc)}
            if loc.get("line_start")
            else {"path": loc["path"]}
            for loc in view["locations"]
        ]
        out.append(
            {
                "finding_ref": view["finding"]["id"],
                "title": view["finding"]["title"],
                "severity": view["effective_severity"],
                "cwes": view["cwes"] or ["CWE-0"],  # schema requires >= 1; flag for human review
                "locations": locations or [{"path": "(unknown)"}],
                "validation_verdict": "not_validated",
            }
        )
    return out


def compute_patch(work: Path, base: str, out_dir: Path, rem_id: str) -> tuple[dict, str]:
    """Return (patch_block_without_strategy_rationale, fix_commit)."""
    fix_commit = sh_ok(work, "git", "rev-parse", "HEAD")
    diff = sh_ok(work, "git", "diff", base, "HEAD")
    if not diff:
        # include unstaged changes if nothing committed yet
        diff = sh_ok(work, "git", "diff")

    diff_path = out_dir / f"{rem_id}-patch.diff"
    diff_path.write_text(
        diff + ("\n" if diff and not diff.endswith("\n") else ""), encoding="utf-8"
    )
    diff_sha = hashlib.sha256(diff_path.read_bytes()).hexdigest()

    numstat = sh_ok(work, "git", "diff", "--numstat", base, "HEAD") or sh_ok(
        work, "git", "diff", "--numstat"
    )
    namestatus = sh_ok(work, "git", "diff", "--name-status", base, "HEAD") or sh_ok(
        work, "git", "diff", "--name-status"
    )

    status_map = {}
    for line in namestatus.splitlines():
        parts = line.split("\t")
        st = parts[0][:1]
        path = parts[-1]
        status_map[path] = {"A": "added", "D": "deleted", "R": "renamed"}.get(st, "modified")

    files_changed = []
    add_total = del_total = 0
    for line in numstat.splitlines():
        a, d, p = line.split("\t")
        a_i = int(a) if a.isdigit() else 0
        d_i = int(d) if d.isdigit() else 0
        add_total += a_i
        del_total += d_i
        files_changed.append(
            {
                "path": p,
                "change_type": status_map.get(p, "modified"),
                "additions": a_i,
                "deletions": d_i,
            }
        )
    if not files_changed:
        files_changed = [
            {"path": "(no changes)", "change_type": "modified", "additions": 0, "deletions": 0}
        ]

    patch = {
        "files_changed": files_changed,
        "diffstat": {
            "files": len(files_changed),
            "additions": add_total,
            "deletions": del_total,
        },
        "diff_path": diff_path.name,
        "diff_sha256": diff_sha,
    }
    return patch, fix_commit


def derive_status(checks: list[dict]) -> str:
    if not checks:
        return "patched"
    outcomes = {c.get("outcome") for c in checks}
    if "fail" in outcomes or "error" in outcomes:
        return "checks_failed"
    return "checks_passed"


def load_evidence(paths):
    """Typed patch evidence from --evidence files, in the order given.

    Accepts one item per file or an array per file. Deliberately does not
    validate or normalise: `reporting validate` checks the report against the
    schema immediately afterwards, and a second opinion here would only drift
    from it.
    """
    if not paths:
        return []
    items = []
    for p in paths:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        items.extend(doc if isinstance(doc, list) else [doc])
    return items


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prepared", required=True, type=Path)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--product", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--checks", type=Path)
    ap.add_argument("--strategy", default="other")
    ap.add_argument("--rationale", required=True)
    ap.add_argument("--behaviour", default="none")
    ap.add_argument("--residual", default="")
    ap.add_argument("--tests-added", default="")
    ap.add_argument(
        "--evidence",
        type=Path,
        action="append",
        default=None,
        help="path to a JSON file holding one patch_evidence item, or an array of "
        "them (repeatable). Typed base-versus-patch evidence; see "
        "remediation.schema.json#/$defs/patch_evidence. Items are passed through "
        "verbatim — the schema, not this script, decides whether a claim of "
        "proof carried both observations.",
    )
    ap.add_argument("--status")
    args = ap.parse_args(argv)

    prepared = json.loads(args.prepared.read_text(encoding="utf-8"))
    subject, item, fork = prepared["subject"], prepared["work_item"], prepared["fork"]
    out_path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    base = subject["sha"]
    patch_block, fix_commit = compute_patch(
        args.worktree, base, out_path.parent, item["work_item_id"]
    )
    patch_block["strategy"] = args.strategy
    patch_block["rationale"] = args.rationale
    patch_block["behaviour_change"] = args.behaviour
    if args.residual:
        patch_block["residual_risk"] = args.residual
    if args.tests_added:
        patch_block["tests_added"] = [t.strip() for t in args.tests_added.split(",") if t.strip()]

    checks = json.loads(args.checks.read_text(encoding="utf-8")) if args.checks else []
    if not checks:
        checks = [{"name": "none", "command": "(no checks run)", "outcome": "skip"}]

    status = args.status or derive_status(checks)
    passed = sum(1 for c in checks if c.get("outcome") == "pass")

    fork_block = {
        "url": f"https://{fork['url']['host']}/{fork['url']['path']}",
        "host": fork["host"],
        "visibility": fork["visibility"],
        "upstream_remote": subject["repository_url"],
        "base_ref": base,
        "base_commit": base,
        "fix_branch": prepared["fix_branch"],
    }
    if re.fullmatch(r"[0-9a-f]{7,40}", fix_commit or ""):
        fork_block["fix_commit"] = fix_commit

    meta = {
        "date": dt.date.today().isoformat(),
        "harness_version": harness_version(),
        "logical_product": args.product,
        "repository": subject["repository_url"],
        "audited_commit": base,
    }
    if item.get("tracker") and item["tracker"]["system"] == "jira":
        meta["jira_keys"] = [item["tracker"]["ref"]]

    findings = build_source_findings(prepared)
    repo_name = subject["repository_url"].rstrip("/").rsplit("/", 1)[-1]
    report = {
        "title": f"{repo_name} — automated remediation for {findings[0]['title']}",
        "metadata": meta,
        "source_findings": findings,
        "fork": fork_block,
        "patch": patch_block,
        "checks": checks,
        "summary": {
            "status": status,
            "checks_passed": passed,
            "checks_total": len(checks),
            "findings_addressed": len(findings),
            "ready_for_review": status in ("checks_passed", "revalidated_fixed", "pr_opened"),
        },
    }

    evidence = load_evidence(args.evidence)
    if evidence:
        report["evidence"] = evidence

    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
