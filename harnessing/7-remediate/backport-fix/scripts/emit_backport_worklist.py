#!/usr/bin/env python3
"""
emit_backport_worklist.py — Advisory disposition worklist from a
*-backport-report.json.

One row per (successful branch × finding ref), suggesting the
`fix_in_progress` disposition: the backport patch exists but is not
merged or verified. This is a TERMINAL, human/agent-review artifact —
NOT disposition-ledger events. Ledger ingestion needs design work first:
canonical finding_ref join (backport refs are triage-file#id or CVE ids,
the layer requires audit finding ids), the canonical event_id formula
(which would collide across branches for the same finding), and the
layer event shape (source.actor, disposition.*).

Usage:
    python3 emit_backport_worklist.py \\
        --backport-report <repo>-backport-report.json \\
        [--output <repo>-backport-worklist.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def build_worklist(report: dict, report_path: str) -> dict:
    source_fix = report.get("source_fix", {})
    finding_refs = source_fix.get("finding_refs", [])
    fix_commit = source_fix.get("commit", "")
    source_branch = source_fix.get("branch", "")

    rows = []
    for branch_result in report.get("target_branches", []):
        # The report contract (traust-contracts v1) has exactly three statuses:
        # succeeded | failed | skipped. A branch whose fix did not land has no
        # patch to merge, so only `succeeded` can suggest fix_in_progress.
        if branch_result.get("status") != "succeeded":
            continue
        # "fix_in_progress" means a patch exists to merge. A successful run
        # whose collection found no candidate.patch has nothing to suggest —
        # claiming otherwise sent reviewers looking for a patch that is not
        # there.
        if not branch_result.get("has_patch"):
            continue
        branch = branch_result.get("branch", "")
        row = {
            "target_branch": branch,
            "finding_refs": finding_refs,
            "suggested_disposition": "fix_in_progress",
            "rationale": (
                f"Backport patch generated for {branch} "
                f"(source fix: {fix_commit[:10]} on {source_branch}). "
                "Pending merge and verification."
            ),
            "has_patch": branch_result.get("has_patch", False),
        }
        for key in ("backport_commit", "backport_branch", "patch_path"):
            if branch_result.get(key):
                row[key] = branch_result[key]
        rows.append(row)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_from": report_path,
        "repository": report.get("metadata", {}).get("repository", ""),
        "note": (
            "Advisory worklist, not ledger events — a human (or the "
            "track-findings agent, once a canonical-ref mapping exists) "
            "decides what enters the disposition ledger."
        ),
        "entries": rows,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Emit an advisory disposition worklist from a backport report."
    )
    parser.add_argument(
        "--backport-report", "-b", required=True, type=Path,
        help="Path to *-backport-report.json"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output path (default: <report>-backport-worklist.json "
             "beside the report)"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print without writing")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.backport_report.is_file():
        log.error("Backport report not found: %s", args.backport_report)
        sys.exit(1)

    with open(args.backport_report) as f:
        report = json.load(f)

    worklist = build_worklist(report, str(args.backport_report))
    log.info("Generated %d worklist entr(ies) from %s",
             len(worklist["entries"]), args.backport_report)

    if args.dry_run:
        print(json.dumps(worklist, indent=2))
        return

    if args.output is not None:
        output = args.output
    else:
        name = args.backport_report.name
        suffix = "-backport-report.json"
        if name.endswith(suffix):
            output = args.backport_report.with_name(
                name[:-len(suffix)] + "-backport-worklist.json"
            )
        else:
            output = args.backport_report.with_name(name + "-backport-worklist.json")
    if output.resolve() == args.backport_report.resolve():
        log.error("Refusing to overwrite the input report: %s", output)
        sys.exit(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(worklist, f, indent=2)
    log.info("Written: %s", output)

    def printable(s: str) -> str:
        # report-controlled strings: neutralize control chars before the tty
        return "".join(c if c.isprintable() else "?" for c in str(s))

    for row in worklist["entries"]:
        refs = ", ".join(printable(r) for r in row["finding_refs"])
        print(f"  {refs} → fix_in_progress on {printable(row['target_branch'])}")


if __name__ == "__main__":
    main()
