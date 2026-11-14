#!/usr/bin/env python3
"""Write run_summary.json for a completed backport batch.

Each branch's status is its canonical verdict from `result.json`, which
run_backport.sh persists at collection time — never the engine's summary.json,
which can stay success-shaped after a nonzero exit. A missing or malformed
record becomes an explicit "unknown" and is counted as failed, so the file can
never disagree with the exit code or the emitted report.

The document is written with json.dump: branch names come from config
filenames (pipeline-controlled), and splicing them into JSON by hand let a
crafted name corrupt or forge the document.

Prints "total passed failed skipped" for the calling shell to reuse, so the
printed counts, the file and the exit status stay in agreement.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

PASSED = ("success", "passed")
SKIPPED = ("pipeline_stop",)


def verdict(branch_dir: Path) -> str:
    """Canonical outcome for one branch, or "unknown" when unreadable."""
    path = branch_dir / "result.json"
    if not path.is_file():
        return "unknown"
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return "unknown"
    outcome = record.get("outcome") if isinstance(record, dict) else None
    return outcome if isinstance(outcome, str) and outcome else "unknown"


def build(output_dir: Path, branches: list[str], image: str | None) -> dict:
    rows = [{"branch": name, "status": verdict(output_dir / name)}
            for name in branches]
    counts = {"total": len(rows), "passed": 0, "failed": 0, "skipped": 0}
    for row in rows:
        if row["status"] in PASSED:
            counts["passed"] += 1
        elif row["status"] in SKIPPED:
            counts["skipped"] += 1
        else:
            counts["failed"] += 1
    return {**counts, "container_image": image, "branches": rows}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write run_summary.json from the branches' canonical verdicts."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--container-image", default="")
    parser.add_argument("--branch", action="append", default=[])
    args = parser.parse_args()

    summary = build(args.output_dir, args.branch, args.container_image or None)
    (args.output_dir / "run_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(summary["total"], summary["passed"], summary["failed"],
          summary["skipped"])


if __name__ == "__main__":
    main()
