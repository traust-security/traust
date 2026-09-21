"""Gate: `locations[].path` must identify an artifact, not the whole repo.

Why a gate and not only a schema rule: a finding's ledger identity is
`repo | sorted canonical paths | primary CWE`, so a location of `.` or `/`
canonicalizes to empty and collapses identity to `(repo, '', cwe)`. Measured
2026-08-18 across the corpus: **hundreds of fingerprints were each shared by
several findings** — "no SECURITY.md" and "not onboarded to OpenSSF
Scorecard" in one repo were the
same finding as far as the ledger could tell, so a disposition on one silently
covered the other.

Three layers enforce this, because each fails alone (P0.1 had the rule and only
checked presence: 606 forged stamps passed for months; `event.fingerprint` had the
code and no schema: every stamped layer failed validation):

1. `traust-contracts` declares the rule and the pseudo-path vocabulary.
2. `traust_ledger.identity.fingerprint(strict=True)` refuses at stamp time.
3. This gate catches reports whose producer skipped validation, before the
   values reach a ledger.

Staged like P0.4 -> P6: warnings today, `--strict` for the flip once the
migration lands. Run over a tree or a single report.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT_MARKERS = {".", "/", "./", "/./"}
MAX_PATH_LEN = 200
PROSE_LEN = 120

REPORT_GLOBS = (
    "*-security-audit.json",
    "*-cloud-config-audit.json",
    "*-container-audit.json",
)


def _reports(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    seen: set[str] = set()
    out: list[Path] = []
    for pattern in REPORT_GLOBS:
        for p in target.rglob(pattern):
            real = str(p.resolve())
            if real in seen:  # the findings tree carries gap-plan symlinks
                continue
            seen.add(real)
            out.append(p)
    return sorted(out)


def _violations(path: str) -> list[str]:
    kinds = []
    if path.strip() in REPO_ROOT_MARKERS:
        kinds.append("repo-root marker")
    if "\n" in path:
        kinds.append("contains a newline")
    if len(path) > MAX_PATH_LEN:
        kinds.append(f"longer than {MAX_PATH_LEN} chars")
    elif len(path) > PROSE_LEN:
        kinds.append(f"longer than {PROSE_LEN} chars (prose?)")
    return kinds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="a report, or a tree to walk")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on any violation (the post-migration flip)",
    )
    ap.add_argument("--quiet", action="store_true", help="counts only")
    args = ap.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"ERROR: {target} does not exist", file=sys.stderr)
        return 2

    counts: Counter[str] = Counter()
    offenders: list[tuple[str, str, str, str]] = []
    reports = _reports(target)
    for report in reports:
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            counts["unreadable report"] += 1
            continue
        for finding in data.get("findings") or []:
            for loc in finding.get("locations") or []:
                raw = loc.get("path")
                if not isinstance(raw, str):
                    continue
                for kind in _violations(raw):
                    counts[kind] += 1
                    offenders.append((str(report), finding.get("id", "?"), kind, raw[:70]))

    print(f"checked {len(reports)} report(s)")
    if not counts:
        print("✓ every location path names an artifact")
        return 0
    for kind, n in counts.most_common():
        print(f"  {kind:34} {n}")
    if not args.quiet:
        for rep, fid, kind, sample in offenders[:15]:
            print(f"    {Path(rep).name} / {fid}: {kind} — {sample!r}")
        if len(offenders) > 15:
            print(f"    … and {len(offenders) - 15} more")
    print(
        "\nA repo-root path collapses ledger identity to (repo, '', cwe). Name the "
        "artifact — an absent SECURITY.md is still 'SECURITY.md' — or use a "
        "pseudo-path from contracts enums/v1/repo-scope-path.json."
    )
    if args.strict:
        return 1
    print("(warning only: --strict is the post-migration flip)")
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "location-paths", *sys.argv[1:]]))
