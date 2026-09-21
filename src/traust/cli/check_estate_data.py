#!/usr/bin/env python3
"""Estate-data guard: keep one deployment's numbers out of a public repo.

This repo is PUBLIC. Anything committed here is published, and unlike a
credential — which is rotated and forgotten — a corpus figure is a
permanent statement about the size, backlog and error rate of the
deployment that produced it. There is no rotating it back.

The failure this exists to stop is not malice and not carelessness about
secrets. It is an engineer writing an accurate, well-documented one-shot
script, recording in its docstring exactly what it measured and changed,
and committing it to the repo where every other script lives. Every
instinct there is correct except the destination.

TWO RULES, and they are different:

  1. A ONE-SHOT MIGRATION IS NOT PORTABLE.
     A migration moves ONE deployment's data from an old shape to a new
     one. An adopter installing today has no old shape — they start at
     the current schema — so there is nothing in it they can run. What
     IS portable is the mechanism it was written against (the schema,
     the recipe, the ledger format); that lives in contracts, ledger and
     engine and stays. The migration is the estate-specific APPLICATION
     of it, and belongs in the deployment's own repository.

     So `src/traust/migrations/` here is for migrations an ADOPTER runs
     — a schema upgrade path shipped with a release. If it names a date
     you measured, a count you observed, or a path only your tree has,
     it is not that.

  2. ESTATE FIGURES DO NOT BELONG IN A PUBLIC TREE.
     Large comma-formatted counts are the tell — a report total, a
     finding total, a review queue stated as "N of M pending".
     Individually harmless-looking, collectively a map of the
     deployment: its size, its backlog, and its error rate.

     This docstring deliberately carries no real example. The first
     draft illustrated the rule with three actual figures from the
     estate, and this gate caught its own author on the commit that
     introduced it.

MOVE, DO NOT SCRUB. When a file is estate-specific, relocating it to the
private repository is the whole fix — the numbers travel with it and
stay useful as the record of what the script did. Scrubbing is only for
content that must REMAIN public. Doing both is wasted work, and it
throws away the evidence.

Scans only files git tracks, and only in a repo that is public: an
internal deployment repo may hold whatever its operators need.

Usage:
    python3 -m traust.cli check estate-data [--json OUT] [--quiet]
Exit 0 when clean, 1 on any finding.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

#: A comma-grouped number of four digits or more. Deliberately narrow:
#: years, versions, CWE ids, ports and byte sizes do not carry a comma,
#: and a figure this shape in prose is almost always a measurement.
COUNT_RE = re.compile(r"(?<![{,\d])\b\d{1,3}(?:,\d{3})+\b(?![,\d}])")

#: A regex quantifier — `{36,255}`, `{10,250}` — is not a measurement.
#: Matched and discarded rather than narrowed into COUNT_RE, because the
#: bound can legitimately be four digits.
QUANTIFIER_RE = re.compile(r"\{\d+,\d+\}")

#: A multi-line source reference — `oauthproxy.go:525,685`,
#: `login.go:127,157`. The comma separates two LINE NUMBERS in one file,
#: which is the most useful thing a finding can cite, and it carries no
#: information about the estate at all. Discarded like a quantifier
#: rather than narrowed into COUNT_RE, because a line number four digits
#: long is ordinary.
SOURCE_LINE_REF_RE = re.compile(r"\.\w+:\d+(?:,\d+)+")

#: A CONFIGURED THRESHOLD, not a measurement: `C >= 8,000`, `C ≥ 8,000`.
#: The distinction is the whole point of this gate — a measurement says
#: what this deployment IS, a threshold says what the policy DOES, and
#: only the first is a disclosure. The tell is a bare symbol and a
#: COMPARISON operator immediately before the number; prose stating a
#: figure does not look like that. Bare `=` is deliberately excluded —
#: `X = 1,234` is an assignment (estate-data-ok: invented), and
#: silencing assignments would hide the most ordinary way a figure
#: gets hard-coded into a script.
THRESHOLD_RE = re.compile(r"\b[A-Z]\s*(?:>=|<=|[><≥≤])\s*\d{1,3}(?:,\d{3})+")

#: Currency. Requires a comma group or decimals so shell `$0` and JSON
#: `$defs` do not match; a bare `$5` is not the disclosure this guards.
#: Spend is estate data for the same reason a corpus count is -- it
#: states what one deployment costs, and there is nothing to rotate.
MONEY_RE = re.compile(r"[$£€]\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?|[$£€]\s?\d+\.\d{2}\b")

#: Paths whose contents are published verbatim and where a count-shaped
#: string is the point rather than a leak.
ALLOWED_DIRS = (
    "CHANGELOG.md",  # a release record states what changed, including counts
    # This gate's own tests must contain count-shaped strings to have
    # anything to assert on. Every figure in that file is invented, and
    # the file says so; exempting it is cheaper and more honest than 18
    # waiver comments that would all cite the same reason.
    "tests/test_check_estate_data.py",
)

#: Files may opt out with a cited reason on the same line.
WAIVER_RE = re.compile(r"estate-data-ok:\s*(\S.*)")

#: Paths where a one-shot's fingerprints are expected and reviewed.
SKIP_SUFFIXES = (".lock", ".svg", ".png", ".jpg", ".gz", ".db", ".ipynb")


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [root / p for p in out if not p.endswith(SKIP_SUFFIXES)]


def is_public(root: Path) -> bool | None:
    """True/False from the forge, None when it cannot be determined.

    Fail CLOSED on None: a repo whose visibility is unknown is treated as
    public, because the cost of being wrong in that direction is a
    publication and in the other direction is a false alarm.
    """
    try:
        url = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return None
    slug = re.sub(r"^.*github\.com[:/]", "", url).removesuffix(".git")
    try:
        result = subprocess.run(
            ["gh", "repo", "view", slug, "--json", "visibility"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)["visibility"] == "PUBLIC"
    except (json.JSONDecodeError, KeyError):
        return None


def staged_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [root / p for p in out if not p.endswith(SKIP_SUFFIXES)]


def scan(root: Path, *, staged: bool = False) -> list[dict]:
    """Findings in the tree, or only in what is being committed.

    `staged` is how this becomes enforceable immediately. A public repo
    that already carries estate figures cannot adopt a whole-tree gate
    without blocking every commit, and a gate people bypass is not a
    gate. Blocking what is ADDED stops the bleeding on day one; the
    existing debt is a separate, reviewed burndown.
    """
    findings: list[dict] = []
    migrations = root / "src" / "traust" / "migrations"
    for path in (staged_files(root) if staged else tracked_files(root)):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWED_DIRS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if WAIVER_RE.search(line):
                continue
            probe = QUANTIFIER_RE.sub("", line)
            probe = SOURCE_LINE_REF_RE.sub("", probe)
            probe = THRESHOLD_RE.sub("", probe)
            for hit in COUNT_RE.findall(probe) + MONEY_RE.findall(probe):
                findings.append(
                    {
                        "file": rel,
                        "line": number,
                        "rule": "estate-count",
                        "match": hit,
                        "text": line.strip()[:120],
                    }
                )
    # Rule 1 is structural, not textual: a migration that no adopter can
    # run has no business in a published package, whatever it says.
    if migrations.is_dir():
        for path in sorted(migrations.glob("*.py")):
            if path.name == "__init__.py":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "adopter-portable" in text:
                continue
            findings.append(
                {
                    "file": path.relative_to(root).as_posix(),
                    "line": 1,
                    "rule": "unportable-migration",
                    "match": path.name,
                    "text": (
                        "a migration in a published package must be one an "
                        "ADOPTER can run; declare it with a docstring line "
                        "'adopter-portable: <why>' or move it to the "
                        "deployment's own repository"
                    ),
                }
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", nargs="?", default=".", type=Path)
    ap.add_argument("--json", dest="json_out", type=Path)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--staged",
        action="store_true",
        help="scan only staged files — the pre-commit mode",
    )
    ap.add_argument(
        "--assume-public",
        action="store_true",
        help="skip the forge lookup and scan regardless of visibility",
    )
    args = ap.parse_args(argv)
    root = args.repo.resolve()

    public = True if args.assume_public else is_public(root)
    if public is False:
        if not args.quiet:
            print("estate-data: repository is PRIVATE — nothing to guard")
        return 0
    if public is None and not args.quiet:
        print(
            "estate-data: visibility UNKNOWN — treating as public (fail-closed)",
            file=sys.stderr,
        )

    findings = scan(root, staged=args.staged)
    if args.json_out:
        args.json_out.write_text(
            json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8"
        )
    if not findings:
        if not args.quiet:
            print("✓ no estate data in the public tree")
        return 0

    by_rule: dict[str, list[dict]] = {}
    for finding in findings:
        by_rule.setdefault(finding["rule"], []).append(finding)

    print(f"\n✗ {len(findings)} estate-data finding(s) in a PUBLIC repo:\n", file=sys.stderr)
    for rule, group in sorted(by_rule.items()):
        print(f"  [{rule}] {len(group)}", file=sys.stderr)
        for finding in group[:20]:
            print(
                f"    {finding['file']}:{finding['line']}  {finding['text']}",
                file=sys.stderr,
            )
        if len(group) > 20:
            print(f"    … and {len(group) - 20} more", file=sys.stderr)
        print("", file=sys.stderr)
    print(
        "MOVE, do not scrub: if the file is specific to one deployment, "
        "relocate it to that deployment's private repository and the figures "
        "travel with it. Scrubbing is only for content that must stay public.\n"
        "A genuinely public figure takes an inline `estate-data-ok: <reason>`; "
        "a portable migration takes a docstring `adopter-portable: <why>`.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
