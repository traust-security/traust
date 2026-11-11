"""``traust triage check``: lint a triage's verdict citations against the target checkout.

Every file:line a verdict cites must exist in the checkout and be in range. It routes, it never
concludes: ``re_vote`` for a dismissal resting on broken evidence, ``review`` for any other verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import TriageArtifact

from traust.context import add_config_home_arg, load


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="traust triage check", description=__doc__.splitlines()[0])
    ap.add_argument("triage", type=Path, help="the triage JSON (contracts triage schema)")
    ap.add_argument("--repo", type=Path, required=True, help="target repo checkout (read-only)")
    ap.add_argument("--json", action="store_true", help="print the violations as JSON")
    add_config_home_arg(ap)
    args = ap.parse_args(argv)
    if not args.repo.is_dir():
        print(f"ERROR: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    try:
        doc = TriageArtifact.parse(args.triage.read_bytes())
    except (OSError, ValidationError) as e:
        print(f"ERROR: {args.triage}: {e}", file=sys.stderr)
        return 2
    report = load(args.config_home).services().findings.decisions.check(doc, args.repo)
    if args.json:
        print(json.dumps([v.model_dump(mode="json") for v in report.violations], indent=2))
        return 0
    print(f"verdict citations: {len(report.violations)} broken")
    for v in report.violations:
        print(f"  {v.action:<8} {v.item}  {v.message}")
    return 0
