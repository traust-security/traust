#!/usr/bin/env python3
"""Compare a scanner's facts across two revisions and emit typed evidence.

This is the executable half of stage 8. `/verify-remediation` is otherwise a
targeted re-audit: it reads the original and patched code and reasons about
them, but executes nothing, which is why `docs/disposition-ledger.md` §8a caps
its evidence at "analysis, not execution". Re-running the backing scanner on
both revisions is cheap, deterministic, and lifts that cap for the one claim
it can actually support: *the pattern that evidenced this finding no longer
fires.*

Emits one object matching
remediation.schema.json#/$defs/patch_evidence (kind: scanner_differential),
carried on a verification report's `evidence[]` (contracts >= 0.4.0).

What the verdict means, and the limit that comes with it:

    fires on base, gone on patched  -> proves
    fires on both                   -> fails_to_prove
    does not fire on base           -> not_attempted

`proves` here is deliberately the weakest of the `proves` results. §8a's
wording is the authority: a cleared fact is not a correct fix — a diff can
silence a scanner by moving the sink. What this establishes is that the
*evidence the finding rested on* is gone, which is a real and checkable
claim, and nothing more.

The third row matters. If the rule does not fire on the unpatched revision
there is no differential to observe: either the finding was not
scanner-backed, or the rule pack has moved since the audit. Saying
`not_attempted` is honest; calling it `proves` because the patched scan is
clean would credit the patch for a fact that was never there.

Inputs are two adapter result files as written by
`python3 -m traust.cli adapters opengrep|checkov` — `report["facts"]`, each
fact carrying `rule_id`, `file`, `start_line` (traust_engine.adapters).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KIND = "scanner_differential"


def _not_attempted(item: dict, reason: str, step: str | None = None) -> dict:
    item["outcome"] = f"not_attempted: {reason}"
    item["deterministic_steps"] = f"skipped: {step or reason}"
    return item


def load_facts(path: str | Path) -> list[dict] | None:
    """`report["facts"]`, or None if the file is missing or unreadable."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    facts = doc.get("facts")
    return facts if isinstance(facts, list) else None


def select(facts: list[dict], rule_id: str | None, file: str | None) -> list[dict]:
    """Facts matching the selector.

    Line numbers are deliberately NOT part of the match: a patch moves lines,
    so matching on them would report every fact as cleared.
    """
    out = []
    for f in facts:
        if rule_id and f.get("rule_id") != rule_id:
            continue
        if file and f.get("file") != file:
            continue
        out.append(f)
    return out


def _describe(facts: list[dict]) -> str:
    if not facts:
        return "no matching fact"
    bits = []
    for f in facts[:3]:
        loc = f.get("file") or "?"
        line = f.get("start_line")
        bits.append(
            f"{f.get('rule_id', '?')} at {loc}:{line}"
            if line
            else f"{f.get('rule_id', '?')} in {loc}"
        )
    more = f" (+{len(facts) - 3} more)" if len(facts) > 3 else ""
    return "; ".join(bits) + more


def build_item(
    *,
    tool: str,
    rule_id: str | None,
    file: str | None,
    base_facts: list[dict] | None,
    patched_facts: list[dict] | None,
    base_ref: str,
    base_report: str,
    patched_report: str,
) -> dict:
    selector = rule_id or (f"any rule in {file}" if file else "any rule")
    item = {
        "kind": KIND,
        "tool": tool,
        "command": f"{tool} on {base_ref} vs the patched revision, selector: {selector}",
        "log_path": patched_report,
        "deterministic_steps": "ran",
    }

    if base_facts is None or patched_facts is None:
        which = "base" if base_facts is None else "patched"
        return _not_attempted(
            item,
            f"the {which} scan produced no readable facts list",
            f"{which} scan unreadable",
        )

    before = select(base_facts, rule_id, file)
    after = select(patched_facts, rule_id, file)

    if not before:
        return _not_attempted(
            item,
            f"{selector} does not fire on the unpatched revision, so there is no "
            "differential to observe — the finding may not be scanner-backed, or "
            "the rule pack has moved since the audit",
            "no backing fact on base",
        )

    item["base_observation"] = (
        f"on the unpatched revision ({base_ref}) the backing scanner reports "
        f"{len(before)} matching fact(s): {_describe(before)} — from {base_report}"
    )
    item["patched_observation"] = (
        f"on the patched revision it reports {len(after)} matching fact(s)"
        + (f": {_describe(after)}" if after else "")
    )

    if after:
        item["outcome"] = "fails_to_prove"
        item["patched_observation"] += " — the patch has not cleared its own backing evidence"
    else:
        item["outcome"] = "proves"
        # The ceiling, restated where a reader of the artifact will see it.
        item["patched_observation"] += (
            " — the pattern that evidenced this finding is gone; this does not "
            "establish the fix is correct or minimal"
        )
    return item


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--base-report", required=True, help="adapter result for the unpatched revision"
    )
    ap.add_argument(
        "--patched-report", required=True, help="adapter result for the patched revision"
    )
    ap.add_argument("--base-ref", required=True)
    ap.add_argument("--tool", default="opengrep")
    ap.add_argument("--rule-id", default=None, help="restrict to one rule (recommended)")
    ap.add_argument("--file", default=None, help="restrict to one path, as the adapter reports it")
    args = ap.parse_args(argv)

    if not args.rule_id and not args.file:
        ap.error(
            "give --rule-id and/or --file: an unrestricted differential "
            "answers a question nobody asked"
        )

    print(
        json.dumps(
            build_item(
                tool=args.tool,
                rule_id=args.rule_id,
                file=args.file,
                base_facts=load_facts(args.base_report),
                patched_facts=load_facts(args.patched_report),
                base_ref=args.base_ref,
                base_report=args.base_report,
                patched_report=args.patched_report,
            )
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
