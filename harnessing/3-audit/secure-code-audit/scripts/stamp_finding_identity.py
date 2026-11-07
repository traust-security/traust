#!/usr/bin/env python3
"""Stamp the cross-scan finding identity on an audit report — the lane-portable
form of the skill's Step 2b.

The CLI door (``python3 -m traust.cli corpus finding-identity fingerprint
<report> --write``) is unreachable in the platform's headless worker lanes:
their permission profiles deny ``python3`` outright and execute python only
through the ``harness-run`` wrapper, which runs scripts under ``/harness``.
Meanwhile the worker stamps ``metadata.additional.harness_version`` on the
report after the agent session, and the contracts schema then REQUIRES
``fingerprint`` on every finding — so a report that skips this step validates
clean in-session and still dies at the platform gate with
``findings/N: 'fingerprint' is a required property`` (the scan-blocking
failure of the 2026-11-06 dev-cluster E2E bring-up; traust-foundry #10,
code fix 1).

This script is a thin wrapper over the SAME implementation the CLI door
calls — ``traust_engine._util.finding_identity.run_fingerprint`` — so there
is one recipe, deterministic and script-computed, never model-authored:

    fingerprint = sha256( canonical repo URL
                        | sorted lineless location paths
                        | primary CWE )

Usage (worker lanes):

    harness-run harnessing/3-audit/secure-code-audit/scripts/stamp_finding_identity.py <report.json>

Usage (interactive lanes):

    python3 harnessing/3-audit/secure-code-audit/scripts/stamp_finding_identity.py <report.json>

Pass ``--allow-identity-move`` only to re-stamp a report whose findings
already carry stamps minted earlier in the same session (locations or cwes
edited after the first stamp): an in-flight report has nothing referencing
its stamps yet. Recorded findings never get re-stamped through this door —
ledger events are keyed on these values, and moving one orphans its history.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_engine._util.finding_identity import IdentityMoved, run_fingerprint


def main(argv: list[str]) -> int:
    flags = [a for a in argv if a.startswith("-")]
    positional = [a for a in argv if not a.startswith("-")]
    unknown = [f for f in flags if f != "--allow-identity-move"]
    if len(positional) != 1 or unknown:
        print(
            "usage: stamp_finding_identity.py <report.json> [--allow-identity-move]",
            file=sys.stderr,
        )
        return 2
    allow_move = "--allow-identity-move" in flags
    report = Path(positional[0])
    if not report.is_file():
        print(f"stamp_finding_identity: not a file: {report}", file=sys.stderr)
        return 2
    try:
        return run_fingerprint(report, write=True, allow_identity_move=allow_move)
    except (OSError, json.JSONDecodeError) as error:
        print(f"stamp_finding_identity: cannot read {report}: {error}", file=sys.stderr)
        return 1
    except IdentityMoved as error:  # run_fingerprint normally catches this; belt
        print(f"{report}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
