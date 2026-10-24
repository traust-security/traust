#!/usr/bin/env python3
"""Turn a base-vs-patched property-test differential into one evidence item.

Emits to stdout a single object matching
remediation.schema.json#/$defs/patch_evidence (kind: property).

The verdict rests on one asymmetry, which is the whole reason a property test
is evidence about a *fix* rather than just a good test:

    base FAILS, patched PASSES  -> proves
    base FAILS, patched FAILS   -> fails_to_prove   (fix incomplete)
    base PASSES                 -> fails_to_prove   (property does not
                                                     witness this finding)

That last case is the one people get wrong. A property that already held
before the patch may be perfectly true and perfectly useless here: it tells
you nothing about whether this fix closed anything. Reporting it as proof
would be the exact overclaim the evidence contract exists to prevent.

pytest exit codes (documented in pytest's own `ExitCode` enum) distinguish
"tests ran and failed" from "nothing ran":

    0 passed | 1 failed | 2 interrupted | 3 internal error
    4 usage error | 5 no tests collected

Only 0 and 1 are verdict-bearing. Everything else means the differential did
not happen, and is reported as `not_attempted` rather than guessed at.
"""

from __future__ import annotations

import argparse
import json
import sys

KIND = "property"

PYTEST_PASSED = 0
PYTEST_FAILED = 1
PYTEST_NO_TESTS = 5
VERDICT_BEARING = (PYTEST_PASSED, PYTEST_FAILED)
TIMEOUT_RC = 124


def _not_attempted(item: dict, reason: str, step: str | None = None) -> dict:
    item["outcome"] = f"not_attempted: {reason}"
    item["deterministic_steps"] = f"skipped: {step or reason}"
    return item


def _describe(rc: int) -> str:
    return {
        PYTEST_PASSED: "passed",
        PYTEST_FAILED: "failed",
        2: "was interrupted",
        3: "hit an internal pytest error",
        4: "was a pytest usage error",
        PYTEST_NO_TESTS: "collected no tests",
        TIMEOUT_RC: "exceeded its timeout",
    }.get(rc, f"exited {rc}")


def build_item(
    *,
    test_path: str,
    base_ref: str,
    base_rc: int,
    patched_rc: int,
    tool_version: str,
    base_log: str,
    patched_log: str,
    boundary: str = "",
) -> dict:
    # Record which boundary produced the verdict: nested podman and a
    # platform-attested sandbox are not equally strong, and a reader of the
    # artifact cannot otherwise tell them apart.
    cmd = f"pytest {test_path}"
    if boundary:
        cmd += f"  [boundary: {boundary}]"
    item = {
        "kind": KIND,
        "tool": tool_version or "hypothesis",
        "command": cmd,
        "log_path": patched_log,
        "deterministic_steps": "ran",
    }

    if TIMEOUT_RC in (base_rc, patched_rc):
        return _not_attempted(item, "property run exceeded its timeout", "timeout")

    if base_rc == PYTEST_NO_TESTS or patched_rc == PYTEST_NO_TESTS:
        return _not_attempted(
            item,
            f"pytest collected no tests from {test_path} — the property was not "
            "injected into the base revision, or the path is wrong",
            "no tests collected",
        )

    for label, rc in (("base", base_rc), ("patched", patched_rc)):
        if rc not in VERDICT_BEARING:
            return _not_attempted(
                item,
                f"the {label} revision's run {_describe(rc)}, so there is no "
                "base-versus-patch comparison",
                f"{label} run {_describe(rc)}",
            )

    item["base_observation"] = (
        f"on the unpatched revision ({base_ref}) the property {_describe(base_rc)} "
        f"— log at {base_log}"
    )
    item["patched_observation"] = f"on the patched revision the property {_describe(patched_rc)}"

    if base_rc == PYTEST_FAILED and patched_rc == PYTEST_PASSED:
        item["outcome"] = "proves"
    elif base_rc == PYTEST_FAILED and patched_rc == PYTEST_FAILED:
        item["outcome"] = "fails_to_prove"
        item["patched_observation"] += " — the property still finds a counterexample"
    else:
        # base passed: whatever this property asserts, it held before the fix.
        item["outcome"] = "fails_to_prove"
        item["patched_observation"] += (
            " — but it also held before the patch, so it does not witness this finding"
        )
    return item


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--test-path", required=True)
    ap.add_argument("--base-ref", required=True)
    ap.add_argument("--base-rc", type=int, required=True)
    ap.add_argument("--patched-rc", type=int, required=True)
    ap.add_argument("--tool-version", default="")
    ap.add_argument("--base-log", default="")
    ap.add_argument("--patched-log", default="")
    ap.add_argument(
        "--boundary",
        default="",
        help="execution boundary the differential ran under "
        "(podman | attested:<label>), recorded in the evidence",
    )
    args = ap.parse_args(argv)

    print(
        json.dumps(
            build_item(
                test_path=args.test_path,
                base_ref=args.base_ref,
                base_rc=args.base_rc,
                patched_rc=args.patched_rc,
                tool_version=args.tool_version,
                base_log=args.base_log,
                patched_log=args.patched_log,
                boundary=args.boundary,
            )
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
