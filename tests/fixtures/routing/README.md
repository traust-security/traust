# Work-routing parity baseline

This is the legacy-baseline portion of
[XWING-2216](https://redhat.atlassian.net/browse/XWING-2216). It runs **302 named
cases against the checked-out Python worklist code**. It does not yet compare
the new `Router.route()` implementation with the legacy behavior.

## Run

From the repository root, after the normal `uv sync --locked` setup:

```bash
uv run --no-sync pytest -q tests/test_route_parity.py
```

Tests need no sibling SDK checkout, Git history, network, external command, or
production data. The primary adapter writes temporary JSONL events and a minimal
SQLite inventory graph. Network connections and subprocesses are blocked during
the test cases. The repository's normal `tests/conftest.py` setup still applies.

## What is preserved

- `python_decisions.json`: 93 decision-table and 20 risk-tier cases.
- `python_primary.json`: 30 event-lane and 159 primary-selection cases, including
  event precedence, consumed/unknown events, status handling, multiple decisions,
  original event indexes and never-audited inventory bootstrap.

Both files are copied byte for byte from the SDK. Their original `source` blocks
identify the Python revision and whole-file SHA-256 used to generate them;
**they have not been relabeled as outputs generated from current main**.
[baseline.json](baseline.json) records the SDK export revision, fixture checksums
and counts, plus the separately reviewed current legacy source checksum.

The reviewed current source differs from that original snapshot in two
threat-model reason strings (`--apply-ratings`). These cases disable threat-model
companions; all 302 expectations remain unchanged. The test adapter is derived
from `generate.py` and `generate_primary.py` in the SDK directory recorded in
the manifest. It compiles the actual checked-out legacy functions/constants and
the original `main()` block from `event_rows` up to `cc_urls`. It does not
reimplement the decision table or regenerate expected answers during tests.

The fixture keys retain their existing SDK spelling for provenance, not as a
proposed Python API. URLs are already canonical; URL normalization is an identity
stub, and the clock is fixed to the original generator's date. IaC/threat-model
companions, fleet ordering, tripwire/refusal handling, budgets, live collectors,
scheduling and dispatch are outside this corpus. It is not full-worklist parity.

## Reviewing drift

The tests check fixture bytes/counts and the **entire legacy source file** against
the manifest. This intentionally conservative check also catches unrelated edits
to that file. It makes source updates visible even if the existing examples still
pass. A mismatch fails with expected/actual hashes and this review procedure:

1. Review the source diff from `reviewed_legacy.revision`; run the named cases to
   see behavioral differences. Do not regenerate expectations to make a failure
   disappear.
2. For an unrelated change, keep both fixture files unchanged and record the new
   reviewed source revision/checksum and explanation in `baseline.json`.
3. For an intentional policy change, review the changed inputs/outputs and extend
   coverage as needed. Generate from an explicitly pinned source and update its
   provenance, fixture checksums/counts and reviewed-source record together. The
   original generators can be retrieved from the SDK export revision in the
   manifest. Merely updating a source checksum cannot hide a behavior mismatch:
   the individual comparisons still run against the fixed expectations.

## Remaining work for XWING-2216

- Add the new-router side after the implementation in XWING-2215 is available.
- Agree how to map this corpus to the new interface: the current core `Route`
  has lane, priority and reason, while these fixtures also record rule IDs,
  risk helpers, bootstrap, and potentially several event decisions per input.
  Do not drop fields/cases or invent a `Route.rule` to force a comparison.
- Keep failures named by case, and demonstrate old/new comparisons run offline
  within the ticket's five-second target.

There is no placeholder or skipped new-router test: a green run currently proves
only that the exported baseline matches the legacy decision paths above.
