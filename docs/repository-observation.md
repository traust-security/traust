# Observe one repository

`traust observe repo-state` collects the facts needed for future work routing,
saves the latest observation, and prints it as JSON. It does not select a lane
or dispatch a job. This is the observation portion of XWING-2214.

```sh
traust observe repo-state --repo https://github.com/example/project
```

The command uses the deployment's existing locations configuration. It reads
the findings projection, audit report, inventory graph, and exposure
designations through `LegacyObservationInputs`. It queries the forge only for
the selected repository. A comparison is requested only when the existing
push-date rule says the audited repository changed. Inventory repositories
without an audit retain the existing bootstrap behavior: no forge calls.

For explicit local paths:

```sh
traust observe repo-state --repo https://github.com/example/project \
  --db /path/to/graph/findings.db \
  --graph-db /path/to/graph/portfolio-graph.db \
  --designations /path/to/findings/_manifest/exposure-designations.json \
  --state-db /path/to/graph/repo-state.db
```

`--no-network` records an observation without querying the forge. `--repo-key`
can select an audit filing without a usable repository URL. The target must be
present in the available audit or inventory views; a failed or missing input
view is not treated as an empty inventory.

## Existing code being extracted

The source is `src/traust/cli/build_rescan_worklist.py`. The per-repository bodies
of `stage1()` and `stage2()` now live in `traust_pack_security.observe` and are
called by both the old batch path and the new observer. The batch path retains
its thread pools, quota allocation, and shared ban breaker. The observer reuses
the existing date parser, risk/exposure classification, file matchers, change
metrics, and forge fetchers. It does not introduce new forge endpoints.

For a single repository, the observer checks GitHub's live remaining quota
before comparing. This check does not reserve capacity or reproduce fleet
ordering. The batch CLI still allocates its quota snapshot by candidate index
and retains its shared ban breaker. Future concurrent callers must coordinate
quota allocation and explicitly share a breaker; independent observations do
not provide those fleet-wide guarantees.

The new code consists of the typed input/output, per-repository orchestration,
repository storage, CLI integration, and tests. `Lane` and `EventSource` are
vocabulary for later routing, not fields on `RepoState`. All vocabulary values
remain those of the worklist; eventual contract registration is XWING-2228.

## Field mapping

- `repo_key` remains the audit/inventory key; `repo_url` becomes typed `repo`,
  with `source_url` retaining the original input for diagnosis.
- `status` becomes `ComparisonStatus`; `tier` becomes `risk_tier`.
- `C` becomes `changed_lines`; `R` becomes `churn_ratio`.
- `S` becomes `sensitive_changed`; `S_lines` becomes `sensitive_lines`.
- `changed` becomes `push_changed`, retaining the push signal needed by routing.
- `truncated` becomes `compare_truncated`.
- `exposure`, `audit_age_days`, `deps_only`, and `ahead_by` keep their names.
- `observed_at` is the timezone-aware observation time; `error` retains a forge
  diagnostic when available.

Unknown measurements are `null`, not zero or false. The old routing context
filled some unavailable measurements with zero; those defaults are not facts
and are deliberately not written into the new record. A successful empty diff
still records measured zero/false. A never-audited repository has no audit age.
Typed URL validation rejects unsafe or unrecognized URLs before forge calls;
the original URL/key remains available in the degraded record. GitHub tree/blob
URLs normalize to `owner/repo`, matching the existing forge target, so calls and
stored identity refer to the same repository. GitLab subgroup paths stay intact.
The original URL remains in `source_url`. Legacy report
SHAs retain their existing abbreviated-SHA handling; no full-SHA requirement
is silently imposed on old reports.

## Storage and failure behavior

The command writes a separate SQLite `graph/repo-state.db` by default. It never
writes the findings or inventory projection. The new `security_repo_state`
table is initialized by the command; an incompatible existing table produces
an error rather than an implicit migration. SQL repositories and transactions
use the pinned Core implementation. In-memory and SQLite backends share tests.
PostgreSQL SQL construction is supported by the Core pattern but is not claimed
as integration-tested by this change.

URL-bearing records use the canonical URL for identity, so a newer audit filing
does not create a second observation for the same repository. Records without
a usable URL use their existing key. Repairing a filing's URL replaces its
previous identity in the same transaction. Different missing-URL records are
never collapsed into one null key.

Expected forge failures and unavailable comparisons are stored as statuses;
the command exits zero after successfully storing them. Zero means the command
recorded the result, not that the forge was reachable. Missing inputs, invalid
configuration, and storage failures remain command errors.
The observer validates forge response shapes and field types before calculating
metrics. Malformed responses become `error`; transport failures become
`unreachable`. These catches cover the forge boundary, not observation
calculations or persistence.

## Boundary with adjacent work

`LegacyObservationInputs` is a temporary repository adapter. It preserves the
existing population dedupe, maximum live risk across sibling filings, report
metadata parser, and inventory membership check. It still reads the local
population view before selecting one repository; it does not repeat the fleet's
network observation. XWING-2213 can replace this adapter with its repositories.
This change does not implement that ticket's Findings repository or relocate
shared findings data out of Core.

Work routing is XWING-2215. Controller scheduling and job dispatch are later
engine work. The existing Go routing PRs and the XWING-2216 routing baseline are
separate. Since extracting code changes the legacy file's checksum, integrating
this branch with the baseline PR requires its documented source-drift review;
do not regenerate routing expectations to hide that change.

## Verification

Run `uv sync --locked` after updating the checkout. Core is a new pinned
dependency. The resolver override unifies the existing contracts revision
across the different remotes named by Core and the older engine/ledger pins;
it does not upgrade the contracts revision.

`tests/test_repo_observation.py` checks all observation statuses, both storage
backends, commits/rollbacks, missing/repaired identities, and command output.
The existing worklist tests exercise the batch path after extraction.

`tests/fixtures/observations/reference.json` records thirteen cases from the old
worklist's actual `main()` at a fixed date. Twelve use synthetic forge replies.
The remaining case replays `recorded-github.json`: repository metadata and a
comparison between fixed commits, captured from the public Traust GitHub
repository using the same field selection as the legacy forge calls. It retains
no headers, credentials, personal identities, patch text, or commit messages.
The audit baseline and quota for that case are synthetic test inputs, not claims
about an actual security audit. GitLab coverage uses synthetic responses.

The reference records the legacy source revision/checksum and the recorded
response fixture's checksum. Its manual generator requires the matching source
file; pass `--recorded-forge tests/fixtures/observations/recorded-github.json` to
include the recorded case. A CLI integration test replays the recorded responses
through the real adapter, observer, and SQLite store. Normal tests require
neither Git, network, nor external commands. These are observation fixtures,
not the 302 routing-decision cases tracked separately by XWING-2216.
