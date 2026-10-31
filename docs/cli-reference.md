# CLI Command Reference

<!-- The group/operation table below is verified against the live GROUPS
     registry by the "CLI reference drift" check in check_docs_consistency.py.
     Add a group or operation in code and this table fails the docs gate
     until it matches — do not hand-wave it. -->

The harness CLI is grouped: **`traust <group> <operation>`**, or
`python3 -m traust.cli <group> <operation>` from the harness venv. Both are the
same entry point (`[project.scripts] traust = "traust.cli.__main__:main"`).

```bash
traust check skill-alignment
python3 -m traust.cli check skill-alignment      # equivalent
```

## Command groups

29 groups.

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `checkov`, `config-matrix`, `crypto-cluster`, `crypto-image`, `crypto-source`, `fork-lag`, `gitleaks`, `govulncheck`, `grpc-guards`, `image-packages`, `image-sbom`, `joern`, `llm-app`, `opengrep`, `osv`, `priv-profile`, `route-guards`, `sanitizers`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `doctor`, `query-index`, `scan-internal-refs`, `toolchain` |
| `assessments` | The audit skills' doors on traust-core | `coverage`, `prepare`, `threats` |
| `attack` | The pack's pinned MITRE ATT&CK release | `validate` |
| `auth` | Who you act as, over traust-core's identity provider | `local`, `login`, `logout`, `refresh`, `service-account`, `status`, `token` |
| `build` | Deterministic builders | `rescan-worklist`, `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `coverage`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `skill-alignment`, `skill-security` |
| `cloud-config` | The cloud-config-audit skill's doors on traust-core | `check`, `record`, `run` |
| `compliance` | compliance-check doors on traust-core (posture: `dashboard view compliance`) | `adrs`, `calibrate`, `check`, `declare`, `evaluate`, `evidence`, `latest`, `policy`, `record`, `resolve`, `scopes` |
| `config` | The config home's one file, `traust.yaml`: `migrate <old home>` writes it from a pre-traust.yaml home and reports every file (carried, dropped, a fact to record with its command) | `migrate` |
| `dashboard` | Dashboard rebuilds, the team report, one insight view and the recorded SLA policy | `refresh`, `sla-policy`, `team-report`, `view` |
| `feeds` | Security feed snapshots (traust-core) and the product-definitions cache | `fetch`, `fetch-products` |
| `findings` | track-findings' and findings-db's doors on traust-core | `apply`, `baseline`, `confirm`, `decide`, `find`, `history`, `import`, `queue`, `record`, `refuted`, `reject`, `request`, `review-cases`, `sarif`, `status`, `summary`, `surfaces`, `tickets`, `timeline` |
| `impact` | Impact analysis; `manifest-sbom` is the `manifest_sbom` materializer, `below-range-scan` the `below_range_packets` one, `below-range-review` / `below-range-record` the review lane's doors | `analyze`, `below-range`, `below-range-record`, `below-range-review`, `below-range-scan`, `calibrate-rule-pack`, `cluster-state-diff`, `document`, `enrich`, `find`, `manifest-sbom`, `package`, `sbom`, `sweep`, `symbols` |
| `isolation` | Tenant-isolation review | `repos` |
| `ledger` | Ledger audit (traust-core) and the doc-variance register | `audit`, `doc-variance` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `lane-costs` |
| `portfolio` | The portfolio on traust-core (the graph ops are retired); `observe` is the `repo_state` materializer; `checkout-refresh` / `mirror-evict` are the repo checkout service's mirror-cache materializers; `plan` / `onboard` / `owner-hints` / `file` / `import-owners` / `import-release` / `release-changes` are add-inputs' and inventory-repositories' doors on traust-core; `dependencies` / `dependents` read traust-core's SBOMs | `checkout-refresh`, `dependencies`, `dependents`, `file`, `import-owners`, `import-release`, `liveness`, `mirror-evict`, `observe`, `onboard`, `owner-hints`, `plan`, `population`, `release-changes` |
| `pqc` | The pqc-readiness skill's doors on traust-core | `blockers`, `check`, `prepare`, `record`, `summary`, `vendor-claims` |
| `products` | corpus-intake's doors on traust-core: products and their corpus ownership | `add`, `list`, `update` |
| `registry` | Model/product registry and the recorded product map | `models`, `product-map`, `products` |
| `remediation` | The remediation loop's doors on traust-core (remediate-finding, patch, property-test, fleet-fix, verify-remediation) | `assemble`, `candidates`, `fleet-approve`, `fleet-claim`, `fleet-record`, `fleet-submit`, `fleet-targets`, `fork`, `mutation-evidence`, `next`, `open`, `prepare`, `progress`, `property-evidence`, `record`, `verifications`, `verify-differential`, `verify-prepare`, `verify-record`, `verify-sweep`, `work-items` |
| `repo` | A commit's files through core's checkout service (the mirror cache): prints the workspace path, for skills and hand runs | `checkout` |
| `reporting` | Report validation, rendering & recording | `lint`, `rate-threats`, `record`, `render`, `sarif`, `validate` |
| `session` | Headless skill sessions and artifact-only task preparation/recording | `prepare`, `record`, `run` |
| `tools` | One door over traust-core's tool registry: each registered tool's readiness, version and database; one tool over a checkout, SBOM, image or symbols, its typed result as JSON | `list`, `run` |
| `triage` | The triage skill's doors on traust-core | `check`, `intake`, `prepare`, `record`, `render` |
| `sweep` | Class-generalization sweep; the rule-proposal gate; recall-benchmark answer key | `benchmark`, `benchmark-targets`, `build-canaries`, `cards`, `collect`, `draft`, `emit`, `mine`, `propose-rule`, `regression-drafts`, `rule-lane`, `score-benchmark`, `screen-injection`, `sweep`, `verify-draft` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |
| `validation` | Core-backed machine validation evidence | `prepare`, `plan`, `record` |

### Artifact-only below-range sessions

The registered `dependency-watch` / `below-range` mode stages the newest recorded packets,
refetches digest-checked sources and resolves reviewer models before starting the session.
It requires recorded packets, OSV API access, a model registry and Claude Code supporting
restricted mode and runner-owned permission hooks (verified with 2.1.312).

```bash
traust session run --skill dependency-watch --mode below-range --repo https://github.com/example/app --run-id <order-uuid> --worker <claiming-worker>
```

The runner launches from the harness directory. The session reads `task.json`, staged
inputs and harness skills; its file tools can write only `output/verdicts.json`. Shell,
code-running and MCP tools are unavailable. Two blind reviewers and a judge use the model
slots in `task.json`. The runner validates the declared output, records applicable findings
and appends task/input/output digests to the leased order's immutable run manifest.
The executor receives its model credentials and standard process environment, without
deployment configuration variables. Temporary task directories are removed on every outcome.

Interactive use splits the same workflow:

```bash
traust session prepare --skill dependency-watch --mode below-range --repo https://github.com/example/app --task /tmp/review-task
# In the agent: /dependency-watch below-range --task /tmp/review-task
traust session record --task /tmp/review-task
```

A manual task has a null run ID; its review remains unattributed and its audit entry is
printed. For an ordered interactive task, give `--run-id` and `--worker` during preparation,
then the same `--worker` during recording. Missing/invalid output fails with
`session-output-invalid`; an executor failure retains measured usage and fails with
`runner-crashed`. Other skill/mode pairs retain their existing command behavior.

### Retired workflow entry points

The core-hub cutover removed the following entry points; they are **not**
deprecated aliases. Their former purposes and replacement owners are listed
here so an old runbook cannot be mistaken for an executable fallback:

| Former entry point | Former purpose | Current owner / port status |
|---|---|---|
| `build cumulative` | Replay legacy layers into findings-current reports | Core finding queries and insight services; report skill port unfinished |
| `check report-digests` | Verify report/artifact digest bindings | Core artifact publishing/index services; gate skill port unfinished |
| `feeds reconcile-cve-provenance` | Reconcile advisory provenance on findings | Core exposure service; skill port unfinished |
| Ledger triage / validation / verification emitters | Convert report verdicts into legacy layer events | `traust triage record` and `traust validation record` use core; the verification/remediation service port remains unfinished |
| `ledger pull` | Ingest external source determinations into the legacy ledger | `traust findings import` uses core attestation and the shared authenticated caller |
| `corpus` group | Report discovery, identity, projections, summaries and precedents | Core assessment and finding services; corpus skill ports unfinished |
| `route` group | Admit impact findings and remediation regressions without changing baselines | Core finding intake; routing skill ports unfinished |

There is no executable fallback for these retired workflows. Do not hand-write a
layer or invoke a removed module. The human countersign workbench below records
judgements on existing core findings; it does not replace machine-report intake.


## Deprecated forms

Two older spellings still work and must not be used in docs, skills, or
command wrappers:

| Form | Example | Use instead |
|---|---|---|
| Pre-grouping module invocation | `python3 -m traust.cli.check_skill_alignment` | `python3 -m traust.cli check skill-alignment` |

The dot-separated form keeps working because each `src/traust/cli/<module>.py`
carries an `__main__` delegate that forwards to the grouped parser — which is
exactly why a stale example drifts silently. `src/traust/cli/groups/tools.py`
self-describes as "deprecated aliases for migrated command groups".

Both are enforced: the **CLI invocation syntax** check in
[`check_docs_consistency.py`](../src/traust/cli/check_docs_consistency.py) fails
the docs gate on any dot-separated invocation in `README.md`, `AGENTS.md`,
`PROCESS.md`, `docs/*.md`, `config/*`, `harnessing/*/SKILL.md`, or
`.claude/commands/*.md`.

> Not every `traust.cli.*` module is a CLI. `traust.cli._doors`, for
> instance, has no `__main__` — refer to it as a module path, never
> as `python3 -m`.

See [tooling-and-structure-files.md](tooling-and-structure-files.md) for what
each packaged CLI does, and [skills.md](skills.md) for the skills that call them.

## New-output versus historical validation

`traust reporting validate` retains historical schema compatibility by default.
For a final newly authored triage, use the explicit shared write contract:

```bash
traust reporting validate /path/to/repo-triage.json --schema triage --canonical-write
```

`--canonical-write` requires `--schema` and a shared `$defs.canonical_write`;
it adds that contract's checks on the serialized bytes to the existing schema
and content checks. It never converts verdicts, invents kinds or rewrites the
report. The triage skill requires this gate before rendering or completion,
including generic scanner inputs that have no recording step. Read-only citation
checking/rendering and exact stored record replay remain separate; do not use
the new-output gate to reject historical artifacts.

Hardening is the user-facing category for `kind: weakness`, not a synonym for
every CWE-described software weakness. CWE tags describe issue types and do
not choose finding kind or verdict: a confirmed exploitable CWE-tagged issue
remains a vulnerability. This terminology does not change the write contract,
severity handling, or historical report bytes.

For a trusted caller's already prepared Core `TriageInput`, the executable
skill supports `traust session run --skill triage --role triage-verifier --
/staged/input.json --prepared-input --auto --votes 1 --repo /staged/checkout
--fresh`. `--prepared-input` is a skill flag after the runner's `--`, not a
new Core API or a wrapper DTO. The skill reads native
`subject/findings/prepared_at/assessor/items`, retains supplied identities and
source labels, and skips intake/prepare/record. The external SDK caller records
the original canonically gated output. Full field handling is in the
[triage skill](../harnessing/4-triage/triage/SKILL.md#1a-detect-input-shape).

### Native verification producer input

The existing verification skill accepts the worker's read-only native
executor input:

```text
/verify-remediation --native-input /workspace/results/<repo>-core-input.json --repo /tmp/repos/<repo> --output /workspace/results/<repo>-verification.json
```

Its runtime fields are `subject` (patched native subject), `source_subject`
(original subject with source SHA/assessment), `findings` (assigned Core
`FindingView[]`), and `source_bindings` (original artifact label to UUID).
The source artifact defaults to the staged sibling `<repo>-security-audit.json`;
`--source-report FILE` selects another already staged source explicitly.
The producer authors `verified_findings[].original_id` from the supplied
`findings[].finding.id`, not the artifact's old label. Timeline and
existing-finding coverage references use that same UUID. This is distinct
from triage, which must not invent `orig_id` from a native UUID.

Original/patch SHAs, before/after code and per-finding root-cause diffs remain
actual source evidence. Missing source/binding/severity data is reported,
never manufactured. Native mode skips Core DB lookups, scanner intake,
DB-backed differential and recording; the final original JSON still passes
`traust reporting validate OUTPUT --schema verification`. The installed
verification schema has no `canonical_write` fragment. The external SDK
caller records the original bytes through Core's existing admission gates.

## Authentication and finding statements

`traust auth login` stores a deployment login obtained by device code.
`traust auth login --token-file /private/token` imports a token without putting
it on argv. A solo installation may instead use:

```bash
traust auth local --identity reviewer@example.com --config-home /path/to/private-config
traust auth status --config-home /path/to/private-config
```

Local tokens are trusted only when `traust.yaml` explicitly sets
`identity: {trust_local: true}`. `auth service-account` and `auth local --machine`
are machine sessions, not human approval. `auth refresh` renews a stored login;
`auth logout` removes it. `auth token` deliberately prints the secret: do not
run it in an agent-visible capture or log.

The `findings` group reads core state (`baseline`, `find`, `status`, `history`),
imports forge/Jira statements (`import`), reads queued statements (`queue`),
and supplies refuted findings, review surfaces, SARIF and ticket links.
`findings decide FINDING --validity <canonical> --rationale '<own judgement>'`
records a statement under the stored, verified caller.

Both `findings confirm ITEM FINDING …` and `findings reject ITEM FINDING …`
require at least one actual `--validity`, `--severity` or `--resolution` and
the human's own `--rationale`. They atomically append that judgement and settle
only that review item. Reject never infers an inverse or means "close without
a decision". No judgement means defer, leaving the item pending.
`--evidence-grade` is optional and never inferred. Exact replay is idempotent;
cross-finding answers or altered replay are refused without an orphan decision.
For full evidence cards, requests and typed single/bulk apply, use
`findings review-cases`, `request` and `apply` below. `findings queue` keeps its
summary-list format, including re-read source statements with report labels.

## Direct human severity recording

The track-findings human review workflow includes direct
validity/severity/resolution judgements, pending review cards, review requests
and single/bulk reviewed apply. All commands use core domain services; no legacy
layer/corpus/db reads or cumulative-file rebuilds are performed.

```bash
traust findings record \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --decision severity --severity high \
    --rationale 'Reviewed the reachable call path and impact with the operator.' \
    --token-stdin --config-home /path/to/private-config \
    < /path/to/private-identity-token
```

Use an **existing core finding UUID** and exact canonical spelling from
`record --help`. `--decision validity --validity <canonical>` and
`--decision resolution --resolution <canonical>` record the corresponding
human judgement. Supply only the field selected by `--decision`.
`--evidence-grade` is optional: omission stays null, never inferred from identity.
Core owns evidence precedence, actor, clock, admission, persistence and replay.

### Review queue and requests

```bash
traust findings review-cases --limit 25 --config-home /path/to/private-config
traust findings review-cases --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef
traust findings review-cases --limit 25 \
    --output /path/to/private-review/countersign-queue.md
traust findings request \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --reason ambiguous_statement --token-stdin \
    < /path/to/private-identity-token
```

Without `--output`, review-cases returns JSON `{"items":[...],"next":null-or-cursor}`.
Core `ReviewItemCase` provides `review_item`, rich `finding`, attributed `history`
and `evidence_artifact_ids`. The client exports those IDs' integrity-checked
payloads, including raw probe observations and validation-recording companions;
core selects evidence, including retained voided recordings, rather than App policy.
`--finding`, `--reason` and `--status` filter the read; status defaults to pending,
limit to 100. Resume with
`--cursor <returned-next>` and unchanged filters/limit until next is null.
Invalid cursors or nonpositive limits fail, not an empty queue. Canonical reason
and status choices come from `review-cases --help`.

`--repo-url URL --report REPORT` (repeat `--report` as needed) adds source links
and live re-read `said` statements to each card, as in the summary queue. These
arguments resolve source labels; they do not replace finding/reason/status filters.

`--output` explicitly creates a new Markdown workbench with permissions 0600;
existing files and symlinks are refused, never overwritten. It includes the same
decision cards/evidence, page filters and next cursor. Stdout is a receipt
`{"written":"path","items":count,"next":null-or-cursor}` without evidence or
submitted rationale. Use a new file per page. The file is intentionally
sensitive, untrusted review material, not authoritative state.

Request optionally takes `--decision <UUID>` for the proposal being reviewed.
The same pending request is idempotent; a cross-finding proposal is refused.
After a settled item, another independent reviewer can request a new pending
item for the same finding/proposal.

### Single and bulk apply

`traust findings apply /path/to/reviewed-answers.json --token-stdin`
reads **one answer object or a nonempty array**, with this shape:

```json
{
  "review_item_id": "6ef12c66-4e7d-4fac-9b05-cfd6777658ea",
  "decision": "reject",
  "answer": {
    "finding_id": "31dcc9b8-b569-4340-9032-3b335d53a9ef",
    "validity": "confirmed",
    "rationale": "The reviewed unauthenticated path still reaches the proven operation.",
    "evidence_grade": "E0"
  }
}
```

`decision` is confirm or reject; **both** require a genuine explicit answer and
the reviewer's own rationale. Reject never infers an opposite classifier.
The nested answer allows only `finding_id`, `rationale`, optional `validity`,
`severity`, `resolution`, `evidence_grade`; core requires at least one judged
field. Actor/source/time/restatement/auto-accept fields are forbidden.
Omit deferred items instead of creating a fake answer.

For the async round trip, the human edits **only** the generated Markdown file's
single marked typed JSON block, adding the above answer objects to `answers`:

````markdown
<!-- traust:countersign-answers:v1:begin -->
```json
{
  "type": "traust.countersign.answers.v1",
  "answers": []
}
```
<!-- traust:countersign-answers:v1:end -->
````

Then run `traust findings apply /path/to/private-review/countersign-queue.md`
(optionally `--token-stdin`). The exact markers, JSON fence and type are required;
the payload is limited to one MiB. Missing, duplicate or malformed controls,
duplicate JSON fields and invalid rows fail rather than being silently ignored.
Cards escape HTML/comment markers and use safe fences; evidence cannot forge
the answer block. Checkboxes, prose, copied report JSON and `DECISION:` lines are
never interpreted as approval. Do not populate answers from machine text.

An unchanged Markdown `answers: []` is an explicit **defer**: verified-human
authentication is still required, but no decision or review is changed. Exit 0
returns `{"results":[],"deferred":true}`. Omitted items remain pending. A plain
JSON empty array still fails; existing JSON object/nonempty-array behavior is
unchanged. All answers use the same strict core service calls regardless of file
format.

Each answer atomically records the human decision and settles that review item.
Exact replay returns the saved item; a changed answer/outcome conflicts without
an orphan decision. Core requires a distinct later E0 second reviewer to dismiss
execution proof: first concurrence leaves it open, replay/same signer is not a
second. Ledger-integrity refusal changes neither decision nor review.
Direct record does not close queue items; selected-review apply does.

Bulk apply is per item, not a batch transaction. It returns
`{"results":[{"ok":true,"review_item":...},{"ok":false,"review_item_id":...,"error":...}]}`.
Successful results include the resolving decision UUID. Exit is 0 when all
succeeded, 2 if any failed. Report partial successes accurately; earlier committed
answers remain saved when a later item fails.
Every successful write receipt includes `finding` with core-derived
`disposition`, `is_open` and effective severity. Review acceptance does not imply
finding closure. If the first E0 dismissal leaves it open, another independent
human must review a new pending item. Re-read accepted cards using
`review-cases --status accepted --finding <UUID>`.

### Identity and receipts

`--config-home` (or `TRAUST_CONFIG_HOME`) selects `traust.yaml`; its `identity:`
configuration owns trust and optional directory policy. Every write requires a
verified human; a machine admin does not qualify. Without `--token-stdin`, the
workbench uses the same stored login verified by `load_caller(core)` as the
`findings` group. An explicit `--token-stdin` reads only stdin and never falls
back to a stored login if missing, invalid or unauthorized. Omit that flag and
the token redirection from the examples to use the stored login.
No second credential store, local bypass flag or caller actor argument is
accepted. Use an argv-list API or shell-safe quoting for dynamic arguments;
never interpolate rationale into shell syntax or put tokens in argv/logs.

For PostgreSQL install the core-owned driver with `uv sync --extra postgres`.
SQLite needs no extra. `database.url` belongs in `traust.yaml`; the app never opens
the connection directly.

Write receipts/errors omit submitted rationale and tokens. Queue history and
evidence deliberately expose prior judgements for review: they are sensitive
review material, not publication receipts. Reload through
`services.findings.history/get`, core `ReviewItemCase` pages and
`services.attestation.for_finding`.
The [skill](../harnessing/4-triage/track-findings/SKILL.md#legacy-parity-and-retirement)
accounts for retired checkbox/prose approval parsing, scan-ID mapping and
file-based state; the typed async workbench does not restore those paths.

## Scanner intake

`traust triage intake <scan> --format sarif|dependabot|govulncheck --repo-url <url>
--sha <commit> --config-home <private-config>` uses
`Context.services().assessment.record_scan`. Core parses the original scanner
output and validates the complete finding batch, including nested locations,
before committing the assessment and intake together. A malformed batch leaves
no partial assessment, occurrence or finding rows. Scanner claims do not create
disposition decisions.

Source comes from the recorded assessment's kind and native scanner name/version;
origin grouping uses the finding's first reporting assessor. There is no `--origin`
override or `FindingCandidate.origin` field. A later scanner can add observations
without replacing that first-source attribution. Raw report origin tags remain
historical/provider evidence, not an alternative Core classifier input.

Service callers replay using the original provenance timestamp; lookup uses the
database's existing timestamp precision. The CLI records each actual invocation
as its own run. `AdapterResultArtifact` uses the scanner-observation contract:
unreported CWEs/description/remediation remain unreported rather than invented.
The real native Gitleaks scan-to-artifact regression now passes without
hand-completing fields. Authored audit reports keep their stricter finding
requirements; artifact admission does not confer validity or evidence strength.
Passing native-format SARIF intake remains a separate recorded path.

## Validation planning and inputs

Prepare the core-owned input for one or more findings (source assessment, prepared
findings and their bound source artifacts). No probe runs; finding IDs must be distinct:

```bash
traust validation prepare --finding-id <uuid> [--finding-id <uuid> ...] \
  --config-home /private/config
```

Publish an immutable proposed attack plan. Publishing a plan is not an authorization
to execute any step:

```bash
traust validation plan --document /private/run/app-attack-plan.json \
  --config-home /private/config
```

## Machine validation recording

Record already-produced evidence without executing any probe:

```bash
traust validation record --report /private/run/app-validation.json \
  --bindings /private/run/source-bindings.json \
  --provenance /private/run/run-provenance.json \
  --target-attestation /private/run/target-attestation.json \
  --config-home /private/config
```

Optional `--install-failure /private/run/install-failure.yaml` retains the exact
supplied text and marks the deployment observation failed. There is no directory
search or sibling-file fallback. Full attestation may instead be embedded in
`metadata.target_attestation` or `bindings.target_attestation`; any explicit false
voids all verdicts. `attested` must be a JSON boolean, not a truthy string/number.

`--bindings` is core's `ValidationRecordInput`. Every report finding needs an
exact source reference/label binding. Multiple sources/repos are supported:

```json
{
  "policy": "current",
  "sources": [
    {
      "source_report": "opaque:original/app-triage",
      "assessment_id": "2d8834fa-4dcc-4374-a79a-b88d075a9589",
      "artifact_id": "4e3ce4b9-34ac-4cbf-b47f-b1dd35483b3b",
      "findings": [
        {
          "source_id": "f001",
          "finding_id": "31dcc9b8-b569-4340-9032-3b335d53a9ef"
        }
      ]
    }
  ]
}
```

UUIDs above are illustrative: supply real stored IDs obtained from core's
assessment/finding/artifact services. `source_report` is the exact
`source_reports[].path` / `validated_findings[].source_report` historical
reference, treated as opaque text, never a filesystem path. `source_id` is the
original finding label in that stored source report, never a core UUID or a
basename-derived alias. Core checks source artifact membership, finding
membership in that source or its immediate baseline, repository/ref and any
supplied source digest. Unknown, ambiguous or cross-repo mappings refuse without
aggregate mutation. Extra source reports are not silently narrowed away.

For the ordinary scanner → triage → validation CLI path, capture the receipt:

```bash
traust triage record <baseline-assessment-UUID> <app-triage.json> \
  --repo <read-only-checkout> --config-home <private-config>
```

Its `baseline_assessment_id` is the actual input baseline. Each `records[]` entry
contains native `decision_id`, `assessment_id`, `artifact_id` and `finding_id`.
The latter assessment/artifact identify the stored **triage** result, not an
automatically discovered original audit. Use them for a `kind: "triage"` validation
source, with the exact stored triage finding's `id` (for example `f001`) as
`source_id`. Match the finding by its explicit source fingerprint/context; do
not reinterpret an audit label as a triage label. No-decision triage output has
an empty `records` list, not fabricated IDs. For other already-stored source
families, the orchestrator obtains the actual corresponding IDs from core's
assessment/finding/artifact services before recording.

`--provenance` is the actual producer run's core `Provenance`, for example:

```json
{
  "run_id": "707cab6e-eb93-48f3-afb5-2daf746fb0e5",
  "source": "validation_report",
  "occurred_at": "2026-10-23T12:00:00Z"
}
```

Use the real run UUID/time, retained for replay; this command never invents a run,
plan, timestamp, human actor or auto-accept flag. `ValidationArtifact.parse`
validates the exact input bytes; `Context.services().validation.record` owns
assessment/artifact persistence, identity, soundness and machine decisions/review.
The JSON receipt includes assessment/artifact/evidence IDs and per-finding
decision/review IDs and flags. Exit 2 means input/config/domain refusal; submitted
report content is not printed in refusal receipts. Raw report bytes, provenance,
target context and supplied observations remain core-owned immutable evidence,
including void/unsound rows without decisions.

**Current versus historical:** `policy` defaults to `current`: target attestation,
passing refutation controls, authz differential probes and explicit confirmation
grades are required regardless of the harness's version reset. Only a deliberate
`historical` replay uses the original 0.176.0/0.177.0/0.178.0/0.179.0 age cutoffs.
Malformed/unknown versions refuse, not grandfather. Explicit failed attestation,
failed controls, nondiscriminating probes and error-signature refutations remain
invalid at every age. Historical absence of a grade remains null, never inferred
execution proof. E3/current-ungraded confirmations and unsound/inconclusive
outcomes go to review, not validity conclusions.

Sound refutations record `false_positive` pending verified human signoff, never
automatic dismissal. Severity proposals are review-only; machines do not write
severity overrides. Core retains explicit E0 precedence and the two independent
later E0 human rule. Replays return the same identities; distinct runs/targets
do not silently supersede each other. OWASP risk rating is unchanged.

The existing [isolated-lab runner](../harnessing/5-validate/validate-findings/SKILL.md#phase-5--report-and-record)
produces typed report bytes and immediately calls this same door with actual
run provenance. Prepare/plan/authorize/live execution and novel-finding intake
remain separate plan24 work; scanner/carried/cumulative families and historical
deployment mapping certification are not completed by this producer slice.
