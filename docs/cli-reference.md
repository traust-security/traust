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
| `compliance` | compliance-check doors on traust-core (posture: `dashboard view compliance`) | `adrs`, `calibrate`, `check`, `declare`, `docs`, `evaluate`, `evidence`, `latest`, `policy`, `record`, `resolve`, `scopes` |
| `config` | The config home's one file, `traust.yaml`: `migrate <old home>` writes it from a pre-traust.yaml home and reports every file (carried, dropped, a fact to record with its command) | `migrate` |
| `dashboard` | Dashboard rebuilds, immutable reported history, the team report and SLA policy | `capture`, `compare`, `explore-loc`, `history`, `read-report`, `refresh`, `sla-policy`, `team-report`, `view` |
| `feeds` | Security feed snapshots, CVE provenance (traust-core) and the product-definitions cache | `fetch`, `fetch-products`, `reconcile-cve-provenance` |
| `findings` | track-findings' and findings-db's doors on traust-core | `apply`, `baseline`, `claim`, `confirm`, `correction-request`, `decide`, `find`, `history`, `import`, `queue`, `rebaseline`, `record`, `refuted`, `reject`, `request`, `review-cases`, `sarif`, `status`, `summary`, `surfaces`, `tickets`, `timeline`, `verified-fix-mtta` |
| `impact` | Impact analysis; `export` reads the retained advisory-wide fleet view; `manifest-sbom` is the `manifest_sbom` materializer, `below-range-scan` the `below_range_packets` one, `below-range-review` / `below-range-record` the review lane's doors | `analyze`, `below-range`, `below-range-record`, `below-range-review`, `below-range-scan`, `calibrate-rule-pack`, `cluster-state-diff`, `document`, `enrich`, `export`, `find`, `manifest-sbom`, `package`, `sbom`, `sweep`, `symbols` |
| `isolation` | Tenant-isolation review | `repos` |
| `ledger` | Ledger audit (traust-core) and the doc-variance register | `audit`, `doc-variance` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `lane-costs` |
| `portfolio` | Native inventory and declared owner/contact/tracker handoffs, forge liveness, recorded dependency/interface facts, unsigned analytical proposals, graph presentation and release discovery | `checkout-refresh`, `crd-consumers`, `crown-jewel-draft`, `dependencies`, `dependents`, `exports-of`, `facts-collect`, `file`, `graph`, `iac-census`, `import-owners`, `import-reference`, `import-release`, `imports-package`, `internal-coupling`, `inventory-export`, `liveness`, `mirror-evict`, `observe`, `onboard`, `org-index`, `owner-hints`, `plan`, `population`, `release-audit`, `release-changes`, `release-discover`, `release-passthrough`, `ships-module` |
| `pqc` | The pqc-readiness skill's doors on traust-core; ranked worklists, bounded stamped refresh and non-destructive report repair | `blockers`, `check`, `prepare`, `record`, `repair`, `summary`, `sweep`, `vendor-claims`, `worklist` |
| `products` | corpus-intake's doors on traust-core: products and their corpus ownership | `add`, `list`, `update` |
| `registry` | Model/product registry and the recorded product map | `models`, `product-map`, `products` |
| `remediation` | The remediation loop's doors on traust-core (remediate-finding, patch, property-test, fleet-fix, verify-remediation) | `assemble`, `candidates`, `fleet-approve`, `fleet-claim`, `fleet-record`, `fleet-submit`, `fleet-targets`, `fork`, `mutation-evidence`, `next`, `open`, `prepare`, `progress`, `property-evidence`, `record`, `verifications`, `verify-differential`, `verify-prepare`, `verify-record`, `verify-sweep`, `work-items` |
| `repo` | A commit's files through core's checkout service (the mirror cache): prints the workspace path, for skills and hand runs | `checkout` |
| `reporting` | Report validation, rendering & recording | `import-fuzz-campaign`, `lint`, `rate-threats`, `record`, `render`, `sarif`, `validate` |
| `session` | Headless skill sessions and artifact-only task preparation/recording | `prepare`, `record`, `run` |
| `tools` | One door over traust-core's tool registry: each registered tool's readiness, version and database; one tool over a checkout, SBOM, image or symbols, its typed result as JSON | `list`, `run` |
| `triage` | The triage skill's doors on traust-core | `check`, `intake`, `prepare`, `record`, `render` |
| `sweep` | Class-generalization sweep; detection-quality reports; recall-benchmark answer key | `benchmark`, `benchmark-targets`, `bootstrap-benchmark`, `build-canaries`, `cards`, `collect`, `compliance-precision`, `critical-misses`, `cve-replay`, `draft`, `emit`, `mine`, `propose-rule`, `regression-drafts`, `rule-lane`, `score-benchmark`, `screen-injection`, `sweep`, `verify-draft` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |
| `validation` | Core-backed machine validation evidence | `prepare`, `plan`, `record` |

### Detection-quality operations

- `traust sweep bootstrap-benchmark --out candidates.yaml [--limit 100]` harvests
  confirmed fixes as **unadmitted** answer-key candidates with fix evidence and a stable
  held-out split. Human review precedes `benchmark-targets candidates.yaml`.
- `traust sweep score-benchmark --runs-dir <runs> --out benchmark.json` also writes
  `benchmark.md`; `--markdown <path>` selects an explicit Markdown destination. Without
  `--runs-dir`, the recorded scorecards receive the same human-readable export.
- `traust sweep cards <deck.yaml> --artifact symbol-index:<card-id>=facts.json`
  compiles pre-generated typed facts without checkout tools. `--checkout` remains the
  live mode; reference cards enumerate textual mentions, not resolved calls. Live target
  sanitizer execution remains tools-package-owned; supplied execution facts are replayable.
- `traust impact calibrate-rule-pack [pack] --fixtures [--rules <path-or-URL@SHA>]`
  runs pack sanity without corpus truth; omit `--fixtures` for integrated pinned-TP rescans.
  `--scan <UUID>` retains recorded-scan scoring. `--out <dir>` writes `calibration.json`,
  `summary.md` and `review-samples.jsonl`; see `--help` for limits/timeouts.
- `traust sweep compliance-precision --framework <framework> --gate 0.5 --out-dir <dir>`
  exports JSON and Markdown field precision from recorded assessments. The inclusive gate
  flags checks for human demotion review; it does not run the evaluator twice or mutate checks.
- `traust sweep critical-misses --campaign-dir <campaign> --out <dir>/CRITICAL-MISSES.md`
  exports Markdown and sibling JSON from critical deltas, replay, triage and sample/report maps,
  including un-ingested candidates. `--start` and `--end` add recorded Core misses.
- `traust sweep cve-replay monitor [--since <ISO8601>]` emits JSON discovery results for newly
  published advisory candidates against recorded audited commits. `oracle`, `candidates`
  and `trends` emit their separate JSON views. Presence uncertainty, near matches and misses stay
  distinct; candidate export never admits findings. Source watermarks advance only after success.
- `traust sweep emit --rule <rule> --sweeps-root <dir>` exports the cached candidate and
  summary payload too; `--force` recomputes rather than being required to export elsewhere.
- `traust sweep benchmark check-trigger --since <ref>` resolves its checkout from explicit
  `--repo-root`, then `BENCHMARK_REPO_ROOT`, then configured `locations.workspace/traust`.

### Compliance assessment output and official documentation

`traust compliance evaluate <boundary> --out <assessment.json>` writes both draft JSON and
a per-control `<assessment.md>` report. `--markdown <path>` chooses a different report path;
the two outputs must not name the same file. Coverage and skipped-framework reasons precede
the individual verdicts, rationales and evidence citations. A failed citation gate still writes
both draft outputs and exits 1; neither output makes a certification claim.

`traust compliance calibrate <boundary>` runs the evaluation twice and compares the full
OSCAL exports as well as assessment/coverage/gate outcomes. UUID and structural differences
fail calibration; only documented run timestamps are ignored. JSON `oscal_compared` states
whether the selected frameworks support the 800-53-spine export.

`traust compliance docs <registered-product-slug>` fetches official guides using that
product's `compliance.docs_targets` entry in `traust.yaml` (see
[setup](setup.md)). The result is JSON containing real source URLs and extracted text,
not generated documentation. For an explicit one-run source selection:

```bash
traust compliance docs <registered-product-slug> \
  --product-slug <official-documentation-slug> --version <official-version> \
  --guide <official-guide-slug>
```

Repeat `--guide` to fetch several guides; omit it (or use `--all-guides`) to discover actual
guide links from the official product page. Explicit mode requires both source slug and version
and does not rewrite configuration. Missing mappings, unknown products and fetch failures
are errors, never fabricated fallback documents.
### Portfolio facts, views and artifact releases

`portfolio facts-collect` records package/interface facts at observed default heads;
repeat `--repository-ref-id` to select pinned commits and `--checkout UUID=PATH`
to supply an existing checkout. `crd-consumers <api-group>` joins owners,
consumers, RBAC and webhook evidence fleet-wide. `imports-package <package>` and
`exports-of [package]` return cited persisted facts; `ships-module <package> --ecosystem <ecosystem>`
reads image SBOMs. `internal-coupling` counts distinct
dependent repositories of packages with declared producing-repository provenance.

`portfolio graph --out <dir>` writes full relationship JSON, GraphViz, Gephi,
interactive offline HTML and a top-20 hub/coverage Markdown report. It reads
native services and optional `--inputs` hierarchy; it never creates a graph database.
`crown-jewel-draft`, `iac-census` and `org-index` accept optional scope and `--out`
to publish JSON/Markdown/HTML; without output they print the typed model.
The crown-jewel proposal is explicitly unsigned human-review input, never
dispatch authorization or a write to approved crown-jewel facts.

`portfolio release-discover` observes payload digests/tags and watched dist-git
heads into the native release-inventory feed. The first observation is a baseline,
not a burst of audit jobs. Changes plan `release-passthrough` and artifact-specific
container/RPM audit batches; major/minor inventory version changes also request a
source threat review when identity is known. Dist-git commits are not versions.
`portfolio release-audit --kind container|rpm --role <role> --run-id <uuid>`
runs the exact observed batch through the existing security skill.


`traust dashboard view executive-summary --out <dir>` accepts repeatable `--panel attack|pqc|isolation|iac`, plus `--by-segment`, `--inputs-root <dir>` and repeatable `--exclude-segment <name>` (default exclusion: `ansible`). Segment rows are first-match in input declaration order and include overlap/unmapped/excluded-only accounting. Optional panels are embedded in all three generated formats, not links to unrelated views. PQC retains its current-state/product-only boundary. `dashboard view scoreboard` composes validation/fuzz, census, patterns and benchmark recall alongside the leadership headlines; harness checkout maturity carries its own current measurement timestamp, independently of `--as-of`.
### Check scope and inputs

`traust check estate-data --staged` reads the Git index, including migration portability
markers, rather than unstaged working-tree revisions. A removed working copy does not hide
its staged contents.
Renames are checked at their destination paths, including files moved into migrations.
Whole-tree scans also check untracked migrations. Invalid UTF-8 cannot suppress migration
portability checks in either mode.

`traust check skill-security` checks each build command's sandbox routing through
`traust util safe-exec run` or `python3 -m traust.cli util safe-exec run`. Prose, comments,
an unrelated wrapped command, and `safe-exec check` do not route a direct build.
Go build/test commands are checked even without package arguments or trailing whitespace.

`traust check docs-consistency --root <path>` compares the model-class index against the
skills in that selected checkout, not the checkout where the checker is installed.

### Immutable as-reported dashboards

`dashboard view` computes a preview; `dashboard capture` also archives the exact report
exports in content-addressed ObjectStore bytes plus an append-only artifact row. Capture
requires `--note` for the counting methodology or change explanation and returns its artifact
UUID/digest. Scoreboard, executive summary and threat register use this shared archive;
other registered views can be captured too. No new schema or legacy metrics JSONL writer is used.

```bash
traust dashboard capture scoreboard --note "Published counting policy" --out <report-dir>
traust dashboard capture executive-summary --product <slug> --note "Leadership brief" --out <report-dir>
traust dashboard capture threat-register --note "Latest recorded threat models" --out <report-dir>
traust dashboard history scoreboard --limit 20 --out <history-dir>
traust dashboard read-report <artifact-uuid> --out <original-report-dir>
traust dashboard compare <artifact-uuid> --against previous --out <comparison-dir>
traust dashboard compare <artifact-uuid> --against recomputed --out <replay-comparison-dir>
traust dashboard compare <artifact-uuid> --against current --out <current-comparison-dir>
```

Capture accepts the same scope/window/configuration options as `view`. Repeat those
scope options for `history`; `--as-of` is excluded from the history key, while view,
product/team/category sets and non-default calculation/window options distinguish streams.
`history` without `--out` lists report metadata; with it, the saved metric columns are also
rendered as Markdown/HTML/JSON. `read-report` without `--out` reads the saved bundle;
with it, original JSON/Markdown/HTML/CSV and `<artifact-uuid>.snapshot.json` bytes are exported.

`previous` compares two immutable reported snapshots linked in the same stream. The
first has no predecessor and returns a not-found error. Each link retains its prior
artifact UUID/digest; concurrent captures can share a predecessor without overwriting
either report. `recomputed` uses today's code/configuration at the saved report time,
where the view supports historical reads; `current` uses today's data cut. The comparison
names both methodologies and shows field-level old/new values and numeric deltas.
Missing values remain distinct from JSON null. No comparison rewrites an archive.
Portable history, comparison and original exports remain script-free.

`traust check drift [--config-home <dir>] [--worklist <file>]`
prints pack configuration checks and the surviving rescan worklist's age backstop.
The worklist override matches `build rescan-worklist --out`; otherwise it uses
configured analysis-results. Bootstrap reads Core's current typed inputs inventory,
including unregistered repositories; there is no graph-database routing override.
The command remains informational (no `--fail-on` gate); native feed/registry age,
upstream releases, stored-PQC-schema compatibility and measured-language coverage are
in `traust dashboard view freshness --out <dir>`.

The surviving `build rescan-worklist` router still reads its existing interim
`findings.db` projection for HEAD code-audit population, live vulnerability risk,
report paths and cloud-config baseline presence. `--db <file>` selects that input;
the default remains `graph/findings.db` under configured analysis-results. This is
not the retired portfolio graph, and the native inventory bootstrap replacement
does not claim that the whole router or its population backend has migrated.

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

### Static configuration and placement diagnostics

`traust adapters config-matrix <checkout> [--max-triples N] [--out F]` retains
judged defaults first and records omitted rows as coverage gaps. Its JSON includes
the checkout name, generation time, harness version, YAML-parser availability and
statistics over the emitted triples. Credential literals remain redacted in every
tier and in sink expressions; a row limit never means complete coverage.

Repository-hygiene placement auditing lives in the checkout, not the installed CLI:
`python tools/classify_script_placement.py [--root <harness checkout>] [--only <class>]`.
It emits a CSV class summary and module rows based on static production/test
importers, registry entries and literal skill references, including nested workflow
skills. Tests never count toward the shared-library threshold. Classes are placement
nominations, not proof that dynamic callers are absent; the tool never moves or
deletes files. Run it with the checkout's installed dependency environment.

### Advisory inputs and sweep-generated analysis

`impact find`, `package`, `symbols`, `analyze` and `sweep` accept repeatable
`--advisory-file <osv.json>` inputs exported from OSV's per-ID endpoint.
When supplied, Core reads only these exports, including connected aliases;
it never falls back to live advisory HTTP. Malformed or unrelated requested
inputs fail without recording an impact. Export every alias needed for coverage.
An offline sweep describes only that supplied advisory collection.

Live sweeps group known aliases by canonical identity, retaining ecosystem,
module, affected spans, explicit versions and fixes from every member. Ordinary
advisories without fixes remain visible with `fix_available: false`.
`impact_argv` arrays retain offline file arguments; execute them as vectors.
`analyze` records each reached ecosystem/module/installed version independently,
returning unique `commits`, `analyses`, classification counts and affected finding IDs.

### Advisory fleet export and verification scope

`traust impact export <advisory-id> [-o <path>]` reads kept advisory identities
(including aliases) and native impact documents without refreshing feeds.
It returns `ImpactExport`: unique `commits`, exported `analyses`, complete
classification counts and `.repos` rows with repository URL/SHA, package/version,
classification/evidence and recorded IDs. Each row's `document` preserves the
complete native payload. Export selects the latest complete preparation scope
for each commit/advisory and retains every declared package/version member.
An incomplete newer scope cannot clear the prior complete result; a complete
corrected SBOM scope replaces obsolete modules and versions. Within that selected
scope the newest packet for a member wins. Without `-o` JSON is printed to stdout.
An unknown advisory fails; a known advisory with no analyses exports empty rows.

`traust remediation verify-sweep --impact-filter <path>` consumes this export,
retaining repositories with an affected/likely row and intersecting any explicit
repository/product scope. Nonmatching or empty filters produce no work, never
the whole fleet. Do not pass the counts-only `impact analyze` response or a
single native artifact as this advisory-wide filter.

### Bulk CVE provenance

```bash
traust feeds fetch --feed rh-cve
traust feeds reconcile-cve-provenance --min-score 0.55 --report /tmp/provenance-preview.json
traust feeds reconcile-cve-provenance --apply --report /tmp/provenance-applied.json
```

The default is a dry run over all recorded code audits and the retained `rh-cve`
snapshot: no advisory or finding link is written. `--apply` records each distinct
finding/CVE reference idempotently and links an unnamed finding's best primary
advisory through Core. Existing primary conflicts stay visible and are never
overwritten; no finding verdict or resolution changes.

Stdout and optional `--report` contain the same typed reconciliation JSON:
per-audit/ref/finding match rows with publication/audit dates, positive lead days,
title score and confidence; distinct-CVE counts; confirmed lead-day min/median/max;
and planned/written link counts. One CVE can match several branch reports but counts
once in `distinct_cves`. The median uses the upper middle row, as the original workflow did.
The score floor must be finite and within 0–1; lowering it below 0.55 does not admit
unclassified matches. Shared CWEs promote confidence but never rescue a title below
the chosen floor. A missing snapshot fails with exit 2: fetch it first. This command
uses recorded assessment IDs and current services, not legacy corpus/layer paths.
### Retired workflow entry points

The core-hub cutover removed the following entry points; they are **not**
deprecated aliases. Their former purposes and replacement owners are listed
here so an old runbook cannot be mistaken for an executable fallback:

| Former entry point | Former purpose | Current owner / port status |
|---|---|---|
| `build cumulative` | Replay legacy layers into findings-current reports | Core finding queries and insight services; report skill port unfinished |
| `check report-digests` | Verify report/artifact digest bindings | Core artifact publishing/index services; gate skill port unfinished |
| Ledger triage / validation / verification emitters | Convert report verdicts into legacy layer events | `traust triage record`, `traust validation record`, and `traust remediation verify-record` persist through Core; use `remediation verifications` and `findings baseline` for recorded/current results |
| `ledger pull` | Export a read-only snapshot of one legacy ledger layer | Legacy layer stores remain retired. Core `ledger.layer(layer_id)` and paged `ledger.events(layer_id, page)` read native layers; `findings import` is a distinct external-statement intake operation, not a snapshot-export replacement |
| `corpus` group | Report discovery, identity, projections, summaries and precedents | Core assessment and finding services; corpus skill ports unfinished |
| `route` group | Admit impact findings and remediation regressions without changing baselines | Core finding intake; routing skill ports unfinished |

There is no executable fallback for these retired workflows. Do not hand-write a
layer or invoke a removed module. The human countersign workbench below records
judgements on existing core findings; it does not replace machine-report intake.

### Remediation target and verification views

- `traust remediation fleet-targets --rollup REGEX --progress PROGRESS.md`
  matches numbered table rows, resolving only their explicit target cell through
  registered inventory. Full registered URLs disambiguate same-path repositories
  on different hosts. Unknown/ambiguous targets refuse the selection; no match is
  an empty fleet, not an all-repository scope.
- `traust remediation fork --list` enumerates inventory mappings under the same
  private-fork policy as single-repository resolution, including unresolved rows
  with a reason. It does not create forks or grant push authorization.
- `traust remediation verify-sweep --include-branches --out worklist.json`
  includes registered non-default branches and writes `worklist.md` beside JSON.
  Each target retains repository/ref UUIDs, branch, head source, pinned/head SHAs,
  counts, and tier or skip. Stored observations are not live probes; an unobserved
  branch's registered commit is labeled separately.
- `traust remediation verify-record REPORT` records the real verification result,
  decisions and regressions idempotently. `remediation verifications --repo-url URL`
  reads those recorded results, while `findings baseline --repo-url URL` reads
  current default-line disposition. Neither sweep rendering nor patch progress
  establishes a verified fix or changes forward-only work-item status.
- `traust findings baseline --repo-url URL --ref-id UUID` reads current findings
  and resolution on that registered branch. The ref must belong to the named
  repository; historical `--as-of` and current `--ref-id` are separate scopes.
  If an original SHA was audited on several named lines, verification reports
  must identify the verified branch with `metadata.patched_ref`; Core refuses an
  ambiguous baseline rather than resolving another line.



## Inventory reference and owner/contact export

```bash
traust portfolio onboard --product example --label Example --org example-org \
  --sub-service Gateway --manager morgan --ownership-source "reviewed org directory"
traust portfolio owner-hints --repo https://github.com/example-org/api --save
traust portfolio import-reference --source /private/inventory-declarations.yaml
traust portfolio inventory-export --format csv
traust products add example --label Example --ownership owned --business-unit Commerce \
  --note "The BU boundary cuts this shared tree."
traust products update example --note "Reviewed boundary exception."
traust products list
```

`plan` accepts the same intake declarations and writes nothing. `--reference <file>` on
`onboard`/`plan` accepts per-repository labels and contacts (and supplies the named repositories):

```yaml
version: 1
repositories:
  - repo_url: https://github.com/example-org/api
    service: Gateway
    individual_owners: [alice]
    ownership_source: "OWNERS at reviewed commit"
    manager: morgan
    business_unit: Commerce
    jira_project: PAY
    jira_component: API
    escalation_contact: oncall@example.com
    payload_versions: ["4.0"]
    operator_versions: ["1.0", "2.0"]
```

`onboard` derives `Resource Type=adhoc`. Organization intake defaults an omitted service
label to the organization name. `--sub-service`, `--individual-owner` (repeatable),
`--ownership-source`, `--manager`, `--business-unit`, `--jira-project`, `--jira-component`
and `--escalation-contact` provide request-wide defaults; per-repository reference values win.
`--payload-version` / `--operator-version` are repeatable observed inventory labels;
onboarding accumulates them without claiming commit-qualified release membership.
CSV exposes these separately from `Recorded Product Versions`.
`import-reference` applies facts to already registered repositories, without forge discovery.
The provider retains these declarations in `<traust.yaml home>/inventory-reference.yaml`
outside domain tables. Omitted fields preserve previous facts; explicit nulls in YAML clear
optional fields; explicit empty version lists replace/clear the authoritative declaration.
No contact, manager or tracker key is fabricated.

`inventory-export` emits JSON by default or spreadsheet-safe CSV with service/intake kind,
team/person/source/manager/BU facts, explicit tracker and escalation routes, shipped
`product:version` labels and trusted product-definitions contacts. A declared manager is a
person fallback only when no individual owners exist. `owner-hints --save` retains the forge
handles and provenance, never a team-ownership assignment. Contacts carry source and embargo
eligibility; neither an exported route nor a candidate grants authority to disclose findings.
The registry join uses `locations.feeds_cache` and the recorded product map, not slug guesses.
For an SLA-specific snapshot, use `traust dashboard view sla --pd-cache-dir <feeds-dir> --out <dir>`;
this override affects only that invocation and leaves deployment configuration unchanged.
Saved forge hints are retained separately (`owner_hints`, `owner_hint_source`), so they cannot
overwrite declared individuals/provenance. Exported people use declared individuals first,
then forge hints, then a known manager. Organization defaults preserve existing service labels.

`products add/update --note` round-trips subject-labelled caveats through the existing
corpus-registry document note. Omitting the flag preserves the caveat; `--note ""` clears
only that product. `products list` returns the note with each product.

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

## Suppressed scanner review and verified-fix timing

`traust triage intake scan.sarif --format sarif --repo-url <url> --sha <commit>
--include-suppressed` includes suppressed SARIF results for explicit review. Without
the flag they remain excluded. Inclusion creates unjudged candidates under the
normal intake gates, not suppression approvals or false-positive verdicts. Other
scanner formats reject the flag.

`traust findings verified-fix-mtta --repo-url <url> [--as-of <ISO-with-zone>]`
returns severity, sample count and elapsed mean days from first recorded
report/decision activity to first validation/verification-backed resolved decision.
Human-only and triage closures do not enter the metric; retracted fixes are excluded.
Severity is the effective rating at the requested time, including an unrated group.
This historical first-fix clock retains fixes even after reopening; use `--open` or
`--closed` to restrict the current population. `findings timeline` remains a separate,
overall bucketed MTTR across all resolving sources.

## Historical report signature verification

`traust reporting validate PATH [--schema layer] --signing-pubkey COSIGN_PUBLIC_KEY`
additionally verifies historical `*-findings-layer.json` documents' stored-event
Merkle tree and public-key signature. Missing or invalid signatures, unusable or
wrong keys, and Merkle tampering exit nonzero. Omit the flag for ordinary unsigned
validation. This read-only historical check does not restore retired layer writers
or verify signatures over ordinary audit-report bodies; all reports still pass
their exact contract schema.

## Human-reviewed claim correction

`traust findings correction-request REPORT --finding UUID --assessment ORIGINAL_UUID
--label LABEL --ticket CHANGE_RECORD --rationale WHY` requires a verified human
login and a schema-valid corrected report for the original repository and commit.
It retains the immutable proposal artifact on the original assessment and opens a
`rebaseline_mapping` review. It does not admit fresh audit work or a verdict.

`traust findings rebaseline REVIEW_UUID --ticket CHANGE_RECORD --rationale WHY`
atomically records human acceptance and applies the stored proposal through canonical
intake. It takes no replacement candidate from the command line, so approval cannot
be reused for changed content. The stable finding UUID, original report/occurrence,
judgement history and original assessment count are retained. Collision and repository
checks still apply; correcting claim text is not a severity/validity judgement.

`traust findings claim FINDING_UUID [--as-of ISO_WITH_ZONE]` reads the accepted
corrected candidate, or null when there is none. Current finding views project the
corrected title, description, locations, CWE and category while preserving the original
reported severity and separate canonical decisions.

## Container cumulative view and rating diagnostics

`traust dashboard view container-findings --assessment-id CONTAINER_ASSESSMENT_UUID
--report-stem IMAGE-container-audit --out DIRECTORY` exports cumulative JSON,
Markdown and HTML under `IMAGE-container-audit-findings-current`, preserving the
full case-sensitive image stem. The anchor is mandatory: only original container
reports for its source repository and image repository contribute. Tag/digest
changes keep the population; unrelated images and code audits do not. Canonical
decisions determine state; absence from a later report never resolves a finding.
`--as-of ISO_WITH_ZONE` selects the historical view.

`traust dashboard view findings-rollup --category authorization --out DIRECTORY`
adds `severity_cvss_mismatches` to the exact label-scoped population: documented
and undocumented counts plus detailed scored-informational and two-band-downgrade
diagnostics. Each score identifies its canonical occurrence or immutable original
report source; the diagnostic does not rerate findings or infer categories from text.
The retired RBAC tiers, pattern buckets and ATT&CK heat are not restored.
