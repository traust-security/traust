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
| `build` | Deterministic builders | `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `coverage`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `skill-alignment`, `skill-security` |
| `cloud-config` | The cloud-config-audit skill's doors on traust-core | `check`, `record`, `run` |
| `compliance` | compliance-check doors on traust-core (posture: `dashboard view compliance`) | `adrs`, `calibrate`, `check`, `declare`, `docs`, `evaluate`, `evidence`, `latest`, `policy`, `record`, `resolve`, `scopes` |
| `config` | The config home's one file, `traust.yaml`: `migrate <old home>` writes it from a pre-traust.yaml home and reports every file (carried, dropped, a fact to record with its command) | `migrate` |
| `dashboard` | Dashboard rebuilds, the team report, one insight view, the recorded SLA policy and the local LoC explorer | `explore-loc`, `refresh`, `sla-policy`, `team-report`, `view` |
| `feeds` | Security feed snapshots, CVE provenance (traust-core) and the product-definitions cache | `fetch`, `fetch-products`, `reconcile-cve-provenance` |
| `findings` | track-findings' and findings-db's doors on traust-core (`claim`, `correction-request` and `rebaseline` refuse until plan 15's decision 1) | `apply`, `baseline`, `claim`, `confirm`, `correction-request`, `decide`, `find`, `history`, `import`, `queue`, `rebaseline`, `record`, `refuted`, `reject`, `request`, `review-cases`, `sarif`, `status`, `summary`, `surfaces`, `tickets`, `timeline`, `verified-fix-mtta` |
| `impact` | Impact analysis; `export` reads the retained advisory-wide fleet view; `manifest-sbom` is the `manifest_sbom` materializer, `below-range-scan` the `below_range_packets` one, `below-range-review` / `below-range-record` the review lane's doors | `analyze`, `below-range`, `below-range-record`, `below-range-review`, `below-range-scan`, `calibrate-rule-pack`, `cluster-state-diff`, `document`, `enrich`, `export`, `find`, `manifest-sbom`, `package`, `sbom`, `sweep`, `symbols` |
| `isolation` | Tenant-isolation review | `repos` |
| `ledger` | Ledger audit (traust-core) and the doc-variance register | `audit`, `doc-variance` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `lane-costs` |
| `portfolio` | The portfolio on traust-core: inventory discovery and routing-event intake, `observe` (the `repo_state` materializer), the checkout mirror-cache materializers, add-inputs' and inventory-repositories' doors, the owner/contact export, SBOM reads (`dependencies`, `dependents`, `ships-module`); `liveness` refuses until plan 15's decision 3 and `release-passthrough` refuses until a release feed exists (NEED(release-passthrough)) | `checkout-refresh`, `dependencies`, `dependents`, `event-intake`, `event-validate`, `file`, `import-owners`, `import-release`, `inventory-discover`, `inventory-export`, `liveness`, `mirror-evict`, `observe`, `onboard`, `owner-hints`, `plan`, `population`, `release-changes`, `release-passthrough`, `ships-module` |
| `pqc` | The pqc-readiness skill's doors on traust-core; native single-commit prescan, ranked sweep worklist and bounded refresh through Core's registered pqc-scan provider | `blockers`, `check`, `prepare`, `prescan`, `record`, `summary`, `sweep`, `vendor-claims`, `worklist` |
| `products` | corpus-intake's doors on traust-core: products and their corpus ownership | `add`, `list`, `update` |
| `registry` | Model/product registry and the recorded product map | `models`, `product-map`, `products` |
| `remediation` | The remediation loop's doors on traust-core (remediate-finding, patch, property-test, fleet-fix, verify-remediation) | `assemble`, `candidates`, `fleet-approve`, `fleet-claim`, `fleet-record`, `fleet-submit`, `fleet-targets`, `fork`, `mutation-evidence`, `next`, `open`, `prepare`, `progress`, `property-evidence`, `record`, `verifications`, `verify-differential`, `verify-prepare`, `verify-record`, `verify-sweep`, `work-items` |
| `repo` | A commit's files through core's checkout service (the mirror cache): prints the workspace path, for skills and hand runs | `checkout` |
| `reporting` | Report validation, rendering & recording | `lint`, `rate-threats`, `record`, `render`, `sarif`, `validate` |
| `session` | Headless skill sessions and artifact-only task preparation/recording | `prepare`, `record`, `run` |
| `tools` | One door over traust-core's tool registry: each registered tool's readiness, version and database; one tool over a checkout, SBOM, image or symbols, its typed result as JSON | `list`, `run` |
| `triage` | The triage skill's doors on traust-core | `check`, `intake`, `prepare`, `record`, `render` |
| `sweep` | Class-generalization sweep; detection-quality reports (`cve-replay` refuses until plan 15's decision 2); recall-benchmark answer key | `benchmark`, `benchmark-targets`, `bootstrap-benchmark`, `build-canaries`, `cards`, `collect`, `compliance-precision`, `critical-misses`, `cve-replay`, `draft`, `emit`, `mine`, `propose-rule`, `regression-drafts`, `rule-lane`, `score-benchmark`, `screen-injection`, `sweep`, `verify-draft` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |
| `validation` | Core-backed machine validation evidence | `prepare`, `plan`, `record` |

### Native PQC facts and Layer-2 handoff

`traust pqc prescan` produces and records Core-native Layer-1 facts for one
explicit repository commit, then exports the published artifact:

```bash
traust pqc prescan --repo-url <URL> --sha <commit> \
  --repo-dir <checkout> --sbom <manifest.json> \
  --out <facts.json> --cbom-out <cbom.json>
traust pqc prepare --repo-url <URL> --sha <commit>
```

Exactly one source is required: `--repo-dir <checkout>` for a source scan, or
`--from-sbom <manifest.json>` for package-only evidence. `--sbom` is optional in
source mode if the commit's manifest SBOM is already recorded; when supplied,
Core ingests it before prescan. `--from-sbom` ingests that manifest and does not
execute the source scanner. `--sbom` and `--cbom-out` are source-only options.
Both modes require `--repo-url`, `--sha` and `--out`; `--public` marks a public
repository and `--config-home <dir>` selects the deployment configuration.
Scanner and rules come only from loader registration, not `--scanner` or
`--rules-dir` overrides. Provider prerequisites are described below.

The JSON receipt identifies the recorded assessment and whether the scan ran
or reused current facts. `--out` is the exact native published artifact payload,
not a reconstruction from the receipt's fact list. Core alone owns policy,
facts, persistence and pack/source-basis cache decisions. Do not add a redundant
`pqc record --facts` step. Core does not retain CBOM: `--cbom-out` exports
unchanged source-scanner bytes only when available, and fails explicitly on
cached reuse without writing either output. The current native CBOM is a JSON
array, not a promised CycloneDX document. Source failures also write neither
output and never manufacture clean facts.

Validate an existing export with
`traust reporting validate <facts.json> --schema pqc-facts`.
`pqc prepare` reads the recorded native producer output for `/pqc-readiness`'s
Layer-2 reasoning; the authored readiness report still uses `pqc check` and
`pqc record --report`. SBOM-only facts do not establish source/configuration
coverage, and an empty package result is not a verified source zero-hit.
The single-commit command is not a fleet campaign; sweeps require an explicit
bounded selection.

### PQC worklist Insight report and sweep

`traust pqc worklist` reads Core's ranked worklist of registered repositories
without requiring a readiness report. Stdout remains the legacy JSON **array**
of entries, including nullable ref, access and scan state; no files are created
by default. `--markdown <path>.md` additionally publishes Core-owned Markdown
at that exact path and an `.html` sibling through shared publication helpers,
with no JSON sidecar and no change to stdout.

Name run priorities with repeatable `--chokepoint <URL fragment>`; no config-home
priority file is read. Omitting chokepoints retains the CLI warning and ranks
crypto-CWE repositories before the remaining tail. Worklist generation only
reads recorded data: it does not scan, check out source, ingest dependencies,
probe liveness or infer readiness from missing scan state.

The generic report door exposes the canonical wrapper, not the legacy array:

```bash
traust dashboard view pqc-worklist --product <slug> \
  --repository-ref-id <ref-uuid> --chokepoint <URL-fragment> --out <directory>
```

Use `--product <slug>` for at most one product; repeat
`--repository-ref-id` and `--chokepoint` to select refs and priorities. Explicit
refs intersect the selected product's shipped refs. Unsupported scope, window
and historical filters are refused. Generic dashboard JSON exports contain
`product_id`, `repository_ref_ids`, `chokepoints` and `entries`, alongside Core's
Markdown and HTML exports.

`traust pqc sweep --limit <n>` remains native bounded scan orchestration using
Core's worklist. `--after <next_cursor>` resumes the batch and `--refresh` also
considers stale scanner/rules stamps. This report migration does not change
scanner behavior, readiness scoring, liveness policy or deployment configuration.

The loader registers Core's provider through `Context.register_pqc_scanner`,
using `skill_dir("pqc-readiness")` to locate `bin/pqc-scan` and `rules/`.
Build the pinned binary with that skill's `build_pqc_scan.sh`; source scans need
the executable and its matching `bin/pqc-scan.sha256`, a readable nonempty rules
pack, and permission for the binary in `traust.yaml` under
`process.allowed_binaries`. Checkout and manifest-SBOM acquisition also require
their normal process permissions, including `git` and `syft` when needed.
Provider registration does not install the binary or grant process permission.
Core reports a missing binary or unready provider as a scan failure, never a
clean readiness result.

An absent provider is a configuration error before a batch acquires source or
ingests dependencies. Already recorded scans remain resumable without a provider
when `--refresh` is not requested; refresh refuses with a configuration error
when the current pack cannot be compared. Source capture, persisted scan state,
facts and replay stay behind Core's PQC service doors.

### Audit publication versus finding admission

`traust reporting record` stores an assessment and artifact. Native finding
admission depends on the selected kind and its canonical document schema:

| Kind | Finding admission on successful recording | Triage handoff |
|---|---|---|
| `secure_code`, `container`, `rpm`, `vuln_scan` | Core admits the document's findings atomically with the assessment | Run `traust triage prepare <returned-assessment-id>` for its native items and any matching precedents |
| `benchmark_audit` | No native finding admission; benchmark reports are scored | Keep the benchmark workflow, not native finding triage |

Core computes finding identity when findings are admitted, including during
recording for the supported kinds above; it does not stamp the report file.
An empty report can legitimately prepare no items, and an empty batch is not
proof that the repository is clean. A re-audit finding that names an already
recorded finding under another identity is held for a person's rebaseline review.
Plan 15's decision 5 may change whether `secure_code` recording admits findings.

`reporting record` and `cloud-config record` take `--run-id <order-uuid>` (default:
`$TRAUST_RUN_ID`, which `traust session run` sets for the agent it starts, along with
`$TRAUST_CONFIG_HOME` when the session was given `--config-home`). The assessment is then that
leased order's result: core refuses an order that isn't leased, whose lease expired, or whose
scope is another repository or none. An ordered `secure-code-audit`, `vuln-scan` or
`cloud-config-audit` session succeeds only if this attempt recorded an assessment of the
skill's kind for its order (an earlier attempt's doesn't count); otherwise it fails with
`session-output-invalid`, so a session that never recorded can't pass as done. `written`
prefers this attempt's assessment; a retry that re-records an unchanged report is handed the
earlier one back, so the order holding its assessment is what the gate checks.

After admission, `traust findings find <report.json> --label <report-local-id>
--repo-url <audited-source-https-url>` is an optional scoped diagnostic. Exit 0 with
`finding_id: null` means no match, not an identity/admission receipt. Do not revive
stamping or invent a canonical-audit intake command to hide that gap.

### Shareable-output redaction

Run `python3 -m traust.cli util redact <output-directory>` in place, then
`python3 -m traust.cli util redact --scan-only <output-directory>` on the final
package. Share only after the final scan exits 0. Scan-only exits 1 when secrets
remain and does not modify deliverables; either mode exits 2 if any file cannot
be inspected or redacted. Read/decode/write errors, inaccessible directories,
symlinks and unsupported files are incomplete inspection, never a clean result.
Readable text still uses Core's established redaction policy. Remove, replace or
convert uninspectable deliverables and rerun the gate; there is no binary fallback.

### Detection-quality operations

- `traust sweep bootstrap-benchmark --out candidates.yaml [--limit 100]` harvests
  confirmed fixes as **unadmitted** answer-key candidates with fix evidence and a stable
  held-out split. Human review precedes `benchmark-targets candidates.yaml`.
- `traust sweep score-benchmark --runs-dir <runs> --out benchmark.json` writes the scored
  run as JSON; without `--runs-dir` it writes the recorded scorecards. There is no Markdown
  report until core registers its Insight view (a priority follow-up).
- `traust sweep cards <deck.yaml> --checkout <dir>` sweeps the valid cards' code-facts
  enumerators over the checkout; reference cards enumerate textual mentions, not resolved
  calls. There is no replay of supplied facts: traust-core's `sweep_cards` runs from the
  checkout.
- `traust impact calibrate-rule-pack <pack> --scan <UUID> [--scan <UUID> ...]` scores the
  named rule pack's recorded scans against confirmed true positives
  (`DetectionQualityService.calibrate`); record the scans first. It scans nothing itself.
- `traust sweep compliance-precision --framework <framework> --gate 0.5 --out-dir <dir>`
  exports field precision from recorded assessments as JSON (no Markdown until core registers its Insight view (a priority follow-up)). The inclusive gate
  flags checks for human demotion review; it does not run the evaluator twice or mutate checks.
- `traust sweep critical-misses --start <ISO8601> --end <ISO8601> [--json-out <file>.json] [--out <file>.md]`
  publishes the `critical-misses` Insight view: critical findings first reported in the
  window that an earlier audit missed. JSON retains its existing list shape; Markdown
  and HTML come from Core's shared renderers. By default all three are written beside
  `CRITICAL-MISSES.json` under `analysis_results`. `--json-out` selects the JSON path;
  `--out` selects the exact Markdown path, with an HTML sibling. Destinations must be
  distinct, including existing hard links. Reports are staged together; replacement
  failures and cancellation before commit restore the previous files. Cancellation then propagates;
  failed rollback retains recovery files and reports their locations. Staging cleanup
  errors are separate warnings, not failed exports after publication has committed.
  Both window bounds require time zones; the end is exclusive. Core permits
  at most 31 days and 10,000 cumulative materialized input/related records; an oversized <!-- estate-data-ok: public Core API workload limits, not deployment data -->
  or dense request fails without partial reports, so narrow the window when refused.
  `area_reported` rows require adjudication, not automatic classification as misses.
  Campaign directories are not read and no findings or tickets are created.
  `traust dashboard view critical-misses --since <start> --until <end> --out <dir>`
  publishes the structured `{window, misses}` ViewModel and the same human renders.
  This is a global recorded-data window, not a historical `--as-of` reconstruction or
  proof of clean coverage; unsupported scope filters are refused.
- `traust sweep cve-replay monitor|candidates|trends|oracle` refuses: "CVE replay needs a
  traust-core decision (plan 15, decision 2)". It never reads a fallback.
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

`traust compliance docs <registered-product-slug>` fetches official guides for an explicit
target (see [setup](setup.md)). The result is JSON containing real source URLs and extracted
text, not generated documentation:

```bash
traust compliance docs <registered-product-slug> \
  --product-slug <official-documentation-slug> --version <official-version> \
  --guide <official-guide-slug>
```

Repeat `--guide` to fetch several guides; omit it (or use `--all-guides`) to discover actual
guide links from the official product page. Both source slug and version are required:
`traust.yaml` carries no docs targets until the contracts config schema does. Missing
selectors, unknown products and fetch failures are errors, never fabricated fallback
documents.
### Portfolio SBOM reads and artifact releases

`portfolio ships-module <package> --ecosystem <ecosystem> [--version V]` lists the images
whose recorded SBOMs ship the package (Exposure's `find_package` then `image_dependents`),
directly or through a base image or internal library. An unrecorded package is an error.

`portfolio release-passthrough --run-id <uuid>` is the `release_passthrough` asset's door. It
refuses its order (NEED(release-passthrough)): traust-core has no release feed yet to plan the
container and RPM audits from. Release discovery from inventory files is retired.

`traust dashboard view executive-summary --out <dir>` accepts repeatable `--panel attack|pqc|isolation|iac`. Optional panels are embedded in all three generated formats, not links to unrelated views. PQC retains its current-state/product-only boundary. `dashboard view scoreboard` reads its headline numbers off the executive summary, findings trend and threat register views as of `--as-of`.

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

`traust check drift [--config-home <dir>]`
prints pack configuration checks. The command remains informational (no `--fail-on` gate); native feed/registry age,
upstream releases, stored-PQC-schema compatibility and measured-language coverage are
in `traust dashboard view freshness --out <dir>`.

`traust build rescan-worklist`, the former daily router, is retired: it read a
`findings.db` projection nothing builds. `traust portfolio inventory-discover`
registers configured input repositories and plans their first observation and
bootstrap audit. `traust portfolio event-intake` turns unconsumed
`rescan-events.jsonl` rows into distinct engine orders. Ordinary routing runs per
repository through `traust.ops.router`
([continuous-operations.md](continuous-operations.md)).

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

`traust adapters config-matrix <checkout> [--out F]` retains judged defaults first, up to
traust-core's default cap, and records omitted rows as coverage gaps. `--max-triples` is
refused: core's config-matrix provider takes no cap yet. Its JSON includes
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

### CVE provenance

```bash
traust feeds fetch --feed rh-cve
traust feeds reconcile-cve-provenance --finding <finding-uuid> [--finding <uuid> ...] --apply \
  [--report /tmp/provenance.json]
```

Each named finding is matched against the retained `rh-cve` snapshot by traust-core's
`ExposureService.reconcile_provenance`: its repository's component, published after the
finding's first report, a like title. When the finding names no advisory, the best match is
recorded as its advisory; a finding naming an advisory the best match is not comes back a
conflict and is never overwritten. Core always records, so there is no dry run: the command
refuses without `--apply` and without at least one `--finding`. The match threshold is core's;
there is no corpus-wide sweep. Stdout and optional `--report` carry the same typed checks.
A missing snapshot fails with exit 2: fetch it first.
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
| `corpus` group | Report discovery, identity, projections, summaries and precedents | Core owns assessment/artifact recording and native finding intake. Recording admits canonical secure-code/container/RPM/vulnerability-scan findings; only admitted candidates/bindings support native triage and precedents. See “Audit publication versus finding admission” above; `findings find` can legitimately return no match |
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



## Owner/contact export

```bash
traust portfolio onboard --product example --label Example --org example-org
traust portfolio owner-hints --repo https://github.com/example-org/api
traust portfolio inventory-export [--pd-cache-dir <feeds-dir>]
traust products add example --label Example --ownership owned --business-unit Commerce
traust products list
```

`inventory-export` composes every registered repository from the portfolio's own lists:
`Repository`, `URL`, `Host`, `Organization/Group`, `Repo Name`, `Owner Team` (current owning
teams), `Products` (products shipping it) and `Accountable Contacts` (product-definitions
candidates for its URL through the recorded product map, with source field and embargo
eligibility), as JSON (no CSV until core registers its Insight view (a priority follow-up)). `--pd-cache-dir` reads a
product-definitions snapshot other than `locations.feeds_cache` for that run only. A contact
is a candidate, never an owner, and grants no authority to disclose findings. Declared
per-repository inventory facts (service labels, managers, tracker routes, escalation
contacts) are retired: traust-core has one ownership source, the onboarding and owner-import
doors. `owner-hints` prints forge hints; it never stores them. Product boundary caveats are
not recorded (NEED(contracts: corpus-registry subject `notes`)).

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

## Claim correction

`traust findings correction-request`, `traust findings rebaseline` and `traust findings claim`
keep their arguments but refuse with "Claim correction needs a traust-core decision (plan 15,
decision 1)": traust-core has no claim-correction door until that decision. They never apply,
store or read a corrected claim.

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
