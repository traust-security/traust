# Continuous scanning — the standing rescan loop

> **Scope.** This is the **work-routing** document: the rescan router, its lanes
> and cadences, and the standing jobs built around them (spend capture,
> dashboards, drift, credentials). It is one of four kinds of routing in the
> harness — see **[routers.md](routers.md)** for the index, and
> **[findings-routing.md](findings-routing.md)** for how a finding reaches the
> ledger, which is a different mechanism with the opposite direction.

How the harness keeps every audited repository's assurance current after its
first audit: each time a repository's `repo_state` is observed, the security
pack's router (`traust.ops.router`) decides which scan lane it needs, and
traust-engine queues the order the dispatch lanes (full audits, diff scans, the
verify treadmill) run. The deps lane is the exception: its routes are
coverage classification — the daily `/dependency-watch` run covers that class
advisory-first without reading the routes (see rule 3b).

Core owns the new-order classifier gate: order states, registered routing lanes,
rescan event sources and machine reason codes come from its pinned contracts.
Asset names such as `feeds_cache` or `dashboards` do not become lanes; an unrouted
order has no lane. Materializer receipts expose stable reason codes
(`bad_request`, `not_found`, `snapshot_unavailable`, `source_unavailable`,
`ledger_unconfigured`); detailed causes are retained in logs with the run id.
Historical order text and the existing router lane spellings are not rewritten.

New completion coverage keys are checked against the common `DegradedKey` causes
or current registered feed/view identifiers. A failed feed such as `kev` and an
unavailable view such as `loc` keep separate counts; they do not become anonymous
failures. Counts must be positive integers. Unknown causes or invalid counts leave
the lease and artifact history unchanged. Imported historical keys remain readable
and are retained when progress updates write a successor manifest.

The thresholds and tier ceilings in this document are the router's shipped
defaults. A deployment re-derives them from its own router telemetry on a
quarterly cadence and records the derivation in its own planning documents;
this page is the operational contract, not the evidence.

**Cutover status.** The cadence and routing methodology below survives the
core-hub cutover, but the former corpus projection, finding routers, ledger
emitters and cumulative-report steps are retired. Their core-service skill
ports are separate from the completed triage and human countersign ports; do not
substitute a human judgement for a missing machine-report intake. See
[components.md](components.md) for ownership and
[disposition-ledger.md §6a](disposition-ledger.md#6a-the-countersign-workbench)
for the reviewed-human workbench. Existing legacy artifacts do not demonstrate
that the full loop completed on current inputs.

## The loop

```
             (per repository, deterministic, no agent spend)
   traust portfolio observe (repo_state) ──► traust.ops.router ──► traust-engine orders
                                     │  compare against the audited commit (C, S, DEPS, zero-diff)
                                     │  decision table → lane + rule + reason
                                     ▼
      ┌───────────┬───────────┬───────────┬────────────┬───────────┐
      ▼           ▼           ▼           ▼            ▼           ▼
  FULL AUDITS  DIFF SCANS  DEPS LANE  THREAT MODELS  VERIFY    (no action)
  weekly batch weekly      osv/impact  pr on surface  SWEEP     zero-diff /
  dual-pass    risk-       determin-   diffs (report  weekly    dormant
               ordered     istic +     -only) ·       treadmill
               trickle +   tripwire    review on      (build_
               P2 sensi-   escalations major/minor    verify_
               tive        │           release ·      sweep.py)
               monthly     │           calendar pool
      └───────────┴────────┴──► /triage ──► evidence artifacts (ledger/dashboard ports unfinished)
```

The threat-model lanes are the exception to that last arrow: they refresh the
*scope* an audit checks itself against, so their output feeds the next audit's
coverage diff rather than the ledger. They never file a finding.

The router routes only — it never authors a finding, verdict, or audit. Its
output is the engine's orders, one per routed lane. `inventory_discovery`
registers configured input URLs and plans their `repo_state` partitions before
those routes run. `rescan_event_intake` directly plans unconsumed external-report,
methodology and CVE rows. Its higher scheduling priority is a preference, not a
completion barrier: event intake and ordinary observations can overlap.

The former daily worklist builder (`traust build rescan-worklist` and its
`rescan-worklist.json`) is retired: it read a `findings.db` projection nothing
builds any more. Its decision table, tripwire, refusal pre-route, threat-model
stamp and additive rows live in `traust.ops.router`, characterized against the
legacy router's outputs (`tests/test_security_router.py`).

## Hosts and credentials

Repositories are reached through the hosts registered in `GIT_HOSTS`. Each
entry is `kind:host`, and the kind selects the transport, because the API and
the CLI differ per forge:

    GIT_HOSTS="gitlab:gitlab.example.com,github:ghe.example.com"

| Registered kind | Stage-1 / stage-2 transport | Credentials |
|---|---|---|
| `github` (github.com is registered by default) | `gh api repos/{org}/{repo}` and `.../compare/{sha}...HEAD` | `gh` CLI auth or `GITHUB_TOKEN` |
| `gitlab` (gitlab.com is registered by default) | traust-core's forge REST (`ForgeApi`) → `/api/v4/projects/:path` and `/repository/compare` | the env var `forge_tokens` names for the host in `traust.yaml`, sent only as a header — never in argv |

**Only these two kinds are implemented.** A repository on any other forge is
not unsupported by policy — nothing rejects it — but no transport claims it, so
it lands as `unsupported-host` below. Adding a forge means adding a kind and its
transport, not editing this table.

A host may be network-gated: with that network down, its repos get per-repo
status `unreachable`, the population counts them, and the MD summary carries a
loud warning — a run with the network down reads as incomplete, never as
falsely green. A missing forge CLI yields `no-credentials`. Hosts not registered
in `GIT_HOSTS` get `unsupported-host`. All three statuses stay in the routed
state (the age-ceiling rule still applies to them); nothing is silently
dropped.

## Lane cadences

| Cadence | What runs |
|---|---|
| Daily (automated, deterministic) | input inventory discovery → observation + router → event and routed orders (a recorded release's change is derived on demand: see *Event feeders*); `/dependency-watch` — the advisory-driven deps lane end to end (feeds → `/impact-analysis` → python3 -m traust.cli route impact-findings direct-entry filing) |
| Weekly session | dispatch the routed full-audit orders as a batch; `/verify-remediation` treadmill sweep (`traust remediation verify-sweep`); triage new findings |
| Monthly | sensitive-change P2 diff scans; validation session (criticals validated-or-blocked inside the SLA window); spend reconcile against the budget policy |
| Weekly (trickle) | the `diff-scan-quarterly` pool drains as a risk-ordered weekly trickle: dispatch rows with `drain_order < weekly rate` (default ceil(pool/13) — the same quarterly volume as a 90-day batch, but a short stable queue instead of a long tail; external-band rows first, target ≤14 days in-pool). Dispatching the drain is an operator decision informed by the deployment's measured per-run cost (see *The diff lane*); the drain ordering accumulates until scheduled |
| Weekly (rule mining) + post-wave | python3 -m traust.cli sweep rule-lane — the /mine-ledger lane: ledger miner → sweep-engine collect/draft → bounded regression-draft staging → delta report vs the previous `rule-mining.json`. Inputs: the confirmed findings and audits' `scanner_correlation` judge decisions recorded in traust-core. Outputs: `lane-delta.{json,md}` under the metrics tree + staged rule drafts, then calibrated pack rules via the scheduled `/mine-ledger` session (the mechanical test-and-calibrate gate is the promotion criterion; sweep hits and mined candidates still route to `/triage` — the lane never auto-files findings). Post-wave trigger: `/drift-watch`'s `rule-mining` row goes stale when ledger changes are >7d newer than the artifact |
| Weekly (threat-model trickle) | the `threat-model-quarterly` pool drains alongside the diff pool, on its own weekly rate (default ceil(pool/13)): dispatch rows with `drain_order < summary.threat_model.quarterly_weekly_rate` as `/threat-model review --auto`. The rate is a **cadence spread, not a budget cap** — no row is ever dropped, only scheduled; `--threat-model-drain-rate` can impose a hard weekly ceiling if spend warrants |
| Quarterly | class-sweep rotation at the measured FN classes; threshold re-derivation from router telemetry; recall benchmark; the threat-model calendar backstop completes one full pass |
| Event-driven | External-report, methodology and CVE rows in `rescan-events.jsonl` (`rescan_event_intake`). A recorded release's major/minor change requests a source `threat-model-review`. The router's `release-passthrough` lane has an asset that refuses its order until traust-core has a release feed (NEED(release-passthrough)); release discovery from inventory files is retired. |

### PQC fleet planning and bounded sweeps

`traust pqc worklist` is Core's read-only worklist Insight report over recorded
repositories, liveness and scan state. Its stdout remains the legacy JSON
array; it creates no files by default. Optional `--markdown <path>.md` creates
only Core-owned Markdown at that path and an `.html` sibling through shared
publication helpers, without a JSON sidecar or changing stdout.

For canonical dashboard wrapper JSON plus human exports, use
`traust dashboard view pqc-worklist --out <directory>`. Scope it to at most one
product with `--product <slug>` and optionally repeat
`--repository-ref-id <uuid>` and `--chokepoint <URL fragment>`. Explicit refs
intersect the selected product's shipped refs. The generic JSON wrapper carries
`product_id`, `repository_ref_ids`, `chokepoints` and `entries`, not the legacy
array. Unsupported scope, window and historical filters are refused.

Chokepoints are run-local priorities, not a deployment configuration file.
Without them the CLI still warns and uses crypto-CWE-then-tail ordering.
Planning does not scan, check out source, ingest dependencies or probe liveness;
unknown scan state does not establish readiness.

`traust pqc sweep --limit <n>` remains native bounded orchestration using Core's
worklist; `--after <next_cursor>` resumes and `--refresh` considers stale pack
stamps. Scanner behavior, readiness scoring, liveness policy and configuration
are unchanged by the reporting migration.

## Standing jobs — the complete inventory

The table above covers the rescan loop's lanes. This inventory is the superset:
**every job the harness expects to run on a cadence**, including the
maintenance/QA jobs that live outside the scan lanes. No scheduler is
configured in this repository: every timer-triggered row is run by the
deployment's orchestrator or by an operator session. Each runner is
orchestrator-neutral by design — the same command behaves identically from an
operator session, cron, or an enterprise scheduler — and the `/drift-watch`
rows named in the last column are the backstop that makes a dead timer visible.

| Job | Cadence | Trigger | Runner | Output gate / staleness backstop |
|---|---|---|---|---|
| Input inventory discovery | daily, before repository observation | timer (`inventory_discovery`) | `traust portfolio inventory-discover` | Registers every typed `locations.inputs` URL as private by default and plans its first observation plus bootstrap audit. Existing orders coalesce idempotently. |
| Operator event intake | daily; higher scheduling priority than observation | timer (`rescan_event_intake`) | `traust portfolio event-intake` | Plans unconsumed methodology and CVE work directly. An external-report row plans separate approved audit and live-validation orders; invalid, unscoped or unregistered rows are visible, never silently dropped. |
| Repository observation + router | per `repo_state` observation | engine tick | `traust portfolio observe`, then `traust.ops.router` | routes only, never authors findings; the engine tick is the cadence |
| **Feed-source liveness** | *retired* with `check drift`; returns as traust-core provider readiness once the live sources are core providers | probe | — | Probes every source in traust-core's shipped `feeds.yaml` carrying a `probe` — both tiers — so a live-tier source that answers with an error is visible. A definitive HTTP error is `drift`; a transport failure is `unavailable`, never `drift`, so an offline workstation does not report every source as broken |
| Release/dist-git event feeder | on demand | a recorded release (`traust portfolio import-release`) | `python3 -m traust.cli portfolio release-changes --product <slug> --version <v>` | derived from recorded releases, nothing stored (`PortfolioService.release_changes`); a dist-git head is the `repo_state` observation of a registered repository. Release discovery from inventory files is retired; `release_passthrough` refuses until a traust-core release feed exists |
| `/dependency-watch` (deps lane end to end) | daily | timer (advisory publication) | `traust feeds fetch`, `traust impact sweep` and `traust impact analyze` | Core exposure services record per-commit impact assessments and dependency finding intake for `affected` commits without changing baselines. Advisory/classification provenance and evidence admission remain core-owned; never invent severity or promote an OSV match directly to a verdict. |
| Below-range verification (packets, then review) | weekly per repository | timer (`below_range_packets`, then `below_range_review` once its packets are fresh) | `traust impact below-range-scan --repo <url>` records the head's packets; the review session runs `traust impact below-range-review`, two blind reviews and a judge on a split, then `traust impact below-range-record` | only `applicable` becomes a dependency finding (D1); `undetermined` cases and coverage gaps stay in the recorded review, never clean; no human queue (D4) |
| **Feed router** — security-data refresh (EPSS / KEV / vendor CVE and VEX feeds) | **daily** | timer | `python3 -m traust.cli feeds fetch --feed all` | Orchestrator-neutral ([routers.md](routers.md)), deliberately not bound to a CI pipeline in this repo. Snapshots every `tier: cached` source in traust-core's shipped `feeds.yaml` through traust-core (`ExposureService.refresh_feeds`: a `feed_snapshot` per source, the bytes in core's object store; `rh-cve` fetches only what published since its last snapshot). A dedicated job exists because consumer-triggered refresh only holds while something runs daily; without one the snapshots silently age. Every source in traust-core's shipped `feeds.yaml` is public. A source that fails keeps its last snapshot and the order is **degraded**, keyed by the source; one with no snapshot at all fails the order. **Backstop:** drift rows `feeds:*` at **48h** — one missed run plus slack; a threshold looser than the cadence it guards is how a dead job stays green |
| Weekly diff-drain tranche | weekly | timer over the router's drain ordering | *retired*: `diff_scan_quarterly`'s pacing and approval in `packs/security/assets.yaml`, routed by `traust.ops.router`; until the cutover, dispatch from the worklist by lane (see *Standing weekly drain* below) | fail-closed selection (refuses a worklist >48h old or a second tranche per ISO week); dispatching is an operator decision informed by measured cost |
| Threat-model re-model lanes | rides the router (daily) + the weekly tranche | change (`pr` stamp), major/minor release event, calendar backstop | `traust.ops.router` routes; the pack router schedules (the tranche script is retired); `/threat-model pr\|review` dispatches | **report-only** — no lane auto-applies an `update`. Drift row `threat-model` (held in lockstep with the lane's calendar threshold) is the dead-timer if the quarterly pool stops draining |
| Remediation lane (`remediate_finding`) | per scheduled fix | core's scheduling door (`POST /v1/remediations`) submits one order naming its work item | `traust session run --skill remediate-finding` → `/remediate-finding`: `traust remediation prepare` and `record` default to the session's order | the report records through the order's lease (`RemediationService.record_order`) on the work item the order names, never another attempt |
| Verify-remediation treadmill | weekly (worklist rebuilt per sweep) | timer | `traust remediation verify-sweep` → `/verify-remediation full-sweep` | verdicts gated by the verification schema + soundness lint; `traust remediation verify-record` records verdicts as decisions and regressions as findings |
| Rule-mining lane | weekly + post-wave | timer + drift row `rule-mining` (ledger changes >7d newer than the artifact) | python3 -m traust.cli sweep rule-lane, then the scheduled `/mine-ledger` session | never auto-files findings; rule promotion sits behind the mechanical test-and-calibrate gate; sweep hits route to `/triage` |
| Ledger audit | weekly | timer | python3 -m traust.cli ledger audit (`LedgerService.audit`) | verifies every ledger layer against its stored events and signature, so an edit to stored decision events is found within a week (appends no longer re-verify the layer); a layer that fails or can't be verified degrades the order, never green |
| CVE-replay FN monitor | operator-selected cadence | operator / orchestrator | `traust sweep cve-replay monitor`; inspect `candidates`, adjudicate with `oracle`, read `trends` | Core retains per-audit source watermarks; failed queries advance nothing. Unknown presence never becomes a confirmed miss; verified-human evidence is required, and no finding or ticket is filed automatically. |
| Critical-miss report | after each campaign wave / triage refresh | operator | `traust sweep critical-misses --start <ts> --end <ts>` | Core's registered critical-misses Insight view: recorded misses/adjudication rows as JSON, Markdown and HTML. No finding or ticket is created |
| `/drift-watch` | on demand; recommended alongside every `/census`; scheduled by the orchestrator | operator / timer | python3 -m traust.cli dashboard view freshness | routes attention only — never auto-rebuilds, auto-advances a pin, or files a finding |
| Census + repo-liveness refresh | at intake and before denominators are consumed | operator / intake flow | `portfolio observe` records forge availability; `portfolio liveness` reads Core's retained history | Unqueried/access-failed repositories remain unknown. Status durations retain their original transition time; a failed observation never fabricates a successful head. |
| FP-precedent cache rebuild | formerly drift-triggered, no timer | former `fp-precedent-cache` drift row | retired: Core matches precedents on admitted native findings; `traust triage prepare` supplies them for triage Phase 2g. Canonical container/RPM/vulnerability-scan recording admits findings; secure-code recording does not | Human and sound machine context informs review, never automatic dismissal. Existing cache artifacts are not a rebuild; an assessment-only audit without admission is not a clean native batch |
| Validation benchmark | release-cut + monthly hybrid | `traust sweep benchmark check-trigger` (exit 10 = benchmark required) + drift row `validation-benchmark` (35d) | python3 -m traust.cli sweep benchmark | below-floor runs exit non-zero; results land in the harness-QA tree, never campaign metrics |
| Recall benchmark | quarterly, plus release scoring | timer / release cut (`--release` scores held-out targets) | `/recall-benchmark run` | manifest never enters an audited tree; held-out split scored only at release |
| Class-sweep rotation | quarterly | timer (measured FN classes) | targeted class-sweep sessions (see *Lane weights*) | sweeps produce candidates for `/triage`, never filed findings |
| Threshold re-derivation | quarterly | timer over router telemetry | re-derivation per the deployment's cadence plan | a human reviews and edits the decision table; the router never self-tunes |
| Stored census builds (the dashboards lane's fast leg: the four census views — findings-rollup, coverage, remediation-index, findings-trend — folded once and stored as one GLOBAL build) | **every 10 minutes** (the insight route's serving window; the console accepts the widened staleness knowingly — a person's judgement is never served stale, and a stalled builder folds instead of serving a stale census) | timer (`insight_builds`, beside `dashboards`) | one command: python3 -m traust.cli dashboard refresh --census (the security pack's `insight_builds` asset: `InsightService.record_builds` through `InsightBuildsMaterializer` — the artifact `GET /v1/insights/{name}` serves between builds, one GLOBAL build for every scope; the caller's authorization filters what it serves) | the census views stop folding per request (the audit's 72-134s cold path, five builds per dashboard load); `?refresh` on the route still folds on demand. Wave (e) lands the SQL aggregation that makes the builder itself fast |
| Dashboards rebuild (all deterministic dashboards: census + exec summary, trends, insecure-patterns, validation-fuzz, rbac-tenancy, sla, compliance, attack-coverage, loc, spend, scoreboard) | **weekly** (inside the scoreboard's 7d drift threshold) | timer | one command: python3 -m traust.cli dashboard refresh (skill wrapper: `/refresh-dashboards`) — the packaged sequential deterministic job, the security pack's `dashboards` asset: traust-core's insight views (`InsightService.refresh` through `DashboardsMaterializer`) render every dashboard, the scoreboard included (`ScoreboardView`, composing the others) — all deterministic, no agent involved; every stage continues on error, failures are collected and reported (a degraded core view is named in the JobResult) | drift rows `dashboards:*` remain the dead-timer backstop (scoreboard >7d, spend >4d). **Orchestrator prerequisites for this job:** `locations:` in `$TRAUST_CONFIG_HOME/traust.yaml` must set `analysis_results` (and usually `workspace`, `progress_tracker`, the default `--out` for core views); and a **write-back path** for `analysis-results` (stamped layers) and `progress-tracker` (the metrics file) — on an ephemeral runner without one, the stamps are computed and then discarded. **Exception that stays operator-side:** the spend-*actuals* leg (python3 -m traust.cli metrics collect-spend --append) reads agent session transcripts on operator workstations — it cannot move to the orchestrator until transcripts are centralized, and its un-appended-actuals >4d drift row exists precisely to keep guarding that leg |
| IaC quarterly re-baseline | quarterly — **human-decision, drift-flagged** | rides `checkov-pin` advances (drift row) | `/cloud-config-audit` re-runs against the IaC-bearing targets | pin advances are deliberate toolchain changes — re-verify one known-good target before the sweep |
| Manifest SBOM sweep | daily per repository (a fetch only where the default head moved) | timer (`manifest_sbom`, after `repo_state`) | `traust impact manifest-sbom --repo <url>` (`ExposureService.record_manifest_sbom`: the forge archive of the head, only the files syft reads, capped; the SBOM gzipped in core) | the blast radius, `traust impact sweep`, `/dependency-watch`, below-range and `dependency-reach` all read these SBOMs; a failed fetch leaves the repository unmeasured in `dependency-reach`, never "no dependencies". Replaces the retired portfolio-graph rebuild |
| Mirror-cache refresh (the repo checkout service) | daily per repository (a fetch only where repo_state says the head moved — pushed since the last audit) | timer (`repo_checkout_refresh`, after `repo_state`) | `traust portfolio checkout-refresh --repo <url>` (`RepoCheckoutService.refresh`: the repository's git mirror fetched to its observed default head, a delta after the seed) | a pre-warm for the lanes' checkouts, never a gate: a mirror the job didn't refresh is fetched at checkout time instead, so results are the same, only slower. A repository at rest keeps whatever mirror it has — nothing seeds the whole inventory |
| Mirror-cache eviction | daily | timer (`mirror_evict`) | `traust portfolio mirror-evict` (`RepoCheckoutService.evict`: mirrors no checkout has touched in 30 days are dropped, the repos named in the run's result) | reclaim, never a gate: a dropped mirror is re-seeded by its next checkout with one full fetch. Only checkouts touch a mirror's last-use marker, so a mirror refreshed but never used is still reclaimed |
| ADR / pin / external-tool advances | **human-decision, drift-flagged** — never automated | drift rows `adr-registry:*`, `checkov-pin`, `external-tools:*` | reviewed commits advancing the pins | no check may auto-advance a pin (drift-watch constraint) |
| Spend capture (`/financial-tracking capture`) | **weekly** | timer; drift rows `dashboards:spend*` (>4d) | `/financial-tracking capture` — see *Spend capture cadence* below | capture is LOSSY if you are late: transcripts are retained for a rolling window only and there is no backfill. The reconcile step is a hard gate — a non-zero exit means recorded spend does not split losslessly by skill |
| Docs semantic sweep | quarterly | drift row `docs-semantic-sweep` (92d) | reviewer sweep per the check-harness-docs SKILL procedure | report lands in the deployment's gap-assessments tree |

## Critical-miss report

Run `traust sweep critical-misses --start <timezone-aware timestamp> --end <timezone-aware
timestamp>` after a campaign wave, triage refresh or disposition refresh. It exports
traust-core's recorded critical misses for that window: critical findings first reported in
it that an earlier audit of the repository missed (`area_reported` rows are for
adjudication, not hits). Outputs are `CRITICAL-MISSES.{json,md,html}` under configured
`analysis_results`. `--json-out <json>` selects the unchanged JSON-array export and,
unless `--out <markdown>` is supplied, its Markdown/HTML siblings. An explicit Markdown
path gets an HTML sibling; all output paths must be distinct, including existing hard links.
The complete set is staged before publication. I/O failures and cancellation during
replacement restore prior reports (or remove newly published files); cancellation then propagates.
If rollback also fails or is interrupted, the error identifies retained recovery directories.
Staging cleanup errors warn with the affected directory but do not change a committed
export's success or mask an earlier failure. This is not a crash-atomic multi-file transaction.
Both bounds are required and timezone-aware, with an exclusive end and a maximum span of
31 days. Core also bounds
the cumulative materialized input/related rows at 10,000; dense or oversized requests fail <!-- estate-data-ok: public Core API workload limits, not deployment data -->
without partial exports and must use a narrower window. This is a row-materialization
bound, not a database scan/sort or row-byte cap. Core owns the registered view, its schema
and human rendering; the operator command only materializes its results. Campaign directories
(probe/matrix deltas, replay candidates, sample maps) are not read. This reports recorded
findings, not advisory discovery or proof of clean coverage, and neither admits findings
nor files tickets.

## Spend capture cadence — capture weekly, report monthly

The capture chain is two deterministic steps, run in order:

```bash
python3 -m traust.cli metrics collect-spend --append      # traust-core spend, per skill
python3 -m traust.cli metrics attribute-spend --reconcile
```

The second is a **gate, not a formality**: a non-zero exit means recorded
spend does not split losslessly by skill, and every
downstream figure is untrustworthy. Stop and say so.

**Why weekly and not monthly.** Agent session transcripts are retained for a
rolling window of about a month, and they are the only source for both token
counts and the per-skill split. A day that ages out is unrecoverable —
there is no backfill, and traust-core keeps only what was captured. Monthly runs
with zero margin: one slipped week and the tail of the previous month is gone
permanently. The chain is deterministic and runs in seconds, so the cadence is
set by data-loss risk, not by cost.

**Capture frequency and reporting period are different things.** The reporting
period stays monthly (`/financial-tracking report`, `bu`); only capture needs to
be weekly. Capture is lossy if you are late; reporting is not.

**This leg is workstation-bound** until transcripts are centralized on the
platform. Leave, or a powered-off laptop, slides the window regardless of
intended cadence.

## Credentials & service accounts for autonomous runs

What the standing jobs need from the platform orchestrator's environment to
run headless. Resolve every row for your deployment before scheduling it.

| Requirement | Consumers | Notes |
|---|---|---|
| **Service identity for each `github`-kind host** (dedicated — not a human's PAT) with read access to the audited orgs, exposed as `GITHUB_TOKEN` | router stages 1–2 (`gh api`), `/dependency-watch`, python3 -m traust.cli check drift (private ADR-registry repos), audit API lookups | A full fleet run consumes most of a core API quota hour and the router's preflight assumes it has the whole window — sharing a human's quota starves both. Anti-scraping **secondary bans are invisible to the `rate_limit` endpoint**: keep fleet sweeps single-pass with bounded parallelism and error-streak gating. Token via env/header only, never argv (rule S5). |
| **Service identity for each `gitlab`-kind host**, as the env var `forge_tokens` names for it in `traust.yaml` | router stages 1–2, ledger/MR flows, secure-rpm-audit | Never in argv or clone URLs — a token-in-URL remote leaks into artifacts. A network-gated host needs a path from the orchestrator, and a run that cannot reach it must surface as `unreachable`, never falsely green (the router's behavior). |
| **Clone credentials via ambient helper** | every lane that checks out code | No credentials in clone URLs; the runner image carries a credential helper wired to the service identities above. |
| **Model-platform credentials + spend recording** | all agentic lanes (full audits, diff scans, triage, verify sweeps) | Per the model-routing contract (docs/model-routing.md); batch spend recorded with `model_registry.py spend` so the budget guard and dashboards stay truthful. |
| **`execution.sandbox` in `$TRAUST_CONFIG_HOME/traust.yaml`** | remediate-finding Phase 4 checks and Phase 4b mutation, property-test differential | Sets how target build/test code runs: `none` (default — direct, scrubbed env, disposable copy) or `podman` (nested rootless container). Leave `none` on a runner that is itself a locked-down job and cannot nest containers; that is the expected orchestrator shape. A configured `podman` mode is never downgraded — without a working runtime the lane reports `not_attempted` and produces no evidence, so do not set it on a runner that lacks one. Detection is `podman info`, so a job image shipping the CLI without a runtime is correctly treated as unusable rather than failing with exit 125. |
| **Scanner binaries in the job image** | deterministic pre-scans; the freshness view's `tool:*` rows | Install the `expected` versions from traust-core's shipped `external-tools.yaml` — the manifest is the shared source of truth, so the image and traust-core's tool floors can never disagree about what should be present. govulncheck must be a *tagged* build (unstamped `go install` builds defeat freshness tracking). Absent tools degrade loudly (`pending`), an install below the manifest floor is not ready, but an image without the scanners isn't doing continuous scanning. |
| Unauthenticated feeds: OSV, EPSS, KEV, Go module proxy, PyPI | deps lane, feeds refresh, drift checks | No service account needed. NVD is keyless but rate-limited — an NVD API key is an optional quality-of-service upgrade for `traust impact document nvd`. |
| **Directory service** reachability | owner assignment, countersign identity verification | Needed only by the routing/accountability lanes, not the scan lanes. Decide which identity the orchestrator binds as. |
| **Issue-tracker service account** | `/file-security-defect` (and the internal extension's backlog sync) | Must be able to set the restricted security level used for embargoed issues. Decide whether filing runs under a service identity or a human — countersign/override events remain human-signed by design. |
| **Collaboration-suite identity** | ownership-tracker updates, document permissions | Human-delegated by default; decide whether these stay operator-session-only. |

The division of labor stays as designed: deterministic runners need only tokens
and binaries; anything that *concludes* (verdicts, countersigns, pin advances)
stays with humans or operator-supervised agent sessions regardless of what the
orchestrator can reach.

## The decision table

Encoded as data in `traust.ops.router` (`RULES`), first match wins. Rule 1 (event injection) runs ahead of the
table — see *Event injection* below.

| Rule | Trigger | Lane | Why this threshold |
|---|---|---|---|
| 1 | repository in the current native inputs inventory with **no baseline audit**, including unregistered URLs | **full audit + threat-model bootstrap** (`rule-1-bootstrap`) | new intake is otherwise invisible to the loop until a human notices. No graph cache or forge calls; exposure uses the curated designation with a private default. The first audit establishes recorded change-detection and dependency-watch context |
| 2 | `C ≥ 8,000` first-party changed lines, OR `R ≥ 10%` of audited LoC (R only where `lines_reviewed` is recoverable from the baseline report) | **full audit** | above this the old audit's coverage map no longer describes the code — the baseline is *invalid*, not merely stale. The line threshold sits near the upper tail of a typical two-week change; a change that large is a new codebase for coverage purposes, while a smaller one carries little churn-attributable expected yield |
| 3 | any changed file matches the narrow sensitive-identifier matcher AND ≥200 changed lines in those files | **full audit** (P0/P1), **diff scan** (P2) | error analysis places the audit false-negative pool disproportionately in auth/config paths — sensitive-path change is the highest-yield trigger and is never throttled. The *narrow* matcher discriminates; a broad infrastructure matcher hits almost every changed repo and is useless |
| 3b | every changed file is a dependency manifest | **deps lane (classification, not a queue)** — the row classifies manifest-only change for advisory-first `/dependency-watch` analysis. The former impact-finding router is retired; core finding intake owns its unfinished filing skill port, with no executable fallback. `/dependency-watch` does not read these worklist rows | manifest-only changes are common and deterministic reachability avoids a full agent scan; analysis is not proof of successful finding admission |
| 4 | audit age > tier ceiling: **P0 180d / P1 270d / P2 365d** | **full audit** | backstop for slow-drip churn that never crosses rules 2–3, and the re-application vehicle for methodology gains. Every full re-visit recovers some findings from *unchanged* code (run-to-run detection variance) — ceilings are a discovery mechanism, not just hygiene |
| 5 | any other first-party change (`C > 0`) | **quarterly diff-scan pool** | new crit/highs do **not** scale with churn; the below-threshold pool carries a small, steady expected yield, so a monthly latency costs far more per finding than full-audit visits do — quarterly keeps changed code ≤90 days unexamined at a fraction of the cost |
| 6 | `pushed_at` moved but 0 commits ahead | none | tag/branch push noise — a noticeable share of stage-1 candidates; the compare, not `pushed_at`, is authoritative |
| 7 | no qualifying change | none | dormant repos re-enter automatically on their next push; dead code is never calendar-rescanned |
| — | `no-pinned-sha` + push signal | **full audit** | a baseline without a parseable `metadata.commit` cannot be change-detected; the fresh audit re-establishes the anchor (self-healing) |
| — | `quota-deferred` | none (next run) | stage-2 compare didn't fit the API quota hour; honest "not classified yet", converges next day |
| — | **tripwire** | **diff-scan** (immediate) | gitleaks runs over the change's patch text for every below-threshold routed row (no clone; GitLab patches arrive free in stage 2, GitHub costs one quota-aware call) — a secrets hit collapses that row's exposure from ≤90 days to ≤1 day. gitleaks is required up front: a run without it refuses before the worklist builds. Routes only; the diff scan adjudicates. `--no-tripwire` disables. Manifest-only changes already reach osv via rule 3b |
| — | **iac route** | **iac-lane** / **iac-baseline** (additive) | any changed first-party file matching `IAC_RX` (Terraform/`cloudformation|cfn` dirs/ARM+Bicep — what `/secure-code-audit`'s Kubernetes-hardening arm does NOT cover) emits an ADDITIVE row alongside whatever lane the table picked: a full audit never runs Checkov's TF/CFN/Bicep policies, so one lane would silently drop the other. `iac-lane` = the repo has a `/cloud-config-audit` baseline (findings.db `report_kind='cloud-config'`) → re-run against it; `iac-baseline` = no baseline yet → the full run creates one. Dispatch = `/cloud-config-audit <clone>`. Quarterly re-baseline rides checkov-pin advances (drift-watch item) |
| — | **threat-model pr stamp** | **rides its diff row** (no new lane) | a `diff-scan` / `diff-scan-quarterly` row whose change touched a sensitive-identifier path (`SENSITIVE_RX`) or an interface-bearing path (`TM_SURFACE_RX` — `cmd`/`api`/`handler`/`route`/`controller`/`webhook`/`middleware`/`admission`/`server`/`endpoint` directories, `main.*`, OpenAPI/Swagger specs, `*.proto`) carries a `threat_model_pr` stamp. The dispatcher then runs `/threat-model pr <clone> --base <resolved anchor>` on the clone the diff scan **already made**, at the anchor it already resolved — a separate lane would re-clone the same repo at the same SHA to ask a different question about the same diff. **Report-only**: `pr` writes no model and re-stamps no SHA; promoting to an auto-applied `update` is a separate decision after a calibration window. `TM_SURFACE_RX` is directory-anchored on purpose (the broad-matcher lesson in rule 3) and is re-derived quarterly with the other thresholds. Rows with no model to assess against are counted (`pr_skipped_no_model`), never silently stamped |
| — | **threat-model review** | **threat-model-review** (additive) | a `release` event whose `release_change` is `major` or `minor` routes one review row per repo (deduped — a single payload bump emits many image events). `patch`, `backfill`, `initial` and `unknown` are honored as passthrough and **counted in `summary.threat_model.release_changes`**, never re-modelled. Dispatch = `/threat-model review --auto` (report-only; the operator promotes to `--apply` per repo) |
| — | **threat-model backstop** | **threat-model-quarterly** (additive, trickle-drained) | a repo whose HEAD model's provenance `date:` is older than the calendar threshold (92 days) and which got no change-triggered re-model this run. The other two threat-model triggers fire only on change, so this is the lane for code that is quiet while its threat landscape is not. Excludes repos already carrying a review row. Reading provenance is local and cheap — a tail-read of the model's provenance section |
| — | **refusal pre-route** | **full audit** | diff-lane rows the resolver would refuse at dispatch are re-routed at build time — a clone-then-refuse dispatch still costs a run. Two legs: a `truncated` compare (GitHub caps `files[]` at 300; GitLab caps `diffs[]`) means C is an *undercount*, so the resolver's clone-side numbers would cross a refusal threshold; and the resolver's >30%-of-first-party-files rule, checked via one quota-aware GitHub tree call per candidate row. The ratio leg is scoped to dispatch-imminent rows (every immediate diff-scan + the quarterly rows inside the next 2 weekly tranches, ≥3 changed first-party files) — an unscoped sweep exhausts the API quota mid-run; tree-fetch failures are counted (`tree_failed`), never silent. GitLab rows skip the ratio leg honestly (no cheap tree count) and stay with the resolver. `--no-preroute` disables. Routes only; the resolver remains the dispatch-time authority |

**Signal definitions.** `C` = summed line changes over *first-party* files only
(excluded: `vendor/`, `node_modules/`, `third_party/`, `dist/`, `*_generated*`,
`*.pb.go`, docs-only `*.md`). `S` = a changed path matching the narrow
sensitive-identifier regex (auth, login, token, secret, cred, crypt(o),
tls/ssl/cert, session, passw, rbac, scc, privilege, sanitize/escape,
deserialize/unmarshal, jwt, oauth, saml, acl — the exact regex lives in the
script and is imported by the diff lane's resolver so the two can never
diverge). Dependency manifests: go.mod/sum, package.json + lockfiles,
requirements*/poetry.lock, pom.xml, Cargo.*, Gemfile*. Both stages are API-only
— no cloning.

**Exposure classes.** Tiers decide what *triggers* a scan; exposure decides how
long a triggered scan may *wait*. A 2×2 of visibility × externality,
**externality dominant**, ranked scan-the-most → scan-the-least. "External" is
a **repository exposure designation** — does the repo's code reach customers or
externally-facing services — curated in
`findings/_manifest/exposure-designations.json` (`--designations`; exact-URL or
org-prefix matches, values `external` / `internal-tooling`). It is **not** the
corpus ownership/BU tag. The visibility axis comes from the stage-1
`visibility`/`fork`/`parent` fields at zero marginal API cost, and **public
visibility defaults to `public-external`** (public ≈ productized) unless the
repo is designated `internal-tooling`:

| Class | Meaning |
|---|---|
| `public-external` | product code made available to customers — largest attack surface |
| `private-external` | private tooling/service repos powering customer-facing services |
| `public-internal` | tools you use but don't productize (world-readable, no customer path) |
| `private-internal` | internal tools that never reach open source or customers |

**The tiering applies universally across the entire audited corpus.** Corpus
ownership / business-unit tags (the `ownership` enum — see
[report-structure.md](report-structure.md)) are metrics-accounting labels only
— they decide which dashboard counts a finding, and play **no role** in
exposure class, routing, ceilings, or drain order. Never use them as a risk
signal.

A private repo that forks/tracks a public upstream counts as *public* on the
visibility axis (the upstream is attacker-readable and its vulnerabilities
propagate on rebases and bumps) — undesignated it lands at `public-internal`
(rank 3, the upstream elevation does not ride the public≈productized default);
designated `external` it lands at `public-external`. Effects: exposure is the
primary sort key inside every lane; the **external band** tightens the rule-4
ceiling one notch (P1 270→180d, P2 365→270d) and is flagged overdue when
undrained past 14 days.

**Risk tiers** (from live crit/high counts, `FindingService.open_count`,
through traust-core's `PortfolioPolicy.risk_tier`): P0 = ≥5 live crit/high, P1 = ≥1, P2 =
clean-and-active, P3 = archived or dormant (>365d no push). Duplicate filings of
one repo are deduped by normalized URL; risk = max across sibling filings.

The thresholds above are re-derived quarterly from the router's own telemetry
and the deployment's paired-audit false-negative calibration. Treat this table
as the operational contract and the deployment's cadence plan as the evidence.

## Lane weights — what each lane reads, costs, and buys

Per-run cost is measured per deployment from session transcripts and recorded
in its cost report; what follows is the relative weight and what each lane buys.

| Lane | What it actually does | Relative cost | Discovery power |
|---|---|---|---|
| Full code audit (`/secure-code-audit`, dual-pass) | whole-repo, threat-model-scoped, ~19 analysis operations across two independent traversal-varied passes + all deterministic pre-scanners | heaviest | the highest anchor recall of any lane; the second pass adds measurably; re-visits recover findings even on unchanged code |
| Diff scan (`/vuln-scan --diff`, context-packet path) | deterministic packet (changed hunks + symbol-index callers + baseline slices) reviewed packet-first, pre-scanners on the changed set, deduped against the baseline | several times cheaper than a full audit | full attention on the changed surface; by design forgoes the unchanged-code recall catch-up a full visit gets |
| Container audit (`/secure-container-audit`) | registry artifact: skopeo config/signature posture + syft SBOM + grype CVEs + source-drift check — no source review | medium | shipped-artifact assurance; immutable per digest |
| RPM audit (`/secure-rpm-audit`) | spec/scriptlets/patches + prepared source tree | medium-heavy | packaging + patched-upstream lens |
| Targeted class sweep | one weakness class, purpose-built prompt, whole fleet slice | medium | strong standalone recall *inside its class* — the only measured mechanism recovering the configuration-class blind spot that every general scan shares |
| Verify sweep (`/verify-remediation`) | per-finding targeted re-audit of previously-filed findings | light | produces verification evidence; ledger resolution and regression admission remain unported |
| Threat-model review (`/threat-model review --auto --apply-ratings`) | deterministic `git diff` pre-pass from the model's provenance SHA, then re-scores **only what moved**; writes OWASP ratings for any unrated threat, everything else report-only | light (bounded by what moved) | keeps the audit coverage diff honest — the surface an audit checks itself against |
| Threat-model pr (`/threat-model pr`) | bounded assessment of one diff, on a clone the diff scan already made | light (bounded by one diff) | flags new entry points / trust boundaries a diff introduced |
| Deps / routing / Kubernetes-hardening / gitleaks lanes | deterministic tooling | none | rule-pack precision, no judgment |

The threat-model lanes run **uncapped** by default so that a deployment's first
quarter produces the measurement; reconcile actual spend against
`--threat-model-drain-rate` before deciding whether a weekly ceiling is needed.

The heavier the lane, the more it re-reads beyond the change — that is
deliberate: whole-repo re-reads are where marginal discovery lives (re-visits
recover findings independent of churn), so heavy lanes are pointed at invalid
baselines, risk concentrations, and ceilings rather than spread evenly. When
choosing by hand, the rule of thumb: **baseline invalid → full audit; baseline
valid + bounded change → diff scan; artifact released → artifact lane; finding
claimed fixed → verify; class suspicion → sweep.** The router encodes exactly
this.

## The diff lane

`diff-scan` / `diff-scan-quarterly` rows are dispatched as
`/vuln-scan <checkout> --diff` (`harnessing/3-audit/vuln-scan/SKILL.md`, "Diff
mode"). The mode auto-resolves its own baseline — `traust assessments prepare
--diff` (traust-core's `AssessmentService.prepare`) looks up the newest
completed `secure-code` audit of the repository's default branch and
anchors the diff at that audit's commit, using the router's first-party
filter and sensitive matcher (one owner in traust-core, so the two can never
disagree). `--since`/`--baseline` exist as overrides only. When the diff
invalidates the baseline (>30% of first-party files changed, C ≥ 8,000
first-party lines, no baseline resolvable, or anchor unreachable) the resolver
refuses with `recommend: full-audit` — re-dispatch the row to the full-audit
lane; the diff lane never silently substitutes for a full audit. Each diff
report stamps `metadata.additional.coverage_diff` (covered/refused split plus
the `(baseline_report, anchor, resolution_source)` triple) — the telemetry the
quarterly threshold re-derivation and recall benchmark consume — and a
`metadata.additional.spend` calibration stamp.

**Fleet dispatch is an operator decision, informed by measured cost.** Measure
per-run cost from transcripts before scheduling the drain: a completed diff
scan, a refusal (clone-dominated, much cheaper), and the mix of small and heavy
diffs in the pool each price differently, and context packets help least when
the diff itself is the bulk of the work. The diff lane runs several times
cheaper than the full audit it substitutes; refusal pre-routing and context
packets are the shipped cost reductions, and packets also open a batch-lane
path via one-shot restructuring (unbuilt). Rule-3 P2 and rule-5 rows
accumulate in the worklist until dispatch is scheduled; rule-4 ceilings bound
how long they can wait.

## Coverage model — the four+one ways a vulnerability arrives

| Arrival channel | Mechanism | Latency |
|---|---|---|
| New CVE in a dependency | deps lane: OSV API fleet sweep on new advisories → `/impact-analysis` reachability (not available air-gapped) | daily, deterministic |
| New vuln introduced by a code change | change-detection loop: rule-2 fulls (weekly batches), rule-3 sensitive fulls/diffs (monthly), rule-5 diffs (quarterly) | days–quarter, by risk |
| Existing vuln the audits missed (FN) | quarterly class sweeps at measured FN classes; rule-4 ceiling audits; dual-pass default | quarterly + ceilings |
| New vuln class / detection technique | methodology events: recall-raising harness release → P0 re-audit ≤1 week; ceilings re-apply improvements fleet-wide | ≤1 week (P0) |
| **External report against your own code** (product security team, researcher, customer) | event-injection lane: immediate full audit + validation of the named repo | next router run (≤1 day) |
| **Attack surface the model never described** (new entry point, new trust boundary, surface added after the model was written) | threat-model re-model cadence: `pr` stamp on surface-touching diffs, `review` on major/minor releases, calendar backstop. Without this channel the audit coverage diff is measured against a model that never ages out, so new surface reads as "covered" | change: with the diff row; release: ≤1 day; quiet code: ≤1 quarter |
| **Newly added dependency, no advisory yet** (typosquat, hijacked maintainer, install-script payload) | today: osv at add time catches *known*-vulnerable versions only; real scrutiny at the next full audit. Planned: a deterministic reputation tripwire on added packages (age, typosquat distance, install scripts, Scorecard) + a fleet "first seen" dependency ledger | today: up to one ceiling period; with the tripwire: ≤1 day |

**Measured residuals** — what "continuous" does NOT guarantee: the
below-threshold churn pool carries a small expected number of unscanned
crit/highs held at most one quarter; a share of ground-truth anchors is missed
by every scan configuration and is recovered by the quarterly class-sweep
rotation, not by more rescans; per-pass audit recall is well below 1. A
deployment re-measures all three quarterly from router telemetry and records
the numbers in its calibration report.

## From signal to accountability — where every lane's output lands

The diagram's final arrow describes the intended accountability chain, not a
working legacy ingestion path. There is one core-owned finding history; no lane
may create a competing mutable record or bypass admission policy.

1. **The router never emits findings.** Its routes are routing
   instructions. Tripwire and dependency hits are escalations with evidence
   attached, not verdicts.
2. **Agent lanes produce assessment evidence.** Audits, triage, validation and
   remediation verification retain their report contracts. Scanner intake,
   `traust triage record` and `traust validation record` use core-owned
   admission; retired direct-entry routers and cumulative union/replay builders
   are not fallbacks. Other unfinished skill ports must be reported as such.
3. **Report evidence is not a saved decision.** Core finding decisions and
   ledger services own persistence and integrity. `/track-findings` uses
   `traust findings` for source imports, direct human judgements and selected
   review answers; it neither ingests machine reports through a legacy emitter
   nor refreshes legacy files.
4. **Dependency evidence uses its domain owner.** `traust feeds fetch`
   snapshots advisory feeds in core; `traust impact sweep` matches recorded
   SBOMs against OSV; `traust impact analyze` records per-commit impact
   assessments and admits dependency findings for `affected` commits through
   core exposure/finding services. A raw match is not a verified verdict.
   Preserve source advisory/classification evidence and declared severity;
   never invent classifiers or use the retired impact router. Findings and
   assessments are not a promise that owner routing, SLA dashboards or issue
   filing have completed.

The old `findings-current` → owner-routing → issue-tracker chain remains
historical context until its producing service and skill ports are complete.
Do not report end-to-end accountability from a successful scan or dashboard
consumer run alone.

## Event injection

Operators (or feed importers) append records to
`analysis-results/findings/_manifest/rescan-events.jsonl`, one JSON object per
line. The file must exist: `rescan_event_intake` refuses a missing one rather than
reading it as no events, so a deployment without events keeps it empty.

```json
{"source": "external-report", "repo": "https://github.com/org/repo",
 "report": "incoming/researcher-report.md",
 "targets": "config/authorized-lab-targets.yaml",
 "note": "researcher report <tracker-id>",
 "date": "YYYY-MM-DD", "consumed": false}
```

`source` is `external-report`, `methodology`, or `cve`. External reports require
both a whitespace-free `report` input reference and a mode-1 `targets.yaml`
scope. Intake binds a canonical event digest into each immutable order manifest
and plans an operator-approved `external_report_audit` plus a distinct
operator-approved `external_report_validation` that waits for the audit, runs
`/validate-findings <report> --targets <targets> --auto --replay-only`, and has
its own outcome. The manifest also binds both input references.
Methodology events queue a full audit only for P0-tier repos; P1+ catch up through the
rule-4 ceiling. CVE events queue an immediate `cve_impact` order running
`/dependency-watch`. Release rows are refused: there is no traust-core release feed yet
(NEED(release-passthrough)).

`rescan_event_intake` has higher scheduling priority than `repo_state`, but both
depend on inventory discovery; there is no completion dependency between them.
Concurrent workers can start ordinary observation before event intake finishes.
Each canonical row's digest is bound into Core's order manifests. Existing open
work is not duplicated, and successful or degraded completion is not dispatched
again. An unsuccessful terminal audit or validation remains visible: subsequent
intake ticks return degraded and log its event digest, asset and order ID.
There are no automatic paid-audit or live-validation retries.

History and manifests are read once per repository/asset group in each tick;
new bindings update that tick's index immediately. When another event owns an
open order for the same group, intake degrades and revisits the waiting row on
the next tick rather than coalescing its inputs.

`consumed` remains an explicit operator archival marker. Review unsuccessful
work before archiving it. An intentional retry can be requested by archiving
the reviewed row and appending a new event with a distinct date/note that records
the retry intent; the new row has its own canonical identity and approvals.
Archiving does not rewrite the failed order as successful. Malformed, unsupported
or unregistered records fail or degrade rather than disappear. Rejected inventory
entries are logged by run ID, entry index and failure class, never raw URL or
exception payload.
If Core's inventory loader rejects a file before materialization, the CLI returns
a failed bad-request result without its validation payload or traceback. Correct
the inventory before retrying discovery; this is not partial success.

### Event feeders

Releases are recorded, not fed. A product version is recorded with
`traust portfolio import-release` (the commits it ships); its change is derived on demand:

```bash
traust portfolio import-release --help
traust portfolio release-changes --product <slug> --version <v>
```

`release-changes` derives the registered release's version movement and added/
removed commits; only major/minor movement requests a threat-model review.
Release discovery from inventory files (payload digests/tags, watched dist-git heads) is
retired: a release's identity never comes from inventory paths. The router's
`release-passthrough` lane is taken by the `release_passthrough` asset, which refuses its
order until traust-core has a release feed to plan container and RPM audits from
(NEED(release-passthrough)).

The retired `/repo-graph` and SQLite graph database are not event authorities.

## Running the router

The router runs inside the engine: `traust-engine shadow … --router
traust.ops.router:SecurityRouter` to see what it would plan, `traust-engine run`
to plan and admit (below). Forge quota is the `repo_state` asset's concern: a
compare that doesn't fit is `quota-deferred` and the next observation
classifies it, never silently lost.

## The shadow run — the engine beside cron, until the cutover

Before traust-engine takes over a standing job, it runs next to cron without
dispatching, and a daily diff shows where the two disagree. Every difference is
fixed or written down; a group of jobs moves to the engine only after two weeks
with none unexplained. `traust-engine` is installed separately from traust (the
runtime image includes it); locally, `uv tool install "traust-engine @
git+https://github.com/traust-security/traust-engine@<sha>"`. Every command takes
the same three paths:

```bash
SHIPPED=$(python3 -c "from traust_core.v1.context import config; print(config.SHIPPED_EXTERNAL_TOOLS.parent)")
E="--core $TRAUST_CONFIG_HOME/traust.yaml --pack packs/security/assets.yaml --pin $SHIPPED/external-tools.yaml --feeds $SHIPPED/feeds.yaml --models $TRAUST_CONFIG_HOME/model-registry.yaml"

# each cron job, wrapped: its run becomes an order the engine counts
traust-engine record $E feeds_cache -- traust feeds fetch --feed all
traust-engine record $E repo_state --repo <url> -- traust portfolio observe --repo <url>

# every 15 minutes: what the engine would plan, one JSON line per pass
traust-engine shadow $E --router traust.ops.router:SecurityRouter --once >> shadow.jsonl

# daily: missed (the engine wanted it, nobody ran it) and early (run before its cadence
# fell due); exit 1 if anything differs
traust-engine diff $E --shadow shadow.jsonl
```

`record` takes over the subject's open order if there is one, so there is still
one open order per asset and repository. `shadow` reaps, plans and admits
nothing. `traust-engine run` is the loop itself, for after the cutover.

### Running orders: `traust-engine claim`

After the cutover, `traust-engine run` plans and admits, and a runner does the
work. `traust-engine claim $E` leases one queued order of an asset with a `run`
command, fills its `{run_id}`, `{repo_url}` and `{rule}` (the router rule that
routed it) tokens from the order, renews the
lease while the command runs, completes the order with the command's JobResult
and exits (0 succeeded, 1 failed, 4 degraded, 5 refused; nothing queued is 0).
It is claim-once, started by an operator or a scheduler, never a daemon.
A skill session is a command too: its `run` is `traust session run --skill
<skill> --role {role}`, which resolves the role's model from the registry and
starts the skill headless in the harness (a repository it reviews is passed by
URL, or as a temporary checkout outside the harness with `--checkout`). A diff
scan whose `--rule` carries the threat-model `pr` stamp then runs `/threat-model
pr <checkout> --base <anchor>` on the same checkout, the anchor from `traust
assessments prepare --diff`; a refused diff skips it, said on stderr. Its
outcome is the session's exit. Pass `--feeds` (traust-core's shipped `feeds.yaml`) to every
`traust-engine` command so core knows the pack's feeds when a run reports one
degraded.

The session's measured usage (Claude Code's JSON result, per model) rides on its
JobResult, and completing the order records it as the order's spend in the same
transaction, in the order's lane, priced by the registry `--models` names; usage it
can't price (no `--models`, or a model the registry doesn't list) still completes
the order and is counted under `spend-unpriced` in its run manifest. Sessions run
with their own Claude config dir, `<config home>/claude-runner` (log in there once
with `CLAUDE_CONFIG_DIR=<it> claude`, or set `ANTHROPIC_API_KEY`), so their
transcripts stay out of `~/.claude/projects` and `traust metrics collect-spend`
(workstation sessions) never counts them twice. `traust metrics lane-costs --days N`
prints each lane's median settled cost per order: the measure for its
`estimate_usd`.

## The local rig — the whole loop on one laptop

The deployment shape above can be rehearsed locally: one Postgres
container, a generated config home and a compressed-cadence copy of the
security pack, all under `.local-ops/` (gitignored, regenerated by
`make ops-reset`). `traust-engine` is installed into this checkout's venv
(`--no-deps`; it needs only traust-core and pyyaml), and every rig command
runs through `uv run --no-sync` so a plain `uv sync` in between cannot
strip it.

```bash
make ops-up          # Postgres on 127.0.0.1:5433 + config home + overlay pack
make ops-doctor      # what is missing, if anything
make ops-run         # pane 1: the tick loop (OPS_EVERY=1m by default)
make ops-claim       # pane 2: claim-once loop, every 5s
make ops-approve ORDER=<id-prefix>  # approve exactly one awaiting order
make ops-approve-all # explicitly approve every awaiting order
make ops-sh          # a shell with the rig's env, for the commands below
make ops-scan REPO=https://github.com/<you>/<small-repo>   # the workflow by hand
make ops-smoke       # one bounded cycle with asserts (a manual full-rig check, not CI)
make ops-down        # stop Postgres, data kept; ops-reset drops it
```

Omitting `ORDER`, supplying a blank value, or adding extra script arguments is
an error before credentials or orders are loaded. A prefix matching multiple
awaiting orders approves none. Bulk approval requires `ops-approve-all` or
`scripts/local_ops.sh approve --all`; empty input never requests it. Selectors
remain literal through Make and the shell, including Make-function syntax.

Fresh setup creates the rig's model registry before the configuration installer
can seed shipped routing. Mythos-class roles use a shipped, approved opus-class
model for this pipeline rehearsal; this is not an audit-quality equivalence.
Existing registries are kept byte-for-byte. To restore shipped routing, copy
`config/model-registry.yaml` over `.local-ops/config/model-registry.yaml`.

A new rig without cosign deliberately configures unsigned ledger operation.
When cosign is installed, failed generation or missing/empty key halves stop
startup before database/auth continuation. An incomplete existing pair is never
overwritten: restore the matching public half, or derive it from the existing
private key with `cosign public-key --key` into a separate file before installing
it. Keep the private identity; do not regenerate over it. A later successful
setup upgrades the rig's empty unsigned placeholder, not operator-owned signing.

The runner's tool grants and Read denials are **not credential isolation**.
Granted Python/Bash can read inherited environment variables and host files.
Use disposable rig credentials only; a deployment must enforce its own execution
boundary, scrubbed tool environment and network egress policy.

The overlay pack compresses cadences to minutes (`24h → 2m`, `7d → 5m`,
`3d → 3m`, `30d → 6m`, `90d → 9m`); freshness `fail:` windows are left
alone, so a stopped rig shows its own staleness, as a real one would.
Tokens live in `.local-ops/env` (created with commented placeholders):
without `GITHUB_TOKEN`, `repo_state` orders fail as `no-credentials`; without
`ANTHROPIC_API_KEY` (or a login under the config home's `claude-runner`),
skill sessions fail as `runner-crashed`. Routed lanes (`full_audit`,
`diff_scan`) queue for approval by design — the smoke never approves, so a
smoke run exercises the deterministic assets without spend. `make ops-smoke`
(what the `ops-smoke` workflow runs on demand) asserts the cycle end to
end over two engine passes: orders drain, `feeds_cache`, `repo_state` and
`manifest_sbom` complete (degraded on a failing feed source is a pass),
nothing left running or queued. **The smoke is not CI**: the
engine runs and collects real data, so it never runs on push or pull_request
— the workflow is a manual full-rig check (workflow_dispatch), and the rig
on a laptop is the integration test.

A deployment needs the same pieces the rig writes: `process.allowed_binaries`
in `traust.yaml` includes `syft` for manifest SBOMs and `gitleaks` for observation;
the rig preserves additional operator grants. `ledger_audit` is refused as `ledger_unconfigured`
until `traust.yaml` has a `ledger:` section; a runner from the runtime image
reads the harness payload (`harnessing/`, `packs/`) from `HARNESS_ROOT`, which the
image sets. A never-audited repository is observed too: `repo_state` keeps its
default head, so `manifest_sbom` and below-range cover it before its first audit.

## Standing weekly drain — orchestrator contract

The weekly trickle-drain is designed to run under an external orchestrator
(cron, Tekton, whatever schedules). The contract is three steps — one
deterministic router run, one deterministic tranche selection, one agentic
dispatch per row:

```bash
# 1. CONTINUOUS — the engine routes each repository as its repo_state is
#    observed (traust.ops.router); its orders are the routed work

# 2. WEEKLY — select this week's routed orders (the tranche
#    script is retired: the pack router's lane pacing and approval
#    replace it, *The security pack's router and its routed lanes*)

# 3. PER ROW — one headless run (agentic; this is the spend). A tranche
#    carries more than one dispatchable lane, so BRANCH ON row.lane
#    (the manifest's `dispatch_by_lane` map is authoritative):
#      clone:    git clone --filter=blob:none <repo_url> <scratch>/clone
#
#    lane diff-scan | diff-scan-quarterly:
#      scan:     /vuln-scan <scratch>/clone --diff
#                (packet path: traust assessments prepare --diff →
#                 packet-first review; a resolver refusal is a valid
#                 terminal outcome — the row routes to full-audit on
#                 the next router run, never widen the scan)
#      output:   <repo>-vuln-findings.{json,md} beside the row's
#                baseline report (where /triage finds them)
#      spend:    model_registry.py spend --skill vuln-scan
#                --batch drain-tranche-<week>
#      THEN, only if the row carries `threat_model_pr` (report-only):
#        /threat-model pr <scratch>/clone --base <the anchor the
#        resolver already returned> — SAME clone, no re-clone. Writes
#        no model and re-stamps no SHA; the assessment is the output.
#
#    lane threat-model-review | threat-model-quarterly:
#      scan:     /threat-model review <scratch>/clone --auto --apply-ratings
#                (report-only except OWASP ratings: writes the review
#                 beside the resolved model and applies only the ratings
#                 it proposes for unrated threats; the render guard keeps
#                 an incomplete model's prose. Promoting a repo to full
#                 `--apply` is a per-repo operator decision)
#      spend:    model_registry.py spend --skill threat-model
#                --batch drain-tranche-<week>
```

Orchestrator rules, non-negotiable:

- **Repo-config isolation (rule S9):** the headless agent's cwd is NEVER inside
  the clone, and target `.claude/`/`CLAUDE.md`/hooks are data under audit,
  never configuration (docs/adversarial-content-doctrine.md).
- **No credentials in clone URLs** — network-gated hosts use the ambient
  network path + credential helper; a token-in-URL remote leaks into artifacts.
- **Refusals are outcomes, not failures.** Retry only transport errors; never
  re-run a refusal as a whole-repo scan.
- **Plan the tranche from measured rates.** Price a tranche from the
  deployment's measured per-scan and per-refusal costs, not from estimates.
- *Retired:* appending batch results (counts + costs) to the metrics ledger
  (`metrics history append --source drain-tranche-<week>`); spend is in
  traust-core's spend ledger and the ops timeline.

A dead observation leg surfaces as overdue `repo_state` orders in the engine's
feed, without the orchestrator having to monitor itself.

## Budget knobs

**Where the ceiling comes from.** Two independent things get called "the
budget", and only one of them can stop a run:

| | What it is | Does it gate a router run? |
|---|---|---|
| `budgets` in `$TRAUST_CONFIG_HOME/traust.yaml` | the policy artifact; its `enforcement` field is `none`, `observe`, `advisory`, or `enforced` | Only at `advisory` or `enforced`. At `none` or `observe` its sole consumer is the spend dashboard's budget-vs-actual chart |
| `--monthly-budget` | explicit operator flag | **Yes** — always |

**Observe mode.** With `enforcement: observe`, every weekly tranche computes a
budget verdict, records it, and **withholds nothing**. This is a measurement
instrument, not a control, so that "how often would the cap bind" is answered by
counting real verdicts rather than predicted.

The safety property is structural, not a convention: `read_policy_budget()`
(the drop path's reader) reports `observe` as **no ceiling**, so `apply_budget()`
physically cannot see one. The ceiling is visible only through
`read_policy_shadow_ceiling()`, which can't filter a work list.

In continuous ops the verdict is traust-engine's: admission checks each planned
order against its lane budget (`Config.budgets`) with the asset's
`admission.estimate_usd`, and records the verdict in the order's run manifest
(`budget`), so the hit rate is a count over manifests. At `observe` nothing is
withheld. (The weekly tranche's `budget_shadow` block retired with the tranche.)

Three details that keep the number honest:

- **Month-to-date comes from per-lane attribution, not the workstation total.**
  A scanning ceiling is derived for steady-state scanning; judging it against
  total workstation spend, which includes everything else an operator does,
  would fire every month and mean nothing.
- **Lanes with no measured unit cost** are counted and named, never priced at
  zero — and they are never selected for withholding, since giving up a row of
  unknown cost frees nothing.
- **`ceiling_unmeetable` is reported explicitly.** With event-injected and
  rule-3 rows protected, the projection can exceed the ceiling with nothing
  left to give up. The report says so rather than looking satisfied.

Sacrifice order, when a verdict does select rows: **risk-ordered and
lane-agnostic** — least exposure first, then lowest tier, regardless of lane.

`read_policy_budget()` reads the policy and returns *(ceiling, why)*. The `why`
string lands in `summary.budget_source` and in the MD summary, so a null
ceiling is never mistakable for "no budget configured". A regression test pins
the shipped policy posture to non-gating; if it fails, the activation was
deliberate and should be confirmed, not asserted away.

`enforcement: enforced` is legal only on the central platform; in a user
checkout it warns and applies the ceiling at advisory strength. A policy that
asks to gate but carries no readable figure is a loud `BUDGET CEILING MISSING`
line, never a silent no-op.

When a ceiling does bind, the router drops lowest-tier table-routed fulls to fit
and lists every drop in `dropped_for_budget` — no silent truncation; event rows
are exempt. When the monthly ceiling binds for real, the knob order is: (1)
batch-restructure the one-shot stages and pursue committed-use pricing
(agentic lanes cannot use a batch API that takes independent one-shot requests
only), (2) raise the rule-2 C threshold — and never touch rule 3: sensitive
changes are the highest-yield trigger.
