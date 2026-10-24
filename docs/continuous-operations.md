# Continuous scanning — the standing rescan loop

> **Scope.** This is the **work-routing** document: the rescan router, its lanes
> and cadences, and the standing jobs built around them (spend capture,
> dashboards, drift, credentials). It is one of four kinds of routing in the
> harness — see **[routers.md](routers.md)** for the index, and
> **[findings-routing.md](findings-routing.md)** for how a finding reaches the
> ledger, which is a different mechanism with the opposite direction.

How the harness keeps every audited repository's assurance current after its
first audit: a deterministic daily router decides which scan lane each repo
needs, and the dispatch lanes (full audits, diff scans, the verify treadmill)
consume its worklist. The deps lane is the exception: its worklist rows are
coverage classification — the daily `/dependency-watch` run covers that class
advisory-first without reading the worklist (see rule 3b).

The thresholds and tier ceilings in this document are the router's shipped
defaults. A deployment re-derives them from its own router telemetry on a
quarterly cadence and records the derivation in its own planning documents;
this page is the operational contract, not the evidence.

## The loop

```
             (daily, deterministic, no agent spend)
   gh/glab fleet refresh ──► python3 -m traust.cli build rescan-worklist ──► rescan-worklist.json
                                     │  stage 1: pushed_at ≥ audit_date → candidates
                                     │  stage 2: compare API (C, S, DEPS, zero-diff)
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
      └───────────┴────────┴──► /triage ──► ledger ──► dashboards
```

The threat-model lanes are the exception to that last arrow: they refresh the
*scope* an audit checks itself against, so their output feeds the next audit's
coverage diff rather than the ledger. They never file a finding.

The router routes only — it never authors a finding, verdict, or audit. Its
output is `analysis-results/findings/_manifest/rescan-worklist.json` plus a
human summary (`rescan-worklist.md`) beside it; `/drift-watch` flags the
worklist when older than 3 days.

## Hosts and credentials

Repositories are reached through the hosts registered in `GIT_HOSTS`. Each
entry is `kind:host`, and the kind selects the transport, because the API and
the CLI differ per forge:

    GIT_HOSTS="gitlab:gitlab.example.com,github:ghe.example.com"

| Registered kind | Stage-1 / stage-2 transport | Credentials |
|---|---|---|
| `github` (github.com is registered by default) | `gh api repos/{org}/{repo}` and `.../compare/{sha}...HEAD` | `gh` CLI auth or `GITHUB_TOKEN` |
| `gitlab` (gitlab.com is registered by default) | `glab api` → `/api/v4/projects/:path` and `/repository/compare` | `glab` CLI auth store or the `GITLAB_TOKEN` env var — never in argv |

**Only these two kinds are implemented.** A repository on any other forge is
not unsupported by policy — nothing rejects it — but no transport claims it, so
it lands as `unsupported-host` below. Adding a forge means adding a kind and its
transport, not editing this table.

A host may be network-gated: with that network down, its repos get per-repo
status `unreachable`, the population counts them, and the MD summary carries a
loud warning — a run with the network down reads as incomplete, never as
falsely green. A missing forge CLI yields `no-credentials`. Hosts not registered
in `GIT_HOSTS` get `unsupported-host`. All three statuses stay listed in the
worklist (the age-ceiling rule still applies to them); nothing is silently
dropped.

## Lane cadences

| Cadence | What runs |
|---|---|
| Daily (automated, deterministic) | fleet refresh + router → fresh worklist; `harnessing/2-threat-model/threat-model/scripts/build_release_events.py` — the release/dist-git event feeders (see *Event feeders*); `/dependency-watch` — the advisory-driven deps lane end to end (feeds → `/impact-analysis` → python3 -m traust.cli route impact-findings direct-entry filing) |
| Weekly session | dispatch the worklist's full-audit rows as a batch; `/verify-remediation` treadmill sweep (`harnessing/8-verify/verify-remediation/scripts/build_verify_sweep.py`); triage new findings |
| Monthly | sensitive-change P2 diff scans; validation session (criticals validated-or-blocked inside the SLA window); spend reconcile against the budget policy |
| Weekly (trickle) | the `diff-scan-quarterly` pool drains as a risk-ordered weekly trickle: dispatch rows with `drain_order < weekly rate` (default ceil(pool/13) — the same quarterly volume as a 90-day batch, but a short stable queue instead of a long tail; external-band rows first, target ≤14 days in-pool). Dispatching the drain is an operator decision informed by the deployment's measured per-run cost (see *The diff lane*); the drain ordering accumulates until scheduled |
| Weekly (rule mining) + post-wave | python3 -m traust.cli sweep rule-lane — the /mine-ledger lane: ledger miner → sweep-engine collect/draft → bounded regression-draft staging → delta report vs the previous `rule-mining.json`. Inputs: the disposition ledgers (`*-findings-current.json`) + audits' `scanner_correlation` judge decisions. Outputs: `lane-delta.{json,md}` under the metrics tree + staged rule drafts, then calibrated pack rules via the scheduled `/mine-ledger` session (the mechanical test-and-calibrate gate is the promotion criterion; sweep hits and mined candidates still route to `/triage` — the lane never auto-files findings). Post-wave trigger: `/drift-watch`'s `rule-mining` row goes stale when ledger changes are >7d newer than the artifact |
| Weekly (threat-model trickle) | the `threat-model-quarterly` pool drains alongside the diff pool, on its own weekly rate (default ceil(pool/13)): dispatch rows with `drain_order < summary.threat_model.quarterly_weekly_rate` as `/threat-model review --auto`. The rate is a **cadence spread, not a budget cap** — no row is ever dropped, only scheduled; `--threat-model-drain-rate` can impose a hard weekly ceiling if spend warrants |
| Quarterly | class-sweep rotation at the measured FN classes; threshold re-derivation from router telemetry; recall benchmark; the threat-model calendar backstop completes one full pass |
| Event-driven | rows injected via `rescan-events.jsonl` (next router run, ≤1 day) — including `release` rows, which additionally route a `threat-model-review` row on a **major/minor** bump |

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
| Fleet refresh + rescan router | daily | timer | python3 -m traust.cli build rescan-worklist | routes only, never authors findings; drift row `rescan-worklist` flags a worklist >3 days old |
| **Feed-source liveness** | rides the drift run | probe | `python3 -m traust.cli check drift` (`feed-source:*` rows) | Probes every source in `config/feeds.yaml` carrying a `probe` — both tiers — so a live-tier source that answers with an error is visible. A definitive HTTP error is `drift`; a transport failure is `unavailable`, never `drift`, so an offline workstation does not report every source as broken |
| Release/dist-git event feeder | daily, beside the router | timer (inventory-CSV diff + dist-git `ls-remote` movement vs the committed seen-set) | `python3 harnessing/2-threat-model/threat-model/scripts/build_release_events.py` | emits events only; the router routes them; dispatch marks `consumed` |
| `/dependency-watch` (deps lane end to end) | daily | timer (advisory publication) | `/dependency-watch` | findings enter the **ledger** via direct-entry at `not_verified` — the claim rides on the event, the baseline is never written (gate A15); `/triage` adjudicates downstream; severity from the advisory, never invented. See [findings-routing.md](findings-routing.md) |
| **Feed router** — security-data refresh (EPSS / KEV / vendor CVE and VEX feeds) | **daily** | timer | `python3 -m traust.cli feeds fetch --feed all` | Orchestrator-neutral ([routers.md](routers.md)), deliberately not bound to a CI pipeline in this repo. Snapshots every `tier: cached` source in `config/feeds.yaml` through traust-core (`ExposureService.refresh_feeds`: a `feed_snapshot` per source, the bytes in core's object store; `rh-cve` fetches only what published since its last snapshot). A dedicated job exists because consumer-triggered refresh only holds while something runs daily; without one the snapshots silently age. Every source in `config/feeds.yaml` is public. A source that fails keeps its last snapshot and the order is **degraded**, keyed by the source; one with no snapshot at all fails the order. **Backstop:** drift rows `feeds:*` at **48h** — one missed run plus slack; a threshold looser than the cadence it guards is how a dead job stays green |
| Weekly diff-drain tranche | weekly | timer over the router's drain ordering | `python3 harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py`, then one run per tranche row **by lane** (`dispatch_by_lane` in the manifest — see *Standing weekly drain* below) | fail-closed selection (refuses a worklist >48h old or a second tranche per ISO week); dispatching is an operator decision informed by measured cost |
| Threat-model re-model lanes | rides the router (daily) + the weekly tranche | change (`pr` stamp), major/minor release event, calendar backstop | python3 -m traust.cli build rescan-worklist routes; `harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py` schedules; `/threat-model pr\|review` dispatches | **report-only** — no lane auto-applies an `update`. Drift row `threat-model` (held in lockstep with the lane's calendar threshold) is the dead-timer if the quarterly pool stops draining |
| Verify-remediation treadmill | weekly (worklist rebuilt per sweep) | timer | `harnessing/8-verify/verify-remediation/scripts/build_verify_sweep.py` → `/verify-remediation full-sweep` | verdicts gated by the verification schema + soundness lint; regressions become ledger findings via python3 -m traust.cli route regressions |
| Rule-mining lane | weekly + post-wave | timer + drift row `rule-mining` (ledger changes >7d newer than the artifact) | python3 -m traust.cli sweep rule-lane, then the scheduled `/mine-ledger` session | never auto-files findings; rule promotion sits behind the mechanical test-and-calibrate gate; sweep hits route to `/triage` |
| Ledger audit | weekly | timer | python3 -m traust.cli ledger audit (`LedgerService.audit`) | verifies every ledger layer against its stored events and signature, so an edit to stored decision events is found within a week (appends no longer re-verify the layer); a layer that fails or can't be verified degrades the order, never green |
| CVE-replay FN monitor | daily (cron-able, stdlib-only) | timer; per-ecosystem OSV watermark advances only on success | *retired with the traust-core hub*; rebuilt on `DetectionQualityService.critical_misses` (*Detection quality*), not in the pack until then | routes, never concludes (`detected`/`unclear`/`missed`); benchmark ground-truth candidates stay a human-gated queue |
| `/drift-watch` | on demand; recommended alongside every `/census`; scheduled by the orchestrator | operator / timer | python3 -m traust.cli check drift | routes attention only — never auto-rebuilds, auto-advances a pin, or files a finding |
| Census + repo-liveness refresh | no fixed timer — run at intake (`/corpus-intake` triggers it), and before denominators are consumed | operator / intake flow | `/census` (runs `harnessing/census/scripts/check_repo_liveness.py` as its Step 2b) | drift rows `repo-liveness` and `corpus-registration` flag age/unregistered trees |
| FP-precedent cache rebuild | drift-triggered — no timer | drift row `fp-precedent-cache` (new countersign/triage/validation adjudications post-build) | python3 -m traust.cli corpus precedent build | annotation only — a precedent informs a verifier, never dismisses |
| Validation benchmark | release-cut + monthly hybrid | `run_validation_benchmark.py check-trigger` (exit 10 = benchmark required) + drift row `validation-benchmark` (35d) | python3 -m traust.cli sweep benchmark | below-floor runs exit non-zero; results land in the harness-QA tree, never campaign metrics |
| Recall benchmark | quarterly, plus release scoring | timer / release cut (`--release` scores held-out targets) | `/recall-benchmark run` | manifest never enters an audited tree; held-out split scored only at release |
| Class-sweep rotation | quarterly | timer (measured FN classes) | targeted class-sweep sessions (see *Lane weights*) | sweeps produce candidates for `/triage`, never filed findings |
| Threshold re-derivation | quarterly | timer over router telemetry | re-derivation per the deployment's cadence plan | a human reviews and edits the decision table; the router never self-tunes |
| Dashboards rebuild (all deterministic dashboards: census + exec summary, trends, insecure-patterns, validation-fuzz, rbac-tenancy, sla, compliance, attack-coverage, loc, spend, scoreboard) | **weekly** (inside the scoreboard's 7d drift threshold), spend rebuild every ≤4d | timer | one command: python3 -m traust.cli dashboard refresh (skill wrapper: `/refresh-dashboards`) — the packaged sequential deterministic job, the security pack's `dashboards` asset: traust-core's insight views first (`InsightService.refresh` through `DashboardsMaterializer`); then the per-dashboard builders (`build_trends.py`, `build_insecure_patterns.py`, `build_validation_fuzz_dashboard.py`, `build_rbac_tenancy_rollup.py`, python3 -m traust.cli metrics sla, `build_attack_coverage.py`, `build_loc_dashboard.py --no-fetch`, python3 -m traust.cli metrics spend) → `collect_harness_metrics.py` last (it harvests the others) — all deterministic, no agent involved; every stage continues on error, failures are collected and reported (a degraded core view is named in the JobResult) | drift rows `dashboards:*` remain the dead-timer backstop (scoreboard >7d, spend >4d). **Orchestrator prerequisites for this job:** `$TRAUST_CONFIG_HOME/locations.yaml` must set `analysis_results` (and usually `workspace`, `progress_tracker`, the default `--out` for core views); and a **write-back path** for `analysis-results` (stamped layers) and `progress-tracker` (the metrics file) — on an ephemeral runner without one, the stamps are computed and then discarded. **Exception that stays operator-side:** the spend-*actuals* leg (python3 -m traust.cli metrics collect-spend --append) reads agent session transcripts on operator workstations — it cannot move to the orchestrator until transcripts are centralized, and its un-appended-actuals >4d drift row exists precisely to keep guarding that leg |
| IaC quarterly re-baseline | quarterly — **human-decision, drift-flagged** | rides `checkov-pin` advances (drift row) | `/cloud-config-audit` re-runs against the IaC-bearing targets | pin advances are deliberate toolchain changes — re-verify one known-good target before the sweep |
| Portfolio-graph heavyweight rebuild | **human-decision, drift-flagged** — after `/repo-graph` refreshes, or when `/impact-analysis` freshness demands it | drift row `portfolio-graph` (build stamp vs inputs HEAD) | `/portfolio-graph` (python3 -m traust.cli portfolio build) | build refuses a stale spine; rebuild timing stays with the operator (clone-sweep cost) |
| ADR / pin / external-tool advances | **human-decision, drift-flagged** — never automated | drift rows `adr-registry:*`, `checkov-pin`, `external-tools:*` | reviewed commits advancing the pins | no check may auto-advance a pin (drift-watch constraint) |
| Spend capture (`/financial-tracking capture`) | **weekly** | timer; drift rows `dashboards:spend*` (>4d) | `/financial-tracking capture` — see *Spend capture cadence* below | capture is LOSSY if you are late: transcripts are retained for a rolling window only and there is no backfill. The reconcile step is a hard gate — a non-zero exit means tokens were lost between the collector and the attribution split |
| Docs semantic sweep | quarterly | drift row `docs-semantic-sweep` (92d) | reviewer sweep per the check-harness-docs SKILL procedure | report lands in the deployment's gap-assessments tree |

## Spend capture cadence — capture weekly, report monthly

The capture chain is three deterministic steps, run in order:

```bash
python3 -m traust.cli metrics collect-spend --append
python3 -m traust.cli metrics attribute-spend --append
python3 -m traust.cli metrics attribute-spend --reconcile
```

The third is a **gate, not a formality**: a non-zero exit means tokens were
dropped between the collector and the per-lane attribution split, and every
downstream figure is untrustworthy. Stop and say so.

**Why weekly and not monthly.** Agent session transcripts are retained for a
rolling window of about a month, and they are the only source for both token
counts and the business-unit bridge. A day that ages out is unrecoverable —
there is no backfill, and the ledger keeps only what was captured. Monthly runs
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
| **Service identity for each `github`-kind host** (dedicated — not a human's PAT) with read access to the audited orgs, exposed as `GITHUB_TOKEN` | router stages 1–2 (`gh api`), `/dependency-watch`, python3 -m traust.cli check drift (private ADR-registry repos + `external-tools:*` release lookups), audit API lookups | A full fleet run consumes most of a core API quota hour and the router's preflight assumes it has the whole window — sharing a human's quota starves both. Anti-scraping **secondary bans are invisible to the `rate_limit` endpoint**: keep fleet sweeps single-pass with bounded parallelism and error-streak gating. Token via env/header only, never argv (rule S5). |
| **Service identity for each `gitlab`-kind host**, as `GITLAB_TOKEN` or the `glab` auth store | router stages 1–2, ledger/MR flows, secure-rpm-audit | Never in argv or clone URLs — a token-in-URL remote leaks into artifacts. A network-gated host needs a path from the orchestrator, and a run that cannot reach it must surface as `unreachable`, never falsely green (the router's behavior). |
| **Clone credentials via ambient helper** | every lane that checks out code | No credentials in clone URLs; the runner image carries a credential helper wired to the service identities above. |
| **Model-platform credentials + spend recording** | all agentic lanes (full audits, diff scans, triage, verify sweeps) | Per the model-routing contract (docs/model-routing.md); batch spend recorded with `model_registry.py spend` so the budget guard and dashboards stay truthful. |
| **`execution-boundaries.yaml` in `$TRAUST_CONFIG_HOME`** | remediate-finding Phase 4 checks and Phase 4b mutation, property-test differential | Sets how target build/test code runs: `sandbox: none` (default — direct, scrubbed env, disposable copy) or `sandbox: podman` (nested rootless container). Leave `none` on a runner that is itself a locked-down job and cannot nest containers; that is the expected orchestrator shape. A configured `podman` mode is never downgraded — without a working runtime the lane reports `not_attempted` and produces no evidence, so do not set it on a runner that lacks one. Detection is `podman info`, so a job image shipping the CLI without a runtime is correctly treated as unusable rather than failing with exit 125. |
| **Scanner binaries in the job image** | deterministic pre-scans; drift `external-tools:*` rows | Install the `expected` versions from `config/external-tools.yaml` — the manifest is the shared source of truth, so the image and `check_drift.py` can never disagree about what should be present. govulncheck must be a *tagged* build (unstamped `go install` builds defeat freshness tracking). Absent tools degrade loudly (`pending`), an install below the manifest floor reports `drift`, but an image without the scanners isn't doing continuous scanning. |
| Unauthenticated feeds: OSV, EPSS, KEV, Go module proxy, PyPI | deps lane, feeds refresh, drift checks | No service account needed. NVD is keyless but rate-limited — an NVD API key is an optional quality-of-service upgrade for `fetch_advisory.py`. |
| **Directory service** reachability | owner assignment, countersign identity verification | Needed only by the routing/accountability lanes, not the scan lanes. Decide which identity the orchestrator binds as. |
| **Issue-tracker service account** | `/file-security-defect` (and the internal extension's backlog sync) | Must be able to set the restricted security level used for embargoed issues. Decide whether filing runs under a service identity or a human — countersign/override events remain human-signed by design. |
| **Collaboration-suite identity** | ownership-tracker updates, document permissions | Human-delegated by default; decide whether these stay operator-session-only. |

The division of labor stays as designed: deterministic runners need only tokens
and binaries; anything that *concludes* (verdicts, countersigns, pin advances)
stays with humans or operator-supervised agent sessions regardless of what the
orchestrator can reach.

## The decision table

Encoded as data in python3 -m traust.cli build rescan-worklist
(`DECISION_TABLE`), first match wins. Rule 1 (event injection) runs ahead of the
table — see *Event injection* below.

| Rule | Trigger | Lane | Why this threshold |
|---|---|---|---|
| 1 | inventory repo (portfolio-graph spine, built from the inputs inventory) with **no baseline audit** | **full audit + threat-model bootstrap** (`rule-1-bootstrap`) | new intake is otherwise invisible to the loop until a human notices. Zero API calls — exposure from the curated designation, private default; the first audit self-heals the repo into change detection, the graph, and dependency watch |
| 2 | `C ≥ 8,000` first-party changed lines, OR `R ≥ 10%` of audited LoC (R only where `lines_reviewed` is recoverable from the baseline report) | **full audit** | above this the old audit's coverage map no longer describes the code — the baseline is *invalid*, not merely stale. The line threshold sits near the upper tail of a typical two-week change; a change that large is a new codebase for coverage purposes, while a smaller one carries little churn-attributable expected yield |
| 3 | any changed file matches the narrow sensitive-identifier matcher AND ≥200 changed lines in those files | **full audit** (P0/P1), **diff scan** (P2) | error analysis places the audit false-negative pool disproportionately in auth/config paths — sensitive-path change is the highest-yield trigger and is never throttled. The *narrow* matcher discriminates; a broad infrastructure matcher hits almost every changed repo and is useless |
| 3b | every changed file is a dependency manifest | **deps lane (classification, not a queue)** — the row records that the repo's change is manifest-only and therefore covered by the daily advisory-driven `/dependency-watch` run (feeds → `/impact-analysis` on hits → `route_impact_findings.py` filing). `/dependency-watch` works advisory-first and does **not** read these worklist rows; the rows keep the router's coverage accounting honest and are the hook if a manifest-driven trigger is ever wired | about half of changed repos touch a manifest — agent-scanning that class would swamp everything; reachability is deterministic, and hits become filed findings, not just analysis |
| 4 | audit age > tier ceiling: **P0 180d / P1 270d / P2 365d** | **full audit** | backstop for slow-drip churn that never crosses rules 2–3, and the re-application vehicle for methodology gains. Every full re-visit recovers some findings from *unchanged* code (run-to-run detection variance) — ceilings are a discovery mechanism, not just hygiene |
| 5 | any other first-party change (`C > 0`) | **quarterly diff-scan pool** | new crit/highs do **not** scale with churn; the below-threshold pool carries a small, steady expected yield, so a monthly latency costs far more per finding than full-audit visits do — quarterly keeps changed code ≤90 days unexamined at a fraction of the cost |
| 6 | `pushed_at` moved but 0 commits ahead | none | tag/branch push noise — a noticeable share of stage-1 candidates; the compare, not `pushed_at`, is authoritative |
| 7 | no qualifying change | none | dormant repos re-enter automatically on their next push; dead code is never calendar-rescanned |
| — | `no-pinned-sha` + push signal | **full audit** | a baseline without a parseable `metadata.commit` cannot be change-detected; the fresh audit re-establishes the anchor (self-healing) |
| — | `quota-deferred` | none (next run) | stage-2 compare didn't fit the API quota hour; honest "not classified yet", converges next day |
| — | **tripwire** | **diff-scan** (immediate) | gitleaks runs over the change's patch text for every below-threshold routed row (no clone; GitLab patches arrive free in stage 2, GitHub costs one quota-aware call) — a secrets hit collapses that row's exposure from ≤90 days to ≤1 day. Routes only; the diff scan adjudicates. `--no-tripwire` disables. Manifest-only changes already reach osv via rule 3b |
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

**Risk tiers** (from live crit/high counts in
`analysis-results/graph/findings.db`; the exact live-finding predicate is
documented in the script docstring): P0 = ≥5 live crit/high, P1 = ≥1, P2 =
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
| Verify sweep (`/verify-remediation`) | per-finding targeted re-audit of previously-filed findings only | light | resolves findings; finds nothing new by design |
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
mode"). The mode auto-resolves its own baseline — the skill's deterministic
`harnessing/3-audit/vuln-scan/scripts/resolve_baseline.py` looks up the newest
valid HEAD code-audit report for the checkout's repo URL in `findings.db` and
anchors the diff at that report's pinned SHA, using the router's own
first-party filter and sensitive matcher (imported from
python3 -m traust.cli build rescan-worklist, so the two can never
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

The diagram's `/triage → ledger → dashboards` arrow, spelled out. There is
exactly **one** accountability surface per repo — no lane gets its own findings
layer:

1. **The router never emits findings.** `rescan-worklist.json` rows are routing
   instructions; tripwire and deps hits are *escalations with evidence
   attached*, which ride into the dispatched lane's context.
2. **Agent lanes file findings.** A full audit writes/refreshes the repo's
   `*-security-audit.json` baseline — **only the three `secure*audit` skills
   may do that** (gate A15). Every other lane files into the **ledger only**: a
   diff scan's verified findings enter as events at `not_verified`, carrying
   their claim on the event (`event.finding`) so `build_cumulative` unions them
   back at replay. Triage adjudicates downstream — no triage precondition on
   entry. Mechanics: [findings-routing.md](findings-routing.md).
3. **The ledger is the accountability record.** `/track-findings` appends
   disposition events to the append-only `*-findings-layer.json` and
   regenerates `*-findings-current.{json,md}` — the artifact owner routing,
   team reports, the SLA view, and issue-tracker filing consume. `findings.db`
   is a rebuildable projection of it; dashboards read the projection.
4. **Deterministic dependency outputs land as artifacts, not findings:**
   `traust feeds fetch` snapshots the advisory feeds in traust-core; `run_osv_scanner.py` matches
   emit escalations (changed-manifest path) or feed `/impact-analysis`;
   `/impact-analysis` writes `analysis-results/impact/<cve>-impact-analysis.json`,
   consumed by `/verify-remediation full-sweep --impact-filter <artifact>`, the
   patch lane, and the findings.db `impact` table (queryable affectedness). A
   deterministic hit becomes a ledger finding **only after an agent lane
   verifies and files it** — the no-verdict doctrine
   (`docs/deterministic-inferential-mix.md`) applied end-to-end.

   **Filing:** `/dependency-watch` runs the whole advisory chain daily (feeds →
   impact-analysis → `route_impact_findings.py`); each `affected` repo's
   dependency finding enters its **disposition ledger** at `not_verified` via
   the direct-entry convention — the claim rides on the event, never appended
   to the baseline (gate A15). Idempotent per repo+module+CVE — dedupe reads
   event-carried findings as well as the baseline, or a daily re-run would
   re-file. Severity from the advisory, never invented — an owned, SLA-clocked
   finding the day the advisory lands. The executive summary carries the
   per-CVE fleet cut (affected vs filed vs resolved).

So: "will people know to address the issues?" — yes, through the same
`findings-current` → owner-routing → issue-tracker path as every audit finding;
the continuous loop changes *when* and *why* scans run, never where
accountability lives.

## Event injection

Operators (or feed importers) append records to
`analysis-results/findings/_manifest/rescan-events.jsonl`, one JSON object per
line:

```json
{"source": "external-report", "repo": "https://github.com/org/repo",
 "refs": [], "note": "researcher report <tracker-id>",
 "date": "YYYY-MM-DD", "consumed": false}
```

`source` is one of `external-report` (→ immediate `full-audit+validate` row),
`methodology` (→ full audit for P0-tier repos; P1+ catch up via the rule-4
ceiling), `cve` (→ impact lane, consumed by the daily `/dependency-watch` run —
analysis AND filing), `release` (→ passthrough note to the branch/container/rpm
audit lanes). Event rows queue AHEAD of the decision table and are never dropped
by the budget guard. The router is read-only over the file: it lists what it
honored in `events_honored` and marks nothing consumed — flip `consumed` to
`true` after dispatching the row.

### Event feeders

`rescan-events.jsonl` is fed two ways: operators append
`external-report`/`methodology`/`cve` rows by hand (or via feed importers), and
**`release` rows originate from a feeder** —
`harnessing/2-threat-model/threat-model/scripts/build_release_events.py`, run
daily alongside the router. Two legs, one committed state file
(`findings/_manifest/release-events-state.json` — the seen-set, so re-runs are
idempotent and a movement-free run emits nothing):

- **Container leg** — diffs the image inventories in the inputs repository
  (the `*-payload-repos.csv` payload and operator-catalog files' image columns)
  against the seen-set; a never-seen digest/tag appends one release event
  carrying the image ref and the CSV-mapped source repo. **CSV diff only** — no
  registry polling (no skopeo/network); a new digest becomes visible when the
  inventory refresh lands. Quota-aware registry tag polling against the same
  state file is the natural extension.
- **Dist-git leg** — reads the operator-curated
  `$TRAUST_CONFIG_HOME/rpm-distgit-watch.yaml` (the template ships with an
  empty `active` list) and runs `git ls-remote` per active https URL (rule S3
  discipline: https-only gate, `GIT_ALLOW_PROTOCOL=https`, `--` separator); a
  moved HEAD appends a release event noting "dist-git commit — route
  secure-rpm-audit". Failures degrade to per-repo skip counts, never a crash.

**Release identity.** Because the router re-models on major/minor releases
only, every event carries a structured version — never free text parsed back
out of `note`. The identity is the **inventory path**, not the image tag: image
tokens are almost always bare keys or digest-pinned and carry no parseable
version, while inventory CSV paths do (for example
`<product>/<product>-<version>-payload-repos.csv`,
`operator-catalog/<operator>/<version>/…`). Each path normalizes to a `family`
(the path with its version replaced by `{V}`) plus a version tuple; the
committed state file remembers the highest version seen per family, and a new
inventory file classifies as `major` / `minor` / `patch` / `backfill` (a version
*below* the high-water mark — an old release inventoried late) / `initial` /
`none`. Events stamp `release_family`, `release_version`, `release_previous`,
`release_change`.

Two coverage limits, stated rather than papered over: the **dist-git leg has no
version at all** — a moved HEAD is a commit sha, not a release — so it
classifies `unknown` and never reaches the threat-model lane; and a state file
that predates version tracking seeds its high-water marks on the first run
(emitting nothing new, since those inventories are already in the seen-set), so
the *next* new inventory version is the first one that classifies against a
real predecessor. The router counts every skipped kind in
`summary.threat_model.release_changes` so "no reviews fired" is always
distinguishable from "nothing qualified".

The first run (no state file) seeds the state and emits nothing — the existing
inventory is baseline, not news. `--dry-run` prints would-be events without
writing. The feeder produces events only; the router routes them (release →
`release-passthrough`), and dispatch marks `consumed` — three components, one
verdict-free chain.

## Running the router

```bash
# daily run (both stages, 12 workers), default paths
python3 -m traust.cli build rescan-worklist

# offline smoke test against a copy, without touching the live worklist
python3 -m traust.cli build rescan-worklist --no-network --limit 5 \
    --out /tmp/rescan-test/rescan-worklist.json

# explicit inputs + advisory budget ceiling
python3 -m traust.cli build rescan-worklist \
    --db analysis-results/graph/findings.db \
    --events analysis-results/findings/_manifest/rescan-events.jsonl \
    --jobs 12 --unit-cost-full <measured-usd> --monthly-budget <usd>
```

Quota behavior: a full fleet run consumes most of a core API quota hour (about
one call per repo in stage 1 and roughly half a call per repo in stage 2). The
router preflights stage 1 and exits 4 (no worklist written) when the quota
cannot cover it — a quota-starved stage 1 classifies thousands of repos as
errors while the output still looks legitimate. Stage 2 is quota-aware instead
of preflighted: compares that do not fit are marked `quota-deferred` (loudly, in
the MD summary) and the next daily run classifies them — convergence within a
day, never silent loss. `--ignore-rate-limit` overrides the preflight; >5% error
rate adds an MD warning and each row carries its API `error` message.

## Standing weekly drain — orchestrator contract

The weekly trickle-drain is designed to run under an external orchestrator
(cron, Tekton, whatever schedules). The contract is three steps — one
deterministic router run, one deterministic tranche selection, one agentic
dispatch per row:

```bash
# 1. DAILY — refresh the routed worklist (deterministic; quota-aware)
python3 -m traust.cli build rescan-worklist

# 2. WEEKLY — emit this week's tranche manifest (deterministic;
#    selection only, no spend). Fail-closed: refuses a worklist older
#    than 48h, one predating the refusal pre-route, or a second
#    tranche in the same ISO week.
python3 harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py [--include-immediate]
#    → analysis-results/findings/_manifest/drain-tranche-<YYYY-Www>.json

# 3. PER ROW — one headless run (agentic; this is the spend). A tranche
#    carries more than one dispatchable lane, so BRANCH ON row.lane
#    (the manifest's `dispatch_by_lane` map is authoritative):
#      clone:    git clone --filter=blob:none <repo_url> <scratch>/clone
#
#    lane diff-scan | diff-scan-quarterly:
#      scan:     /vuln-scan <scratch>/clone --diff
#                (packet path: resolver → build_diff_packet.py →
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
- Batch results (counts + costs) append to the metrics ledger
  (`python3 -m traust.cli metrics history append --source drain-tranche-<week>`),
  which the trends dashboards chart.

`/drift-watch` flags a worklist older than 3 days, so a dead daily leg surfaces
without the orchestrator having to monitor itself.

## Budget knobs

**Where the ceiling comes from.** Two independent things get called "the
budget", and only one of them can stop a run:

| | What it is | Does it gate a router run? |
|---|---|---|
| `$TRAUST_CONFIG_HOME/budget-policy.yaml` | the policy artifact; its `enforcement` field is `none`, `observe`, `advisory`, or `enforced` | Only at `advisory` or `enforced`. At `none` or `observe` its sole consumer is the spend dashboard's budget-vs-actual chart |
| `--monthly-budget` | explicit operator flag | **Yes** — always |

**Observe mode.** With `enforcement: observe`, every weekly tranche computes a
budget verdict, records it, and **withholds nothing**. This is a measurement
instrument, not a control, so that "how often would the cap bind" is answered by
counting real verdicts rather than predicted.

The safety property is structural, not a convention: `read_policy_budget()`
(the drop path's reader) reports `observe` as **no ceiling**, so `apply_budget()`
physically cannot see one. The ceiling is visible only through
`read_policy_shadow_ceiling()`, whose sole caller is
traust.cli.budget_shadow — a module that returns a
*report* and has no ability to filter a work list.

Each tranche manifest gains a `budget_shadow` block: month-to-date lane spend,
this tranche's estimate, the verdict, and the exact rows that *would* have been
withheld. `--append-shadow` records the verdict to the metrics ledger
(`budget-shadow`) so the hit rate accumulates.

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
