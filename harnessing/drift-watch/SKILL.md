---
name: drift-watch
description: Use when the user asks whether inputs, supported consumers or paired sources are stale or drifting — "is anything stale", "check for drift", "did inputs change since the graph was built" — or on a regular cadence. Shows traust-core's freshness view over security feeds, reference-registry age, scanner readiness and upstream release age, stored PQC schema compatibility, dominant-language dependency/reachability coverage, review clocks, assessment cadence and reported audit gaps. The companion check drift command watches the surviving worklist and pack configuration; inventory bootstrap reads native inputs, never a stale graph export. Writes freshness.{md,html,json} where asked.
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Read
  - Bash(python3 *traust* -m traust.cli.check_drift:*)
  - Bash(python3 *-m traust.cli dashboard view freshness:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# Drift Watch — Staleness & Source-Agreement Report

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Everything derived can silently age, and any two sources describing the
same fact can silently diverge. This skill makes both visible on a
cadence: traust-core's freshness view, derived on demand (never a
stored report).

Distinct from the retired C3 *delta-watch* idea (re-auditing changed
target repos — superseded by Konflux): drift-watch checks the
**harness's own artifacts and source pairs**, not audit targets.

## Procedure

1. Show the view (deterministic; one pass, every item, worst first):

   ```bash
   python3 -m traust.cli dashboard view freshness --out <dir> [--product <slug>]
   python3 -m traust.cli check drift
   ```

2. Read the report back. Lead with `drift` items, then `stale`, then
   `review_due`; `pending` items are gaps that will close as planned
   phases land (say which phase); a fully-`fresh` report is the answer
   "nothing is stale", not a wasted run.
3. For each actionable item, offer the refresh command from the report
   — **but do not execute rebuilds unprompted**; the checker routes
   attention, the human decides (rebuild timing can matter
   mid-campaign).
4. *Retired:* committing the report. The view derives from recorded
   state on demand, so there is no file to keep.

## What it checks

| Item | Staleness / drift signal |
|---|---|
| `feeds:*` | traust-core feed snapshot age, for every `tier: cached` security source in the feeds registry traust-core ships: `epss`, `kev`, `rh-cve`, `vex`. Each feed's own `max_age_hours` (24h for the daily feeds), judged by traust-core (`FreshnessQuery.stale`), which also adds a readiness row per feed provider (`feed:*`) |
| `registry:product-definitions` | The view reads the existing product-definitions provider's retrieval metadata from the same effective feeds cache as `traust feeds fetch-products` (`FEEDS_CACHE_DIR`, configured cache, then the configured progress-tracker's `feeds` directory). This reference registry is **not a security feed**. Older than 168h is `stale`; never fetched is `pending`; broken metadata or a lost recorded cache is `unavailable`. The ownership lookup's longer tolerance does not weaken this independent refresh backstop. |
| `findings.db` | *Age probe retired:* the former hub check compared `built_at` with the newest ledger/report mtime. Findings are Core recorded state; the last reader, `build rescan-worklist`, is retired with it. |
| `ledger:*` | *Retired:* the disposition layers went with the hub; the ledger is traust-core's. Was: does the ledger actually COVER the corpus — nothing asked this before. `audits-without-a-layer` (an audited repo with no disposition layer), `layers-without-a-report-digest`, `incomplete-claim-hashes`, and the informational `colliding-layer-ids`. Signature coverage and the findings-db projection were both guarded; whether a ledger EXISTS per audited repo was not |
| `ledger-signature-coverage` | *Retired:* the disposition layers went with the hub. Was: disposition layers that are Merkle-rooted AND signed vs the total. `pending` when signing is not configured, `drift` when rooted-but-unsigned layers exist — an unsigned layer is a disposition history nothing attests to |
| `fp-precedent-cache` | *Retired:* no cache file; precedent is read from recorded decisions. Was: `metadata.generated` vs newest `*-findings-layer.json` mtime — new countersign/triage/validation adjudications after the build mean /triage 2g and the audit fp-precedent gate route on stale precedent; rebuild via `build_fp_precedent_cache.py build` |
| `rule-mining` | *Retired:* into the security pack's continuous-ops mine-ledger lane, which runs on its own schedule. Was: `progress-tracker/metrics/rule-mining/rule-mining.json` age vs the newest `*-findings-layer.json` mtime across analysis-results — stale when ledger changes are >7 days newer (`RULE_MINING_LAG_DAYS`, the weekly-lane grace window): a large audit/triage wave lands confirmations no rule has seen. This row is the rule-mining lane's post-wave trigger; refresh via python3 -m traust.cli sweep rule-lane (see the mine-ledger SKILL's *Scheduled lane*) |
| `portfolio-graph` | *Retired after caller cutover:* no SQLite graph is routing authority (the router reads observed `repo_state`), so there is no cached graph build to compare against inputs HEAD. Native graph exports are presentation snapshots, not routing inputs. |
| `validation-benchmark` | *Retired:* into the security pack's continuous-ops benchmark lane; scorecards are traust-core's detection quality. Was: scorecard age vs the 35-day monthly cadence (P7 hybrid; the release-cut leg is `traust sweep benchmark check-trigger`) |
| `impact:<cve>` | *Retired:* impact analyses are recorded and read as of a time; there is no artifact to age against a graph. Was: each `analysis-results/impact/*-impact-analysis.json` vs the portfolio-graph build it queried — a graph rebuilt after the artifact means the blast radius may have shifted; re-run `/impact-analysis` |
| `repo-liveness` | *Retired:* liveness derives on read (`PortfolioService.liveness`); observation cadence is the engine tick. Was: artifact age |
| `corpus-registration` | *Retired:* no corpus trees. Was: output trees on disk vs corpus-config (unregistered trees = **drift**) |
| `ref-provenance` | *Retired:* no corpus reports; an assessment names its commit. Was: slug-derived ref vs declared `metadata.ref` on every corpus report — a report carrying **both** must agree (disagreement = **drift**: stale slug after a move/rename, or a wrong-checkout stamp; branch-awareness Phase 4). Reports carrying only one form are not comparable and stay silent |
| `adr-registry:*` | *Now:* `traust check drift` (interim, until the security pack validates its own config). each register's pinned SHA vs live upstream HEAD (pending until compliance Phase 2c) |
| `checkov-pin` | The view compares the authoritative Core `CHECKOV_VERSION` pin's PyPI publication date with the clock: older than 90 days is `stale`. This policy-content age is independent of whether the installed Checkov is ready and correctly pinned; lookup failures are `unavailable`, never evidence of freshness. |
| `yara-rules-pin` | *Now:* `traust check drift` (interim, until the security pack validates its own config). pinned ReversingLabs YARA rules SHA vs upstream `develop` HEAD. The malware-family pack ages FASTER than the yara engine whose floor `external-tools:yara` watches: a frozen pin silently stops matching NEW families |
| `argus-rules-pin` | *Now:* `traust check drift` (interim, until the security pack validates its own config). pinned argus-observe-rules SHA vs upstream `main` HEAD. An OPT-IN crypto/PQC supplement, not the default pack — a stale pin costs coverage on a lane nobody is forced to run, so it is watched but is not scan degradation |
| `external-tools:*` | The view uses the shipped tool manifest's upstream references to compare installed numeric versions with upstream releases. Behind a newer release published more than 14 days ago is `stale`; not installed is `pending`, unknown/unstamped versions and failed lookups are `unavailable`. Adopter-provided tools use their declared tested pin when no local binary is expected. The separate `tool:*` readiness rows still enforce expected version floors. A stale upstream row never advances the pin or installs anything. |
| `feed-source:*` | *Now:* the view's `feed-source:*` rows (traust-core `ProviderCatalog` readiness of each source's declared probe); a definitive HTTP error and a transport failure are both `unavailable`, the detail says which. Was: liveness of every source in the feeds registry carrying a `probe` — **both tiers**. The live tier previously had no freshness signal at all: `fetch_advisory.py csaf` requested `advisories/<cve>.json` and 404'd for every CVE ever passed to it (Red Hat keys CSAF advisories by RHSA, not CVE) and nothing failed, because a hardcoded URL has no registry to inspect. A definitive HTTP error = **drift** (registry and service disagree about the endpoint's shape; refresh line says fix the `url_template`); a transport failure = **unavailable**, never drift, so an offline workstation does not report every source broken. Status only — the response body is never read |
| `grype-db` | *Now:* the view's `database:grype` row (database age vs the tool's own max age). Was: grype's vulnerability DB **content** age, not its binary version — `external-tools:grype` watches the binary and grype ships matchers separately, so a current grype can carry a months-old DB while that row stays green (measured 2026-08-25: grype 0.117.0 == latest, DB built 2026-07-30, `Status: invalid`). Threshold is grype's OWN 5-day max age (`GRYPE_DB_MAX_AGE_DAYS`) — past it grype invalidates the DB itself — and the row fires on age even while grype still reports `valid`. Not-installed = `pending`; an unparseable `grype db status` = `unavailable`, never fresh. Refresh is `grype db update`, then re-run any container/SBOM scan whose findings must reflect current CVE data |
| `pqc-facts-stamps` | *Now:* traust-core's PQC reads route facts stamped by another pack as `unrefreshed` (re-scan). Was: reproducibility stamps in every corpus `*-pqc-facts.json` vs the current `ADAPTER_VERSION` / `PQC_SCAN_COMMIT` pins in `pqc_facts.py` — the write-time schema gate protects new writes only; when the adapter or scanner pin moves, this makes the aging corpus visible (stale facts self-heal via re-scans). Head-read of the stamps block, O(corpus) cheap |
| `pqc-facts-schema` | The view proactively reads the newest 50 distinct published PQC facts through `ArtifactPublisher`, verifies their digests and parses against the current schema. An incompatible, corrupt or missing stored document is `stale`, with artifact IDs and issue paths; an empty corpus is `pending`. The bounded result says whether more documents exist: a clean sample is not a full-corpus compatibility claim. The write gate protects new records, not documents recorded before a schema tightening. |
| `pqc-backfeed` | *Retired:* PQC attributes are not stored in a graph that a rebuild can clobber; the PQC reads use the facts. Was: count of portfolio-graph repo nodes carrying `$.pqc` vs the pqc corpus that feeds it (`pqc-backfeed-summary.json:repos_with_pqc_attrs`, else the `*-pqc-facts.json` corpus count). Below `PQC_BACKFEED_MIN_RATIO` (50%) of the corpus = **drift** — the graph-rebuild clobber signature that once dropped 3142 stamped repos to 41 and zeroed the per-product PQC reports (`build_pqc_product_reports.py` requires `json_extract(attrs,'$.pqc') IS NOT NULL`). The structural fix is `build_portfolio_graph.ENRICHMENT_ATTR_KEYS`; this row is the backstop. Read-only; `pending` when `portfolio-graph.db` or the corpus is absent. Refresh = re-run `scan_pqc_dependencies.py` |
| `identity:*` | *Retired:* identity is stamped by traust-core's finding intake on every recorded finding. Was: the corpus-wide fingerprint sweep — every finding in every `*-security-audit.json`, recomputed against the installed `traust_ledger.identity` recipe. `unstamped-findings` = **drift** (a finding with no `fingerprint` cannot be matched to its own history on re-audit); `non-reproducing-stamps` = **drift** (a value the recipe does not produce: not written by `traust_ledger.identity`, edited under, or missed by an `ALGO_VERSION` re-stamp — the remedy is to LOOK, since re-stamping changes identity and orphans disposition history); `degenerate-findings` = **stale**, the burndown counter for findings whose locations all canonicalize to empty, which is what gates the `fingerprint(strict=True)` flip (plan item 4b); `colliding-fingerprints` = **info**, findings sharing an identity with another finding in the SAME report — the false-MERGE dual of the rows above and invisible to them, since both stamps recompute perfectly and simply name the same thing. Informational rather than actionable because it is a property of the recipe (repo+paths+primary CWE distinguishes nothing between two same-file same-CWE findings), not a regression: it is contained today by dispositions keying on (layer, finding_ref) rather than identity (**D9**) and by rebaseline tier-1 refusing a non-unique candidate, and it bites only where something DOES key on the fingerprint. Degenerate findings are excluded so the two rows never report one defect twice. Why it belongs here: every other identity gate lives in the producing session (the audit skill's stamp step, then the validator's error on an absent or non-reproducing value), and `analysis-results` has no hook and no CI — so an artifact written outside the skill path meets no gate on the way in. ~3s over 8k reports; `unavailable` rather than silent when a report will not parse |
| `framework-spine:upstream` | *Now:* `traust check drift` (interim, until the security pack validates its own config). vendored 800-53/800-53B derivations vs the pinned usnistgov/oscal-content commit — a moved upstream means NIST may have revised the catalog (review before re-deriving) |
| `provenance:*` | *Now:* `traust check drift` (interim, until the security pack validates its own config). dated policy values (SLA policy, compliance spine, org-parameters, **and the PCI/SOC 2/GDPR ids-only catalogs' `reviewed` dates**) past the 180-day review window — frameworks without machine feeds are staleness-checked through their review dates |
| `rescan-worklist` | *Retired with the daily router:* routing runs per repository in the engine; a dead observation leg shows as overdue `repo_state` orders in the engine's feed. |
| `threat-model` | *Now:* the view's `assessments:threat-model` row (each repository's latest completed model, stale past 92 days). Was: backstop for the re-model cadence (shipped 2026-08-05): three router lanes refresh models — a `/threat-model pr` stamp on diff rows, a release-review on major/minor events, and a 92-day quarterly sweep. This row is the dead-timer guard on that last one: any model older than 92d is stale |
| `language-coverage:*` | The view counts each scoped repository's dominant measured language on its current default ref, independently of completed audits. A language dominant in at least 10 repositories without supported dependency extraction or a reasoned no-dependency allowlist entry is `stale`. The supported roster derives from the current SBOM provider, not the retired graph cache; missing default-ref/language measurements remain visible rather than counting as covered. |
| `language-cache-freshness` | *Retired:* no language cache; language counts are recorded per commit. Was: age of the `gh-languages` cache that `language-coverage:*` reads. That cache is not refetched on cadence, so a stale one lets the tripwire run on old data and miss a genuinely new language entering the portfolio. `/loc-dashboard` (with fetch) refreshes it |
| `reachability-coverage:*` · `reachability-watch:review` | The view independently flags languages dominant in at least 50 repositories with no wired symbol-tier reachability analyzer and no no-dependency exemption. Source-only `likely_affected` promotion is not symbol-tier coverage. The human review clock reads `reachability-watch.yaml` in the config home (template `config/reachability-watch.example.yaml`); missing/unreviewed is `pending`, invalid is `unavailable`, and an exceeded review cadence is `stale`. Recorded latest-audit gaps remain a separate section, not a substitute for either tripwire. |
| `dependency-pins:*` | *Retired:* `uv.lock` pins each sibling by commit and `uv sync --locked` refuses skew; a workstation check, not a product report. Was: installed sibling-package versions vs the git-tag pins in `pyproject.toml` `[tool.uv.sources]` (`traust-engine`, `traust-ledger`, `traust-contracts`). Absent = **drift** (`NOT INSTALLED`), wrong version = **drift** (`VERSION SKEW`), fix is `uv sync`. Replaced the `submodules:*` row when the C8 restructure swapped those submodules for pip deps — the failure class did not go away, only its delivery: both are "a dependency is not the version this tree expects", surfacing as an import error naming neither the dependency system nor the fix (2026-08-13: 18 test modules died at collection after a traust-ledger bump; 2026-08-14: `traust_engine` simply absent until `uv sync`). CI cannot cover it — CI builds its own venv, while skills run on the operator workstation. Fails open (`unavailable`) on an unreadable pyproject |
| `sibling-readme:*` | *Retired:* developer CI, not a product report. Was: each sibling repo's README vs that repo's own `pyproject` and module surface — the same failure class as `dependency-pins:*` one level out: a *documented* claim reality has moved past. Measured on traust-ledger 2026-08-17 |
| `dashboards:*` | *Retired:* views derive on demand; there is no stored dashboard to age. Was: generated dashboards refresh on demand, not on a schedule — `harness-scoreboard` (`Generated` stamp > 7d), `spend` (stamp > 4d), and `spend-actuals` (newest session-actuals row > 4d — a rebuilt dashboard can hide an un-appended ledger). Backstop until the refreshes fold into a scheduled loop — the packaged refresh command is `/refresh-dashboards` (python3 -m traust.cli dashboard refresh); the 2026-07-24 scoreboard (6 days / 88 versions stale) is the motivating incident |
| `docs-semantic-sweep` | *Retired:* a reviewer process (check-harness-docs), not a product report. Was: age of the newest `progress-tracker/gap-assessments/docs-verification-*.md`. The mechanical doc gates catch counts, links, flags and enums — not behavioral claims, which are bounded by a quarterly reviewer sweep. Stale past 92d |
| `docs-versions:*` | *Now:* `traust check drift` (interim, until the security pack validates its own config). the doc-variance lane's version watch: each product's declared docs-product-map versions vs its live docs.redhat.com landing page. A NEW upstream version missing from the map is drift (variance tracking is not covering it); a retired one is drift too; below-window historical versions are ignored and a network failure is `unavailable`, never fresh |

New source pairs (IaC-source pin vs inputs, config-vs-cluster once
live inventories exist) register as new rows of traust-core's freshness
view — statuses only from the fixed vocabulary.

## Cadence

On demand any time; recommended alongside every `/census` run; a
scheduled run is **Konflux fragment 6** (capability-roadmap C3 list)
when that integration lands. *Retired:* `--fail-on` (the view has no exit gate; the engine acts on staleness).
This skill's place among the harness's standing jobs — and the jobs
whose staleness its rows backstop — is inventoried in
docs/continuous-operations.md ("Standing jobs — the complete inventory").

## Constraints

- Deterministic checker: **routes attention, never concludes** — no
  check may auto-rebuild, auto-advance a pin, or file a finding.
- Drift between two sources is reported symmetrically; the checker
  never picks a winner (precedence rules live in the compliance plan's
  Graph-wiring section, and applying them is a human/skill decision).
- Freshness thresholds belong to their owners in traust-core; the surviving
  worklist-age backstop remains a pack check. Review clocks use the dated
  reference's declared cadence. Change policy with review, not per-run.

*Retired:* `docs-semantic-sweep` — the newest `progress-tracker/gap-assessments/docs-verification-*.md` report must be younger than 92 days (quarterly semantic docs sweep; procedure in the check-harness-docs SKILL).

## Integrations

**Consumes:** traust-core's freshness view — security feed snapshots, registry
retrieval metadata, scanner readiness, upstream releases and databases,
stored PQC facts, current default-ref language measurements, the scope's
assessments and their reported gaps — plus the config home's reachability
review reference.

**Emits:** `freshness.{md,html,json}` where `--out` says — a terminal
operator dashboard; its
stale rows route work to the owning skills (e.g. the
`assessments:threat-model` row → `/threat-model`).
