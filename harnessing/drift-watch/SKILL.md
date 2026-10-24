---
name: drift-watch
description: Use when the user asks whether derived artifacts or paired sources are stale or drifting — "is anything stale", "check for drift", "are the feeds/graphs/findings-db current", "did inputs change since the graph was built", "run the drift report" — or on a regular cadence. Runs the deterministic staleness/drift checker over feeds, findings.db, repo-/portfolio-graph vs the inputs inventory, repo-liveness, corpus registration, finding-identity stamping across every audit report, ADR-registry pins, external-tool freshness (installed scanners vs latest upstream releases), docs-product-map version enumeration (declared doc versions vs the live docs.redhat.com landing pages — catches FUTURE product-doc versions the variance lane isn't covering), pqc-facts stamps/schema provenance, and dated policy provenance; writes drift-report.{json,md} to progress-tracker/metrics/drift/.
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Read
  - Bash(python3 *traust* -m traust.cli.check_drift:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# Drift Watch — Staleness & Source-Agreement Report

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Everything derived can silently age, and any two sources describing the
same fact can silently diverge. This skill makes both visible on a
cadence and files the evidence where campaign reporting lives:
`progress-tracker/metrics/drift/drift-report.{json,md}`.

Distinct from the retired C3 *delta-watch* idea (re-auditing changed
target repos — superseded by Konflux): drift-watch checks the
**harness's own artifacts and source pairs**, not audit targets.

## Procedure

1. Run the checker (deterministic; one pass, all checks,
   skip-and-record per item):

   ```bash
   python3 -m traust.cli check drift [--fail-on stale|drift]
   ```

2. Read the report back. Lead with `drift` items, then `stale`, then
   `review_due`; `pending` items are gaps that will close as planned
   phases land (say which phase); a fully-`fresh` report is the answer
   "nothing is stale", not a wasted run.
3. For each actionable item, offer the refresh command from the report
   — **but do not execute rebuilds unprompted**; the checker routes
   attention, the human decides (rebuild timing can matter
   mid-campaign).
4. Commit the report to progress-tracker so trends in drift are
   themselves visible in git history.

## What it checks

| Item | Staleness / drift signal |
|---|---|
| `feeds:*` | traust-core feed snapshot age, for every `tier: cached` security source in `config/feeds.yaml`: `epss`, `kev`, `rh-cve`, `vex`. 48h — one missed run of the daily feed router plus slack |
| `registry:product-definitions` | a reference registry, **not a security feed** — Red Hat Product Security's product/ownership data, absent from `config/feeds.yaml` by design. It keeps its own `registry:` row, read from `feeds-meta.json` (`traust feeds fetch-products`). VPN-only and pull-through, so it refreshes at 24h but is only flagged at 168h; never fetched is `pending`, not `unavailable`, so an optional source stays out of `--fail-on` |
| `findings.db` | `built_at` vs newest ledger/report mtime |
| `ledger:*` | does the ledger actually COVER the corpus — nothing asked this before. `audits-without-a-layer` (an audited repo with no disposition layer), `layers-without-a-report-digest`, `incomplete-claim-hashes`, and the informational `colliding-layer-ids`. Signature coverage and the findings-db projection were both guarded; whether a ledger EXISTS per audited repo was not |
| `ledger-signature-coverage` | disposition layers that are Merkle-rooted AND signed vs the total. `pending` when signing is not configured, `drift` when rooted-but-unsigned layers exist — an unsigned layer is a disposition history nothing attests to |
| `fp-precedent-cache` | `metadata.generated` vs newest `*-findings-layer.json` mtime — new countersign/triage/validation adjudications after the build mean /triage 2g and the audit fp-precedent gate route on stale precedent; rebuild via `build_fp_precedent_cache.py build` |
| `rule-mining` | `progress-tracker/metrics/rule-mining/rule-mining.json` age vs the newest `*-findings-layer.json` mtime across analysis-results — stale when ledger changes are >7 days newer (`RULE_MINING_LAG_DAYS`, the weekly-lane grace window): a large audit/triage wave lands confirmations no rule has seen. This row is the rule-mining lane's post-wave trigger; refresh via python3 -m traust.cli sweep rule-lane (see the mine-ledger SKILL's *Scheduled lane*) |
| `portfolio-graph` | build stamp vs the inputs inventory's HEAD (`locations.inputs`) — **inputs is the sole topology authority; a moved HEAD means inventory/ownership may have changed under the graphs** |
| `validation-benchmark` | scorecard age vs the 35-day monthly cadence (P7 hybrid; the release-cut leg is `run_validation_benchmark.py check-trigger`) |
| `impact:<cve>` | each `analysis-results/impact/*-impact-analysis.json` vs the portfolio-graph build it queried — a graph rebuilt after the artifact means the blast radius may have shifted; re-run `/impact-analysis` |
| `repo-liveness` | artifact age |
| `corpus-registration` | output trees on disk vs corpus-config (unregistered trees = **drift**) |
| `ref-provenance` | slug-derived ref vs declared `metadata.ref` on every corpus report — a report carrying **both** must agree (disagreement = **drift**: stale slug after a move/rename, or a wrong-checkout stamp; branch-awareness Phase 4). Reports carrying only one form are not comparable and stay silent |
| `adr-registry:*` | each register's pinned SHA vs live upstream HEAD (pending until compliance Phase 2c) |
| `checkov-pin` | age of `CHECKOV_VERSION` in traust-core's `models/cloud_config.py` on PyPI — Checkov's ~1000 policies ship inside the release, so an aging pin means aging cloud-config policies (age-based, not version-lag: Checkov ships several patch releases a week) |
| `yara-rules-pin` | pinned ReversingLabs YARA rules SHA vs upstream `develop` HEAD. The malware-family pack ages FASTER than the yara engine whose floor `external-tools:yara` watches: a frozen pin silently stops matching NEW families |
| `argus-rules-pin` | pinned argus-observe-rules SHA vs upstream `main` HEAD. An OPT-IN crypto/PQC supplement, not the default pack — a stale pin costs coverage on a lane nobody is forced to run, so it is watched but is not scan degradation |
| `external-tools:*` | each unpinned PATH-invoked deterministic scanner from the `config/external-tools.yaml` manifest (roster + expected floors, shared with the orchestrator job-image build): installed below the manifest's `expected` = **drift** (environment disagrees with declared config); installed behind the latest upstream release past the grace window (`EXTERNAL_TOOL_LAG_GRACE_DAYS`) = **stale** — detection content (detectors, matchers, ecosystems) ages with the install. Not-installed reports `pending`, unstamped `v0.0.0` go builds report `unavailable`, an unloadable manifest is one loud `unavailable` row. Checkov is excluded (covered by `checkov-pin`); advancing `expected` or upgrading remains a deliberate config change — re-verify one known-good target before a sweep |
| `feed-source:*` | liveness of every source in `config/feeds.yaml` carrying a `probe` — **both tiers**. The live tier previously had no freshness signal at all: `fetch_advisory.py csaf` requested `advisories/<cve>.json` and 404'd for every CVE ever passed to it (Red Hat keys CSAF advisories by RHSA, not CVE) and nothing failed, because a hardcoded URL has no registry to inspect. A definitive HTTP error = **drift** (registry and service disagree about the endpoint's shape; refresh line says fix the `url_template`); a transport failure = **unavailable**, never drift, so an offline workstation does not report every source broken. Status only — the response body is never read |
| `grype-db` | grype's vulnerability DB **content** age, not its binary version — `external-tools:grype` watches the binary and grype ships matchers separately, so a current grype can carry a months-old DB while that row stays green (measured 2026-08-25: grype 0.117.0 == latest, DB built 2026-07-30, `Status: invalid`). Threshold is grype's OWN 5-day max age (`GRYPE_DB_MAX_AGE_DAYS`) — past it grype invalidates the DB itself — and the row fires on age even while grype still reports `valid`. Not-installed = `pending`; an unparseable `grype db status` = `unavailable`, never fresh. Refresh is `grype db update`, then re-run any container/SBOM scan whose findings must reflect current CVE data |
| `pqc-facts-stamps` | reproducibility stamps in every corpus `*-pqc-facts.json` vs the current `ADAPTER_VERSION` / `PQC_SCAN_COMMIT` pins in `pqc_facts.py` — the write-time schema gate protects new writes only; when the adapter or scanner pin moves, this makes the aging corpus visible (stale facts self-heal via re-scans). Head-read of the stamps block, O(corpus) cheap |
| `pqc-facts-schema` | newest `PQC_FACTS_SCHEMA_SAMPLE` facts files vs `contracts/schemas/pqc-facts.schema.json` — bounded sample (new files can't violate thanks to the write gate); a violation means the schema was tightened after the fact, and the corpus needs a sweep before its consumers (`/patch` pqc ingest, L2 prepass) trip on it |
| `pqc-backfeed` | count of portfolio-graph repo nodes carrying `$.pqc` vs the pqc corpus that feeds it (`pqc-backfeed-summary.json:repos_with_pqc_attrs`, else the `*-pqc-facts.json` corpus count). Below `PQC_BACKFEED_MIN_RATIO` (50%) of the corpus = **drift** — the graph-rebuild clobber signature that once dropped 3142 stamped repos to 41 and zeroed the per-product PQC reports (`build_pqc_product_reports.py` requires `json_extract(attrs,'$.pqc') IS NOT NULL`). The structural fix is `build_portfolio_graph.ENRICHMENT_ATTR_KEYS`; this row is the backstop. Read-only; `pending` when `portfolio-graph.db` or the corpus is absent. Refresh = re-run `scan_pqc_dependencies.py` |
| `identity:*` | the corpus-wide fingerprint sweep — every finding in every `*-security-audit.json`, recomputed against the installed `traust_ledger.identity` recipe. `unstamped-findings` = **drift** (a finding with no `fingerprint` cannot be matched to its own history on re-audit); `non-reproducing-stamps` = **drift** (a value the recipe does not produce: not written by `traust_ledger.identity`, edited under, or missed by an `ALGO_VERSION` re-stamp — the remedy is to LOOK, since re-stamping changes identity and orphans disposition history); `degenerate-findings` = **stale**, the burndown counter for findings whose locations all canonicalize to empty, which is what gates the `fingerprint(strict=True)` flip (plan item 4b); `colliding-fingerprints` = **info**, findings sharing an identity with another finding in the SAME report — the false-MERGE dual of the rows above and invisible to them, since both stamps recompute perfectly and simply name the same thing. Informational rather than actionable because it is a property of the recipe (repo+paths+primary CWE distinguishes nothing between two same-file same-CWE findings), not a regression: it is contained today by dispositions keying on (layer, finding_ref) rather than identity (**D9**) and by rebaseline tier-1 refusing a non-unique candidate, and it bites only where something DOES key on the fingerprint. Degenerate findings are excluded so the two rows never report one defect twice. Why it belongs here: every other identity gate lives in the producing session (the audit skill's stamp step, then the validator's error on an absent or non-reproducing value), and `analysis-results` has no hook and no CI — so an artifact written outside the skill path meets no gate on the way in. ~3s over 8k reports; `unavailable` rather than silent when a report will not parse |
| `framework-spine:upstream` | vendored 800-53/800-53B derivations vs the pinned usnistgov/oscal-content commit — a moved upstream means NIST may have revised the catalog (review before re-deriving) |
| `provenance:*` | dated policy values (SLA policy, compliance spine, org-parameters, **and the PCI/SOC 2/GDPR ids-only catalogs' `reviewed` dates**) past the 180-day review window — frameworks without machine feeds are staleness-checked through their review dates |
| `rescan-worklist` | `analysis-results/findings/_manifest/rescan-worklist.json` missing or `generated_at` older than 3 days — the continuous-operations router (python3 -m traust.cli build rescan-worklist, docs/continuous-operations.md) is the daily authority on rescan frequency; a stale worklist means scan dispatch is flying blind on old change data |
| `threat-model` | backstop for the re-model cadence (shipped 2026-08-05): three router lanes refresh models — a `/threat-model pr` stamp on diff rows, a release-review on major/minor events, and a 92-day quarterly sweep. This row is the dead-timer guard on that last one: any model older than 92d is stale |
| `language-coverage:*` | portfolio language composition vs dependency-graph ecosystem coverage — the **anti-Go-bias tripwire**. Loads the portfolio language cache (`analysis-results/findings/_manifest/portfolio-lang/gh-languages-cache-merged.jsonl`) and counts the repos each GitHub language is *dominant* in (max bytes). A language dominant in `>= LANGUAGE_COVERAGE_THRESHOLD` (default 10) repos that maps to NEITHER a covered ecosystem (`manifest_parsers.LANGUAGE_ECOSYSTEMS`/the universal docker·actions·helm surfaces/the `GRAPHED_NON_MANIFEST_LANGUAGES` carve-out for Go's go.mod L1 lane) NOR the explicit `NO_DEPS_LANGUAGE_ALLOWLIST` (shells, markup/templating/query languages, IaC/policy surfaces owned by other lanes) is a NEW language the graph is silently under-covering (Swift/Elixir/PHP/Kotlin/Scala if uncovered) = **drift** — same philosophy as the docs-product-map FUTURE-version check. When `analysis-results/graph/deps-multi-stats.json` exists it also emits one informational row per ecosystem (`language-coverage:eco:<eco>` — repos_with_manifest, dep_edges) and flags any ecosystem whose manifests were discovered (repos_with_manifest > 0) but yielded 0 dep_edges = **drift** (a silently-broken extraction lane / coverage regression, mirroring the builder's `loud_fail`). Extend the allowlist (with a reason) rather than lowering the threshold |
| `language-cache-freshness` | age of the `gh-languages` cache that `language-coverage:*` reads. That cache is not refetched on cadence, so a stale one lets the tripwire run on old data and miss a genuinely new language entering the portfolio. `/loc-dashboard` (with fetch) refreshes it |
| `reachability-coverage:*` · `reachability-watch:review` | portfolio language mass vs **symbol-tier reachability** coverage — the sibling of `language-coverage:*` one rung up the evidence ladder (that row asks whether a language's dependency graph is built; this one asks whether a finding in it can ever reach `affected`). A language dominant in `>= REACHABILITY_COVERAGE_THRESHOLD` (default 50) repos with no entry in `check_drift.REACHABILITY_ENGINES` and no `NO_DEPS_LANGUAGE_ALLOWLIST` excuse = **drift**, reported with its repo mass so the priority ordering is visible; without an engine every dependency finding in it ceilings at `likely_affected` on manifest evidence ("a pin is never reachability", docs/reachability.md). Wiring an engine means adding its language to `REACHABILITY_ENGINES` — an un-updated map keeps flagging (loud) rather than silently marking a language covered. `reachability-watch:review` is the review clock on `reachability-watch.yaml` in the config home (template `config/reachability-watch.example.yaml`), whose revisit triggers (does OSV carry call-graph data yet; has a permissively-licensed engine matured) have no machine feed, so the review window IS the staleness mechanism — same convention as the compliance catalogs' `reviewed` keys. Scoped pilot for the currently-flagged languages: `progress-tracker/plans/joern-python-js-reachability-pilot-plan.md` |
| `dependency-pins:*` | installed sibling-package versions vs the git-tag pins in `pyproject.toml` `[tool.uv.sources]` (`traust-engine`, `traust-ledger`, `traust-contracts`). Absent = **drift** (`NOT INSTALLED`), wrong version = **drift** (`VERSION SKEW`), fix is `uv sync`. Replaced the `submodules:*` row when the C8 restructure swapped those submodules for pip deps — the failure class did not go away, only its delivery: both are "a dependency is not the version this tree expects", surfacing as an import error naming neither the dependency system nor the fix (2026-08-13: 18 test modules died at collection after a traust-ledger bump; 2026-08-14: `traust_engine` simply absent until `uv sync`). CI cannot cover it — CI builds its own venv, while skills run on the operator workstation. Fails open (`unavailable`) on an unreadable pyproject |
| `sibling-readme:*` | each sibling repo's README vs that repo's own `pyproject` and module surface — the same failure class as `dependency-pins:*` one level out: a *documented* claim reality has moved past. Measured on traust-ledger 2026-08-17 |
| `dashboards:*` | generated dashboards refresh on demand, not on a schedule — `harness-scoreboard` (`Generated` stamp > 7d), `spend` (stamp > 4d), and `spend-actuals` (newest session-actuals row > 4d — a rebuilt dashboard can hide an un-appended ledger). Backstop until the refreshes fold into a scheduled loop — the packaged refresh command is `/refresh-dashboards` (python3 -m traust.cli dashboard refresh); the 2026-07-24 scoreboard (6 days / 88 versions stale) is the motivating incident |
| `docs-semantic-sweep` | age of the newest `progress-tracker/gap-assessments/docs-verification-*.md`. The mechanical doc gates catch counts, links, flags and enums — not behavioral claims, which are bounded by a quarterly reviewer sweep. Stale past 92d |
| `docs-versions:*` | the doc-variance lane's version watch: each product's declared docs-product-map versions vs its live docs.redhat.com landing page. A NEW upstream version missing from the map is drift (variance tracking is not covering it); a retired one is drift too; below-window historical versions are ignored and a network failure is `unavailable`, never fresh |

New source pairs (IaC-source pin vs inputs, config-vs-cluster once
live inventories exist) register as new check functions in
`check_drift.py` — one function per pair, statuses only from the fixed
vocabulary.

## Cadence

On demand any time; recommended alongside every `/census` run; a
scheduled run is **Konflux fragment 6** (capability-roadmap C3 list)
when that integration lands. `--fail-on drift` makes it CI-gate-able.
This skill's place among the harness's standing jobs — and the jobs
whose staleness its rows backstop — is inventoried in
docs/continuous-operations.md ("Standing jobs — the complete inventory").

## Constraints

- Deterministic checker: **routes attention, never concludes** — no
  check may auto-rebuild, auto-advance a pin, or file a finding.
- Drift between two sources is reported symmetrically; the checker
  never picks a winner (precedence rules live in the compliance plan's
  Graph-wiring section, and applying them is a human/skill decision).
- Thresholds are constants in the script header — change them there
  with review, not per-run.

Also checked: `docs-semantic-sweep` — the newest `progress-tracker/gap-assessments/docs-verification-*.md` report must be younger than 92 days (quarterly semantic docs sweep; procedure in the check-harness-docs SKILL).

## Integrations

**Consumes:** the artifacts it watches — feeds, findings.db,
repo-/portfolio-graph vs the inputs inventory, corpus registration,
ADR pins, external-tools manifest, pqc-facts stamps, dated policies
(the full row list lives in python3 -m traust.cli check drift).

**Emits:** `drift-report.{json,md}` into
`progress-tracker/metrics/drift/` — a terminal operator dashboard; its
stale rows route work to the owning skills (e.g. `dashboards:*` rows →
`/refresh-dashboards`).
