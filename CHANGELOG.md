# Changelog

All notable changes to Traust are documented here.

## [0.3.0]

## Changes

- **Reverted the 0.10.0 findings.db and census changes.** Every consumer
  reads the previous nine-table `findings.db` projection again and the census
  walks reports as before. Pins: contracts 0.35.0 (the 0.33.0 storage
  contract), engine 0.16.0, ledger 0.6.32. 0.10.0 remains tagged and should
  not be pinned. Rebuild `findings.db` with `traust corpus findings-db` after
  upgrading; a store built by 0.10.0 is refused.

## [0.2.13]

- **The reachability graphs now say what they are for**, not just what they
  are. Their purpose is deciding whether an advisory reaches *your* code: a
  manifest pin proves a vulnerable package is present, not that anything calls
  the vulnerable function. `/impact-analysis` uses the answer as its strongest
  evidence tier, and `/secure-rpm-audit` uses it too.

  Documents the asymmetry that makes the tier trustworthy: a resolved
  first-party call promotes to evidence `symbol` and classification
  `affected`, package-level calls promote `manifest` → `symbol-usage`, and an
  absent call path **never demotes anything** — DI, reflection and
  MethodHandles hide edges from static analysis, so `no_call_sites_found` is
  recorded honestly. Also why the tier is gated on cheaper tiers (a CPG is
  expensive) and that an absent Joern records `skipped`, never a fake pass.

## [0.2.12]

- **`findings.db` removed from the graph list.** It is a relational projection
  of the findings corpus, not a graph — the page even said so while listing
  it. It appears now under an explicit "Not a graph" heading, because its
  location in `analysis-results/graph/` invites the assumption. One table
  inside it, `graph_edges`, is imported from repo-graph so findings can be
  joined to what ships them; a borrowed edge table does not make the database
  a graph.

- **Joern is described as what it is: a Code Property Graph.** AST, control
  flow and data flow in one queryable graph, built by `joern-parse` with the
  frontend named per language and queried with CPGQL. Calling it a "call
  graph" undersold it. Still transient — built in a temp dir and discarded
  with the run — so it and the govulncheck call graph are the richest graphs
  the harness touches and the only ones that cannot be queried afterwards.

## [0.2.11]

- **`docs/graphs.md` now covers every graph the harness builds or reads**, not
  two of them. Added: `findings.db` (the findings projection), the ATT&CK
  Navigator coverage layer and how its observed/modeled/derived scores differ,
  per-finding `attack_chains[]`, and the transient reachability call graphs
  built by `adapters govulncheck` / `adapters joern` — which are analysis
  steps with nothing persisted, worth saying so nobody looks for an artifact.

  Retitled: calling both graphs "portfolio graphs" reproduced the exact
  confusion the page exists to remove. One is `repo-graph`, one is
  `portfolio-graph`.

  Also dropped the doc's opening banner, which described how the page was
  researched rather than telling a reader anything.

## [0.2.10]

- **`docs/` is adopter-facing; estate specifics removed.** `docs/graphs.md`
  carried one deployment's graph sizes and node counts, and
  `docs/model-classes.md` carried development history. Neither is product
  documentation. Sizes are now stated as deployment-specific with a pointer to
  `repo-graph-stats.md`, which reports the reader's own.

- **New docs-consistency check, `docs/ estate neutrality`.** The deployment
  vocabulary was applied to `config/` but never to `docs/`, which is how those
  specifics passed every gate. The same block/review rules now run over
  `docs/**/*.md`. All 32 existing docs pass unchanged; mutation-tested by
  injecting a vocabulary match.

  Note the limit: estate-specific *figures* — graph sizes, corpus counts —
  match no pattern and stay a review concern. Write them as
  deployment-specific rather than quoting one deployment's numbers.

## [0.2.9]

- **New `docs/graphs.md`** — how `/repo-graph` and `/portfolio-graph` are
  actually used, which was documented nowhere. The two SKILL.md files were the
  only substantive source; every mention across `docs/` was a one-line passing
  reference with no section.

  Covers what each graph holds and the question it answers, the L0–L4 layer
  model, that `repo-graph.json` is `/portfolio-graph`'s L0 spine (so it is a
  prerequisite, not an alternative), the full consumer list for each artifact,
  and what a stale graph gets wrong — a stale repo-graph misstates coverage
  and ownership, a stale portfolio-graph *understates* blast radius, which
  reads as good news.

- **`/portfolio-graph` gains the `## Integrations` section it was missing.**
  `/repo-graph` had one; the skill holding the code-level graph
  documented neither its consumers nor what depends on it being fresh.

- **New docs-consistency check, `graph consumer lists`.** The consumer lists
  were built by searching for the artifact filenames, so they rot as soon as a
  new consumer lands. The check fails when anything opens
  `portfolio-graph.db` or `repo-graph.json` without being named in the doc.
  Mutation-tested with a throwaway module, and it caught two real cases while
  being written: itself (it holds the artifact names as data) and
  `check_drift`, which is documented under its skill name `/drift-watch`.

## [0.2.8]

- **Documents how an adopter configures their own models**, which was the one
  question `model-classes.md` could not answer. `model-registry.yaml` is a
  seeded shipped default and the copy in `$TRAUST_CONFIG_HOME` wins, but that
  was a single clause in `model-routing.md` and said nothing about how.

  New "Configuring your own models" section covers the per-role granularity
  (repoint one role, the rest keep their defaults), the exact schema
  requirements at provider/model/role level, that no vendor is assumed, that
  `validate` refuses a sub-floor approval, and what
  `install_traust --doctor`/`--force` do to a deliberate override. Linked from
  `model-routing.md`, `requirements.md` (which now says outright that the
  classes are defaults, not requirements) and `config/README.md`.

  Every claim was executed against a scratch config home, which caught the
  worked example being wrong: replacing a role block drops `candidates` and
  `ledger_validity_writer`, both schema-required, so the YAML an adopter
  would have copied failed validation. The example now changes only the
  `approved` line.

## [0.2.7]

- **New `docs/model-classes.md`**, linked from `requirements.md` and
  `model-routing.md`: what each of the four tier classes is for, the eleven
  role floors, which roles may write a validity verdict into the ledger, the
  escalation triggers, and a per-skill class index.

  Two things it clears up, because both were causing the question "where is
  this documented" to have no good answer. The per-skill classes live in *two*
  tables — `campaign-workflow.md` (21 pipeline skills) and
  `standalone-usage.md` (27 standalone skills) — which are complementary, not
  duplicates, so neither reads as authoritative. And skill frontmatter's
  `harness.tier` (`primary`/`secondary`/`tertiary`/`ci`) is a *different axis*
  entirely, which makes it look like the answer when it is not.

- **New docs-consistency check, `model-class index`.** The index is derived
  from the two usage tables and nothing links a skill to a class
  mechanically, so the check fails on a misclassed skill, a name that is not a
  skill, an indexed skill with no class in either table, or a classed skill
  missing from the index. Mutation-tested both ways.

## [0.2.6]

- Pin traust-contracts v0.5.0, traust-engine v0.2.5 and traust-ledger v0.3.0.
  Brings in the `evidence` projection column (so typed patch evidence is
  queryable in SQL, not just present in the payload), the fixed
  `traust_storage` PostgreSQL namespace, and the ledger's stamp/whoami REST
  verbs.

  Smoke-tested against the pinned copy rather than assumed: the
  proof-requires-both-observations rule still holds, the verification family
  still carries `evidence`, and both projection tables now report an
  `evidence` column from the pinned DDL.

## [0.2.5]

- Point every sibling pin at the new `traust-security` GitHub organisation:
  traust-contracts v0.4.0, traust-engine v0.2.4, traust-ledger v0.2.3.

  The org move could not be a URL edit. uv honours `[tool.uv.sources]` inside
  git dependencies, so a tag cut before the move carries the old URL and
  resolution fails with "conflicting URLs for package traust-contracts". The
  corrected URL only reaches consumers as a new tag, making this the same
  bottom-up train a schema change needs: ledger 0.2.3, engine 0.2.4, then
  here.

## [0.2.4]

- **The execution boundary is a config setting, not an invented env var.**
  0.2.3 added `TRAUST_SANDBOXED_RUNNER`, a variable nothing on the platform
  exports — a convention only this repo knew about, so the path it guarded
  would never have fired. Replaced by `sandbox:` in
  `$TRAUST_CONFIG_HOME/execution-boundaries.yaml`, with a template in
  `config/` seeded by `install_traust`.

  `sandbox: none` is the default: direct execution with a scrubbed
  environment, on a disposable copy rather than the worktree the diff comes
  from. `sandbox: podman` opts into a nested rootless container and is never
  silently downgraded — with no working runtime the lane reports
  `not_attempted`. Detection stays `podman info` rather than
  `command -v podman`.

  Verified on both lanes in both modes: default runs and returns `proves`
  (mutation 19/19; property failed-then-passed), a configured `podman` with no
  runtime refuses with that reason, and an invalid value falls back to the
  documented default. Documented in setup.md, config/README.md,
  external-dependencies.md and the orchestrator prerequisites.

## [0.2.3]

- **The evidence lanes no longer hard-require podman.** `run_mutation.sh` and
  `run_property.sh` accept either nested podman or a platform-attested
  sandbox, declared by the orchestrator as
  `TRAUST_SANDBOXED_RUNNER=<runner-label>`. On a central runner whose image
  carries the toolchain but cannot nest containers, both lanes would otherwise
  have returned `not_attempted` on every run, permanently.

  Still no *unattested* fallback: with neither boundary the lanes emit
  `not_attempted` rather than running target code in the open. The env var is
  a declaration of deployment fact, not a security control — its only job is
  to stop podman's absence from being read as permission.

- **Boundary detection uses `podman info`, not `command -v podman`.** The
  client binary is present on a host whose VM is stopped and in images that
  ship the CLI with no runtime; choosing podman there failed every run with
  exit 125 — the exact failure the change was meant to prevent. Caught by
  running it with the VM deliberately stopped.

- The resolved boundary is recorded in each evidence item's `command`, since a
  verdict from nested podman and one from an attested sandbox are not equally
  strong. `docs/external-dependencies.md` gains the boundary contract and
  names the new podman consumers; `docs/continuous-operations.md` gains the
  orchestrator prerequisite row.

## [0.2.2]

- Pin traust-contracts v0.4.0 / traust-engine v0.2.3 / traust-ledger v0.2.2,
  so a *verification* report can carry the typed patch-evidence block.
- **`/verify-remediation` gains its one executed claim** (ToB plan item 5b).
  Step 4-pre already re-ran the scanner on the patched checkout and compared
  against facts recorded in the original report — which is why it warned that
  a vanished fact can be rule evolution rather than a code change. New step
  4-pre.5 scans BOTH revisions and emits a typed `scanner_differential`
  evidence item, making the rule-evolution case an explicit
  `not_attempted` instead of a silent mis-read.

  §8a's stage-8 ceiling is lifted for that differential only: `proves` means
  the pattern the finding rested on is gone — pattern-level, since a diff can
  silence a scanner by moving the sink. Findings with no scanner backing stay
  analysis-only, and step 4a's root-cause check remains mandatory.

## [0.2.1]

- Pin traust-contracts v0.3.0, traust-engine v0.2.2 and traust-ledger v0.2.1 —
  the final hop of the train for the remediation `evidence[]` block. Until
  this pin, `reporting/validate.py` rejected any report carrying it, because
  the remediation schema is `additionalProperties: false`.

  Smoke-tested rather than assumed: the same evidence-carrying report
  validates with 0 errors against the newly pinned schema and is rejected
  against v0.1.1 with *"Additional properties are not allowed ('evidence' was
  unexpected)"*, and all eight enforcement cases behave — a `proves` claim
  missing either observation is refused, `not_attempted` without a reason is
  refused, and invented kinds/outcomes are refused.

## [0.1.1]

## Changes

- Event `occurred_at` is built through contracts' `to_rfc3339` via
  `traust.lib.event_time.report_occurred_at`, replacing the same f-string in
  four emitters. A report stating an unusable date now raises instead of
  getting a silent substitute; an absent one falls back to `recorded_at`.
  A triage report carrying `"triage_completed": true` previously emitted the
  literal `'TrueT00:00:00+00:00'`.

- `--recorded-at` is validated at the CLI boundary in all six producers. It
  fed `recorded_at` unchecked, whose `[:10]` prefix reaches interactive
  `source.ref` and therefore `event_id`.

- New migration `traust.migrations.fix_event_timestamps`: converts bare dates
  to midnight UTC (preserving the `[:10]` prefix, so `event_id` does not
  move), drops an unrepairable `occurred_at`, and reports a non-conforming
  `recorded_at` rather than rewriting a required field. Dry-run by default,
  idempotent, and a layer that arrives signed must leave signed.

- Read sites prefer a *parseable* timestamp over a merely present one.
  `build_trends.py` bucketed via `date.fromisoformat(value[:10])` and crashed
  on `'TrueT00:00'`.

- Unrelated fix, bundled: `check_reference_integrity` allowlisted only
  `<skill_dir>/scripts/` while the docs use `<skill-base>`, so it flagged a
  valid reference as stale and failed on a clean tree. It also missed a
  genuinely stale path in the same file. Both corrected.

### Upgrading

Pins move to contracts / engine / ledger 0.1.1, which enforce RFC 3339 on
`LayerEvent.recorded_at` and `.occurred_at` on read as well as write. Run the
migration against any existing corpus first:

```bash
python3 -m traust.migrations.fix_event_timestamps <results-root>          # dry run
python3 -m traust.migrations.fix_event_timestamps <results-root> --apply  # write
```

`--apply` re-roots each repaired layer, so it needs a signing identity
(`LAAS_SIGNING_KEY_PATH` + `COSIGN_PASSWORD`) for layers that are currently
signed. Unsigned layers only need re-stamping.

## [0.1.0]

Workflow engine for automated, multi-framework security assessment of
software portfolios — source repositories, container images, RPM packages,
Kubernetes operators, and infrastructure-as-code. Provides the skills, slash
commands, schemas, and prompt engineering that let an AI coding agent run
consistent, repeatable audits, then triage and validate findings, recording
every disposition in a signed ledger.
