---
name: mine-ledger
description: Use when the user asks to mine the disposition ledger for confirmed true positives, build or refresh the rule-calibration corpus, find rule-pack coverage gaps, check per-rule precision, or produce the opengrep rule-authoring backlog — e.g. "mine the ledger", "what TP clusters have no rule", "how precise are the traust rules", "refresh the rule-mining report". Runs out-of-band from audits; audits themselves feed it via structured scanner_correlation entries. Mined and adopter-supplied rules require deterministic CLI admission with native Opengrep validation and strict tests before accepted-pack writes; never defer acceptance to CI.
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Bash(python3 *traust* -m traust.cli sweep:*)
  - Bash(python3 *traust* -m traust.cli sweep rule-lane:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# Mine Ledger

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Turn the campaign's disposition ledger into rule-authoring fuel: extract
every ledger-**confirmed** true positive from traust-core's recorded
findings (their folded disposition), cluster by (primary CWE, language),
match against the Traust opengrep pack (shipped in the security pack, the
only copy), and aggregate the
per-fact judge decisions audits record in `scanner_correlation` into
campaign-wide per-rule precision.

Adopter-authored rules are an additional input, not a replacement for portfolio/ledger mining.
Continue `traust sweep mine`, `regression-drafts` and `rule-lane` for the existing
finding-driven workflow. Portfolio graph/database pre-queries can scope the work; the
authoritative mining corpus remains Core's recorded findings and confirmed dispositions.
Adopters can also supply local or pinned-Git rule packs. Both origins must use the
same native pre-write admission tool before accepted rules are written or selected
through `overrides.rule_pack_allowlist`; configuring a pack does not disable mining.

This skill is the out-of-band half of a loop the audits feed by default:
`/secure-code-audit`'s pre-scan records every promote/dismiss decision as a
structured `scanner_correlation` entry (tool `opengrep`, `rule_id`,
`result: promoted|dismissed`), and this skill harvests them. (traust-core
reads them as the rule on each finding's occurrence, judged by the
finding's disposition.)

## Input

`$ARGUMENTS` (all optional):

- A findings tree to mine — *retired*: `sweep mine` reads traust-core's
  recorded findings.
- `--pack <name>` — rule pack to check coverage against (default `traust`: the
  pack the security pack ships, `packs/security/detection/opengrep-rules/`,
  or `locations.opengrep_rules`; an enabled allowlist supplement by its name).
- `--out <file>` — also write the whole mining (with the TP corpus) as
  JSON; the command prints it without the corpus.

## Bundled precedent cards

[precedent-cards/pilot.yaml](precedent-cards/pilot.yaml) supplies the pilot
cards traust-core's tests use to check card validation and sweep behavior
(`python3 -m traust.cli sweep cards <cards.yaml> [--checkout <dir>]`). Consult it when maintaining precedent-card
compilation; these fixtures are not findings or production sweep inputs.

## Procedure

**Step 1 — run the deterministic miner** (all analysis is script-side):

```bash
python3 -m traust.cli sweep mine [--pack <name>] [--out <file>]
```

Output: `corpus` (one confirmed TP per finding — the rule
specification material, in `--out`), `covered` / `uncovered` clusters,
`languages`, `precision`, `worklist`. (`tp-corpus.jsonl` and
`rule-mining.{json,md}` are still written by the lane, `sweep rule-lane`.)

> **Optional accelerator — findings-db pre-queries.** Cluster-shape
> questions ("which CWE×language pairs dominate confirmed TPs?", "how
> many resolved-at-fix-commit findings exist for CWE-78?") can be
> answered instantly from the C9 projection (`/findings-db`) before
> committing to a full mine. The miner reads the recorded dispositions — its
> output is rule-authoring material and must reflect the live ledgers,
> not a projection that may be one census behind. DB for scoping,
> miner for the corpus of record.

**Step 2 — interpret the backlog.** For the top uncovered clusters, read
3–5 of the example findings (ids are in each cluster's `examples`; fetch
them with `python3 -m traust.cli findings find <id>`) and answer, per cluster: *is this mechanically
detectable?* Clusters like missing-authentication (CWE-306) or confused
deputy (CWE-441) usually are not — say so and move on. For detectable
clusters, propose concrete rule candidates: language, sources/sinks or
pattern shape, expected sanitizers, and the example finding ids that
specify the behavior. That proposal — not rule YAML — is this skill's
deliverable; authoring follows the pack README's standards and its
test-and-calibrate gate.

**Step 3 — review precision.** Precision only counts reports where the
pre-scan actually ran: check `metadata.additional.deterministic_steps`
(`"opengrep": "ran"` vs `"skipped: …"`) before treating an absence of
judge decisions as signal — a skipped scanner is not a quiet rule.
(`mine_rules` counts only occurrences a rule matched; an unjudged hit
counts as `other`, never as clean.) Any
rule whose campaign precision (from
audits' judge decisions) sits below the plan's ~50% gate is flagged: read
a sample of its dismissal rationales from the source reports and propose a
tightening (sanitizer, metavariable constraint, benign-suffix exclusion)
or retirement.

**Step 4 — hand back.** Report: TP corpus size, top uncovered clusters
with a detectability verdict each, the per-language coverage table
(confirmed TPs, covered/uncovered clusters, pack rule count — sorted by
uncovered-TP count, the tranche-priority order), rule candidates
proposed, precision flags, and the calibration-worklist size (repos
whose confirmed TPs the pack should rediscover — the re-scan set for
validating pack changes).
Update the rule-pack backlog your deployment keeps when the picture has
changed materially.

## Mandatory validation before accepted-rule writes

This applies to rules authored from mined findings **and** rules supplied by adopters.
Author candidates and paired fixtures only in a private working directory. Never use
`Write`, a copy command or a category-file edit to add unvalidated rules to an installed
pack. A CI result is not an admission receipt.

Use the deterministic CLI tool to accept a complete candidate pack:

```bash
python3 -m traust.cli sweep import-rules <candidate-pack> --into <new-adopter-pack-directory>
```

The tool must perform these steps before writing the accepted destination:

1. Snapshot the input in private temporary staging.
2. Run Opengrep's own [`validate`](https://www.opengrep.dev/docs/commands/validate.html)
   (YAML, schema, parsed patterns and metachecks) and
   [`test --json --strict`](https://www.opengrep.dev/docs/commands/test.html)
   (annotated matching behavior, with parser warnings treated as failures).
3. Require positive `ruleid:` and negative `ok:` assertions for every rule, exact
   expected matches and complete native test results. Zero tests, missing/skipped
   results, unexpected matches or a native error mean refusal, even with exit 0.
4. Only after passing, import the tested bytes into a previously nonexistent
   destination. Never overwrite an installed pack or reread changed input as accepted.

Use same-basename rules and fixtures, for example `policy.yaml` and `policy.py`, or
`policy.test.yaml` for YAML rules. A `.fixed.py` output is not negative matching
coverage. Preserve relevant operations in safe/fixed/guarded fixtures; do not replace
them with unrelated no-ops or weaken assertions to pass.

Missing CLI/native capabilities or a failed check **stop admission**. Do not copy the
rule anyway, wait for a later scan, or delegate the decision to Konflux/adopter CI.
Native fixtures establish matching behavior, not business-logic correctness: inspect
input control, effective guards, authorization and deployment assumptions, and retain
the existing semantic-review and recorded-scan calibration requirements.

For updates, prepare the complete revised pack privately and import into a new
versioned directory. Select its reviewed rule IDs and source in the existing
`overrides.rule_pack_allowlist` only after the promotion requirements pass.

## Regression-rule drafts (C6)

Every RESOLVED-at-a-fix-commit ledger finding is a free calibration pair:
pre-fix file (rule must fire) and post-fix file (rule must not). Stage
drafts, author, verify, promote:

```bash
# 1. stage drafts (deterministic; identical pairs skipped) into
#    locations.rule_drafts (traust-core regression_pairs; skipped fixes listed with why)
python3 -m traust.cli sweep regression-drafts [--cwe CWE-494] [--limit 6]
# 2. author rules and paired ruleid:/ok: fixtures in a private candidate pack.
python3 -m traust.cli sweep verify-draft <rule-drafts>/<draft> \
    --rule <candidate-pack>/<language>/<category>.yaml
# passes only when before/ fires and after/ is silent; not a promotion receipt.
# 3. after semantic review/calibration, use the mandatory native pre-write tool:
python3 -m traust.cli sweep import-rules <candidate-pack> --into <new-adopter-pack-directory>
# 4. select reviewed IDs and this source in overrides.rule_pack_allowlist.
# Keep regression_of (fingerprint + fix commit); never copy deployment-specific
# rules into the public baseline. Delete authoring drafts only after promotion.
```

Not every fix is rule-expressible: additive-coverage fixes (a filter
gained patterns) and cross-file behavioral fixes have no matchable
pre-shape — reject those drafts with a note rather than authoring a
noisy rule. First promoted regression rule:
`traust-bash-regression-codecov-uploader-latest` (bash/supply-chain).

Draft skeletons and before/after snapshots are authoring material, not an active
pack and not evidence of passing native checks. Adopter packs are supported
through the existing allowlist: `source` may be a local rule directory relative
to that allowlist file, or an HTTPS Git source pinned to a 40-hex commit SHA
(the repository's existing `rules/` subtree convention). Enabled packs need
explicit unique rule IDs and paired native fixtures. Import the complete revised
pack through the pre-write tool above, not just its selected IDs. Scan-time native
checks are additional protection, not permission to bypass admission.

## Class-generalization sweeps (plan §6, Phase 4)

Every **confirmed** finding with a syntactic signature — a sink call
form, a config key+value, an annotation misuse, a hardcoded literal —
defines a class the whole corpus should be checked for. The sweep
engine (python3 -m traust.cli sweep) extends the backlog flow above into
a full loop: **backlog item → draft → calibrate → SWEEP → triage**.
Four resumable stages:

```bash
# 1. gather + classify confirmed findings (validity=confirmed, as
#    recorded in traust-core); rule-expressible vs
#    not is decided deterministically and every "not" carries a reason
python3 -m traust.cli sweep collect
# 2. stage candidate rules for expressible classes with no pack
#    coverage (dedup against pack rule ids + existing drafts); drafts
#    land in rule-drafts/ per the conventions above, each citing its
#    source confirmed finding(s) in metadata.generalized_from
python3 -m traust.cli sweep draft
# 3. author the pattern (human+LLM, same authoring contract as C6),
#    calibrate via the pack's test-and-calibrate gate, then sweep —
#    shallow clones into a bounded temp root, one rule, --limit capped
python3 -m traust.cli sweep sweep --rule <draft-or-rule-id>
# 4. aggregate hits into the triage-ready candidates file + summary
python3 -m traust.cli sweep emit --rule <draft-or-rule-id>
```

**Run-by-default policy (plan §6):** once a class rule is authored and
calibrated, the corpus-wide sweep RUNS by default — it is not a
proposal to maybe sweep later — and its results ENTER TRIAGE. The
artifact says so in its own header. The engine never files findings,
never routes to Jira, and never adjudicates a hit.

**Human points, unchanged:** (1) pattern authoring against the cited
source findings; (2) rule promotion into the shipped pack, which stays
with the existing mine-ledger calibration path (fixture `ruleid:`/`ok:`
lines, the plan's test-and-calibrate gate — never promoted by the
engine); (3) verdicts on sweep hits, which belong to /triage and its
disposition ledger like any other candidate batch.

**Proposing a rule for an uncovered shape.** When an audit or a
coverage gap shows a code shape no pack rule covers, you may propose a
rule for it. Author one rule and meaningful vulnerable and equivalent safe,
fixed, sanitized or guarded examples in a private working directory, with `ruleid:`
and `ok:` assertions for every rule. Preserve valid positives and test the
actual guard boundary, not an unrelated no-op. The proposal CLI performs native
validation/tests before writing an admitted draft; never write into `rule-drafts/`
by hand. Use the mandatory import tool before adding the reviewed pack to installed rules.

```bash
python3 -m traust.cli sweep propose-rule --rule <rule.yaml> --example <example.py> \
  --shape "<the uncovered shape, one line>" --checkout <the repository it came from>
```

The gate admits it only if all of these pass:
- it is one well-formed rule (id, message, languages, severity, `metadata.cwe`);
- no pattern is a catch-all;
- no path glob leaves the tree or selects every file;
- no regex has a backreference, lookbehind or nested quantifier;
- native `opengrep validate` and `opengrep test --json --strict` succeed;
- every rule has positive and negative assertions with exact expected matches,
  including no unannotated extra matches and no missing, unknown or skipped
  check receipts;
- the checkout scan completes without engine errors or unknown coverage, and
  its hits stay under the cap; partial error-bearing scans refuse admission.

A rule that fails a static check never runs. Native validation and strict
tests are mandatory before admission and cannot be skipped. Exit 0 means it
was staged as an authored draft, not promoted or proved exploitable. Exit 1
lists failing checks: fix it or drop the proposal, never loosen the examples
to pass. An admitted draft then follows steps 3–4: calibrate, `sweep sweep`,
`sweep emit`. Its hits are triage candidates, never findings.

Before promotion, a reviewer must check whether the matching shape really
supports the claimed security/business logic: input control, framework/version
behavior, effective guards, authorization and deployment boundaries. Native
fixtures establish matching correctness only. File-level words, name-based
heuristics and sanitizer call shapes do not establish real-world safety or
exploitability. Promotion remains a human point.

Sweep output lands at
`analysis-results/scan-testing/sweeps/<rule-id>/sweep-candidates.json`
(schema: repo, file:line, matched excerpt, rule id, source-finding
provenance) plus a `sweep-summary.md`, and is consumed as /triage input
material. Stage state lives in traust-core (its object store);
every stage skips work already done (re-run to resume).

## Scheduled lane (python3 -m traust.cli sweep rule-lane)

The deterministic half of this skill runs as a standing lane
(docs/continuous-operations.md, "Lane cadences") — orchestrator-neutral in
the dependency-watch pattern: identical behavior from an operator
session, cron, or any enterprise scheduler. One entry point chains the
miner, `sweep collect` + `draft`, bounded regression-draft
staging (`sweep regression-drafts --skip-existing --limit N` — existing
draft dirs are never clobbered; the lane skips this stage when no forge
reads are configured), and a **delta report** against the
previous `rule-mining.json` (new/resolved/changed uncovered clusters,
precision movements crossing the ~50% gate, TP-corpus growth) written to
`progress-tracker/metrics/rule-mining/lane-delta.{json,md}`. Exit 0 =
quiet, 1 = attention needed (the delta says what), 2 = a stage failed.
No model calls happen inside the runner.

**Stage-A gate reachability.** Each pass also answers, per watched
language and candidate pack, *is calibrating this language possible
yet?* — no clones, pure corpus plus the cached pack. A rule clears the
rediscovery gate only by firing in ≥3 repos that share a CWE the pack
targets, so when no covered CWE spans that many the run is unwinnable
before it starts and would return a table of structural zeros. Measured
2026-08-07 against argus-observe-rules: rust/c/csharp max span **1**,
cpp **0** — all blocked on ground truth, not tooling. The lane raises
attention only when a gate **opens**; a steady blocked state is silent,
because a weekly complaint about a known-blocked language is noise.
Watched set: `WATCHED_LANGS` / `WATCHED_PACKS` in traust-core's `models.rule_mining`.

**Enabled external-pack rules are re-checked against the precision
gate.** An external pack is enabled per-rule via
`overrides.rule_pack_allowlist` in `traust.yaml` (`run_opengrep.py --rule-allow @<file>`),
never wholesale — argus ships 640 rules of which 19 are 86% of volume.
Stage A can only measure *rediscovery* before a rule has ever run;
precision arrives afterwards from `scanner_correlation`, so each pass
re-scores every allowlisted rule and flags any that fell below the ~50%
gate as a demotion candidate (one YAML line). Rules not yet judged in
any audit are listed separately — silence is not a pass.

```bash
# weekly (Mondays 06:40), from the campaign workspace root — plus
# on-demand whenever /drift-watch's `rule-mining` row goes stale
# (ledger events >7d newer than the artifact, the post-wave trigger)
40 6 * * 1  cd $WS && python3 -m traust.cli sweep rule-lane
```

**Standing delegation (user, 2026-07-29):** scheduled agent runs of this
skill proceed from the lane's delta report through semantic review, rule
authoring and **the full test-and-calibrate gate** without per-run approval:
(1) the mandatory CLI import tool runs native `opengrep validate` and
`opengrep test --json --strict`, exact expected matches and positive/negative
coverage for every rule before writing accepted rules; (2) the default-scan
canary (`uv run pytest tests/test_default_rule_packs.py`); and (3) TP-rediscovery
calibration against recorded corpus scans. No judgment waives a failed leg or
defers admission to CI. Matching tests never substitute for semantic review.
Sweep hits and mined candidates still route to **/triage** like any other
candidate batch — the lane never auto-files findings, writes to ledgers or
touches Jira.

## Constraints

- Read-only over the findings tree; never edits reports or ledgers.
- The miner is a candidate generator: cluster counts and precision numbers
  route attention, they do not conclude — rule decisions stay with the
  authoring loop and its mechanical calibration gate (delegated for
  scheduled runs as above).
- Cadence: weekly via the lane runner (python3 -m traust.cli sweep rule-lane,
  see *Scheduled lane*), plus a post-wave trigger — `/drift-watch`'s
  `rule-mining` row goes stale when ledger changes are >7 days newer
  than `rule-mining.json`, so a large audit/triage wave summons the lane
  ahead of schedule.

## Integrations

- **Inputs:** cumulative `*-findings-current.json` ledgers and the
  `scanner_correlation` judge decisions audits record by default
  (`sweep mine` and the lane read them from traust-core).
- **Inputs (sweeps):** *retired:* the prior confirmation artifacts under
  `analysis-results/scan-testing/` (fast-track critical confirmations,
  matrix votes, fresh-only triage); confirmations are traust-core's recorded findings.
- **Outputs:** `rule-mining.{json,md}` inform the opengrep-pack backlog
  (plan doc) and are freshness-gated by `/drift-watch`'s `rule-mining`
  row; `tp-corpus.jsonl` is the rule-authoring specification
  corpus consumed by the pack's test-and-calibrate workflow — a human
  authoring loop, deliberately not another skill; sweep runs
  write `sweep-candidates.json` and `sweep-summary.md` per rule under
  `analysis-results/scan-testing/sweeps/`, consumed by **/triage** as
  raw candidate input (run-by-default policy, error-correction plan §6;
  the ingest mapping — `candidates[]` fields, `origin: sweep`,
  provenance-as-context — is the triage SKILL.md's "Note —
  class-generalization sweep candidates").
- **Outputs (lane):** `lane-delta.{json,md}` (producer:
  python3 -m traust.cli sweep rule-lane) — consumed by the operator /
  scheduled `/mine-ledger` session as the worklist for the delegated
  authoring-and-calibration pass (*Scheduled lane* above), and by
  `/drift-watch`'s `rule-mining` staleness row, which triggers the next
  lane run when ledgers outrun the artifact. The lane's nonzero exit is
  the scheduler-facing attention signal.
