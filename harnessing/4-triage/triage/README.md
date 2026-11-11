# triage

A Claude Code skill that triages a batch of raw security-scanner findings:
verifies each is real, collapses duplicates, re-ranks by derived
exploitability, and tags each survivor with a component owner. Turns a raw
dump into a short, ranked, owned list.

## Status

Ingests secure-code-audit reports, `*-vuln-findings.json` (legacy
`VULN-FINDINGS.json`), vuln-pipeline
`results/` directories, and loosely-structured JSON or markdown from other
scanners.

## Requirements

- Claude Code (or Crush) installed and authenticated
- A read-only checkout of the target codebase (verification reads source;
  it does not build or run anything)
- A file or directory of findings to triage

## Installation

Ships with this repo like every other skill: `harnessing/4-triage/triage/` is the
source of truth, discovered via the `.claude/skills/triage` and
`.crush/skills/triage` symlinks (see AGENTS.md "Adding a new skill"). For
use outside this repo's workspace, symlink it user-scoped:

```bash
ln -s /path/to/traust/harnessing/4-triage/triage ~/.claude/skills/triage
```

## Deterministic accelerators

The skill uses two harness scripts (see
`docs/deterministic-inferential-mix.md`): python3 -m traust.cli check citations
gates each finding's cited file/line/anchor before verifier votes are
spent, and python3 -m traust.cli admin query-index gives verifiers one-lookup
definition/reference queries over a per-run symbol index keyed by
`(repo, sha)`. Both degrade gracefully — on any error the skill falls back
to full votes and plain Grep. Neither ever authors a verdict.

## Usage

From a Claude Code session in the target repo:

```
/triage path/to/findings.json
```

Interactive mode (the default) opens with a short interview about your
environment, threat model, and preferred scoring standard — these shape how
reachability is judged and how severity is labeled. To skip the interview
and use defaults:

```
/triage path/to/findings.json --auto
```

Common invocations:

```
/triage <repo>-vuln-findings.json                   # vuln-scan output, repo = cwd
/triage results/mytarget/2026-04-14/ --repo .       # vuln-pipeline output
/triage scanner_export/ --votes 5 --repo ~/src/app  # high-stakes batch, 5-vote verify
/triage backlog.md --auto --votes 1                 # quick first pass on a markdown report
```

The installed headless runner invokes the same executable skill:

```bash
traust session run --skill triage --role triage-verifier -- \
    /absolute/path/to/raw-findings.json --auto --votes 1 \
    --repo /absolute/path/to/read-only-target --fresh
```

Run from the harness environment, not the target checkout. The runner resolves
the configured model-registry role and requires Claude Code authenticated in
`$TRAUST_CONFIG_HOME/claude-runner` or `ANTHROPIC_API_KEY`. The source-reading
agent and its verifier Tasks author the judgments; no deterministic helper
does. For controlled producer coverage, copy the shipped
`fixtures/canary-findings.json` to a disposable output directory and pass its
paired `fixtures/canary-target` as `--repo`. The seven inputs cover exploitable
findings, a verified weakness, duplicates, refutations and unlocatable evidence.
Capture the real emitted JSON and final validation result; expected outcomes
are not a replacement report. This runs a real model and incurs model spend.

### Read-only Core-prepared input

For remote execution, the trusted caller prepares Core's native `TriageInput`
once and stages its JSON without an envelope. The actual producer accepts it
explicitly:

```bash
traust session run --skill triage --role triage-verifier -- \
    /staged/core-triage-input.json --prepared-input --auto --votes 1 \
    --repo /staged/read-only-checkout --fresh
```

The root fields are `subject`, `findings`, `prepared_at`, `assessor`, `items`.
`subject` contains the repository IDs/URL/ref/SHA and source `assessment_id`;
`findings` is native `FindingContext`. Each item contains `finding`,
`occurrence`, `locations`, `precedents`. The skill retains these native
objects read-only, copying the supplied title/rule/severity/kind and exact
fingerprint/version into working findings while verifiers independently
judge the source. Native IDs are never replaced by triage-local `fNNN` labels.
The current DTO exposes no original scanner report ID, description,
recommendation or arbitrary label collection; absent fields are not invented.

This mode skips **all intake, prepare and record calls**, including on resume.
Source-reading verification, canonical-write validation and deterministic
rendering still run. Output is written next to the prepared input, named from
the supplied repository URL; the external caller records the original JSON
through the native SDK against its original Core source assessment.

## Output

- `<findings-dir>/<repo>-triage.json` — every input finding, annotated with
  `verdict`, optional non-null `kind`, `verify_verdict`, recomputed
  `severity` (non-weakness true positives only), `severity_alignment` vs.
  the scanner's claim, `preconditions`, `vote_breakdown`, `rationale`
  citing file:line evidence, `owner_hint`, and `duplicate_of` where applicable.
  Written next to the input report, sorted by what to act on first.
- `<repo>-triage.md` — deterministic reviewer-facing report: an "Act on these"
  section for non-weakness true positives, a separate "Hardening backlog"
  for verified weaknesses, an "Undetermined" section, then a "Dropped"
  table for refutations and duplicates.

**Verdict and kind are separate.** A proven exploitable finding uses
`verdict: true_positive, kind: vulnerability`; a verified defense-in-depth
or benchmark gap (CIS/STIG/Scorecard/SLSA-style) without a concrete exploit
path uses `verdict: true_positive, kind: weakness`, null severity and
exclusion rule 13. Both are real; only the former is ranked as a
vulnerability. Unknown kind stays omitted, never `null` or a vulnerability
default. The remaining triage verdict semantics are defined by the
[installed triage contract](https://github.com/traust-security/traust-contracts/blob/development/artifacts_schema/v1/triage.schema.json): undetermined
means no conclusion, false positive means refuted, and duplicate routing
is unchanged. Missing source or runtime-only uncertainty is not refutation,
and a known kind alone never confirms an undetermined/manual-review item.

`summary.hardening` counts verified weaknesses; `summary.true_positives`
counts non-weakness true positives (including omitted kind). These buckets
are disjoint, and `by_severity` never includes weakness. Historical final
`verdict: hardening` remains readable in the backlog, but is not new output.
The transient verifier `HARDENING` vote and all four existing
`vote_breakdown` keys/counters remain intact, including FP dissent.

Recording maps TP+weakness to `validity: confirmed, kind: weakness`, not
`validity: hardening`; `needs_manual_test` and undetermined cases go to
review instead of confirmation. Core's canonical-write admission gate
refuses new deprecated hardening verdicts; prose is not write enforcement.
The final producer gate is
`traust reporting validate <report>-triage.json --schema triage --canonical-write`.
It checks the serialized report against the shared contract, including
input-only runs that do not record Core decisions. Default validation,
`triage check` and `triage render` remain historical-read compatible.
Exact stored historical triage replay remains idempotent, without rewriting
its artifact.

A `needs_manual_test` verify-verdict means static reasoning hit its limit
on that finding — treat it as a recommendation for a human to build a
controlled proof-of-concept, not as a failure.

## Checkpointing and resume

Per-phase state is written to `./.triage-state/`. If a run is interrupted
(rate limit, context exhaustion, Ctrl-C), re-invoking `/triage` with the same
arguments resumes from the last completed phase — the interview is not
re-asked and verifiers already tallied are not re-spawned. Old phase/shard
hardening conclusions are interpreted as TP+weakness in working state;
disjoint lists and final output are rebuilt before new emission. Stored
checkpoints and historical triage artifacts are not migrated or rewritten.
Pass `--fresh` to start over. `./.triage-state/` is scratch; add it to
`.gitignore`.

## What it does and doesn't do

- **Does:** read source, grep for callers, reason about reachability and
  protections, vote, rank, and route.
- **Does not:** build, run, or test the target; install dependencies;
  reach the network; write proof-of-concept exploits. All conclusions are
  static. This is deliberate — the skill is meant to run in a review box
  alongside a read-only checkout.

## Provenance

Derivative work of the `triage` skill in
**defending-code-reference-harness** (Copyright 2026 Anthropic PBC, Apache
License 2.0 — see the harness root `NOTICE` and `LICENSES/Apache-2.0.txt`),
ported into this harness at v0.22.0 and modified per `CHANGELOG.md` —
notably the citation gate, symbol index, verdict taxonomy, and
installed triage contract machine gate, which are harness additions.
