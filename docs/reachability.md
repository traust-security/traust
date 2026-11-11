# Reachability — how the harness decides "is the vulnerable code actually called?"

The reference for every reachability mechanism the harness runs: which
engines exist, what each may conclude, who consumes the result, and the
guardrails that bound it. The per-language coverage matrix is in
[language-support.md](language-support.md).

**Coverage is tracked, not just documented.** `/drift-watch`'s freshness
view lists the coverage gaps each repository's latest audit reports
(`AssessmentService.coverage`), a missing symbol-tier engine among them. A
language with no engine is a standing precision gap, not a neutral absence:
every dependency hit in it ceilings at `likely_affected` on manifest evidence.

> **Joern does not deliver dependency reachability for Java, and the reason
> is structural.** Java resolves calls through interfaces; an advisory names a
> library-internal implementation, and the static call graph cannot connect
> the application's interface call to that implementation. Widening the CPG
> to the dependency closure links the JARs but still does not resolve the
> path. Measured on a full Maven advisory sweep the promotion rate to
> `affected` was zero, and the Java tier was withdrawn. The C/C++ Joern tier
> is **promotion-only**: a found call site upgrades evidence; an absent path
> proves nothing. Before adding or restoring a Joern reachability tier,
> answer: does the language resolve calls statically or through
> interfaces/duck typing; does the validation corpus contain
> library-internal advisory symbols or only directly-called API; does the
> tier change a classification or only an evidence level; and what is its
> measured promotion rate on a real advisory corpus.

## The rule that shapes everything

Reachability tooling obeys the deterministic-tooling doctrine
([deterministic-inferential-mix.md](deterministic-inferential-mix.md)):
a deterministic tool may **route, gate, tag, or index — never conclude**.
Reachability output is a *tag with evidence attached* (a call path or call
site), consumed by audit/triage agents and classification logic. It is never
a finding, never a verdict, and never grounds for auto-dismissal.

## The engines

| Engine | Languages | Question answered | Soundness | Artifact |
|---|---|---|---|---|
| **govulncheck** (python3 -m traust.cli adapters govulncheck) | Go | is a vulnerable *function* on a static call path from first-party code? | **Sound both directions**: `symbol_reachable` promotes; `package_imported_not_observed` / `module_required_not_observed` are honest negatives (vocabulary is deliberately `not_observed`, never "unreachable") | `<repo>-govulncheck.json` — one candidate per OSV advisory, shortest observed call path caller-first, full tool/DB/SHA provenance at emission time |
| **Joern c2cpg** (python3 -m traust.cli adapters joern, `--language c`) | C/C++ | does first-party code call the vulnerable function directly? Exact function-name matching (prefix matching over-matches short C identifiers) | **Promotion-only**: a found call site upgrades evidence; an absent path proves nothing (function pointers hide edges). Line numbers are approximate — file + caller function are authoritative | `<clone>-joern-reachability.json` — call sites with caller attribution, `test_path` tags, explicit caps, soundness block on every artifact |
| **Symbol-usage scan** (traust-core `SourceScanAnalyzer`) | Java, Python, JS/TS, Rust, Ruby, .NET | does first-party source reference the vulnerable module's symbols textually? | presence evidence, not a call path — caps at `symbol-usage`. The names come from `traust impact symbols` (published by the source, or mined from the fix commits) | recorded in impact-analysis evidence fields |
| **ELF scans** (python3 -m traust.cli util elf, via impact-analysis) | C/C++, Go binaries | is the library linked (`DT_NEEDED`) / are the vulnerable symbol names present in the shipped binary's strings? | presence evidence, not a call path — caps at `symbol-usage`/`binary` tiers | recorded in impact-analysis evidence fields |
| **Taint-flow enumerator** (python3 -m traust.ops.enumerate_taint_flows) | Java, C | related but distinct: does *request data flow* source→sink? Emits judged rows, not reachability verdicts | opt-in ops tool, invoked by no skill; calibration against a precision bar gates any default use | flow rows with path excerpts, `passes_through`, `sanitizer_hint` |

The Joern adapter itself still supports the Java frontend (`javasrc2cpg`);
nothing in the impact pipeline invokes it, for the reason in the note above.

## The evidence ladder and what it may conclude

`/impact-analysis` records per-repo `evidence_level`
(`symbol > symbol-usage > binary > manifest > none`) and classifies:

- **`affected`** requires symbol-tier proof: govulncheck `symbol_reachable`
  (Go) or a Joern resolved direct call to the vulnerable function itself
  (C/C++, witness cited in `joern_witness`).
- **Manifest evidence ceilings at `likely_affected`** — "a pin is never
  reachability." Textual symbol usage and package-level calls reach
  `symbol-usage`, same ceiling.
- **Only Go may demote on a negative** (govulncheck's `not_observed` classes
  are sound). The Joern tier never demotes anything — `no_call_sites_found`
  is recorded honestly and the classification stays where the cheaper tiers
  put it.

## Who consumes reachability

- **`/impact-analysis`** — classification per the ladder above; CVE
  blast-radius sweeps.
- **`/secure-code-audit` Precision Gate** — a critical/high Go dependency-CVE
  finding may not be filed without govulncheck symbol-mode evidence;
  manifest-only matches downgrade to `dependency_audit`.
- **`/triage`** — two paths: a SHA-matched `<repo>-govulncheck.json` beside
  the baseline feeds matched findings a `DEPENDENCY-REACHABILITY` block as
  **annotation-only** verifier context (no vote-count changes); and
  `traust triage intake` records govulncheck native `-json` streams as
  findings, the reachability class kept in each finding's description.
- **`/verify-remediation`** — `--impact-filter` scopes full sweeps to repos
  an impact analysis classified `affected`/`likely_affected`.
- **The assurance promotion ladder** — `affected` is machine-static (ledger
  class 3); `/create-fuzzing` (reproducing crash = E0) and live validation
  promote to execution evidence, with the static call path doubling as the
  attack-plan seed.

## Guardrails (non-negotiable)

1. **"Not observed" never auto-dismisses.** Static analysis misses
   reflection, plugins, dynamic dispatch, config-driven invocation. A
   reachability tag may at most lower a prior; false-positive determinations
   remain countersign-gated and execution-overridable.
2. **Never a finding of record.** Reachability hits route attention; the
   finding list stays agent-authored, or the harness converges to commodity
   SAST.
3. **Provenance at emission time.** Tool versions, DB freshness, SHAs, and
   tags are written into artifacts when produced — replays never re-derive
   them.
4. **Honest vocabulary.** `not_observed`/`unknown`, never "unreachable";
   `test_only` entry points labeled, never laundered into production
   reachability; Joern line numbers labeled approximate on every artifact.

## Revisit when

Two triggers no feed answers; review them on a quarterly clock (they were the
deployment's `reachability-watch.yaml`, retired with one-file config):

- **OSV publishes call-graph or vulnerable-symbol data for PyPI / npm.** Then
  Python/JS reachability is a feed-join, not a per-repo CPG pilot: prefer it.
  As of 2026-08-11 OSV carries per-symbol data for Go only
  (`ecosystem_specific.imports`); verify at the schema, not from memory.
- **A permissive (Apache-2.0 or equivalent) symbol-level engine for Python or
  JS/TS matures.** A permissive licence is a precondition, never evidence of
  precision: measure promotion on a real advisory corpus before any wiring.
  Joern's pysrc2cpg/jssrc2cpg are permissive; their blocker is resolution
  maturity, and the structural argument above (advisories name
  library-internal symbols first-party code never calls) applies to them too.
  Reopen for all languages at once when dependency code enters the graph.

## Validation records

Every engine is admitted or kept on the strength of a ground-truth corpus,
and the corpora live in the deployment's harness-QA trees (registered in the
corpus config with `ownership: harness-qa`, so they never enter metrics):

- Joern tiers — a validation corpus of human-audited direct calls, one
  directory per target, under `analysis-results/scan-testing/`.
- Taint enumerator — its judge-pass precision measurement, under the same tree.
- govulncheck — the manual-approval-gate pilot artifact in the findings tree,
  whose symbol-reachable versus module-only split motivated the program.

Wiring a new engine follows the same pattern: a facts-only wrapper validated
against a ground-truth corpus before any default use, with the measured
promotion rate on a real advisory corpus as the admission criterion.
