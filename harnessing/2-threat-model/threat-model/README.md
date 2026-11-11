# threat-model

A Claude Code skill that builds **and maintains** a threat model for a
target codebase. Build modes: **bootstrap** derives the threat model from
the target itself (source tree, git history, public advisories, optional
past-vulns and `--context` docs); **interview** discovers it by walking an
application owner through the four-question framework;
**bootstrap-then-interview** chains the two. Maintenance modes: **review**
measures an existing model's drift against the current code and offers to
apply fixes; **update** applies targeted feedback without regenerating;
**pr** threat-models a diff and returns a review verdict. Build modes write
`<repo>-threat-model.md` (named after the target; legacy `THREAT_MODEL.md`
files are still read and migrated on write) in a shared schema,
deterministically gated by python3 -m traust.cli reporting lint.

## Status

The skill is read-only (it does not build,
run, or probe the target) and is safe to point at any local checkout. The
output is a starting point for human review, not a substitute for it.

## Why a threat model

Vulnerability scanners find instances; a threat model is the map of where
instances are likely to be and which ones matter. Hand the pipeline a threat
model and it knows where to look. Hand triage a threat model and it knows
which findings to escalate. Use the output's focus areas to steer
`/secure-code-audit` coverage and to inform how you prioritize `/triage`
results.

## Model selection

The skill has no `model:` frontmatter pin; it runs on whatever model your
session uses (or `--model` if you pass one). It is designed for
reasoning-capable Claude models — use the same model you run the rest of the
pipeline with. If you want to lock the model regardless of session, add a
`model:` line to `SKILL.md`; frontmatter takes precedence over `/model` and
`--model`.

## Installation

Ships with this repo like every other skill: `harnessing/2-threat-model/threat-model/` is
the source of truth, discovered via the `.claude/skills/threat-model` and
`.crush/skills/threat-model` symlinks (see AGENTS.md "Adding a new skill").
For use outside this repo's workspace, symlink it user-scoped:

```bash
ln -s /path/to/traust/harnessing/2-threat-model/threat-model ~/.claude/skills/threat-model
```

## Usage

### Bootstrap (derive from target, git history, advisories)

Use when no application owner is available. Point it at a checkout and,
optionally, a list of past vulnerabilities:

```
/threat-model bootstrap targets/drlibs
/threat-model bootstrap targets/drlibs --vulns targets/drlibs/vulns.txt
```

Without `--vulns` the skill mines `git log`, `CHANGELOG`, and GitHub Security
Advisories itself; with it, it ingests your supplied list first.

The skill spawns a parallel research swarm (docs reader, surface mapper, asset
finder, git-history miner, advisory fetcher, vuln-file parser), synthesizes
their returns into the system-context / assets / entry-points sections,
generalizes the collected vulns into threat classes, gap-fills with STRIDE for
surfaces the vuln history didn't cover, and writes
`targets/drlibs/drlibs-threat-model.md`. On small targets (<50 source files) it runs
the same briefs sequentially instead of spawning.

### Interview (discover via owner conversation)

Use when an application owner is in the session.

```
/threat-model interview targets/alsa
/threat-model interview targets/alsa --design-doc targets/alsa/README.md
```

Without `--design-doc` the interview opens cold by asking the owner to
describe the system; with it, the skill reads the doc first and summarizes it
back for confirmation.

The skill will walk the owner through the four questions ("what are we working
on?", "what can go wrong?", "what are we going to do about it?", "did we do a
good job?"), grounding answers in the code as it goes, and write
`targets/alsa/alsa-threat-model.md`.

### Bootstrap then Interview (bootstrap a draft, then refine via interview)

Use when an owner is available but their time is limited: bootstrap produces
the draft unattended, then the interview spends owner time only on what the
code couldn't answer.

```
/threat-model bootstrap targets/drlibs/
/threat-model interview targets/drlibs/ --seed targets/drlibs/drlibs-threat-model.md
```

The interview will focus on the bootstrap's open questions instead of starting
cold.

### Review (measure drift, optionally apply)

Use when a threat model already exists and the code has moved on
(`<repo>-threat-model.md`, or the legacy `THREAT_MODEL.md`, which is
renamed to the canonical form if the review is applied). The
skill diffs the checkout against the SHA in the model's provenance, re-rates
only what changed (new surface, stale threats, implemented mitigations,
invalidated assumptions — weighing newer pipeline artifacts by assurance),
reports the drift, and then asks whether to apply the changes:

```
/threat-model review targets/drlibs
```

Interactive by default; for automation, `--auto` emits the review report
only (never prompts, never modifies — batch drift sweeps) and `--apply`
accepts every proposed change without prompting.

### Update (targeted changes, no regeneration)

Use to apply specific feedback while preserving continuity — threat IDs are
never renumbered, removed threats are retired into the deprioritized section
with a dated reason, and an update-history row is appended to provenance:

```
/threat-model update targets/drlibs "retire T3, upgrade T5 to critical, add a threat for the new Redis cache"
```

### PR (threat-model a diff)

Use in code review. Scopes analysis to the branch diff plus one hop of
neighbors, cross-references the existing threat model if present, and returns
a lightweight assessment ending in **approve / approve_with_conditions /
request_changes**. Does not write a model file:

```
/threat-model pr targets/drlibs --base main
```

## Checkpointing and resume (bootstrap mode)

Bootstrap writes per-stage checkpoints to `./.threat-model-state/` in the
current working directory (cwd-confined by `checkpoint.py`). If a run is
interrupted, re-invoking `/threat-model bootstrap <target-dir>` from the same
working directory
resumes from the last completed stage — the research swarm is not re-spawned
if Stage 1 already landed. Pass `--fresh` to start over. The state directory
is scratch; add it to `.gitignore`.

## Output

`<target-dir>/<repo>-threat-model.md` with seven required sections — system context
(opening with a jargon-free executive summary and closing with a threat-actor
landscape), assets (with optional data-classification columns), entry points
& trust boundaries, threats (the table), deprioritized, open questions,
provenance (with `harness_version` and an update history) — plus two
optional additive sections: recommended mitigations and attack scenarios
(narratives for the top 3-5 threats, lifted verbatim into team packages by
`/generate-team-report`). See `schema.md` for the full contract; worked
examples live throughout `analysis-results/findings/` as
`<repo>-threat-model.md`.

Recommended mitigations always include `effort` in the JSON: a canonical
size from the [registry](https://github.com/traust-security/traust-contracts/blob/development/enums/v1/mitigation-effort.json),
or `null` when unknown. The independent optional `blocked_external` field
records a known boolean only; missing means unknown, not `false`.
Historical uppercase sizes remain readable, with exact registry-approved
replacements used only for fresh canonical output. Stored historical
artifacts are not rewritten. Recommendations order known sizes by size,
never treating unknown effort as cheapest; see schema.md section 8.

Every emission is validated by the deterministic linter before the run is
considered complete:

```bash
python3 -m traust.cli reporting lint <target-dir>/<repo>-threat-model.md
```

It enforces sections/columns/enums, the coverage invariant (every entry
point threatened or explicitly parked), threat-ID stability, provenance
completeness, and evidence-cell hygiene (vuln references only — file:line
citations are rejected, keeping threats at the abstraction level that
survives a patch). Directory sweeps work too:
python3 -m traust.cli reporting lint analysis-results/findings/<product>/.

## Design decisions (deliberately not adopted)

Evaluated against the ProdSec threat-modeling-guild module (2026-07; the
comparison drove the v0.33.0 additions — validator gate, review/update/pr
modes, attack scenarios + executive summary, `--context` ingestion, actor
landscape, data-classification columns, conditional LINDDUN overlay), three
guild ideas were rejected on purpose. Do not reintroduce them casually:

- **Per-threat `file:line` code references** — conflict with the
  threat-vs-vulnerability litmus test; citations pull threats to patch
  granularity and rot as code moves. Sibling locations belong in
  `/vuln-scan` leads, not the evidence column (the linter rejects them).
- **Narrative-first output with optional structure** — downstream parsers
  consume the schema; the attack-scenarios section delivers the story
  without surrendering the contract.
- **Broad `allowed-tools` (Bash + WebFetch)** — the safety preamble and
  read-only discipline are non-negotiable, especially with subagents
  inheriting constraints verbatim.

## Provenance

Derivative work of the `threat-model` skill in
**defending-code-reference-harness** (Copyright 2026 Anthropic PBC, Apache
License 2.0 — see the harness root `NOTICE` and `LICENSES/Apache-2.0.txt`),
ported into this harness at v0.23.0 and modified per `CHANGELOG.md`. The
upstream skill's impact/likelihood scoring guide has been replaced by the
OWASP Risk Rating Methodology (see References).

## References

- Shostack, *The Four Question Framework for Threat Modeling* (2024) —
  https://shostack.org/files/papers/The_Four_Question_Framework.pdf
- OWASP Threat Modeling Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Foundation, *OWASP Risk Rating Methodology* —
  https://owasp.org/www-community/OWASP_Risk_Rating_Methodology. The threat
  rating; reimplemented in original wording (licence terms:
  `docs/external-dependencies.md`).
- This repo's AGENTS.md "Security Testing Context" section.
