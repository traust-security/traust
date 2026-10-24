---
name: fleet-fix
description: Use when the user wants to remediate a SYSTEMIC pattern (one weakness class × N repos — an insecure-patterns CWE entry or a PROGRESS.md rollup like the Konflux mutable-pipelineRef) as one campaign instead of per-finding fixes — "fix this pattern everywhere", "fleet fix", "pin pipelineRefs across the fleet", "batch-remediate CWE-X". Authors one reviewed transform spec with golden tests, applies it across every affected repo via apply_fleet_fix.py (diffs only), and only after human batch approval opens MRs/PRs through the remediate-finding fork flow; merge events flow back through track-findings for pattern burndown.
argument-hint: "[<spec-id>|<pattern>] [apply|review|open-mrs] [--repos ...]"
metadata:
  harness.tier: "primary"
allowed-tools:
  # per-script grants only — this skill clones and mutates N target
  # repos; an unscoped interpreter under injected content is fleet-wide
  # code execution (audit D5, plan P2.11; A11 un-grandfathered)
  - Bash(python3 *harnessing/7-remediate/fleet-fix/scripts/apply_fleet_fix.py:*)
  - Bash(python3 -m traust.cli remediation fleet-targets:*)
  - Bash(python3 -m traust.cli remediation fleet-apply:*)
  - Bash(python3 -m traust.cli remediation fleet-record:*)
  - Bash(bash *run_checks.sh:*)
  - Bash(git clone:*)
  - Bash(git ls-remote:*)
  - Bash(ls:*)
  - Bash(jq:*)
  - Read
  - Grep
  - Write
---

# Fleet-Fix — one transform, every affected repo

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Lens 3 identifies patterns ("1 weakness × N repos"); this skill buys them
down as ONE campaign: a single reviewed transform, applied mechanically
fleet-wide, shipped as a coordinated batch of MRs. Distinct-vulnerability
count drops fastest per engineering hour here.

## Hard gates (never waived)

1. **The spec is the change.** Every transform lives as a schema-validated
   spec (`contracts/schemas/fleet-fix.schema.json`) in `specs/`, carrying its own
   golden tests. `apply_fleet_fix.py` refuses to touch any repo while a
   golden test fails (and `traust remediation fleet-record` refuses to
   record the spec).
2. **Diffs before forks, forks before MRs, humans before both.** The
   applier only modifies working clones and emits `<repo>-<id>.diff` +
   result JSON. Opening MRs is a separate stage that requires the user's
   explicit batch approval of the reviewed diffs — never auto-merge, never
   MR-on-apply.
3. **Allowlist scope.** The matcher touches only its `file_glob`; guards
   (`max_files_changed`, clean-tree) revert anything that oversteps.

## Procedure

### 1. Identify the fleet

One deterministic command — never hand-grep:

```bash
python3 -m traust.cli remediation fleet-targets \
    (--cwe CWE-1104 | --package-id <package-uuid> | \
     --repo-url https://github.com/org/a --repo-url https://github.com/org/b) \
    -o /tmp/fleet-fix/<id>/fleet.json
```

For dependency-bump campaigns driven by a specific CVE, an
`/impact-analysis` artifact is a ready-made fleet: pass the repos
classified `affected`/`likely_affected` via `--repo-url` (e.g.
`jq -r '.repos[] | select(.classification=="affected" or
.classification=="likely_affected") | .repo'
analysis-results/impact/<cve>-impact-analysis.json`). This scopes the
campaign to demonstrated exposure instead of every importer of the
module.

Sources: `--cwe` reads the repositories with an open finding of that
class (CWE-class fleets); `--rollup` (PROGRESS.md) is *retired* — the
CWE and package scopes read the findings themselves; `--package-id`
reads the package's dependents in traust-core — dependency fleets: every
repo depending on it directly, through a base image or an internal
library. (No door looks a package up by name yet: `--module` /
`--ecosystem` are gone until one exists.)
Every target is enriched
with **product reach** (fix highest-blast-radius repos
first — the output is already sorted by it); **owner team** (MR
routing at stage 5) has no door yet. Every target is a registered
repository; an unknown one is refused, never guessed. `fleet.json` is the
campaign's target list of record.

> **Optional accelerator — findings-db candidate listing.** When scoping
> a fleet by finding state rather than pattern/module (e.g. "every repo
> with an open finding matching this fingerprint"), the C9 projection
> answers in one query (`/findings-db`, `v_open` + `graph_edges`). Use
> it to *shortlist*, then feed the repos through `traust remediation
> fleet-targets --repo-url …` so the target list of record still carries the standard
> enrichment — and confirm finding state against the live ledger before
> generating diffs; the DB can be one census behind.

### 2. Author or select the transform spec

`specs/<id>.yaml` — matcher (`pinned_ref_line` for guarded line rewrites
with a git ls-remote resolver; `ast_grep` for structural rewrites),
rewrite template, guards, and at least one positive + one negative golden
test. New specs get a human review of the spec itself plus one
hand-reviewed golden diff before fleet application. Record the reviewed
spec with `python3 -m traust.cli remediation fleet-record specs/<id>.yaml`
(its golden tests run first).

### 3. Apply across the fleet (diffs only)

For each repo (workflow batch for large fleets):

```bash
GIT_ALLOW_PROTOCOL=https git clone -- <repo> /tmp/fleet-fix/<id>/<repo> && \
python3 harnessing/7-remediate/fleet-fix/scripts/apply_fleet_fix.py \
    --spec harnessing/7-remediate/fleet-fix/specs/<id>.yaml \
    --repo /tmp/fleet-fix/<id>/<repo> \
    --out-dir /tmp/fleet-fix/<id>/out
```

Interactive apply stays here until traust has an ops CLI to
submit/approve/claim a fleet-fix run order — NEED(ops CLI). Under a
leased fleet-fix run order, apply the recorded spec through the door
instead (a fresh clone of the repo's default-branch head, diff only):
`python3 -m traust.cli remediation fleet-apply <fleet-fix-id> --repo-url <repo> --order <order-id> -o /tmp/fleet-fix/<id>/out/<repo>.json`.
Collect the per-repo results: applied / no-match / unresolved / guard
refusals. Where the target repo has usable checks, run
`harnessing/7-remediate/remediate-finding/run_checks.sh` against the modified clone
and record outcomes.

### 4. Human review of the batch

Present every diff (they are small by construction) with the campaign
summary: N applied, M no-match (pattern already fixed — burndown
evidence), K unresolved. **Stop here** unless the user approves opening
MRs.

### 5. Open MRs (approved batches only)

Reuse the remediate-finding fork flow per repo: private fork, branch
`fleet-fix/<id>`, the applier's diff as the commit, MR/PR with the shared
campaign body (pattern, evidence, spec link, golden tests) via `gh`/`glab`.
Track MR URLs in the campaign result JSON.

### 6. Burndown

`track-findings` ingests merge events against the pattern's findings;
insecure-patterns/trends show the pattern shrinking. Re-run step 3 on a
cadence: no-match on every repo = pattern extinct.

## Outputs

| Artifact | Purpose |
|---|---|
| `specs/<id>.yaml` | The reviewed transform (goldens included) |
| `<repo>-<id>.diff` / `-result.json` per repo | Reviewable change + application record |
| Campaign summary (applied / no-match / unresolved / MRs) | The batch-approval packet and burndown record |

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `GOLDEN TEST FAILED` | spec drifted from its own expectations | fix the spec, never the applier |
| exit 2 `working tree is not clean` | reused clone | fresh clone per application |
| `unresolved: no URL in window` | file shape differs from matcher assumptions | extend the spec (with a new golden) — don't hand-edit the repo |
| many no-match results | pattern already remediated there | that's burndown, record it |
