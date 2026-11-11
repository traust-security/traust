# /threat-model review and update

> **Re-read note:** If you need this file mid-session and the Read tool
> reports "file unchanged", the prior result was evicted from context; reload
> with `cat <skill-base>/review.md` via Bash.

Threat models decay: code changes, features ship, dependencies move,
mitigations land. `review` measures the drift of an existing
threat model against the current checkout and reports it; `update`
applies changes (from a review, or from direct user feedback) while
preserving continuity. Review flows into update interactively — the user
stays in one flow but always sees the review before anything is modified.

Both sub-modes obey the Step-0 safety preamble (static analysis only) and
the schema contract in `schema.md`. Neither re-runs a full bootstrap; both
touch only what moved.

---

## Inputs

- `<target-dir>` (required): local checkout or findings directory
  containing the model, or an explicit path to the model file. Resolve
  the model via SKILL.md's model-file resolution rule — it covers the
  canonical name (`<repo>-threat-model.md`, optionally branch-suffixed)
  plus the legacy `THREAT_MODEL.md`, and refuses to guess between branch
  variants. All reads and write-backs below target the resolved file;
  a resolved legacy `THREAT_MODEL.md` is renamed to `<model-file>`
  before any write, per SKILL.md.
- `review` only — automation flags (mirror `/triage --auto`; interactive
  is the default):
  - `--auto`: report-only. Emit the review, write it beside the resolved
    model (naming per R4), and stop — never prompt, never
    modify the model. For batch drift sweeps.
  - `--apply`: apply every proposed change without prompting (continues
    into `update` with the full change set). Use only when the caller has
    already decided to accept the review wholesale — e.g. a pipeline that
    re-lints and diffs afterwards.
  - `--apply-ratings` (with `--auto`): report-only for everything EXCEPT the
    R3b ratings, which are written. This is how the scheduled check-up
    (quarterly and release-review lanes) moves unrated models to the OWASP
    Risk Rating Methodology without a human applying each report. See R6.
  - Neither flag → interactive (R5 below).
- `update` only — feedback, any of:
  - free text after the target ("remove T3, upgrade T5 to critical, add a
    threat about the new Redis cache")
  - `--from-review <path>`: a review report emitted by `review`
  - nothing: ask the user "What changes would you like to make to the
    existing threat model?" and wait.

If resolution finds no model at the target, stop and say so — suggest
`/threat-model bootstrap` instead. Never fabricate a model to review.

---

## `review` — measure drift

### R1. Parse the existing model

Read the resolved model file. Extract: section 3 entry points, section 4 rows,
section 5 parked threats, section 6 open questions, section 8 mitigations,
and the provenance block — especially `target: … @ <SHA>` and `date`.

If provenance has no SHA (older artifact), fall back to
`git log -1 --format=%H --before=<provenance date>` for an approximate
baseline, and say so in the report.

### R2. Deterministic drift pre-pass (before any LLM judgment)

Bound the re-analysis with git, not intuition:

1. `git -C <target-dir> diff --stat <provenance-SHA>..HEAD` — the full
   change footprint. If empty, report "no drift: code unchanged since
   <date>" and stop (offer to re-lint the artifact against the current
   schema anyway).
2. `git -C <target-dir> diff --name-status <provenance-SHA>..HEAD` — bucket
   changed paths:
   - files matching the bootstrap surface-mapper grep table (routes,
     parsers, sockets, deserializers, IaC, CI) → **surface-relevant**
   - dependency manifests (`go.mod`, `package.json`, `requirements.txt`,
     `Cargo.toml`, lockfiles) → **supply-chain-relevant**
   - deleted files → candidate **stale-threat** signals
   - everything else → note the count, do not re-analyze
3. If the repo has been through the harness pipeline since the model's
   date, list newer artifacts (`*-triage.json`, `*-findings-current.json`,
   `*-validation.json`) — resolved or newly confirmed findings are drift
   evidence too, weighted by assurance exactly as in `bootstrap.md`
   ("Harness pipeline artifacts as vuln evidence").

### R3. Re-rate only what moved

For each **surface-relevant** change, read the code and decide:

- **New attack surface**: entry point not in section 3 → candidate new
  threat(s). Name the missing section 3 row.
- **Removed component**: threats whose `surface` no longer exists → stale.
- **Changed controls**: a mitigation from section 8 now implemented (grep
  for it — rate limiter middleware, parameterized queries, size caps), or a
  control removed → the rating factors that control acts on, or the status,
  shift. Cite the code you read; if
  the evidence is a resolved pipeline finding, cite its canonical ID
  (`{REPO_SLUG}-{SHORTSHA}-{NNN}`), the same reference the disposition
  ledger uses.
- **Invalidated assumptions/open questions**: section 6 items the diff now
  answers.

Use only the schema enums when proposing changes — a stale threat becomes a
section 5 row with a reason; a mitigated threat gets `status: mitigated`;
never invent new verdict vocabulary.

### R3b. Rate threats the model hasn't rated yet

If any threat lacks a `risk_rating` (it still carries legacy
`impact`/`likelihood` labels), propose an OWASP Risk Rating Methodology
rating for **every** such threat, not only the ones that moved. Score the
factors from the model, the current code and the evidence, following the
schema.md [Scoring guide](schema.md#scoring-guide), and give a reason for
each factor that evidence or a control moved. Don't derive the factors from
the legacy labels; they were never calibrated. These ratings are proposed
changes like any other: the report lists them, and `update` writes them.

### R4. Report

Emit the review to the conversation (and, if the user asks for a file, to
the resolved model's path with `-threat-model.md` replaced by
`-threat-model-review.md`; for a resolved legacy `THREAT_MODEL.md`, use
`<model-file>`'s name with the same replacement):

1. **Health summary** — one paragraph: mostly accurate / significantly
   outdated / dangerously stale; model date, commits and files drifted.
2. **New attack surface** — what appeared, why it matters, proposed new
   threat rows (full section 4 shape, ids continuing from the highest
   existing).
3. **Stale threats** — id, title, why (component removed, class-level
   mitigation landed).
4. **Changed risk** — id, old → new severity (with the factors that moved)
   or status, and the code or pipeline evidence.
5. **Ratings to adopt** (only when R3b found unrated threats) — for each,
   the proposed severity, likelihood and impact, and the factor scores with
   their reasons.
6. **Mitigation status** — section 8 rows with implemented / partial /
   not-found evidence.
7. **Invalidated assumptions** — section 6 items now answerable.
8. **Recommended actions** — prioritized.

### R5. Offer to apply (interactive default)

`--auto` → write the review file (per R4 naming, beside the resolved
model) and stop here, unless `--apply-ratings` is also set (R6).
`--apply` → skip the prompt and continue into `update` with every proposed
change. Otherwise:

Ask via AskUserQuestion: **"Apply these changes to the threat model now?"**
with options: apply all / let me pick per change / no, report only. For
"pick per change", walk the proposed changes one AskUserQuestion at a time —
the change rendered in the option preview so the user never has to hold the
report in their head. On any form of yes, continue into `update` below with
the accepted changes as feedback. On no, stop — the review stands alone.

### R6. Apply ratings only (`--auto --apply-ratings`)

After writing the review file, if R3b proposed ratings, write those and
nothing else:

1. In the JSON, give each unrated threat its proposed `risk_rating`
   (factors, basis, reasons) and drop its legacy `impact`/`likelihood`.
   Change no other field. New threats, stale threats, changed controls and
   every other proposal stay in the report for a human.
2. Append one update-history row ("rated T1-Tn with the OWASP Risk Rating
   Methodology"; reason "scheduled review, ratings applied").
3. Run `rate-threats`, `validate`, then `render -o <model>.md`, then `lint`.
   **If `render` refuses** because the new rendering would drop or empty a
   section the `.md` has, the JSON is incomplete (a pre-schema backfill).
   Don't pass `--allow-section-loss`. Restore the JSON from before step 1,
   and add "ratings not applied: model JSON incomplete; re-model needed" to
   the review file.
4. Report the outcome (applied, or why not) in the review file's last line.

---

## `update` — apply changes, preserve continuity

### U1. Continuity rules (non-negotiable)

- **Never renumber.** Existing ids are stable; a removed threat's id is
  retired, never reused; the next new threat takes the next never-used
  number.
- **Removed ≠ deleted.** A removed threat moves to section 5 with the
  reason and date ("retired 2026-07-12: component removed in abc1234").
  Future reviewers must see it was a conscious decision.
- **Human edits survive.** Prose, annotations, and custom content not
  contradicted by the feedback are preserved verbatim.
- **Provenance appends, never replaces.** Keep the original provenance
  lines and `mode`; add or extend the `### Update history` table
  (schema.md section 7) with one row: date, changes, reason.
- **Only touch what the feedback names.** "Add a threat about the Redis
  cache" re-analyzes Redis-adjacent code only; it does not re-run
  discovery on the rest of the tree.
- **One exception: the rating migration.** When a pass writes a model that
  still has threats without a `risk_rating`, it rates all of them (review
  R3b) and drops their legacy `impact`/`likelihood` labels, so the model
  moves to the OWASP method in one step. Record it in the update history
  ("rated T1-T9 with the OWASP Risk Rating Methodology").
- **Mitigation effort and blocking stay independent.** For mitigation
  additions or edits, follow schema.md section 8: required canonical
  `effort` or JSON `null` for unknown size, plus `blocked_external` only
  when its boolean state is known. Preserve existing reported blocking;
  absence is unknown, not `false`. Reading a historical uppercase size is
  valid; use only its exact registry-approved replacement when composing
  fresh canonical output, without rewriting stored history. Keep unknown
  effort separate from the cheapest known-size recommendations.

### U2. Apply

Parse the feedback into per-threat operations (remove/retire, add, modify
field, re-rank). For additions, read the relevant code first — new rows get
the same evidence discipline as bootstrap Stage 3 (evidence = confirmed
vuln references only; the rating from the scoring guide). Run
`python3 -m traust.cli reporting rate-threats` on the JSON, then re-sort
section 4 by severity, impact score and likelihood score, all descending.
Sorting is presentation, not renumbering. If the model has a section 9, refresh it: retire scenarios for
retired threats, and add/replace scenarios so it still covers the top 3-5.

### U3. Validate and hand back

Run the deterministic gate until it passes:

```
python3 -m traust.cli reporting lint <resolved-model-file>
```

Then hand back: path, a one-line-per-change summary (id, what changed,
why), the new top-5, and any feedback items you could **not** apply with a
reason (e.g., "upgrade T9" refused: T9 does not exist). Never silently drop
a requested change.
