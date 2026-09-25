---
name: patch
description: Generate candidate fixes for verified security findings. Consumes
  <repo>-triage.json (preferred; legacy TRIAGE.json accepted), a <repo>-security-audit.json report,
  *-vuln-findings.json (or legacy VULN-FINDINGS.json), *-pqc-facts.json
  (actionable first-party PQC blockers only), or an external
  vuln-pipeline results directory.
  Pipeline input is delegated to the execution-verified
  `vuln-pipeline patch` ladder; static-analysis input gets a per-finding
  patch subagent + independent reviewer and is written as inert diffs and
  git-am-ready patches for human review. Writes
  PATCHES/bug_NN/{patch.diff,patch.patch,patch_result.json},
  PATCHES.md, and PATCHES.json. Use when asked to "fix the findings",
  "patch these vulns", "generate fixes", or "close the loop on triage".
argument-hint: "<findings-path> [--repo PATH] [--top N] [--id fNNN] [--model M] [--fresh]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(python3 *-m traust.cli.checkpoint:*)
  - Bash(vuln-pipeline patch:*)
  - Bash(git -C * rev-parse:*)
  - Bash(git -C * worktree:*)
  - Bash(git -C * add:*)
  - Bash(git -C * commit:*)
  - Bash(git -C * diff:*)
  - Bash(git -C * format-patch:*)
  - Bash(git -C * apply:*)
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
  - Bash(file:*)
  - Bash(jq:*)
---

# patch

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Third leg of the static pipeline (`/secure-code-audit` or `/vuln-scan` →
`/triage` → `/patch`). Turns a ranked list of verified findings into
candidate diffs.

The skill **never modifies the target repo**. Subagents edit disposable
git worktrees, and the resulting diffs and `git am`-ready patches are
captured as inert text in `./PATCHES/` for a human to review and apply
out-of-band. There is no
`--apply` or `--approve` flag by design: the capability isn't present, so
it can't be prompt-injected into use. (For patches on private forks with
build/test verification, use the harness's `remediate-finding` skill
instead — `/patch` is the lightweight, offline counterpart.)

**Paths:** `<skill-base>` is this skill's base directory (injected by the
runtime as "Base directory for this skill"; it is
`traust/harnessing/7-remediate/patch`). `<harness>` is the
traust repo root, i.e. `<skill-base>/../..`; checkpoint I/O
uses `python3 -m traust.cli admin checkpoint`. Resolve both to absolute
paths once at startup.

Invoke with `/patch <findings-path> [--repo PATH] [--top N] [--id fNNN]
[--model M] [--fresh]`.

**Arguments** (parse from `$ARGUMENTS`):
- findings path (first positional, required): `<repo>-triage.json` (or legacy `TRIAGE.json`), a
  `<repo>-security-audit.json` report, `*-vuln-findings.json` (or legacy
  `VULN-FINDINGS.json`), `*-pqc-facts.json` (PQC readiness Layer 1
  output), an external
  vuln-pipeline `results/<target>/<ts>/` directory, or any JSON the `/triage`
  ingest table recognizes.
- `--repo PATH`: target codebase (default cwd). Required for
  static mode; the skill stops if cited files don't resolve under it.
  The repo itself is never modified — edits go into disposable worktrees.
- `--top N`: patch only the N highest-severity true positives (static
  mode), ranked on the shared enum: critical > high > medium > low >
  informational (match case-insensitively; legacy inputs may use
  HIGH/MEDIUM/LOW). `hardening`-verdict findings are excluded from `--top` (they are
  posture backlog, not vulnerabilities) but MAY be patched explicitly via
  `--id` — fixing a hardening gap also de-amplifies co-located confirmed
  findings in the trends blast-radius view.
- `--id fNNN`: patch only the finding with this id.
- `--model M`: passed through to `vuln-pipeline patch` in execution-verified
  mode. Ignored in static mode (subagents inherit the orchestrator's model).
- `--fresh`: ignore `./.patch-state/` checkpoint and start over.

**Tools.** Prefer Read, Glob, Grep, Write, Task. Some sessions do not
provision Glob or Grep; `allowed-tools` is a permission filter, not a loader.
When they are unavailable, fall back to the read-only Bash commands
whitelisted above: `rg`/`grep` for search, `ls` for enumeration,
`head`/`file`/`wc` for sniffing, `jq` for JSON ingest, `git` for worktree
management and diff generation. Bash is also permitted for
`python3 -m traust.cli admin checkpoint` (state I/O) and
`vuln-pipeline patch` (execution-verified delegate). `find` is NOT
permitted.

**Write scope.** The orchestrator may Write ONLY to `./PATCHES/` and
`./.patch-state/`. Never write into `--repo` directly. Source edits go
into disposable git worktrees created under `/tmp/` — these are removed
after the diff is captured. `git apply --check` (dry-run validation) is
permitted for validating diffs against `--repo`.

---

## Checkpointing (runs before Phase 0 and after every phase)

State persists to `./.patch-state/` so a fresh `/patch` session resumes
without re-spawning patch or reviewer subagents. All checkpoint I/O goes
through `python3 -m traust.cli admin checkpoint` (atomic, JSON-validated).
The Write→`--from` pattern keeps repo-derived bytes out of Bash argv; never
pass payload via heredoc or stdin.

State files: `progress.json` (single source of truth: `{"status":
"running"|"complete", "phase_done": N, "shards_done": [...]}`),
`phaseN.json`, `_chunk.tmp`.

**Start of run.** Bash:
`python3 -m traust.cli admin checkpoint load ./.patch-state`

- `status == "absent"` OR `"complete"`, OR `--fresh` in `$ARGUMENTS` →
  fresh start. Bash:
  `python3 -m traust.cli admin checkpoint reset ./.patch-state`,
  proceed to Phase 0.
- `status == "running"` with `phase_done == N` → resume. Read
  `phase0.json`..`phaseN.json` in order (and any `shard_*.json` listed in
  `shards_done`), merge into working state, print
  `Resuming from checkpoint: Phase N complete`, skip to Phase N+1. Do not
  re-spawn any subagent whose output is already checkpointed.

**End of every phase N.** Write tool → `./.patch-state/_chunk.tmp` with the
phase's JSON, then Bash:
`python3 -m traust.cli admin checkpoint save ./.patch-state <N> <name> --from ./.patch-state/_chunk.tmp`

**End of run.** After writing `PATCHES.md` and `PATCHES.json`, Bash:
`python3 -m traust.cli admin checkpoint done ./.patch-state 4`

---

## Phase 0: Parse arguments and detect mode

### 0a. Parse `$ARGUMENTS`

Extract findings path (first positional), `--repo` (default `.`), `--top`,
`--id`, `--model`, `--fresh`. If no findings path, stop and ask.

### 0b. Detect mode

Inspect the findings path:

- **execution-verified mode** when the path is a directory containing
  `reports/manifest.jsonl` OR `found_bugs.jsonl` OR `run_*/result.json`
  (pipeline output). The findings have PoC bytes + ASAN traces + reproduction
  commands; the pipeline's verification ladder applies.
- **static mode** otherwise: `*-triage.json` / legacy `TRIAGE.json`, `*-security-audit.json`,
  `*-vuln-findings.json`/`VULN-FINDINGS.json`, `*-pqc-facts.json`,
  generic finding JSON, or
  markdown. No PoC; the
  oracle is a fresh-context reviewer.

Record `mode` in working state. The two modes share Phase 1 ingest then fork
at Phase 2.

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 0, "mode": "exec"|"static", "args": {repo, top, id, model, findings_path}}`
Then Bash:
`python3 -m traust.cli admin checkpoint save ./.patch-state 0 mode --from ./.patch-state/_chunk.tmp`

---

## Phase 1: Ingest and normalize

Same input contract as `/triage` Phase 1. Normalize every input format to a
flat `findings[]` of dicts. Pull what's present; never guess what's absent.

### 1a. Recognized containers (priority order)

1. **`<repo>-triage.json`** (or legacy `TRIAGE.json`) — read `.findings[]`. **Filter to `verdict ==
   "true_positive"`.** This is the canonical input: already verified,
   deduped, ranked, owner-tagged, and (since harness 0.37.0) carrying the
   input's `recommendation` through verbatim.
2. **`<repo>-security-audit.json`** (a `contracts/schemas/report.schema.json`
   document) — read `.findings[]`; the alias table below maps its
   `remediation` guidance to `recommendation` and `locations[0]` to
   `file`/`line`. Skip findings already dispositioned `false_positive`.
   Unverified; print `Warning: audit findings are claimed, not verified.
   Consider /triage first.` and continue.
3. **`*-vuln-findings.json`** (or legacy `VULN-FINDINGS.json`) —
   `/vuln-scan` output; read `.findings[]` (ignore the `known_findings`
   list — those belong to the baseline audit). Unverified; print
   `Warning: vuln-scan output is unverified scanner candidates. Consider
   /triage first.` and continue.
4. **`*-pqc-blockers.json`** (findings projection of the pqc-readiness
   report; shape contract: `contracts/schemas/pqc-blockers.schema.json`, emitted and
   gated by `harnessing/3-audit/pqc-readiness/scripts/build_pqc_blockers.py`) — detect by
   `"artifact": "pqc-blockerss"` in the top-level object. Read
   `.findings[]` exactly like a security-audit report (same field
   vocabulary: `locations[0]` → `file`/`line`, `remediation` →
   `recommendation`; `pqc_classification` is already populated, so
   domain-knowledge recipe routing applies unchanged). **When this file
   exists for a repo, prefer it over raw `*-pqc-facts.json` filtering
   (input 4b below) — it is the already-curated remediation set.**
   Unverified; print `Warning: PQC blockers are schedule-risk projections,
   not verified exploits.` and continue.
4b. **`*-pqc-facts.json`** (PQC readiness Layer 1 output; shape contract:
   `contracts/schemas/pqc-facts.schema.json`, gated at write time by
   `pqc_facts.py`) — a crypto census, not a bug list. Detect by
   `"artifact": "pqc-facts"` in the top-level object. Fallback when no
   `*-pqc-blockers.json` projection exists. **Filter to actionable first-party facts only:**
   - `path_class == "first_party"` AND
   - `rule_id` starts with `HP_GROUPS_` or `HP_ENV_` (config blockers), OR
   - `rule_id == "HP_CHAIN_GO_TOOLCHAIN"` with `pqc_capable == false`

   Map each passing fact to a finding:
   - `file` ← `fact.file`
   - `line` ← `fact.line`
   - `category` ← `"cryptography"`
   - `pqc_classification` ← `"pqc-blocker-config"`
   - `severity` ← `"high"` for group pins/kill switches, `"medium"` for
     toolchain version
   - `title` ← derive from `rule_id` (e.g. `HP_GROUPS_HAPROXY_CURVES` →
     "HAProxy curve pin blocks ML-KEM negotiation")
   - `description` ← `fact.detail` or `fact.match`
   - `recommendation` ← "Remove the restriction; the runtime negotiates
     PQC automatically when unconstrained." (domain-knowledge enrichment
     will inject the full recipe)
   - `cwes` ← `["CWE-327"]`

   `repository` from the top-level `repository` field. Print: `PQC facts
   input: {N} actionable blockers from {total} facts.`
5. **Pipeline results directory** (external vuln-pipeline output) — one
   finding per `reports/bug_NN/`.
   Map `report.json` → `description`, `crash.crash_type` → `category`,
   ASAN top-frame → `file`/`line`. Record `bug_id = NN` for the
   `--bug N` delegate flag.
6. Generic `*.json` with a top-level list or a `findings`/`results`/
   `issues`/`vulnerabilities` array.

### 1b. Field aliases (canonical ← also-accept)

| Canonical        | Also accept                                              |
|------------------|----------------------------------------------------------|
| `file`           | `path`, `location.file`, `filename`, `locations[0].path` |
| `line`           | `line_number`, `location.line`, `lineno`, `locations[0].lines` (first line of the range) |
| `category`       | `type`, `cwe`, `rule_id`, `crash_type`                   |
| `severity`       | `severity_rating`, `level`, `priority`                   |
| `title`          | `name`, `summary`, `message`                             |
| `description`    | `details`, `report`, `body`, `evidence`, `rationale`     |
| `recommendation` | `fix`, `remediation`, `mitigation`                       |
| `owner_hint`     | `owner`, `component`                                     |

Attach `id` (`f001`, `f002`, ... in ingest order; preserve existing ids
from the triage JSON and campaign-format ids `{REPO_SLUG}-{SHORTSHA}-{NNN}`
from audit reports or `*-vuln-findings.json`) and `source` (relative path
of the file it came from). The `--id` filter accepts either form.

### 1c. Filter and order

- If `--id fNNN`: keep only that finding.
- If `--top N` (static mode): sort by `severity` (critical > high >
  medium > low > informational, case-insensitive; legacy HIGH/MEDIUM/LOW
  map to their lowercase equivalents) then `confidence` desc, keep the
  first N.
- Drop findings with no `file` (cannot patch what cannot be located). Record
  them as `skipped` with reason `"no source location"`.

### 1d. Locate the target codebase (static mode)

Resolve `--repo`. For the first 5 findings with a `file`, check the path
resolves under repo (try as-given, then with common prefixes stripped). If
none resolve, **stop**: tell the user the cited files aren't reachable and
suggest a `--repo` value.

Confirm `--repo` is a git repository: Bash:
`git -C <repo> rev-parse --git-dir`. If this fails, **stop** and tell the
user `--repo` must be a git repository (diff validation requires it).

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 1, "mode": ..., "findings": [...], "skipped": [...], "repo": ...}`
Then Bash:
`python3 -m traust.cli admin checkpoint save ./.patch-state 1 ingest --from ./.patch-state/_chunk.tmp`

---

## Phase 2: Generate patches

Forks on `mode`.

### 2A. Execution-verified mode — delegate to the pipeline

The pipeline already implements the build → reproduce → regress → re-attack
ladder with executable oracles. Do not reimplement it.

For each finding (or once for the whole directory if no `--id`/`--top`
filter), Bash:

```
vuln-pipeline patch <findings_path> --model <--model arg> [--bug <bug_id>]
```

The pipeline writes `<findings_path>/reports/bug_NN/{patch.diff,
patch_result.json}` itself. After it returns, Read each `patch_result.json`
and copy `verdict` + `rationale` into working state. Set
`verified: "ladder_passed"` when `verdict.passed == true`, else
`verified: "ladder_failed"`.

If the CLI exits non-zero (no `build_command`, missing target config), record
the stderr as the finding's `error` and continue with remaining findings.

Skip Phase 3 (the ladder is the verifier). Proceed to Phase 4.

**Checkpoint per finding:** Write tool → `./.patch-state/_chunk.tmp` =
`{"id": ..., "verified": ..., "verdict": ..., "diff_path": ...}`, then Bash:
`python3 -m traust.cli admin checkpoint shard ./.patch-state <id> --from ./.patch-state/_chunk.tmp`.
After all findings, write the consolidated phase payload to `_chunk.tmp` then:
`python3 -m traust.cli admin checkpoint save ./.patch-state 2 generate --from ./.patch-state/_chunk.tmp`

### 2B. Static mode — one patch subagent per finding

One Task per finding, all in a SINGLE assistant message for parallel
execution. `subagent_type: "general-purpose"`. Never set
`run_in_background` — you need the diff text, not an async handle.

Each subagent gets a dedicated disposable git worktree. It edits files
there to implement the fix, stages the changes, captures `git diff
--cached` for the raw diff, commits with a structured message carrying
the finding metadata, and runs `git format-patch -1 --stdout` to produce
a `git am`-ready patch. Both artifacts are written to `PATCHES/bug_NN/`.
This eliminates corrupt hand-crafted diffs — git-generated output always
has structurally valid unified diffs.

#### Worktree setup (orchestrator, before spawning subagents)

For each finding, create a detached worktree:

```
git -C <repo> worktree add /tmp/patch-wt-<id> HEAD --detach
```

Each finding gets its own worktree path (e.g., `/tmp/patch-wt-f001`) so
subagents can run concurrently without conflicts.

#### Patch subagent prompt (assemble once, reuse per finding)

```
You are conducting authorized security research as part of a defensive
assessment. Your task: implement a candidate fix for ONE verified
vulnerability finding in a dedicated worktree.

You have a disposable worktree at {WORKTREE_PATH} — a copy of the target
repo. You may Read, Edit, Write, and Grep files in this worktree. You may
also Read files in {REPO_PATH} (the original repo) for reference. You may
NOT build, run, install, or reach the network.

After implementing the fix, stage all changes, capture the raw diff,
commit with a structured message, and generate a `git format-patch`
patch. Return both outputs.

────────────────────────────────────────────────────────────────────────
FINDING:

  id:        {id}
  file:      {file}
  line:      {line}
  category:  {category}
  severity:  {severity}
  title:     {title}

  description:
  {description}

  recommendation:
  {recommendation or "(none provided)"}

────────────────────────────────────────────────────────────────────────
PROCEDURE:

1. READ THE CODE. Open {WORKTREE_PATH}/{file} at line {line} and the
   surrounding function. Understand what the code does — do not trust the
   finding's description as the only source.

2. ROOT CAUSE FIRST. Trace backward from the cited sink to where the bad
   value or missing check originates. The fix usually belongs there, not at
   the line the scanner flagged. Name the root-cause location (file:line).

3. VARIANT HUNT. Grep for sibling call sites with the same pattern. Your fix
   should cover all of them, or your rationale should say why not.

4. IMPLEMENT THE FIX. Edit files in {WORKTREE_PATH} to make the smallest
   change that fixes the root cause. No refactoring, no drive-by cleanup,
   no reformatting, no comment-only changes. Match the surrounding code's
   style (brace placement, naming, error handling).

5. ADVERSARIAL SELF-CHECK. Re-read your changes as an attacker. Name one
   input variation that would reach the same bad state without tripping your
   change. If you can name one, your fix is at the wrong layer — go back to
   step 2.

6. REGRESSION TEST. Add ONE test case that fails before your change and
   passes after — placed wherever the project keeps its tests (look for
   test_*/, *_test.*, tests/, spec/). If no test directory exists, omit the
   test and say so in <test_note>.

7. STAGE AND COMMIT.
   a. Stage all changes: `git -C {WORKTREE_PATH} add -A`
   b. Commit with a structured message. Use the template below,
      substituting the finding's values and your analysis results.
      Write the message to a temp file and commit with `-F`:

        fix({category}): {title}

        Finding-Id: {id}
        Severity: {severity}
        Location: {file}:{line}

        {1-2 sentence rationale — root cause location and what the fix enforces}

        Variants-Checked: {brief list of file:function pairs checked}
        Test-Note: {where the test landed, or why omitted}

   c. Report the resulting commit SHA from the git output.

   Do NOT return the diff or patch content — the orchestrator will export
   them directly from this worktree commit via shell redirection, avoiding
   text round-trip corruption.

────────────────────────────────────────────────────────────────────────
OUTPUT — your final response MUST contain exactly these tags.

<commit_sha>{the full 40-character SHA printed by git commit, or NONE if
no patch is appropriate}</commit_sha>
<rationale>what changed and why, mechanically — file:line of root cause,
what the change enforces</rationale>
<variants_checked>file:function pairs you grepped for the same
pattern, and whether each needed the fix</variants_checked>
<bypass_considered>the input variation you tried in step 5 and why it
no longer reaches the bad state</bypass_considered>
<test_note>where the regression test landed, or why none was
added</test_note>

If you determine the finding is NOT fixable as described (wrong file, code
already patched, finding is a false positive), emit:

<commit_sha>NONE</commit_sha>
<rationale>why no patch is appropriate</rationale>
```

#### Domain-knowledge enrichment (crypto / PQC findings)

Before assembling the subagent prompt, check whether the finding carries
`category: cryptography` OR any `pqc_classification` tag. If so, load
domain-specific remediation context:

1. Read `<skill-base>/../pqc-readiness/remediation/index.yaml`.
2. Match the finding against recipe entries (first match wins — index is
   ordered most-specific-first):
   - **AND across dimensions:** all non-empty `matches` keys in the recipe
     must match the finding. If the recipe omits a key, that dimension is
     unconstrained (wildcard).
   - **OR within a dimension:** any listed value satisfies that key.
   - **Field mappings:** finding `cwes[]` (array) matches recipe `cwe` if
     any element intersects. Finding `pqc_classification` is a single string.
   - **Missing finding field:** if the finding lacks a field that the recipe
     requires (e.g. `context`), that recipe does NOT match — skip to next.
3. Determine the sub-recipe file:
   - **Language keys** (go, python, nodejs, rust): match on source file
     extension from the finding's `file` field.
   - **Domain keys** (non-language): match on evidence keywords in the
     finding's `title`, `description`, `recommendation`, or `file`:
     * GODEBUG / env var / JVM property / NODE_OPTIONS → `runtime-switches`
     * CurvePreferences / ssl_ecdh_curve / namedGroups / curves → `curve-pins`
     * crypto-policies / update-crypto-policies → `crypto-policy`
     * certificate / X.509 / CA / cert-manager → `certificates`
     * JWT / token / OIDC / sa-token / JWKS → `tokens`
     * cosign / sigstore / gpg / sign / notary → `code-signing`
   - **Fallback:** `generic` if present, otherwise first key in the map.
4. Read the matched recipe markdown file.
5. Append the recipe content to the subagent prompt as a
   `DOMAIN KNOWLEDGE` section between `FINDING` and `PROCEDURE`:

```
────────────────────────────────────────────────────────────────────────
DOMAIN KNOWLEDGE (from remediation recipe: {recipe_id}):

{recipe markdown content}

────────────────────────────────────────────────────────────────────────
```

If no recipe matches, proceed without domain knowledge (the subagent
still has the finding's own `recommendation` field).

The recipes express fix *principles* (remove restrictions, inherit
defaults, make configurable) — they do not track external project
timelines. The patch agent should verify applicability by reading the
target's actual dependencies (go.mod, package.json, Dockerfile base
image) rather than relying on version assertions in the recipe.

#### Spawn

For each finding in `findings[]`, build a Task call with the prompt above
(substituting `{REPO_PATH}`, `{WORKTREE_PATH}`, `{id}`, `{file}`,
`{line}`, `{category}`, `{severity}`, `{title}`, `{description}`,
`{recommendation}`, and the optional `DOMAIN KNOWLEDGE` section from the
enrichment step). `description: "patch {id}"`.

If `len(findings) > ~40`, shard into sequential batches of ~40 (each batch
one message). Per-finding shard checkpoint after each result is parsed.

If any Task call returns `status: "async_launched"` instead of the
subagent's text, the runtime backgrounded it. Pick one recovery and use it
for the whole batch:
  - If completion notifications arrive in your conversation: parse each
    subagent's tagged blocks from its notification `result` as it lands. Do
    not end your turn until every finding is accounted for.
  - If notifications do not arrive: do NOT poll transcript files. Re-spawn
    the missing patch subagents in a fresh Task batch (smaller shard, e.g.
    10) and use the synchronous results.
The same recovery applies to reviewer subagents in Phase 3.

#### Parse, export, and validate

From each Task result, extract the five tagged blocks (`commit_sha`,
`rationale`, `variants_checked`, `bypass_considered`, `test_note`).
Tolerate leading/trailing whitespace, stray ``` fences, and
HTML-escaped entities (`&lt;` `&gt;` `&amp;` — some runtimes escape
angle brackets in notification payloads; unescape before using). If
`<commit_sha>` is `NONE` or empty, mark `status: "no_patch"`. Otherwise
proceed to export and validation:

**Export from worktree** (runs for every non-NONE `<commit_sha>`):

The orchestrator exports the diff and patch **directly** from the
subagent's worktree commit via Bash shell redirection. This bypasses
the LLM text boundary entirely — git writes the bytes straight to disk,
eliminating the context-line corruption that occurs when diff content is
returned as subagent text and re-written via the Write tool.

1. Bash: `git -C /tmp/patch-wt-<id> diff HEAD~1 > ./PATCHES/bug_NN/patch.diff`
2. Bash: `git -C /tmp/patch-wt-<id> format-patch -1 --stdout > ./PATCHES/bug_NN/patch.patch`
   (NN = zero-padded index in sorted order.)

**Diff validation** (runs after export):

3. Bash: `git -C <repo> apply --check ./PATCHES/bug_NN/patch.diff`
   (`--check` is a dry-run: it confirms the diff would apply cleanly
   without modifying any files.)
4. **Exit 0 (pass):** Set `diff_validated: true`.
   Record `rationale`, `variants_checked`, `bypass_considered`, `test_note`.
5. **Non-zero (fail):** Since the diff was exported directly by git (not
   round-tripped through text), a validation failure is unexpected —
   likely a worktree state issue. Leave the exported files in place
   (consumers may want to inspect them). Set `diff_validated: false`,
   `diff_error: "<stderr>"`, `status: "bad_diff"`.

#### Worktree cleanup (orchestrator, after export and validation)

After exporting and validating all diffs, clean up every worktree:

```
git -C <repo> worktree remove --force /tmp/patch-wt-<id>
```

Run cleanup for all findings, including those with `status: "no_patch"`.

**Checkpoint per finding:** Write tool → `./.patch-state/_chunk.tmp` =
`{"id": ..., "bug_nn": "NN", "status": ..., "diff_validated": ..., "diff_error": ..., "rationale": ..., ...}`,
then Bash:
`python3 -m traust.cli admin checkpoint shard ./.patch-state <id> --from ./.patch-state/_chunk.tmp`.
After all findings, write the consolidated phase payload to `_chunk.tmp` then:
`python3 -m traust.cli admin checkpoint save ./.patch-state 2 generate --from ./.patch-state/_chunk.tmp`

---

## Phase 3: Independent review (static mode only)

**3-pre. Deterministic differential for scanner-backed findings.** Before
spawning reviewers: if the finding is scanner-backed (an opengrep
`scanner_correlation` promotion with a `rule_id`, or a `KHS-*`-cited
config finding — see `/secure-code-audit`'s pre-scan sections), apply the
candidate diff to a scratch worktree (`git worktree add` + `git apply`;
never the primary checkout) and re-run the backing scanner
(`run_opengrep.py` / `scan_k8s_hardening.py`) on it:

- backing fact **gone** → record `"fact_differential": "cleared"` in the
  finding's `patch_result.json`;
- fact **persisting** → `"fact_differential": "persists"` — the diff does
  not silence its own evidence; mark the patch `verdict: rejected` unless
  the reviewer articulates why the scanner is wrong;
- not scanner-backed or tools absent → `"fact_differential":
  "not-applicable: <reason>"` (recorded, never implied).

Remove the worktree afterwards. This is evidence for the reviewer, not a
substitute: a cleared fact says the pattern is gone, not that the fix is
correct or minimal.

One reviewer subagent per generated diff, all in ONE message,
`subagent_type: "general-purpose"`.

**The reviewer never sees the finding's `description`, `recommendation`, or
the patch author's `rationale`.** It gets only `{file, line, category}`
plus the raw diff bytes, and re-derives whether the diff is a minimal,
in-scope fix by reading the source itself. This keeps any instructions
embedded in finding prose from reaching both the author and the gate.

#### Reviewer prompt (assemble once, reuse per diff)

```
You are reviewing a candidate security patch as a maintainer would. You have
read-only access to the unpatched source at {REPO_PATH}. You may use Read,
Glob, Grep. You may NOT build, run, or apply the diff.

You have NOT seen the scanner's description of the vulnerability or the
patch author's reasoning. Work only from the location, the category, and the
diff.

LOCATION: {file}:{line}
CATEGORY: {category}

DIFF UNDER REVIEW:

Read the diff at ./PATCHES/bug_NN/patch.diff using the Read tool.

────────────────────────────────────────────────────────────────────────
ANSWER FOUR QUESTIONS:

1. SCOPE. Does the diff touch only files/functions on the path between
   {file}:{line} and its callers? List any hunk that falls outside that
   path.

2. SUPPRESSION. Does the diff fix a root cause, or does it suppress the
   symptom (try/except: pass, early-return on a magic value, deleting the
   check that fired, lowering a log level)?

3. NEW SURFACE. Does the diff add parsing, trust a new input field, weaken
   validation elsewhere, or remove a security-relevant check?

4. STYLE. 0-10: would you merge this as-is?
   0-3 wrong layer / suppression; 4-6 correct but noisy; 7-10 minimal,
   targeted, matches surrounding style.

────────────────────────────────────────────────────────────────────────
End your response with EXACTLY:

  REVIEW: ACCEPT | REJECT
  STYLE_SCORE: <0-10>
  OUT_OF_SCOPE_HUNKS: <comma-separated file:line, or none>
  REASON: <2-4 sentences citing specific diff hunks and source lines>

ACCEPT requires: in-scope, root-cause fix, no new attack surface,
style >= 5. Otherwise REJECT.
```

#### Spawn and parse

One Task per finding with `status != "no_patch"` and `status != "bad_diff"`.
Parse the trailing block.
Attach `review`, `style_score`, `out_of_scope_hunks`, `review_reason` to the
finding. Set `verified: "static_review_only"` for every static-mode result
regardless of ACCEPT/REJECT — the label describes the verification class,
not the outcome.

**Checkpoint:** Write tool → `./.patch-state/_chunk.tmp`:
`{"phase": 3, "findings": [...]}`
Then Bash:
`python3 -m traust.cli admin checkpoint save ./.patch-state 3 review --from ./.patch-state/_chunk.tmp`

---

## Phase 4: Output

### 4a. Per-finding `patch_result.json`

For each finding (both modes), Write
`./PATCHES/bug_NN/patch_result.json`:

```json
{
  "id": "f003",
  "source": "<repo>-triage.json#2",
  "title": "...",
  "file": "...",
  "line": 0,
  "category": "...",
  "severity": "HIGH",
  "owner_hint": "...",
  "mode": "exec" | "static",
  "verified": "ladder_passed" | "ladder_failed" | "static_review_only",
  "review": "ACCEPT" | "REJECT" | null,
  "style_score": 0,
  "out_of_scope_hunks": [],
  "rationale": "...",
  "variants_checked": "...",
  "bypass_considered": "...",
  "test_note": "...",
  "review_reason": "...",
  "diff_validated": true,
  "diff_error": null,
  "diff_retry_count": 0,
  "verdict": { "t0_builds": true, "...": "(exec mode only, from pipeline)" }
}
```

In exec mode, also Read the pipeline's
`<findings_path>/reports/bug_NN/patch.diff` and Write its bytes to
`./PATCHES/bug_NN/patch.diff` so both modes land in the same place.
(Exec mode does not produce `patch.patch` — the pipeline does not create
commits; only `patch.diff` is copied.)

### 4b. `./PATCHES.json`

```json
{
  "patch_completed": true,
  "mode": "exec" | "static",
  "repo": "...",
  "summary": {
    "input_count": 0,
    "patched": 0,
    "no_patch": 0,
    "accepted": 0,
    "rejected": 0,
    "bad_diff": 0,
    "ladder_passed": 0
  },
  "findings": [ { ...patch_result.json shape... } ]
}
```

### 4c. `./PATCHES.md` (incremental)

**Step 1 — header.** Write tool → `./PATCHES.md` (clobbers prior):

````markdown
# Candidate Patches

{if mode == "static":}
> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself before applying: check it compiles
> in your head, fixes the root cause rather than the symptom, doesn't
> break callers, and introduces no new input paths. For build/test-verified
> patches, use the `remediate-finding` skill instead.

{if mode == "exec":}
> **Execution-verified.** Each diff passed (or failed) the pipeline
> verification ladder: build → reproduce → regress → re-attack. The ladder
> proves the crash is gone, not that the diff introduces no new problems.

**Input:** {findings_path} · **Repo:** {repo} · {N} findings → {M} diffs

---
````

**Step 2 — per finding** (sorted: ACCEPT/ladder_passed first, then by
severity). Write `./.patch-state/_chunk.tmp`:

````markdown
## bug_{NN}: [{severity}] {title}  ({id})

`{file}:{line}` · {category} · owner: {owner_hint or "?"}
**Status:** {verified} · review {review or "n/a"} · style {style_score or "n/a"}/10
**Diff:** `PATCHES/bug_{NN}/patch.diff` ({hunk count} hunks, {line count} lines) — {if diff_validated:}validated{else:}INVALID: {diff_error}{endif}
**Patch:** `PATCHES/bug_{NN}/patch.patch` (git-am-ready, includes commit message with finding metadata)

**Rationale:** {rationale}
**Variants checked:** {variants_checked}
**Bypass considered:** {bypass_considered}
{if review == "REJECT":}
> **Rejected by reviewer:** {review_reason}
{if out_of_scope_hunks:}
> **Out-of-scope hunks:** {out_of_scope_hunks}

---
````

Then `checkpoint.py append ./PATCHES.md --from ./.patch-state/_chunk.tmp`.

**Step 3 — footer.** Append a `## Skipped` table for findings with no `file`,
`status == "no_patch"`, or `status == "bad_diff"`, one line each with the
reason.

**Checkpoint (final):** Bash:
`python3 -m traust.cli admin checkpoint done ./.patch-state 4`

### 4d. Terminal summary

Under ~10 lines:

```
Patches generated ({mode} mode): {N} findings → {M} diffs.

  Accepted:  {n}   {title of top accepted}
  Rejected:  {n}
  No patch:  {n}
  Bad diff:  {n}
  {if exec:} Ladder passed: {n}/{M}

Wrote ./PATCHES/bug_NN/, ./PATCHES.md, ./PATCHES.json
{if static:} These are drafts. Review each diff before applying.
```

---

## Guard rails

- **Never modify `--repo` directly.** All source edits go into disposable
  git worktrees under `/tmp/`. Worktrees are removed after the diff is
  captured. `git apply --check` (dry-run validation) is permitted for
  validating diffs against `--repo`.
- **Orchestrator writes only under `./PATCHES/` and `./.patch-state/`.**
  Subagents may write to their assigned worktree paths.
- **Reviewer isolation.** The reviewer prompt receives `{file, line,
  category, diff}` and nothing else from the finding. Do not pass it
  `description`, `recommendation`, `exploit_scenario`, or the patch author's
  `rationale`.
- **Always set `subagent_type`.** Forking would leak every finding's prose
  into every patch subagent.
- **All Task calls for a phase in ONE message.** Serial spawning is correct
  but N× slower.
- **Checkpoint before starting the next phase**, every time.
- **Exec mode delegates, never reimplements.** `vuln-pipeline` is an
  external CLI (not part of this harness); if `vuln-pipeline patch` isn't
  on PATH, stop and tell the user; don't fall back to static mode silently.

---

## Testing this skill

Static mode (the `targets/canary` fixture with planted bugs ships with the
external vuln-pipeline repo, not this harness — any small target with known
findings works the same way):

```
/vuln-scan targets/canary
/triage targets/canary/canary-vuln-findings.json --repo targets/canary --auto
/patch <repo>-triage.json --repo targets/canary --top 3
```

Expected: three diffs under `PATCHES/bug_00..02/`, each
`verified: "static_review_only"`, `review: ACCEPT`, style ≥ 7 for the
planted overflow/UAF/format-string bugs.

Execution-verified mode against output of the external vuln-pipeline CLI:

```
vuln-pipeline run drlibs --runs 3 --parallel --stream --model <m>
/patch results/drlibs/<ts>/ --model <m>
```

Expected: delegates to `vuln-pipeline patch`, surfaces
`verified: "ladder_passed"` per bug, copies diffs into `./PATCHES/`.

---

## Design notes

- **Triage JSON is canonical input** because patching unverified findings
  wastes tokens on false positives. Audit reports and vuln-scan output
  are accepted with a warning for convenience.
- **The auditor's `remediation` guidance reaches the patch author on every
  path.** Audit reports carry it directly (aliased to `recommendation`);
  the triage JSON carries it through verbatim since harness 0.37.0. It is a
  hint only — the subagent's procedure is root-cause-first, and the
  reviewer never sees it (see reviewer isolation).
- **Static mode includes a regression test in the diff** rather than
  running it. Subagents edit test files in the worktree alongside the fix;
  `git diff` captures both. The skill cannot execute target code
  (constraint of the static pipeline); the test is for the human who
  applies the diff.
- **Reviewer never sees finding prose.** Target source can contain
  injected instructions that survive into a scanner's `description` field.
  The patch author sees that prose (it has to, to know what to fix); the
  reviewer doesn't, so injected text cannot pass its own gate.
- **`verified` is the verification class, not pass/fail.**
  `static_review_only` means "an agent read it" regardless of
  ACCEPT/REJECT. `ladder_passed`/`ladder_failed` means "ASAN decided."
  Downstream tooling should branch on this field, not on `review`.
- **Output shape matches the pipeline** (`PATCHES/bug_NN/{patch.diff,
  patch.patch,patch_result.json}`) so consumers don't care which mode
  produced it. `patch.diff` is a raw unified diff for `git apply`;
  `patch.patch` is a `git format-patch` output for `git am` — same code
  changes, but the patch carries a commit message with finding metadata
  (id, severity, location, rationale). Exec mode only produces
  `patch.diff` (the pipeline does not create commits).
- **Diffs and patches are generated by git and exported directly to
  disk.** Subagents edit files in a disposable worktree, stage with
  `git add -A`, and commit with a structured message carrying finding
  metadata. The orchestrator then exports `git diff HEAD~1` and
  `git format-patch -1 --stdout` from the worktree commit directly to
  `PATCHES/bug_NN/` via Bash shell redirection — git writes the bytes
  straight to disk, never passing through the LLM text boundary. This
  eliminates two historical failure modes: (1) hand-crafted diffs with
  corrupt hunk headers, wrong line counts, or missing leading spaces on
  blank context lines (solved by using git to generate diffs), and
  (2) context-line corruption when diff content was returned as subagent
  text and re-written via the Write tool (solved by the direct export).
  `git apply --check` still validates the result as a safety net — it is
  a read-only probe that never modifies the target repo.

---

## Provenance

Derivative work of the `patch` skill in
**defending-code-reference-harness** (Copyright 2026 Anthropic PBC, Apache
License 2.0 — see the harness root `NOTICE` and `LICENSES/Apache-2.0.txt`),
ported into this harness at v0.23.0 and modified per `CHANGELOG.md`.

## Spend declaration (calibration tuple)

After this skill's report/artifact is written, declare the run's spend
against the target so `estimate_scan` can calibrate per-skill cost
models (contract: docs/model-routing.md; analysis:
progress-tracker/metrics/estimate-calibration-analysis.md §F5):

```bash
python3 -m traust.cli registry models spend --skill patch \
    --model <resolved model id> [--tokens-in <N>] [--tokens-out <N>] \
    --repo <target-slug> --loc <target size, if known> [--batch <batch-id>]
```

Token counts are OPTIONAL and best-effort: pass them when the
orchestrator has them (Task results carry per-subagent usage),
otherwise omit them — an agent cannot observe its own usage mid-run.
**This row is a routing marker, not a cost claim**; actual per-lane
cost is attributed from session transcripts by
python3 -m traust.cli metrics attribute-spend. Never skip the row: an
unattributed run is a calibration gap.

## Integrations

**Consumes:** `<repo>-triage.json` (preferred; legacy `TRIAGE.json`
accepted) from `/triage`; `<repo>-security-audit.json` from
`/secure-code-audit` or `*-vuln-findings.json` from `/vuln-scan`
(unverified-input warning); `*-pqc-facts.json` from `/pqc-readiness`.

**Emits (terminal by design):** `./PATCHES/bug_NN/{patch.diff,
patch_result.json}`, `PATCHES.md`, `PATCHES.json` are a
**human-review packet, not a pipeline artifact** — no skill or script
consumes them (verified repo-wide, docs-verification 2026-07-31
wiring F4), and that is deliberate: this skill produces inert
candidate diffs for a human to review and apply out-of-band, with no
`--apply` flag anywhere. Applying a reviewed diff and verifying it is
the `/remediate-finding` → `/verify-remediation` fork flow; a patch
accepted from this packet enters the ledger only through those lanes
(or a human-recorded `/track-findings` event), never automatically.

**Where executed patch evidence lives.** This skill cannot run target code,
so it produces no typed evidence of its own. Typed base-versus-patch evidence
(`patch_evidence`) comes from three places:
`/remediate-finding` Phase 4b (`mutation`, Go) and Phase 4c (`property`,
Python, with the test authored by `/property-test`), and `/verify-remediation`
step 4-pre.5 (`scanner_differential`). The regression test this skill ships in
its diff is where those lanes start.

**Optional external reviewer aid.** Reviewing this packet is manual, and an
installed third-party plugin can render the diff for that review:
[review-walkthrough](https://github.com/trailofbits/skills/tree/main/plugins/review-walkthrough)
from the `trailofbits` marketplace. It is entirely optional, invoked directly
by the reviewer, and nothing here depends on it: no step below calls it, and
its absence changes no output. Its licence posture and freshness row are
recorded in `docs/external-dependencies.md` under **Agent skills (runtime
plugins)** — it is used, never adapted into this tree.
