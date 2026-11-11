---
name: check-harness-docs
description: Use when changing harness skills, scripts, schemas, pipeline stages, or documentation, or when checking for documentation drift before a commit. Verify counts, local paths, inventory coverage, CLI examples, external dependency records, and version consistency against the tree; update stale documentation and rerun the checks.
argument-hint: "[--root DIR]"
user-invocable: true
metadata:
  harness.tier: "ci"
allowed-tools:
  # Scoped per A11 — this skill runs exactly one script. Never widen to a
  # bare interpreter.
  - Bash(python3 *-m traust.cli.check_docs_consistency:*)
  - Read
  - Edit
  - Glob
  - Grep
---

# Check harness docs for drift

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


A guardrail for the harness's **own** documentation. The docs repeatedly state
countable facts about the tree — "26 active skills", "31 slash command
wrappers", "Twelve Python scripts", "8-stage pipeline" — and cross-reference
files by path. Both rot silently as the harness grows. This skill runs the
deterministic checker and, if it finds drift, fixes the **docs** to match the
tree.

## When to use

Run it whenever you:

- add / rename / remove a skill under `harnessing/`,
- add / remove a script under `scripts/`, a schema under `contracts/schemas/`, or a
  command wrapper under `.claude/commands/`,
- add or remove a `## Stage N` in `PROCESS.md`,
- bump `VERSION`, or
- edit any of `README.md`, `AGENTS.md`, `PROCESS.md`, or `docs/*.md`.

## Run it

```bash
python3 -m traust.cli check docs-consistency
```

Exit `0` = docs consistent. Exit `1` = drift; each issue is printed. The same
logic runs in the test suite as `tests/test_docs_consistency.py`.

## What it checks

1. **Count assertions.** Global inventory claims in `README.md` / `AGENTS.md` /
   `PROCESS.md` / `docs/*.md` must equal the live tree count:
   | Claim | Source of truth |
   |---|---|
   | `N skills` / `N active skills` / `all N skills` | `harnessing/*/SKILL.md` |
   | `N slash command` | `.claude/commands/*.md` |
   | `N Python scripts` (digit or word form) | `scripts/*.py` |
   | `N-stage` | `## Stage N` headings in `PROCESS.md` |
   Expected numbers are computed from the tree, so the checker never itself
   goes stale.

2. **Dead paths.** Every Markdown link with a repo-relative target and every
   backtick path under a known in-repo dir (`harnessing/`, `scripts/`,
   `contracts/`, `traust-ledger/`, `schema/` (retired — always dead, tripwire
   against reintroduction), `docs/`, `.claude/`, `.crush/`, `config/`,
   `tests/`) must resolve.
   Sibling-repo paths (`analysis-results/`, …), externals (`http(s)`),
   glob/placeholder patterns (`*`, `<repo>`, `**`), and historical records
   (`CHANGELOG.md`) are intentionally skipped.

3. **Enumeration coverage.** Docs that present themselves as inventories must
   mention every item: each skill needs a `## <name>` section in
   `docs/skills.md` and a mention in `README.md`; every schema and every
   `docs/*.md` guide must be reachable from `README.md`. Count checks alone
   let a table silently omit entries while the stated total stays right.
   `docs/skills.md` itself is **generated** from the skill tree by
   python3 -m traust.cli build skills-reference and the gate
   fails when the committed copy differs from a fresh render — never hand-edit
   it; edit the skill's frontmatter and regenerate.

4. **Version sync.** `pyproject.toml` `[project] version` must equal the
   `VERSION` file (it once drifted 30 releases silently).

5. **Symlink integrity.** Every symlink under `.claude/` and `.crush/` must
   resolve — catches half-removed wrapper pairs the dead-path checks skip.

6. **External CLI tools.** Every binary the harness shells out to
   (`subprocess`, `shutil.which`, self-named `--tool` defaults, vendored
   `bin/` paths, `command -v`) must have a row in
   `docs/external-dependencies.md` — the CLI-tool counterpart of the
   `/check-licensing` Python-dependency gate.

7. **CLI-example flag drift.** Every maintained-doc line that invokes an
   in-repo Python script has its `--flags` verified against that script's
   source — the rot class where a documented flag no longer exists and the
   reader's first command fails (`validate_report.py --validate` survived
   ~150 releases before this check). Values are not checked; `--help` is
   argparse-implicit; dynamic flags go in the checker's per-script
   allowlist with justification.

8. **Partial enum quotes.** A maintained-doc line that names a schema
   enum-bearing field and backtick-quotes 3+ of its values but not all of
   them is a lagging enumeration (the class where `validation_status` docs
   missed `hardening` for months). Only fields whose enum is identical
   everywhere it appears in `contracts/schemas/*.json` are tracked; enum lists belong
   in `docs/report-structure.md` — link, don't restate.

9. **As-of banners.** Any `docs/*.md` whose name marks it as an
    assessment, draft, or comparison must carry a dated as-of banner —
    point-in-time judgments presented as live status rot silently (four
    such docs were up to ~143 releases stale at the 2026-07-25 sweep).

## Quarterly semantic sweep

The mechanical checks above catch counts, paths, CLI flags, and enums —
not behavioral claims ("X overrides Y", "Z is unwired"). Those are bounded
by a quarterly reviewer sweep:

1. Fan out parallel reviewer agents, one per doc cluster (~3-4 docs each),
   each instructed to extract every checkable claim and verify it against
   the tree with file:line evidence — verified discrepancies only,
   severity-rated (high = actively misleading).
2. Consolidate into `progress-tracker/gap-assessments/docs-verification-<date>.md`
   (the 2026-07-25 report is the template), then fix findings in priority
   order via per-cluster fix agents re-verifying each finding before
   editing.
3. `/drift-watch` flags `docs-semantic-sweep` as stale when the newest
   report is older than 92 days — that is the cadence trigger.

The 2026-07-25 baseline: 23 docs, ~60 findings (9 high), ~700K tokens.

> Content licensing is **not** checked here: it has its own gate — the
> [`check-licensing`](../check-licensing/SKILL.md) skill wrapping
> python3 -m traust.cli check content-licenses — which the same pre-push hook runs
> independently alongside this checker.

## How to fix drift

**Update the docs, not the checker.** The counts are computed from the tree, so
a failure means a doc is wrong, not the script. For a count failure, correct the
number in the named doc (and, for a new skill, add its row + section to
`docs/skills.md`). For a dead path, repoint or remove the reference. Re-run
until it exits `0`. Only touch python3 -m traust.cli check docs-consistency itself to
change *what* is checked (e.g. add a new count claim or an allowlist entry).

**Unresolved conflict markers** (added 2026-08-13). Every tracked text file is scanned for `<<<<<<< ` / `>>>>>>> ` at line start; a hit fails the gate. Motivated by a live bad push — a rebase-resolution script failed silently, `git rebase --continue` committed the conflicted file, and CHANGELOG.md reached main with six markers while every other gate passed, because none of them looked. `=======` is deliberately NOT a trigger (it is a legitimate Markdown setext H1 underline); the two directional markers have no legitimate line-start use and a conflict always carries one. Runs FIRST, since a conflicted file makes the other checks emit confusing downstream noise. A doc that legitimately demonstrates conflict resolution opts out with `docs-check: allow-conflict-markers`. Fails open when git cannot list tracked files.
