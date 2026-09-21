---
name: check-alignment
description: Use before committing any new or edited skill to the traust repo, or when asked "are the skills aligned", "did my skill drift from the conventions", "run the alignment check" — runs python3 -m traust.cli check skill-alignment, the cross-skill contract guard the pre-commit hook enforces. Verifies referenced scripts exist, deterministic pre-scan recording conventions (deterministic_steps, judge protocol) travel with the tools that require them, audit-profile skills link the shared report structure instead of restating it, liveness consumers name the census artifact, skill frontmatter matches its directory, and discovery wiring (.claude/.crush symlinks + command wrapper) is complete.
metadata:
  harness.tier: "ci"
allowed-tools:
  - Read
  - Bash(python3 *traust* -m traust.cli.check_skill_alignment:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# Check Alignment

The cross-skill contract guard. The harness's skills interlock through
shared conventions — single-source report structure, deterministic
pre-scan recording, promote-or-dismiss judge protocols, census-owned repo
liveness, swappable rule packs, discovery wiring — and every documented
consistency regression entered through one skill restating or
half-adopting a convention the others had moved past. This skill (and the
pre-commit hook wrapping the same script) makes those contracts
mechanical, so a new skill cannot land misaligned.

## Run it

```bash
python3 -m traust.cli check skill-alignment
```

Exit `0` = aligned. Exit `1` prints each misalignment with its rule id:

| Rule | Contract |
|---|---|
| A1 | Every `scripts/*.py|sh` / skill-local script a skill references exists (repo- or skill-relative) |
| A2 | A report-producing skill that runs `run_opengrep.py` carries `deterministic_steps` + the judge protocol |
| A3 | A report-producing skill that runs `scan_k8s_hardening.py` carries `deterministic_steps` |
| A4 | A skill that sets `metadata.audit_profile` links `docs/report-structure.md` (never restates it) |
| A5 | A skill consuming repo liveness names the census artifact (`repo-liveness.json`) as its source |
| A6 | SKILL.md frontmatter `name:` equals the directory name |
| A7 | Discovery wiring complete: `.claude/skills/<name>`, `.crush/skills/<name>`, `.claude/commands/<name>.md` |
| A8 | A skill that runs `run_checkov.py` carries `deterministic_steps` recording plus declared-configuration labeling (a declared-only assessment never claims observation) |
| A9 | Every hyphenated data artifact a skill emits has a consumer in some other skill, is terminal-classed (dashboard/rollup/summary/tracker), or carries a reviewed exemption — catches under-wired new skills (the operator-priv-profile / impact-analysis gap) |
| A10 | A skill emitting non-terminal artifacts documents its consumers in an `## Integrations` / Downstream section |
| A11 | No allowed-tools entry grants a whole interpreter or shell (`Bash(python3:*)`, `Bash(bash:*)`, `Bash(*)`) — an unscoped interpreter is arbitrary code execution, and a skill reading untrusted target checkouts can be steered into running it. Scope each script the skill runs (`Bash(python3 *<script>.py:*)`). Pre-A11 harness-internal skills are grandfathered via printed exemptions; never add a new exemption for a target-facing skill |
| A13 | A staged `harnessing/*/SKILL.md` change ships with a staged `docs/skills.md` update in the same commit, so the skills reference can't silently lag (the 2026-07-25 sweep found ~25% of entries lagging). Pre-commit-only (`HARNESS_PRE_COMMIT=1`, set by the hook); waive doc-irrelevant changes with `SKILLS_DOC_WAIVER=<reason>` |
| A12 | Concrete model identifiers (claude-*, gpt-*, gemini-*, …) appear ONLY in `config/model-registry.yaml` — skills/scripts name tier classes and resolve via python3 -m traust.cli registry models (`docs/model-routing.md`); attribution/license prose excluded |
| A14 | An allowed-tools interpreter grant may not start its script pattern with a bare `*` (`Bash(python3 *<name>.py:*)`) — any path ending in that filename matches, including one planted in a hostile checkout. Anchor the pattern to the harness tree (`Bash(python3 *traust/scripts/<name>.py:*)`). Sibling of A11: A11 catches the unscoped interpreter, A14 the unanchored script |
| A15 | Audit baselines belong to exactly three skills — `/secure-code-audit`, `/secure-rpm-audit`, `/secure-container-audit`. Every other skill or script records a LEDGER EVENT instead, never the baseline file. A baseline mutation changes the claim set with no event recording it, which breaks the ledger's events-not-state tenet (`docs/disposition-ledger.md`) and bypasses the rescan router's authority over when a baseline is cut. Found 2026-08-17: three non-audit producers had mutated baselines |
| A16 | Ledger layers are written through the SDK (`LedgerService`/`LedgerClient`), never via `_write_layer_file` or a direct `write_text` on a layer path — a direct write bypasses the `Backend.mutate` lock that keeps mutate + stamp + sign atomic. That split left 112 signed corpus layers unsigned on 2026-08-31 while every one was reported written and successful. Scoped to writes whose target is bound to a layer path, so ordinary report and dashboard writes are unaffected |
| A17 | A SKILL.md naming `analysis-results/` or `progress-tracker/` carries the note that those are the DEFAULT layout, resolved through `locations.yaml` in `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations) — a reader outside this deployment cannot otherwise tell a documented default from a hardcode |
| A18 | Engine and config-home resolution happen ONLY in `src/traust/context.py`, the single composition root — `HarnessEngine.load()` / `HarnessEngine(...)` or a direct `deployment_config_dir()` elsewhere re-resolves config on its own terms and loses the fail-loud `SystemExit(2)` contract the 93 `load_engine()` call sites rely on. Matches the CALL, not the import: annotating a parameter with `HarnessEngine` is fine |
| U3 | Every SKILL.md declares `metadata.harness.tier` — `primary` (work only an LLM can do), `secondary` (stands in for capability the surrounding tooling doesn't provide), `tertiary` (org-specific island, or not an LLM's job), or `ci` (the harness's own gates). The tier says whether a skill should exist and what investment it earns (`docs/skills.md#tiers`). Takes no exemptions — the fix is one frontmatter line |

## How to fix a failure

**Fix the skill, not the checker.** Adopt the missing convention (the
rule message names it; the canonical definitions live in
`docs/report-structure.md` and `/secure-code-audit`'s pre-scan sections),
create the missing wiring, or repoint the dead reference. Only when the
trigger is genuinely inapplicable — a passing mention, a
deliberately-different architecture — add an `EXEMPTIONS` entry in
python3 -m traust.cli check skill-alignment **with the reason**; exemptions print
on every run so they stay reviewed. An exemption without a defensible
reason is a misalignment with extra steps.

## Enforcement points

- `.githooks/pre-commit` runs this checker on every commit (enable once
  per clone: `git config core.hooksPath .githooks`) — misalignment blocks
  the commit before it exists, unlike the push-time docs/licensing gates.
- `tests/test_check_skill_alignment.py` runs it against the live tree in
  every test run.
- New-skill authoring checklist: run this + `/check-harness-docs` +
  `/check-licensing` before the first commit of any skill.

## Extending the contracts

When a new cross-skill convention is established (the way
`deterministic_steps` or the liveness artifact were), add a rule here in
the same data-driven shape — trigger regex, required co-mentions, scoped
to the files where the convention applies — with fixture tests. A
convention without a rule is a convention that will drift.
