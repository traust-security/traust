# AGENTS.md

> **Canonical file.** `CLAUDE.md` is a symlink to this file for Claude Code compatibility.

This file provides guidance to AI coding agents when working with code in this repository.

## Project Purpose

This is **Traust**, an agent harness for automated vulnerability discovery, validation, and remediation across a software portfolio — source repositories, container images, RPM packages, Kubernetes operators, infrastructure-as-code and the services built from them — at the scale of hundreds or thousands of repositories. Which repositories that is comes from the deployment's inventory (`locations.inputs`), never from this tree; the executive-summary dashboard under the configured `progress-tracker` root reports current coverage.

The harness contains 52 active skills, slash commands, JSON schemas, report tooling, and the prompt engineering that drives autonomous multi-framework security assessments. It is designed to be agent-agnostic, with current implementations for Claude Code and Crush.

## Repository Architecture

### Skills

Every skill lives as a self-contained directory with a `SKILL.md` prompt and optional implementation scripts. This is the single source of truth. The tree has two levels:

- **Workflow skills** sit under their pipeline stage — `harnessing/<N>-<stage>/<name>/`, e.g. `harnessing/4-triage/triage/`. The nine stage directories are ①–⑨ and carry their order in the name.
- **Everything else** (gates, dashboards, graphs, corpus-QA, quarantined skills) stays at `harnessing/<name>/`, because it is not a stage and filing it under one would make the tree lie.

**Never enumerate skills by globbing `harnessing/*/`.** Go through `skill_dirs()` / `skill_dir(name)` in [`src/traust/paths.py`](src/traust/paths.py), which spans both levels; a one-level glob silently finds only the root-level skills. Likewise, look a skill up by name rather than building `harnessing/<name>` from parts.

Agent discovery layers are symlinks, and the name an agent sees stays flat regardless of stage:
- `.claude/skills/<name>` → `../../harnessing/[<N>-<stage>/]<name>` (Claude Code)
- `.crush/skills/<name>` → `../../harnessing/[<N>-<stage>/]<name>` (Crush)
- `.claude/commands/<name>.md` — slash command wrappers (thin files that invoke the skill; they reference `.claude/skills/<name>/SKILL.md`, so they never name a stage)
- `.crush/commands/<name>.md` → `../../.claude/commands/<name>.md`

Regenerate the links with [`bin/link_skills.sh`](bin/link_skills.sh), which walks both levels.

When editing a skill, always edit the file under `harnessing/`. Never create a separate copy in `.claude/skills/` or `.crush/skills/`.

### Scripts

Multi-skill CLIs live in `src/traust/cli/` and are invoked as `traust <group> <op>` (or `python3 -m traust.cli <group> <op>` from the harness venv) — see [docs/cli-reference.md](docs/cli-reference.md). Each module also still answers to `python3 -m traust.cli.<module>` via its `__main__` delegate, but the grouped form is what docs and skills use. Ops live under `src/traust/ops/`; `src/traust/migrations/` is only for migrations an ADOPTER runs (see the placement rule below) — deployment-specific one-shots belong in the deployment's own private repo. Single-skill CLIs are co-located under `harnessing/<skill>/scripts/`.

## Script placement rule

- Single-skill CLI: the skill's own `scripts/` (co-located with SKILL.md, so under the stage directory for a workflow skill)
- Multi-skill CLI: `src/traust/cli/` (installed package)
- Shared library (>=3 importers): `src/traust/lib/`
- Ops: `src/traust/ops/`
- **Migrations: `src/traust/migrations/` is for migrations an ADOPTER runs**
  — a schema upgrade path shipped with a release, declared with an
  `adopter-portable: <why>` line in its docstring. A one-shot that cleans
  up THIS deployment's data is not that: an adopter installing today has
  no old shape to migrate from, so there is nothing in it they can run.
  Those go in the deployment's own private repository
  (`traust-internal/migrations/`), and the measured counts go WITH them —
  move, never scrub, because the figures are the record of what the
  script did. `traust check estate-data` enforces both rules pre-commit.

`validate_report`, `render_report`, `checkpoint`, `countersign`, `emit_triage_ledger_events`, `emit_validation_ledger_events`, and related tooling are package modules (many in sibling `traust-engine`). Skills invoke them via python3 -m … from the harness venv. The citation gate and symbol index are triage accelerators — they route, gate, tag, or index, and never author a verdict (see [`docs/deterministic-inferential-mix.md`](docs/deterministic-inferential-mix.md)).

Legacy placement (pre-C8):
- Used by exactly one skill: place under `harnessing/<skill>/`
- Invoked by 2+ skills as a CLI: place under `src/traust/cli/`
- Imported as a module by 3+ callers: shared library under `src/traust/lib/` or `traust-engine`
- Ops/cron only (no skill references): `src/traust/ops/`
- One-shot migrations/backfills for THIS deployment: the private `traust-internal/migrations/`, with a dated header. This repo is public.

### Metrics consistency layer

`$TRAUST_CONFIG_HOME/corpus-config.yaml` (ownership tags per output tree; write only
via `/corpus-intake`) + `traust_engine.corpus.resolver` (shared discovery/identity/
dedup resolver) + `/census` (denominator authority: population,
duplication vectors, distinct-vulnerabilities headline, repo liveness)
keep every dashboard's numbers reconcilable. Dashboards embed a standard
population block and label metrics by the three-lens taxonomy (work
performed / distinct exposure / systemic patterns — see PROCESS.md).
When adding a dashboard or changing what one counts, build on corpus.py
and state the population block — never hand-roll a walker.

### Sibling repositories

The agent runs from a parent workspace with three sibling trees (the inputs inventory, `analysis-results/`, `progress-tracker/` — all resolved through `locations.yaml`). Skills reference siblings by relative path. See [docs/setup.md](docs/setup.md) for the full workspace layout.

### Deployment configuration vs shipped configuration

`config/` in this repo ships **only** estate-neutral files (`external-tools.yaml`,
`feeds.yaml`, `model-registry.yaml`) plus a `*.example.*` template for every
deployment-specific file. The real corpus registry, product map, budget policy,
safe-exec profiles, rule-pack allowlist, hardening weights, dist-git watch list,
internal vocabulary and ledger signing key live in the directory named by
**`TRAUST_CONFIG_HOME`** (default `~/.traust/config`; a deployment usually points it
at its own private configuration repository, set by the orchestrator). `scripts/install_traust`
creates that directory from the templates and is the documented starting point;
`install_traust --doctor` checks it. Resolve every such file through
`config_path("<name>")` from `traust.paths` (or
`traust_contracts`) — never `HARNESS_ROOT / "config" / …`. It raises
`DeploymentConfigMissing` rather than falling back to a template. traust-engine
ships no config files at all. The docs gate fails when anything else lands in
`config/` or a shipped file carries estate markers. Full contract:
[config/README.md](config/README.md).

### Python dependencies (sibling repos)

Installed via `pyproject.toml` / `[tool.uv.sources]`. Edit these repos when
changing shared scanners, ledger logic, or schemas — not only this tree.

| Package | Repo |
|---|---|
| **traust-engine** | sibling repository `traust-engine` |
| **traust-ledger** | sibling repository `traust-ledger` |
| **traust-contracts** | sibling repository `traust-contracts` |
| **traust-core** | sibling repository `traust-core` |

**Pins live only in `pyproject.toml`** — do not duplicate shas/version tags in docs.
`[tool.uv.sources]` pins by commit `rev`, not `tag`: a tag requires a release
cut first, a commit doesn't, so this repo can pick up a contracts/ledger/engine
change as soon as it merges upstream instead of waiting on a tagged release.
`dependencies` carries the bare package name with no floor — the `rev` is the
floor now; a duplicated semver constraint is just a second number that can
drift out of sync with the pin.

After contracts, ledger, or engine merges a change you depend on: bump the
`rev` here to that commit, `uv lock`, run the full test suite, then open a
PR. `/drift-watch` compares installed versions to those pins.

### Running the tests

**pytest is the only test runner**: `.venv/bin/python -m pytest tests/` (or `python -m pytest tests/` inside the venv). Do NOT use python3 -m unittest discover — a substantial share of the suite (~30%, spread across many modules — [`tests/test_scope.py`](tests/test_scope.py), [`tests/test_validate_findings.py`](tests/test_validate_findings.py), the gate/ledger regression files, and more) is pytest-native and silently errors out of a unittest run, hiding real failures. pytest runs the stdlib-unittest modules natively, so one invocation covers everything. A clean run shows zero errors; treat any error as a real failure, never ambient noise.

### Adding a new skill

1. Decide where it goes: a pipeline stage → `harnessing/<N>-<stage>/<name>/SKILL.md`; anything else → `harnessing/<name>/SKILL.md`. Create it there with the skill prompt.
2. Add implementation scripts alongside `SKILL.md` if needed
3. Link it for both agents by running [`bin/link_skills.sh`](bin/link_skills.sh) (it walks both levels and names the link after the skill, not the stage)
4. Optionally add a slash command: create `.claude/commands/<name>.md` and symlink `.crush/commands/<name>.md → ../../.claude/commands/<name>.md`
5. **Wire the integrations.** Diff the new skill's inputs/outputs against the rest of the harness: for every artifact it emits, either wire a consumer (and reference the producer from the consuming skill) or record why it is terminal; for every artifact it consumes, name the producer. Document the result in an `## Integrations` section in the SKILL.md — python3 -m traust.cli check skill-alignment (rules A9/A10, pre-commit) enforces both, and an unwired artifact is a gate failure, not a style nit. The under-wired launches of operator-priv-profile and impact-analysis are the failure mode this step exists to prevent.

## Security Testing Context

All security testing code and tools in this repository are used for:
- Authorized security assessments of repositories the deploying organisation owns or has permission to assess
- Live validation against clusters the deploying organisation controls, with explicit authorization
- Defensive security tool development
- Security research in controlled environments

When developing security tools:
- Assume all testing is against authorized targets with explicit permission
- Implement safety controls (e.g., scope validation via [`harnessing/5-validate/validate-findings/scope.py`](harnessing/5-validate/validate-findings/scope.py) and [`harnessing/5-validate/validate-browser-finding/scripts/scope.py`](harnessing/5-validate/validate-browser-finding/scripts/scope.py))
- Avoid techniques designed solely for detection evasion in production environments

### Running validate-browser-finding

```bash
cd harnessing/5-validate/validate-browser-finding
python run.py <validation-dir> [--destructive] [--out <dir>]
```

Requires root deps (`pip install -r requirements.txt`, includes Playwright) and either a remote Playwright WS endpoint or local Chromium (`playwright install chromium`). Scope is fail-closed: every step needs a resolvable URL and an explicit `allowed_verbs` list on the matching browser target. Reports land next to the validation dir (`*-validation.json`, `validation-audit.jsonl`, `artifacts/`).

When building or modifying agent skills:
- Design agents to operate within defined scopes and constraints
- Implement clear logging and audit trails for all agent actions
- Build in safeguards against unintended target expansion
- Validate that tools respect scope limitations and authorization boundaries

## Model routing & spend (read before hardcoding any model ID)

Never hardcode a model identifier in a skill or script — alignment rule
A12 fails the commit. Name a tier class and resolve via
python3 -m traust.cli registry models resolve <role>; stamp routed
decisions into `metadata.additional.model_routing`; record batch spend
with `model_registry.py spend`. Spend is also collected automatically
from session transcripts and dashboarded — the whole contract, including
the real-time view (python3 -m traust.cli metrics collect-spend), is in
[docs/model-routing.md](docs/model-routing.md).

## Versioning

The harness is versioned via the `VERSION` file at the repository root using semantic versioning (`MAJOR.MINOR.PATCH`). Every report produced by the harness must embed the current harness version in `metadata.harness_version` so that report quality can be traced back to a specific harness revision.

The `VERSION` file contains only the semver (e.g., `0.1.0`). At report time, skills append the short git SHA of the harness repo to produce the full version string (e.g., `0.1.0-4dd9796`). This keeps the file stable across commits while still pinning every report to an exact revision.

Bump the version when:
- **PATCH**: Bug fixes or minor wording changes to skills or prompts
- **MINOR**: New skills, new report sections, or changes to audit methodology
- **MAJOR**: Breaking changes to report format, schema, or validation

Tag each release: `git tag v$(cat VERSION)`.

### Dashboards

Changes to report schemas, finding disposition states, or metrics computed by skills like `track-findings`, `findings-trends`, `executive-summary-findings`, `loc-dashboard`, or `validation-fuzz-dashboard` can silently break or invalidate what those dashboards render. When you change the harness in a way that could affect a dashboard's inputs or assumptions, rebuild the affected dashboards with `/refresh-dashboards` (python3 -m traust.cli dashboard refresh — per-stage via `--only`); `/drift-watch`'s `dashboards:*` rows are the staleness backstop. Emitters that place untrusted text in dashboard output use `traust_engine.escaping` (see Code Standards).

## Documentation upkeep

The 2026-07-25 docs-verification sweep (report:
`progress-tracker/gap-assessments/docs-verification-2026-07-25.md`) found ~60
discrepancies that had accumulated over ~150 releases. Four conventions,
three of them mechanically enforced, keep that from recurring:

- **Skill changes update the reference in the same commit.** A staged
  `harnessing/*/SKILL.md` change must ship with a staged [`docs/skills.md`](docs/skills.md)
  update (alignment rule **A13**, pre-commit). Genuinely doc-irrelevant
  changes (typos, comments) are waived with
  `SKILLS_DOC_WAIVER=<reason> git commit ...`.
- **Enum lists live in one place.** Docs must not restate schema enums —
  link [`docs/report-structure.md`](docs/report-structure.md) or the schema. A doc line that names an
  enum-bearing field and quotes 3+ of its values but not all of them fails
  the doc gate (partial-enum check).
- **Assessments are dated snapshots.** Any `docs/*assessment*.md`,
  `*draft*.md`, or `*comparison*.md` must carry a dated as-of banner
  ("as of / snapshot / assessed at" + a YYYY-MM date); Status columns in
  such docs are point-in-time, never live (doc gate enforces the banner).
- **Quarterly semantic sweep.** The mechanical gates catch counts, links,
  CLI flags, and enums — not behavioral claims. Those are bounded by a
  quarterly reviewer sweep (procedure in the check-harness-docs SKILL);
  `/drift-watch` flags the sweep as stale after 92 days.

## Code Standards

- Security tools should validate their target scope before execution
- Include usage examples that demonstrate authorized testing scenarios
- Document any dependencies on external security frameworks or tools
- Consider operational security when handling credentials or sensitive findings
- **Untrusted text never reaches an emitter raw** — finding titles, repo/
  team names, URLs, and anything quoted from an audited repository must
  pass through `traust_engine.escaping` before landing in generated HTML
  (`esc_html`), inline `<script>` JSON (`json_script`), Markdown table
  cells (`md_cell`), fenced blocks (`fence_untrusted`), CSV cells
  (`csv_cell`), or path/API segments (`safe_slug`). One sibling having
  the control while its neighbor lacks it was the measured failure shape
  (assessment 2026-07-31 root cause 4) — import the shared helpers, do
  not re-implement them locally
- **Never put an Authorization header (or any secret) in curl argv** — argv
  is ps-visible to every local user. Pipe `header = "Authorization: …"` to
  `curl --config -` on stdin (enforced by check_skill_security rule S5)
- **Insecure-TLS flags (`curl -sk`, `--insecure`) are lab-target-only** —
  acceptable against disposable/self-signed validation clusters named in a
  ROE targets file, never against production or external endpoints
- **Target-derived commands run through the safe_exec sandbox** — build
  systems, test suites, and scanners that load code from an audited
  checkout are hostile-input execution; route them through
  python3 -m traust.cli util safe-exec with a profile from
  `$TRAUST_CONFIG_HOME/safe-exec-profiles.yaml` (gate rule S10 blocks bare
  invocations). Headless agents additionally run under repo-config
  isolation — cwd outside the checkout, repo `.claude/`/`CLAUDE.md`
  never loaded as config (rule S9). Full contract: [docs/safe-exec.md](docs/safe-exec.md)
- Git commands on non-literal URLs set `GIT_ALLOW_PROTOCOL=https` and gate
  the URL to `^https://` (rule S3); runtime installs pin exact versions
  (rule S7); state/credential files live in per-user 0700 dirs, never
  fixed `/tmp` names (rule S6)
