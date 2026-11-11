---
name: check-licensing
description: Use before pushing to the traust repo, after adding or editing any skill, rule pack, doc, or script, or when adopting a new external tool, framework, data feed, or rule pack — runs python3 -m traust.cli check content-licenses to verify no restrictively-licensed framework text has been re-imported (PEACH-adaptation fingerprints, restrictive content-license markers outside the licensing docs, CIS benchmark recommendation-text signatures), and walks the checklist for licensing a NEW external dependency into docs/external-dependencies.md. Use when asked to "check licensing", "run the license check", "did I re-import licensed content", "can we use/ship this tool or ruleset", or "add a license row".
metadata:
  harness.tier: "ci"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash(python3 *traust* -m traust.cli.check_content_licenses:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# Check Licensing

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


The licensing gate for the harness's own tree. Two jobs:

1. **Guard** — verify nothing in the repo re-imports restrictively-licensed
   framework content. Deterministic, zero-judgment, enforced on every push.
2. **Intake** — when the harness adopts a *new* external tool, framework,
   data feed, or rule pack, drive the verification-and-documentation
   checklist so `docs/external-dependencies.md` stays the single source of
   truth.

Background for both: [`docs/external-dependencies.md`](../../docs/external-dependencies.md)
(the verified license inventory and commercialization assessment).

## Job 1 — run the guard

```bash
python3 -m traust.cli check content-licenses
```

Exit `0` = clean. Exit `1` prints each violation with `file:line`. The three
violation classes:

| Class | Meaning |
|---|---|
| NonCommercial marker outside the allowlisted licensing docs | CC-NC-licensed content was re-imported somewhere in the tree (rule 1a) |
| ShareAlike marker outside the allowlisted licensing docs | a CC-BY-SA work arrived with its licence notice attached — i.e. it was pasted in rather than excerpted under the recorded posture (rule 6). BY-SA 3(b) wants a CC ShareAlike Adapter's License; Apache-2.0 is not one. Using a BY-SA skill at runtime is free of obligation; adapting its prose is not. Reimplementing from the ideas in original wording is permitted — BY-SA covers expression, not concepts — so cite the upstream as prior art |
| PEACH-adaptation fingerprint | text from the removed pre-v0.54.2 Wiz-derived tables (or its upstream source) was pasted back in |
| CIS recommendation-text signature | CIS benchmark control text was copied in — the harness cites bare section IDs only |
| Dependency without an intake row | a `pyproject.toml` package (core or any optional group, inline or block form) has no row in `docs/external-dependencies.md` — Job 2 was skipped; run it |

**How to fix: remove or rewrite the flagged text — never edit the guard's
patterns to make it pass.** The rationale for each rule is in
`docs/external-dependencies.md` → *Security frameworks & content licenses*. If a
legitimately-licensing-focused doc needs to name a license, that is what
the guard's ALLOWLIST is for — extending it is a deliberate, reviewed act,
not a fix for a violation.

**Enforcement points** (all must stay wired; verify when touching them):

- `.githooks/pre-push` runs the guard on every push, independently of the
  doc-consistency checker. `git config core.hooksPath .githooks` enables it
  per clone.
- `tests/test_check_content_licenses.py` runs the guard against the live
  tree in every test run.
- This skill runs it on demand.

## Job 2 — license intake for a new external dependency

**Gate-enforced for Python packages since v0.73.2**: adding a dependency
to `pyproject.toml` without its `docs/external-dependencies.md` row fails
the guard (and therefore the push) — the intake below stops being
optional at exactly the moment it used to get forgotten (the sigstore
retroactive intake is the cautionary example). CLI tools, data feeds, and
frameworks remain convention-enforced; add their rows with the same
rigor.

When a skill or script gains a new tool, framework, data feed, or rule
pack:

1. **Verify upstream, never from memory** — read the actual LICENSE file or
   terms page; record the SPDX ID (or terms name) and the evidence URL.
2. **Classify the usage model**, because obligations differ:
   subprocess CLI (weakest obligations) < imported library < **referenced
   content** (framework text, rule packs — binds hardest and is where every
   commercialization blocker so far has lived).
3. **Add the row** to the matching table in `docs/external-dependencies.md`
   (tools / Python / MCP / data feeds / frameworks), with the
   licensing note; a risk tier of Medium or above is recorded in the
   deployment's commercialization assessment (progress-tracker).
4. **Install note** — add the tool to traust-core's shipped `external-tools.yaml` (pin +
   consumers) and to the capability row in `docs/requirements.md` if users
   must install it.
5. **Pin for reproducibility** — version (and data/DB or ruleset SHA) must
   be recordable in `metadata.tools` by the consuming skill.
6. **Extend the guard when a new protected content class enters** — new
   fingerprint phrases or text signatures go into
   python3 -m traust.cli check content-licenses's pattern lists, with matching
   fixture tests.
7. Re-run Job 1 plus python3 -m traust.cli check docs-consistency (the new
   row's paths and any count claims must resolve).

## Job 3 — retirement review (quarterly)

Intake has a gate; exit needs one too, or the tool list only ever grows.
Once a quarter (or when asked "do we have too many tools"), review the
CLI-tools table in `docs/external-dependencies.md` for retirement
candidates:

1. **Usage evidence, two sources per tool.** (a) Is it still invoked by
   any script/skill? — `grep -rl '<tool>' scripts/ harnessing/` (the
   `/check-harness-docs` gate guarantees invoked tools have rows, but
   nothing removes rows when the last invocation goes). (b) Did it
   actually *run* this quarter? — search recent report `metadata.tools`
   entries across the findings trees:
   `grep -rl '"<tool>' ../analysis-results/findings --include='*-security-audit.json' | head`.
2. **Classify each zero-use tool**: *dormant-but-wired* (invocable,
   no recent runs — usually fine: seasonal skills like provisioning),
   *fallback shadowed by a better default* (e.g. second/third LoC
   counter never selected), or *orphaned* (no invocation site remains —
   retire now).
3. **Retire deliberately, not silently**: remove the invocation site (if
   any), the `docs/external-dependencies.md` row, the manifest entry in
   traust-core's shipped `external-tools.yaml`, and the `docs/requirements.md` mention in one commit whose message names the replacement or the reason;
   note the retirement in the *Maintenance* section of
   `docs/external-dependencies.md` so the license history stays
   reconstructable.
4. **Overlap check while you're there**: any two tools claiming the same
   detection role must have a documented decision rule (the
   govulncheck/osv-scanner and opengrep/k8s-scanner precedents) — if the
   rule is missing, either write it or retire the weaker tool.

The review's deliverable is a short verdict per flagged tool (keep /
retire / consolidate), not a mass deletion.

## Constraints

- The guard detects *re-importation of known text shapes*, not novel
  paraphrases — derivative-work judgment on new prose stays with counsel
  (flagged items in `docs/external-dependencies.md`).
- Never vendor an externally-licensed rule pack or framework text into the
  repo; swappable-input patterns (`run_opengrep.py --rules`) exist so that
  never becomes necessary.
