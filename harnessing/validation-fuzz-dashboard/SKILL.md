---
name: validation-fuzz-dashboard
description: Use when the user asks for a live-validation dashboard, fuzzing-results dashboard, validation coverage roll-up, or "how many findings were confirmed exploitable / refuted" — e.g. "build the validation dashboard", "combine validation and fuzz results", "what did live validation confirm", "validation false-positive rate". Renders traust-core's validation-fuzz view from recorded validation and fuzz runs into a self-contained dashboard (md/html/json).
metadata:
  harness.tier: "secondary"
---

# Live Validation & Fuzzing — Portfolio Dashboard

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Roll up every live-validation report (verdicts rendered against static-audit
findings in real environments) and the offline fuzz campaign into a single
self-contained dashboard: confirmed-exploitable hero number, verdict share
by claimed severity, validation coverage, top targets by confirmed findings,
attack chains with a confirmed step, fuzz pattern hit-rates, and the confirmed
fuzz-bug table.

The dashboard is traust-core's `validation-fuzz` insight view: core builds it
from recorded validation and fuzz runs (`ValidationService`), renders it, and
writes nothing — the command below saves the render.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Standard run — render the view over the whole portfolio, write it. |
| `--product <slug>` / `--team-id <uuid>` | Scope the view to a product or team (repeatable). |
| `open` | Open the resulting HTML in the default browser when done. |
| `summary` | After building, print verdict totals and top-5 targets to the conversation. |

---

## Procedure

### Step 1 — Render the view

```bash
traust dashboard view validation-fuzz \
    --out progress-tracker/metrics/dashboards [--product <slug>] [--team-id <uuid>]
```

Core writes `<out>/validation-fuzz/<stem>.{md,html,json}` (markdown, a
self-contained HTML render, and the view model as JSON). `traust dashboard
refresh` rebuilds this view alongside every other deterministic dashboard.

What the view shows (core computes these from recorded state):

1. Claimed-severity × verified-outcome matrix over every bound recorded validation
   finding-check, using recording-policy outcomes rather than severity as proof.
   Original declared verdicts, soundness flags, evidence grades and artifact IDs
   remain available in the JSON/check-detail table.
2. Per-repository/target-environment attempted, total and confirmed checks, plus
   the confirmed checks claiming Critical (not a declaration of verified severity).
3. Every mapped attack chain and its steps, narrative, entry point, terminal asset,
   ATT&CK references and report references. Confirmed-step counts do not imply that
   the complete chain is confirmed; invalid target environments are excluded from
   observed exploitation evidence.
4. Attempted / total finding-check coverage and a population block. Repeated runs
   are work observations, distinct from the latest-verdict-per-finding summary.
5. Each target's latest recorded fuzz run: ranked crashers with CVSS vectors,
   declared analyst narrative/fix/priority and negative-control references,
   reproducer locations, explicit batch and tested-pattern counts, and gaps.
   Prior executions and supplied historical campaign snapshots are separate
   tables; missing pattern outcomes do not become negative results. Import
   supplied historical summaries with `traust reporting import-fuzz-campaign`
   (see [create-fuzzing](../6-fuzz/create-fuzzing/SKILL.md#6-report-batch-mode)).

### Step 2 — Report back

Always tell the user:

- The output paths (HTML + Markdown + JSON).
- Headline numbers: validations recorded, confirmed / refuted / inconclusive /
  blocked totals, confirmed-Critical count, coverage %, fuzz bugs confirmed.
- The top 3 targets by confirmed findings.

If `summary` was requested, also print the verdict-by-severity table.
If `open` was requested, open the HTML in the default browser.

---

## Outputs

| File | Purpose |
|---|---|
| `validation-fuzz/<stem>.html` | Self-contained report: population, claimed-severity/outcome matrix, check coverage, target checks, confirmed-Critical checks, chain steps and fuzz evidence tables. |
| `validation-fuzz/<stem>.md` | Markdown report with the same model-backed tables and provenance. |
| `validation-fuzz/<stem>.json` | The view model (machine-readable). |

The render is deterministic and reads only traust-core's recorded state — re-run
it whenever new validation or fuzz runs are recorded.

## Trends

*Retired:* the run no longer appends `confirmed_exploitable` / `refuted` / `checks_attempted` /
`chains_confirmed` / `fuzz_bugs` (source `validation-fuzz`) to the central
metrics ledger or injects a trend-vs-previous banner (the metrics history is retired; see
[`traust-metrics`](../traust-metrics/SKILL.md)).
