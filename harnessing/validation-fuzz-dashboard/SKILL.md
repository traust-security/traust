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

1. The verdict × claimed-severity matrix over every recorded validation
   (`verdict` ∈ confirmed / refuted / inconclusive / blocked-by-scope /
   not-attempted).
2. Per-target confirmed counts and the confirmed-Critical finding list.
3. Attack chains with ≥ 1 confirmed step — never the raw mapped-chain count
   (most steps are not-attempted and the raw number misleads).
4. Validation coverage (attempted / total checks), shown as a coverage meter
   so validated and unvalidated populations are never conflated.
5. Each target's latest recorded fuzz run: crashers ranked by CVSS then
   proposed severity, pattern hit-rates, and the surfaces left unfuzzed.

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
| `validation-fuzz/<stem>.html` | Self-contained dashboard: hero (confirmed-exploitable), KPI tiles, verdict-by-severity stacked bars, coverage meter, top-targets bars, fuzz pattern hit-rates, confirmed fuzz-bug and confirmed-Critical tables. |
| `validation-fuzz/<stem>.md` | Markdown one-pager with the same numbers — headline, verdict×severity table, top targets, fuzz hit-rates/bugs, confirmed-Critical list. Paste-ready for docs or Slack. |
| `validation-fuzz/<stem>.json` | The view model (machine-readable). |

The render is deterministic and reads only traust-core's recorded state — re-run
it whenever new validation or fuzz runs are recorded.

## Trends

*Retired:* the run no longer appends `confirmed_exploitable` / `refuted` / `checks_attempted` /
`chains_confirmed` / `fuzz_bugs` (source `validation-fuzz`) to the central
metrics ledger or injects a trend-vs-previous banner (the metrics history is retired; see
[`traust-metrics`](../traust-metrics/SKILL.md)).
