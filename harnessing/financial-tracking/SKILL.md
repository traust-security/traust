---
name: financial-tracking
description: Use when the user asks what the campaign or harness is costing, how spend is trending, which business unit a cost lands on, cost per finding or per repo, whether spend is on budget, or asks to capture/refresh financial tracking over time — e.g. "what did July cost", "spend by business unit", "are we over budget", "cost per critical", "is spend going up", "refresh the financial report". Runs the deterministic spend chain (session actuals → per-lane attribution → business-unit bridge → unit economics → trend) and reports estimates that are always labelled as estimates, with an --invoice seam for reconciling against real billing.
argument-hint: "[report|capture|bu|reconcile] [--month YYYY-MM] [--months N] [--invoice <csv>]"
metadata:
  harness.tier: "tertiary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - AskUserQuestion
  # Anchored to the harness tree on purpose: a bare `*<name>.py`
  # pattern also matches a same-named script planted in an audited
  # checkout (alignment rule A14).
  - Bash(python3 *traust* -m traust.cli metrics collect-spend:*)
  - Bash(python3 *traust* -m traust.cli metrics attribute-spend:*)
  - Bash(python3 *traust/harnessing/financial-tracking/scripts/build_financial_report.py*)
  - Bash(python3 *traust* -m traust.cli metrics spend:*)
  - Bash(python3 *traust* -m traust.cli metrics history:*)
  - Bash(python3 *traust* -m traust.cli registry models:*)
---

# Financial tracking

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Answers the questions a budget owner asks — what did it cost, whose
budget, is it going up, what did a finding cost — from data the harness
already collects. This skill **orchestrates and interprets**; it owns no
new source of truth.

## Step 0 — the honesty preamble (never skip)

Every figure this skill produces is a **list-price estimate**, not an
invoiced actual. Two limits must appear in anything you hand to a human:

1. **At least one rate is unverified.** `config/model-registry.yaml`
   flags some models as not on the published rate card (a trailing
   `price unverified` comment), and as of 2026-08 the affected
   opus-class model carries most campaign spend. Never hardcode which
   one — `build_financial_report.py` reads the current set from the
   registry and prints it. Do not strip that line when summarising.
2. **Business-unit coverage is partial.** Spend carries no BU tag
   anywhere, so it is bridged from the findings tree a session touched.
   Measured 2026-08-06: ~35% of period cost resolves to a BU; the rest
   is `bu-unknown`. Never redistribute the unknown remainder across
   known BUs to make a chart total 100% — quote the coverage figure.

If asked for a number without context, give the number **and** which of
these apply. A confident unqualified figure is the failure mode here.

## Modes

| Token | Does |
|---|---|
| `report` (default) | Build the period report: cost, unit economics, trend |
| `capture` | Refresh the underlying data first, then report |
| `bu` | Report including the business-unit split (slower — walks transcripts) |
| `reconcile` | Compare estimates against a supplied invoice CSV |

### report

```bash
python3 harnessing/financial-tracking/scripts/build_financial_report.py --month <YYYY-MM> --months 6
```
Reads the metrics ledger only (fast, no transcript walk). Add
`--out <path>` to write Markdown, `--json` for the structured form.

### capture — refresh, then report

Run in order; each is deterministic and idempotent:

```bash
# 1. session actuals -> ledger (completed days only)
python3 -m traust.cli metrics collect-spend --append

# 2. per-lane attribution -> ledger (spend-attribution:<skill>)
python3 -m traust.cli metrics attribute-spend --append

# 3. prove the attribution split lost nothing
python3 -m traust.cli metrics attribute-spend --reconcile   # exit 1 = mismatch

# 4. report
python3 harnessing/financial-tracking/scripts/build_financial_report.py --months 6
```

Step 3 is a gate, not a formality: a non-zero exit means tokens were
dropped between the collector and the attribution split, and any
downstream figure is untrustworthy. Stop and say so.

### bu — business-unit split

```bash
python3 harnessing/financial-tracking/scripts/build_financial_report.py --month <YYYY-MM> --by-bu
```

Walks the transcripts (~30s over the current corpus). The BU comes from
`findings.db`'s `business_unit` column, which is sourced from
`$TRAUST_CONFIG_HOME/corpus-config.yaml` — the metrics-accounting taxonomy. That is
exactly what it is for; note that the same tags are explicitly **not** a
risk signal and play no role in routing or ceilings
(docs/continuous-operations.md, operator directive 2026-07-27).

**Reading the output correctly:** the BU table and the per-lane table
partition the *same* total along *different* axes. A session can touch a
BU's tree without invoking a skill, or run a skill against no tree. The
rows will not reconcile against each other, and that is not an error.

### reconcile — check estimates against reality

```bash
python3 harnessing/financial-tracking/scripts/build_financial_report.py --month <YYYY-MM> \
    --invoice <path.csv>
```
CSV columns: `period,amount_usd[,note]` where `period` is `YYYY-MM`.
The report then shows estimate vs invoiced vs variance. Until an invoice
is supplied, say plainly that nothing has been checked against billing.

## Budget posture — what is and is not enforced

Do not imply spend is being controlled. As of 2026-08-06:

- `$TRAUST_CONFIG_HOME/budget-policy.yaml` runs `enforcement: observe` — every weekly
  tranche computes a budget verdict, records it, and **withholds
  nothing** (traust.cli.budget_shadow).
- The only lane the router can ever drop is a full audit, and only when
  enforcement is `advisory`/`enforced`.
- `--monthly-budget` on the router is the sole live gating knob.

To answer "are we over budget": compare the period's **lane** subtotal
(not the workstation total) against `monthly_budget.usd_central`. The
ceiling was derived for steady-state scanning, so judging it against
total workstation spend overstates the overage by a multiple — the
workstation figure carries every session on the machine, lane
attribution does not.

Recorded verdicts accumulate under `budget-shadow` in the ledger — count
them to answer "how often would the cap have bound".

## Unit economics — the denominator trap

`usd_per_finding` and `usd_per_repo` divide **one period's** spend by an
**all-time** corpus count, so they understate true unit cost. State that
whenever you quote them. `/census` remains the denominator authority for
any published coverage claim; these are internal cost ratios, not
coverage metrics.

## Cadence

Monthly is the natural period, matching the budget. `capture` is safe to
run any time — both append steps skip the current (incomplete) day, so
re-running never double-counts and never freezes a partial day.

## Integrations

**Consumes:** Claude Code session transcripts (via
`collect_session_spend.py` / `attribute_session_spend.py`); the
hash-chained metrics ledger (`spend-attribution:*`, `budget-shadow`,
`model-spend:*`); `analysis-results/graph/findings.db` (`business_unit`,
finding and repo counts); `config/model-registry.yaml` (prices);
`$TRAUST_CONFIG_HOME/budget-policy.yaml` (ceiling and enforcement posture);
optionally an operator-supplied invoice CSV.

**Emits:** a Markdown/JSON financial report (default stdout; `--out` to
persist). Terminal by design — it is a reporting view over existing
artifacts and introduces no new campaign artifact for another skill to
consume. The per-lane numbers it reads are the same ones
`build_spend_dashboard.py` renders, so the two cannot disagree.

**Related:** `/refresh-dashboards` rebuilds the spend dashboard;
`/drift-watch` flags stale spend data; the budget-guard phases are
tracked in
`progress-tracker/plans/budget-guard-widening-plan.md`.
