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
  - Bash(python3 *traust* -m traust.cli dashboard view spend:*)
  - Bash(python3 *traust* -m traust.cli registry models:*)
---

# Financial tracking

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
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
   one — the spend view reads the current set from the
   registry and prints it. Do not strip that line when summarising.
2. **Business-unit coverage is partial.** Spend carries no BU tag
   anywhere, so it is bridged from the run order it was recorded against
   (repository → product → corpus registry); workstation sessions have no
   order. The view states the share of period cost that resolves to a BU;
   the rest is `unattributed`. Never redistribute the unknown remainder across
   known BUs to make a chart total 100% — quote the coverage figure.

If asked for a number without context, give the number **and** which of
these apply. A confident unqualified figure is the failure mode here.

## Modes

| Token | Does |
|---|---|
| `report` (default) | Build the period report: cost, unit economics, trend |
| `capture` | Refresh the underlying data first, then report |
| `bu` | Report including the business-unit split |
| `reconcile` | Compare estimates against a supplied invoice CSV |

### report

```bash
python3 -m traust.cli dashboard view spend --since <first of the month 5 months back, e.g. 2026-05-01T00:00:00Z> \
    --until <first of the month after <YYYY-MM>> --out <dir>
```
Reads traust-core's recorded spend (fast, no transcript walk). Writes
`spend.md` (and `.html`) under `--out`; `spend.json` is the structured form.

### capture — refresh, then report

Run in order; each is deterministic and idempotent:

```bash
# 1. session actuals -> traust-core (completed days only)
python3 -m traust.cli metrics collect-spend --append

# 2. per-lane attribution (step 1 records spend per skill; nothing to append)

# 3. prove the attribution split lost nothing
python3 -m traust.cli metrics attribute-spend --reconcile   # exit 1 = mismatch

# 4. report
python3 -m traust.cli dashboard view spend --since <...> --until <...> --out <dir>
```

Step 3 is a gate, not a formality: a non-zero exit means recorded spend
does not split losslessly by skill, and any
downstream figure is untrustworthy. Stop and say so.

### bu — business-unit split

```bash
python3 -m traust.cli dashboard view spend --since <...> --until <...> --out <dir>
```

The spend view carries the split. The BU comes from the corpus registry's
`business_unit` for the products shipping the run order's repository,
which is sourced from corpus intake — the metrics-accounting taxonomy. That is
exactly what it is for; note that the same tags are explicitly **not** a
risk signal and play no role in routing or ceilings
(docs/continuous-operations.md, operator directive 2026-07-27).

**Reading the output correctly:** the BU table and the per-lane table
partition the *same* total along *different* axes. An order can carry a
BU's repository without a skill, or a skill can run with no order. The
rows will not reconcile against each other, and that is not an error.

### reconcile — check estimates against reality

```bash
python3 -m traust.cli dashboard view spend --since <...> --until <...> \
    --invoice <path.csv> --out <dir>
```
CSV columns: `period,amount_usd[,note]` where `period` is `YYYY-MM`.
The report then shows estimate vs invoiced vs variance. Until an invoice
is supplied, say plainly that nothing has been checked against billing.

## Budget posture — what is and is not enforced

Do not imply spend is being controlled. As of 2026-08-06:

- `budgets` in `$TRAUST_CONFIG_HOME/traust.yaml` run `enforcement: observe` — every planned
  order gets a budget verdict, recorded in its run manifest, and **withholds
  nothing** (traust-engine's admission).
- The only lane the router can ever drop is a full audit, and only when
  enforcement is `advisory`/`enforced`.
- `--monthly-budget` on the router is the sole live gating knob.

To answer "are we over budget": compare the period's **lane** subtotal
(not the workstation total) against `monthly_budget.usd_central`. The
ceiling was derived for steady-state scanning, so judging it against
total workstation spend overstates the overage by a multiple — the
workstation figure carries every session on the machine, lane
attribution does not.

Recorded verdicts accumulate in the orders' run manifests (`budget`) — count
them to answer "how often would the cap have bound".

## Unit economics — the denominator trap

`cost per finding` and `cost per repository` divide **one period's** spend by an
**all-time** corpus count, so they understate true unit cost. State that
whenever you quote them. `/census` remains the denominator authority for
any published coverage claim; these are internal cost ratios, not
coverage metrics.

## Cadence

Monthly is the natural period, matching the budget. `capture` is safe to
run any time — the append step skips the current (incomplete) day, so
re-running never double-counts and never freezes a partial day.

## Integrations

**Consumes:** Claude Code workstation session transcripts (via
`metrics collect-spend`; runner sessions settle against their order instead); traust-core's spend events (per skill, lane
and run order); run manifests' budget verdicts; the corpus registry (`business_unit`)
and the portfolio's finding and repo counts; `config/model-registry.yaml` (prices);
`budgets` in `$TRAUST_CONFIG_HOME/traust.yaml` (ceiling and enforcement posture);
optionally an operator-supplied invoice CSV.

**Emits:** the spend view, `spend.{md,html,json}` under `--out`.
Terminal by design — it is a reporting view over existing
artifacts and introduces no new campaign artifact for another skill to
consume. The per-lane numbers it reads are the same ones
the program view (`dashboard view program`) renders, so the two cannot disagree.

**Related:** `/refresh-dashboards` (*retired:* its spend-dashboard stage; the spend view replaces it);
`/drift-watch` flags stale spend data; the budget-guard phases are
tracked in
`progress-tracker/plans/budget-guard-widening-plan.md`.
