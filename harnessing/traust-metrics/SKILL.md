---
name: traust-metrics
description: Use when the user asks for campaign metrics, a leadership scoreboard, or to (re)build/refresh progress-tracker/metrics/dashboards/scoreboard/traust-metrics.md. Deterministically harvests headline numbers from traust-core's executive summary, findings trend and threat register views into one consistently-updatable Markdown scoreboard.
metadata:
  harness.tier: "secondary"
---

# Traust Metrics

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Maintain one Markdown scoreboard — `progress-tracker/metrics/dashboards/scoreboard/traust-metrics.md` —
holding every number the team quotes in leadership decks and
status reports, so those numbers are regenerated from the pipeline's own
artifacts instead of being copied around and going stale.

The skill never authors a metric. traust-core's `ScoreboardView` reads each value
off the views it composes (executive summary, findings trend, threat register)
and names them in its About section; anything it cannot derive renders as "-".
*Retired:* the data-freshness table (the views read recorded state, so nothing
is stale) and the manual block (core rewrites the view; keep narrative claims
in a file beside it).

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| `--workspace-root <dir>` | *Retired:* the view reads traust-core, not the workspace |
| `--out <dir>` | Output folder (default: `progress-tracker/metrics/dashboards/scoreboard`) |
| `--refresh-sources` | *Retired:* the composed views are built live (see step 2) |

## Procedure

1. **Run the collector:**

   ```bash
   python3 -m traust.cli dashboard view scoreboard [--as-of <ISO time>] \
       --out progress-tracker/metrics/dashboards/scoreboard
   ```

   It writes `traust-metrics.{md,html,json}`; numbers the views can't
   derive render as "-".

2. **Check the Data freshness table** — *retired:* the scoreboard reads
   traust-core's views live, so no source can be stale or missing. Was: each
   source row showed the artifact's own `Generated:` date and stale sources
   were rebuilt with their owning skill first. What each old source became:

   | Old source | Now |
   |---|---|
   | `Executive-summary-findings.metrics.json` sidecar | `ExecutiveSummaryView` (composed) |
   | `census/census.json` | *retired:* ownership cuts and branch confirmations (scope is product/team; one finding per repository) |
   | `insecure-patterns/insecure-patterns.json` | not on the scoreboard (insecure-patterns has its own view port) |
   | `benchmark/benchmark.json` | not on the scoreboard (a `/recall-benchmark` campaign artifact; report it from there) |
   | `trends/trends.json` | `FindingsTrendView`, latest bucket (composed) |
   | `Live-validation-fuzz-dashboard.md` and the fuzz campaign sidecar | not yet: the validation-fuzz view waits on `ValidationService.summary` |
   | `threat-register/threat-register.md` | `ThreatRegisterView` (composed) |
   | `progress-tracker/tracking/opened-tickets.md` | findings filed in Jira, from the findings' Jira links |
   | cloud-config lane (`findings.db`) | counted in the findings totals (one finding model) |
   | harness repo tree/git metadata | *retired:* not portfolio data; the traust-core version is stamped in About |

   `/refresh-dashboards` (python3 -m traust.cli dashboard refresh) renders
   the scoreboard with every other view in its `views` stage.

3. **Report back.** Read the generated file and give the user the headline
   numbers grouped as the file groups them (scale, impact, validation,
   delivery), calling out any metric that moved
   sharply since the previous version of the file (use `git -C
   progress-tracker diff traust-metrics.md` when the file is tracked, or
   build the view at an earlier `--as-of`).

4. **Manual block (optional).** *Retired:* core rewrites the view on every
   run. If the user supplies narrative claims
   (cost comparisons, remediation stories, the ask), keep them in a file
   beside the scoreboard — never hand-edit generated rows; fix the upstream
   record instead.

## Metrics history — the append-only improvement ledger

*Retired:* the collector no longer appends a snapshot row to
`progress-tracker/metrics/metrics-history.jsonl` or renders
`metrics/metrics-history.md` (`--note` and `--no-history` are gone).
traust-core records every finding and decision with its time, so a past
number is the view built at an earlier `as_of` (`/findings-trends`,
`traust dashboard view … --as-of`). Rows already in the JSONL stay as they
are; never hand-edit or prune them. When a run follows a methodology or
pipeline change, say so when you report the numbers.

## Output

`progress-tracker/metrics/dashboards/scoreboard/traust-metrics.{md,html,json}` — sections: About · Scale & coverage ·
Findings & impact · Empirical validation · Delivery & adoption.

## Notes

- **Deterministic at metric time**: like the dashboards, this skill only
  replays recorded state — no model call participates in producing
  a number, so reruns are reproducible and diffs are meaningful.
- *Retired:* the maturity metrics (version, commits, releases, LoC, test
  count) counted from the harness checkout; About stamps the traust-core version.
- Severity counts quote the executive summary's totals (each finding once).

## Spend metrics (separate dashboard, not harvested here)

The scoreboard does **not** read spend data and the scoreboard carries
no spend section — spend lives in its own dashboard
(python3 -m traust.cli dashboard view spend; *retired:* the legacy
`progress-tracker/metrics/dashboards/spend/` dashboard and its `/refresh-dashboards` stage).
An earlier revision of this skill claimed the scoreboard harvested
`model-spend:*` ledger rows; no such code ever existed
(docs-verification 2026-07-31, wiring c5). When reporting scoreboard
numbers, point spend questions at the spend dashboard; treat a
>7-day-old spend dashboard as stale and rebuild via
`/refresh-dashboards`. Real-time view and the full tracking chain live in your
deployment's private configuration repository, if it keeps one.
