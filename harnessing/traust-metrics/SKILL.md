---
name: traust-metrics
description: Use when the user asks for campaign metrics, a leadership scoreboard, or to rebuild the scoreboard. Composes recorded executive, trend, threat, validation/fuzz, census, insecure-pattern and detection-quality views with separately measured harness checkout maturity.
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
   python3 -m traust.cli dashboard capture scoreboard [--as-of <ISO time>] \
       --note "<counting methodology or change explanation>" \
       --out progress-tracker/metrics/dashboards/scoreboard
   ```

   It writes `traust-metrics.{md,html,json}` and a digest-verified snapshot bundle,
   returning the snapshot's artifact UUID. Numbers the views can't derive render as "-".

2. **Read the source semantics.** Portfolio numbers come from recorded domain state at the requested cutoff, not from parsing rendered dashboards. An absent benchmark answer key is unknown recall, not zero recall. No validation or fuzz run is not evidence of a clean result. Harness maturity is a separate current-checkout measurement with its own timestamp, not a historical audit fact.

   | Old source | Now |
   |---|---|
   | `Executive-summary-findings.metrics.json` sidecar | `ExecutiveSummaryView` (composed) |
   | `census/census.json` | `CensusView` ownership, distinct-exposure and branch-confirmation cuts (composed) |
   | `insecure-patterns/insecure-patterns.json` | `InsecurePatternsView` systemic-pattern cuts (composed) |
   | `benchmark/benchmark.json` | `DetectionQualityService.scorecards`, versioned recall with an audit cutoff; scoped requests explicitly leave fleet recall unavailable |
   | `trends/trends.json` | `FindingsTrendView`, latest bucket (composed) |
   | `Live-validation-fuzz-dashboard.md` and the fuzz campaign sidecar | `ValidationFuzzView`, latest recorded target runs and validation verdicts (composed) |
   | `threat-register/threat-register.md` | `ThreatRegisterView` (composed) |
   | `progress-tracker/tracking/opened-tickets.md` | findings filed in Jira, from the findings' Jira links |
   | cloud-config lane (`findings.db`) | counted in the findings totals (one finding model) |
   | harness repo tree/git metadata | `HarnessMetadataProvider`, registered by the CLI; separate measurement time, unknown fields and limitations retained |

   `/refresh-dashboards` (python3 -m traust.cli dashboard refresh) renders
   the scoreboard with every other view in its `views` stage.

3. **Report back.** Read the generated file and give the user the headline
   numbers grouped as the file groups them (scale, impact, validation, delivery).
   Use `traust dashboard compare <artifact-uuid> --against previous --out <dir>`
   to show changes from the previous reported snapshot in the same scope.
   The first snapshot has no previous report; do not substitute a recomputation.

4. **Manual block (optional).** *Retired:* core rewrites the view on every
   run. If the user supplies narrative claims
   (cost comparisons, remediation stories, the ask), keep them in a file
   beside the scoreboard — never hand-edit generated rows; fix the upstream
   record instead.

## Metrics history — immutable as-reported reports

`dashboard capture` stores the exact JSON, Markdown and no-script HTML exports
(and CSV when available), the current Core version, scope, generation time and required
methodology note through the existing artifact/ObjectStore owner. Each snapshot records
the previous same-scope report's artifact UUID and digest; earlier bundles are never rewritten.
Concurrent captures may share a predecessor; both reports remain archived.

```bash
traust dashboard history scoreboard --out <history-dir>
traust dashboard read-report <artifact-uuid> --out <original-report-dir>
traust dashboard compare <artifact-uuid> --against previous --out <comparison-dir>
traust dashboard compare <artifact-uuid> --against recomputed --out <replay-comparison-dir>
traust dashboard compare <artifact-uuid> --against current --out <current-comparison-dir>
```

History lists snapshots newest first and renders their **saved** values, not replayed
numbers. Repeat the original product/team/category/window options to select the same
history; `as_of` alone does not change that scope. `previous` compares two reported
snapshots. `recomputed` rebuilds at the saved report time with today's code and configuration;
`current` rebuilds now. Neither is the historical reported truth. Latest-only views
reject historical recomputation rather than pretending to support it.

`dashboard view` remains a non-recording preview. Existing legacy
`metrics-history.jsonl` rows stay untouched; never hand-edit, prune or import them
as newly computed history. Describe methodology changes in the capture note.

## Output

`progress-tracker/metrics/dashboards/scoreboard/traust-metrics.{md,html,json}` — About, scale and coverage, findings and impact, empirical validation, delivery, corpus ownership and distinct exposure, systemic patterns, benchmark recall and separately measured harness maturity.

## Notes

- **Deterministic calculation, immutable publication**: no model call produces a number.
  Late ingestion, changed configuration or methodology can change a recomputation;
  a captured report's bytes and numbers do not change.
- Maturity reports the harness VERSION, revision, reachable commits, local release tags, first-party Python physical source lines and AST-defined test functions. These are checkout facts, not executed test results or audit effectiveness. Missing Git/history/tests or denied Git execution remain explicitly unknown; shallow/local-only limitations are rendered. `--as-of` never backdates this measurement.
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
