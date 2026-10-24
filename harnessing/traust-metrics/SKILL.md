---
name: traust-metrics
description: Use when the user asks for campaign metrics, a leadership scoreboard, or to (re)build/refresh progress-tracker/metrics/traust-metrics.md. Deterministically harvests headline numbers from the campaign's derived artifacts (executive summary, validation/fuzz dashboard, threat register, progress-tracker control files) and the harness's own tree/git metadata into one consistently-updatable Markdown scoreboard.
metadata:
  harness.tier: "secondary"
---

# Traust Metrics

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Maintain one Markdown scoreboard — `progress-tracker/metrics/traust-metrics.md` —
holding every number the team quotes in leadership decks and
status reports, so those numbers are regenerated from the pipeline's own
artifacts instead of being copied around and going stale.

The skill never authors a metric. `collect_harness_metrics.py` parses each value
from a generated artifact (or counts it from the harness tree) and cites the
source next to it; anything it cannot find renders as "—" and is flagged in
the data-freshness table. Narrative claims no artifact can compute live in a
manual block that survives regeneration.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| `--workspace-root <dir>` | Parent workspace holding the sibling repos (default: the harness checkout's parent) |
| `--out <file>` | Output path (default: `progress-tracker/metrics/traust-metrics.md`) |
| `--refresh-sources` | Before collecting, rebuild stale upstream artifacts (see step 2). Skill-level token — interpreted by the agent running this skill, NOT an argparse flag on the collector script |

## Procedure

1. **Run the collector:**

   ```bash
   python3 traust/harnessing/traust-metrics/scripts/collect_harness_metrics.py
   ```

   It writes the scoreboard and exits non-zero if any source artifact is
   missing (the file is still written, with the gaps flagged).

2. **Check the Data freshness table** in the output. Each source row shows the
   artifact's own `Generated:` date. If a source is missing, or older than the
   latest audit activity and the user asked for `--refresh-sources` (or asks
   for current numbers), rebuild it with the owning skill first, then rerun
   the collector:

   The collector reads eleven sources (this table mirrors its `sources`
   dict — keep them in sync; docs-verification 2026-07-31 found it
   documenting 4 of 11):

   | Stale source | Rebuild with |
   |---|---|
   | `progress-tracker/metrics/dashboards/Executive-summary-findings.metrics.json` (machine sidecar; the `.md` is the human companion) | `/executive-summary-findings` |
   | `progress-tracker/metrics/dashboards/census/census.json` | `/census` |
   | `progress-tracker/metrics/dashboards/insecure-patterns/insecure-patterns.json` | `/insecure-patterns` |
   | `progress-tracker/metrics/dashboards/benchmark/benchmark.json` | `/recall-benchmark` (a full benchmark run — never rebuild casually; report staleness) |
   | `progress-tracker/metrics/dashboards/trends/trends.json` | `/findings-trends` |
   | `progress-tracker/metrics/dashboards/Live-validation-fuzz-dashboard.md` | `/validation-fuzz-dashboard` |
   | fuzz campaign sidecar (`fuzz-campaign.json`, beside the validation dashboard) | `/validation-fuzz-dashboard` |
   | `progress-tracker/metrics/dashboards/threat-register/threat-register.md` | `/threat-register` |
   | `progress-tracker/tracking/opened-tickets.md` | human-curated by the filing flow (`/file-security-defect` reporting) — report staleness, never rebuild |
   | cloud-config lane (`findings.db`) | `/census` (findings-db projection) |
   | harness repo tree/git metadata | nothing to rebuild — read live |

   When several sources are stale at once, prefer the full chain over
   per-artifact rebuilds: `/refresh-dashboards`
   (python3 -m traust.cli dashboard refresh) rebuilds every deterministic
   dashboard in dependency order and runs this collector last.

3. **Report back.** Read the generated file and give the user the headline
   numbers grouped as the file groups them (scale, impact, validation,
   delivery, maturity), calling out: any **MISSING** sources, any source whose
   `Generated:` date is more than ~a week old, and any metric that moved
   sharply since the previous version of the file (use `git -C
   progress-tracker diff traust-metrics.md` when the file is tracked).

4. **Manual block (optional).** A hand-added `<!-- MANUAL:BEGIN/END -->` block is
   preserved verbatim across runs. If the user supplies narrative claims
   (cost comparisons, remediation stories, the ask), edit them **inside that
   block only** — never hand-edit generated rows; fix the upstream artifact
   instead.

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

`progress-tracker/metrics/traust-metrics.md` — sections: Scale & coverage ·
Findings & impact · Empirical validation · Delivery & adoption · Platform
maturity & reliability · optional manual block (preserved if present) · Data freshness.

## Notes

- **Deterministic at metric time**: like the dashboards, this skill only
  replays already-derived artifacts — no model call participates in producing
  a number, so reruns are reproducible and diffs are meaningful.
- The maturity metrics (version, commits, releases, LoC, test count) are
  counted live from the harness checkout, so they are correct even when no
  campaign artifact has been rebuilt recently.
- Severity counts quote the executive summary's totals (occurrences) and note
  unique counts alongside, matching how that report itself leads.

## Spend metrics (separate dashboard, not harvested here)

The collector does **not** read spend data and the scoreboard carries
no spend section — spend lives in its own dashboard
(`progress-tracker/metrics/dashboards/spend/`, rebuilt by
python3 -m traust.cli metrics spend, stage 14 of `/refresh-dashboards`).
An earlier revision of this skill claimed the scoreboard harvested
`model-spend:*` ledger rows; no such code ever existed
(docs-verification 2026-07-31, wiring c5). When reporting scoreboard
numbers, point spend questions at the spend dashboard; treat a
>7-day-old spend dashboard as stale and rebuild via
`/refresh-dashboards`. Real-time view and the full tracking chain live in your
deployment's private configuration repository, if it keeps one.
