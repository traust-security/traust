---
name: findings-trends
description: Use when the user asks whether portfolio security findings are trending up or down, wants a burndown, remediation velocity, MTTR, risk-index, or accepted-risk trend, or asks to (re)build the findings-trends dashboard — e.g. "are we getting better", "findings over time", "how fast are we remediating", "what risk have we accepted". Replays every repo's recorded findings and decisions against time buckets and emits the findings-trend view {json,md,html}.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# Findings Trends

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Track whether the portfolio is getting better or worse. Because
traust-core records every decision on a finding as a timestamped,
append-only event, the portfolio's state at **any past date** can be reconstructed by
replaying only the events dated before it — no snapshots, no stored trend
state, fully deterministic. This skill runs that replay (traust-core's
`FindingsTrendView`) at monthly (or
weekly) boundaries and reports the direction of every metric.

## When to Use

- "Are findings trending up or down?" / "are we getting better?"
- "Show me the burndown" / "remediation velocity" / "MTTR"
- "How much risk have we accepted?" / "what's on the accepted-risk register?"
- "Rebuild the trends dashboard"

## Invocation

```
python3 -m traust.cli dashboard view findings-trend $ARGUMENTS
    [--bucket month|week]       # default month
    [--since <ISO time>]        # window start, with a zone
    [--product <slug>]          # one product's repositories (repeatable)
    [--as-of <ISO time>]        # pin the series end (reproducible runs)
    --out DIR                   # e.g. progress-tracker/metrics/dashboards/trends
```

Outputs `<stem>.{json,md,html}` into `--out` (core renders them, stores nothing). Alongside the population block, the latest-bucket ownership cuts split open findings, open Critical/High and risk index by the recorded corpus ownership class. Product/team scope does not replace this split. Unclassified repositories stay unknown; repositories belonging to multiple ownership classes appear in each cut, so cuts are not additive.

## Semantics

- **Option A open counting.** Every finding from every audited repo counts
  as *open* until a decision closes it. Findings without decisions therefore
  contribute permanent open exposure — that is the point: total exposure is
  what leadership needs. (The view prints the coverage figure: the
  repositories with a decision recorded, of those reported, per bucket.)
- **Accepted risk is not remediation.** `risk_accepted` findings leave
  "open" but land on a standing **Accepted Risk Register** — unfixed and
  unmitigated, reported with severity, CVSS, who accepted, when, and the
  recorded rationale. The register never decays; it shrinks only through
  remediation or re-triage. The accepted-risk CVSS sum is its own trend
  series, distinct from the open risk index. (The view lists the
  register's entries and the accepted CVSS sum, `accepted risk index`,
  per bucket.)
- **Risk index = CVSS sum.** Sum of `cvss.score` over open findings;
  findings without CVSS use their severity band midpoint (critical 9.5,
  high 8.0, medium 5.5, low 2.0, informational 0). Custom weighting is
  a deliberate non-goal for now. (The view computes it.)
- **OWASP headline uses evidence, not severity.** Complete recorded CVSS v3
  vectors supply likelihood and impact; canonical CVE aliases join the EPSS/KEV
  snapshots retrieved by each bucket's end. The series includes the OWASP band
  distribution and High/Critical share of open findings. Missing vectors stay
  unrated; the percentage is unknown if any open finding is unrated.
- **Coverage cohorts remain visible.** Recorded occurrence refs split repositories
  by corpus ownership and recorded default line (HEAD), named non-default
  branch, or unknown. Coverage requires a decision bound to that ref/line, not
  merely a HEAD or unbound decision on the same finding. One repository can
  appear in several cohorts.
- **Assurance is explicit.** Claimed is the raw report population, verified
  replays without E0 decisions, and proven requires an open, execution-proven
  confirmed disposition. Final lenses expose triage/validation risk deltas,
  human FP assertions overridden by proof, and confirmed vulnerabilities
  co-located with hardening gaps. No historical hardening weight is invented.
- **Buckets use `occurred_at`.** Events bucket by their source timestamp
  (commit date, Jira transition, MR comment date) when the adapters
  recorded one, falling back to `recorded_at` — late ingestion does not
  distort the series.
- **Countersign rule honoured.** State replay reuses traust-core's
  decision fold, so a machine-refuted finding stays
  open until an LDAP-verified human countersigns the false positive.

## Metrics and polarity

| Metric | Good direction |
|---|---|
| Open findings, risk index, OWASP High/Critical %, new findings, MTTR, FP rate, regressions, accepted risk index | ↓ |
| Remediation velocity, ledger coverage | ↑ |

Direction = last bucket vs the mean of up to three prior buckets, with a
±10% dead band rendered as → flat. Worsening metrics carry a ⚠ flag.
(The view computes the directions, FP rate and velocity.)
OWASP and risk-index directions with unknown measurements are omitted, not treated as zero.

## Procedure

1. **Refresh the exploitation feeds** when online. The builder only reads
   recorded snapshots, uses each bucket's last available evidence, and falls
   back to CVSS-only likelihood when no snapshot existed:

   ```bash
   python3 -m traust.cli feeds fetch   # EPSS + CISA KEV, 24h freshness
   ```

2. Resolve arguments; run the command (above). It replays each
   repository's recorded findings and decisions in scope. Findings with canonical
   advisory/CVE links gain an **exploitation-evidence likelihood factor** from
   recorded KEV membership or their maximum EPSS band. Feed evidence never
   supplies a verdict or an assurance level.
3. Read `findings-trend.md` back to the user. Lead with the direction
   table, then call out:
   - any **worsening ⚠** metric, with the driving repos where identifiable
   - the **Accepted Risk Register** headcount and its highest-CVSS entries
   - the **ledger coverage** figure and its trend — if coverage is low,
     say explicitly that the open count is dominated by untracked repos
4. Offer the HTML dashboard path for sharing.

## Gotchas

- **The final bucket is usually partial.** A mid-month run undercounts the
  current month; the classifier still uses it. For board-ready numbers run
  with `--as-of` set to the last day of the previous month.
- **Trends only move when decisions are recorded.** If nothing was ingested since
  the last run, the series is identical — flat is the correct answer, not
  a bug. Coverage ↑ is the first trend to chase on a new portfolio.
- **Don't hand-compute the numbers.** All aggregation lives in
  traust-core's `FindingsTrendView`; the skill presents, it never re-derives.
- **A shrinking open count with shrinking coverage is a red flag** — check
  whether repos were removed from the portfolio rather than remediated.
