---
name: insecure-patterns
description: Use when the user asks which insecure coding patterns recur across the portfolio, wants findings grouped/ranked by CWE or OWASP ASVS category, asks "what are our top vulnerabilities by pattern", "which repos share CWE-X", or asks to (re)build the insecure-patterns dashboard. Reads source-code findings recorded in traust-core (separate ownership cuts), enriches reviewed CWE/ASVS/fix references, and writes a detailed Markdown report, interactive HTML explorer and full JSON roll-up.
argument-hint: "[summary] [open]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 -m traust.cli dashboard view insecure-patterns:*)
  - Bash(ls:*)
  - Bash(open *.html:*)
  - Read
---

# Insecure Coding Patterns — ASVS 5.0 roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Aggregate every source-code security finding across the campaign into a ranked
table of recurring insecure coding patterns, categorised against the OWASP
ASVS 5.0 taxonomy, with example `repo · file · function` tuples and a
one/two-line root-cause fix per pattern.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Default run — every ownership class in traust-core, write the outputs. |
| `summary` | Also print the ranked top-50 summary to the conversation. |
| `open` | Open the resulting dashboard in the default browser when done. |
| `<path>` | *Retired:* the view reads traust-core, not an analysis-results tree. |

---

## Procedure

### Step 1 — Locate the analysis-results root

*Retired:* traust-core holds the findings; there is no root to locate.

### Step 2 — Run the view

```bash
python3 -m traust.cli dashboard view insecure-patterns \
    [--product <slug>…] [--as-of <ISO time>] [--since <ISO time>] [--bucket day|week|month] \
    --out progress-tracker/metrics/dashboards/insecure-patterns
```

What the view does:

1. *Retired:* the report-file glob and tree tagging. It reads the current
   findings recorded in traust-core, so the false-positive drop honours human
   triage and machine validation dispositions. The owned and upstream cuts are
   the corpus registry's ownership classes, aggregated separately — the owned
   cut drives the ranking and the upstream cut is never folded into it.
2. Keeps findings with at least one source-code location extension or explicitly
   recorded source language. Config/manifest-only and unclassified findings are
   excluded; CWE names, titles and finding kind never decide code vs config.
3. Drops findings with `validation_status: false_positive`.
4. **Pattern key = primary CWE** (`cwes[0]`, required by the report schema).
5. De-duplicates occurrences by `(repo, cwe, path)` — applied within each
   ownership class independently — so per-branch report copies count once.
6. Resolves names, ASVS 5.0 sections and root-cause fixes through Core's read-only
   reviewed CWE reference provider and `TaxonomyPolicy`. Recorded ASVS labels
   take precedence; unmapped CWEs retain their ID with explicitly absent guidance.
7. *Retired:* the evidence-text function-name regexes. An example is
   `repo · file:lines · symbol`, with the symbol only where traust-core recorded one.
8. Ranks patterns by **distinct repository count**, then occurrence count.
   Every ownership class gets its own ranking by the
   same key, rendered as its own section in `insecure-patterns.md` and
   `insecure-patterns.html`, and as its own cut in `insecure-patterns.json`.
9. Writes the artefacts under `progress-tracker/metrics/dashboards/insecure-patterns/`.

### Step 3 — Report back

Always tell the user:

- The output paths.
- Corpus stats: scoped repositories, source findings kept, non-code/unknown and
  false-positive exclusions, occurrences without a CWE and distinct patterns,
  separately for each ownership cut.
- The top-50 summary (CWE · name · ASVS § · repos · occurrences), and the
  upstream cut headline when present. The full-detail report and HTML explorer
  retain every ranked pattern even when the summary is truncated.

If `open` was requested, open the dashboard:
`open progress-tracker/metrics/dashboards/insecure-patterns/insecure-patterns.html`

---

## Outputs

| File | Purpose |
|---|---|
| `insecure-patterns/insecure-patterns.md` | Top-50 summary per ownership class, followed by every pattern's ASVS reference, co-tagged CWEs, up to six highest-severity location/symbol examples and reviewed root-cause fix. |
| `insecure-patterns/insecure-patterns.html` | Self-contained, script-free explorer: ownership summaries, ASVS chapter bars, independent chapter/CWE filters, expandable examples and inline fixes; followed by the detailed report. Browser Find searches names/fixes. |
| `insecure-patterns/insecure-patterns.json` | Every ranked pattern per cut, metadata, counts/exclusions, population roots/scope and historical comparison values. |

All outputs include a population block: registered roots with ownership,
source-finding/occurrence units, actual filters and scoped-repository denominator.
Cut counts may overlap when a repository ships in multiple ownership classes.

---

## Tuning

`CodeFindingPolicy` owns the explicit source extension/language vocabulary and can
be supplied to `InsecurePatternsView` by a Core integration. Reviewed names,
ASVS crosswalks and fixes live in `providers.cwe_reference`, migrated from the
Apache-2.0 main builder with source attribution; update that provider, not a
second harness table. `Location.symbol` remains authoritative: function regex
guessing stays retired.

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Pattern has no display name or ASVS guidance | No reviewed reference for that CWE and no recorded ASVS label | Preserve the unmapped result; submit a reviewed reference update, not an inferred mapping. |
| Examples mostly `file:lines` | traust-core recorded no symbol for the location | Expected — the fallback is intentional. |
| A config-only finding is absent from the ranking | No positive source extension/language evidence | Expected; the population's non-code/unknown exclusion count accounts for it. |
| Filters show no rows | Selected CWE belongs to a different chapter | Choose All chapters or All CWEs; each ownership cut filters independently. |

## Trends

The trend banner compares source findings and distinct CWEs with the state
immediately before the requested window start, or the current bucket start
(monthly by default). Both states are derived from historical finding reads,
using the same current scoped population and registered ownership cuts.
The comparison timestamp is printed explicitly; it is not "previous dashboard
run" history. Rebuilding does not append a metrics ledger or create snapshots.
