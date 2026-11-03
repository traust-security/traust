---
name: loc-dashboard
description: Use when the user asks how many lines of code have been scanned/audited, wants a LoC breakdown by language or repo across the security-audit campaign, or asks to (re)build the LoC dashboard. Produces the lines-of-code view {json,md,html} from the code facts traust-core has measured.
metadata:
  harness.tier: "tertiary"
allowed-tools:
  - Read
  - Write
  - Bash(python3 -m traust.cli dashboard view loc:*)
  - Bash(python3 -m traust.cli dashboard explore-loc:*)
  - Bash(open *loc-explorer.html:*)
  - Bash(open *lines-of-code.html:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# LoC Dashboard

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Report measured lines-of-code coverage from traust-core's inventory and recorded code-facts scans. Portable HTML is script-free; a separate trusted local explorer consumes the JSON export for sorting, corpus-tree/language/size filters, bucket bars and language-mix strips.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Every repository in the inventory; rebuild the dashboard. |
| `refresh` | *Retired:* lines are measured by the code-facts scan and stored; nothing is fetched or cached. |
| `no-fetch` | *Retired:* nothing is fetched (same reason). |
| `open` | Open the resulting dashboard in the default browser when done. |
| `summary` | After building, print a plain-text summary table to the conversation. |
| `<product slug>` | Only that product's repositories (`--product`, repeatable; `--team-id <uuid>` for a team). |
| `as-of <ISO timestamp>` | Recompute at an earlier recorded measurement (`--as-of`); requires a time zone. |
| `compare-as-of <ISO timestamp>` | Compare against an earlier measurement (`--compare-as-of`); growth includes only repositories measured at both points. |
| `first-party-divisor <number>` | Opt in to a labelled first-party estimate using an explicitly supplied finite positive divisor; no default is assumed. |
| `explore` | Write and open the trusted local JSON explorer, then select `lines-of-code.json`. |

---

## Procedure

### Step 1 — Locate the dashboards folder

*Retired:* the repositories come from traust-core's inventory, not the analysis-results manifests. Write the view to `progress-tracker/metrics/dashboards/` (or where the user asks).

### Step 2 — Run the command

```bash
python3 -m traust.cli dashboard view loc \
    [--product <slug>]... [--team-id <uuid>]... \
    [--as-of <ISO timestamp>] [--compare-as-of <earlier ISO timestamp>] \
    [--first-party-divisor <explicit positive divisor>] \
    --out <progress-tracker>/metrics/dashboards
```

What it does (traust-core's `LocView`, one `InsightService.publish`):

1. Takes every repository in scope from the inventory (unique rows; no manifests, no dedupe by URL).
2. Selects the observed default-branch head at `--as-of` (latest when omitted), then reads the latest code-facts scan at that commit no later than the selected time. A repository with no measurement is listed under "Not measured" with the reason; GitLab repositories are measured like any other. A recorded empty language list is a genuine zero; missing measurements are not zero.
3. Counts measured lines, not byte estimates (the `BPL` table is retired).
4. Sums lines by language, documentation languages apart, and names each repository's primary language.
5. Writes:
   - `lines-of-code.{md,html,json}` in `--out` — the dashboard and its model. Nothing is cached or stored.

For interactive exploration (local, offline, no deployment credentials or network access):

```bash
python3 -m traust.cli dashboard explore-loc \
    --out <progress-tracker>/metrics/dashboards/loc-explorer.html
open <progress-tracker>/metrics/dashboards/loc-explorer.html
```

Select the exported `lines-of-code.json` in the page. Repository search, recorded corpus-tree membership, language and size filters compose; column headings sort the table. Corpus buckets resolve exact registry repository URLs or registered product memberships, remain unassigned when unknown, and can overlap without double-counting headline totals. Language strips include documentation languages and expose their counts. No report data is embedded in the executable page, sent over the network or saved in browser storage.

### Step 3 — Report back

Always tell the user:

- The output paths.
- Headline numbers: measured code-LoC, total-LoC, repo counts and not-measured count. When explicitly requested, also report the first-party estimate and divisor, labelled **estimate, not measured**; never infer a calibration ratio.

If `summary` was requested, also print the per-bucket and top-10-language tables to the conversation.

### Step 4 — Interpretation note (include once per session)

> Whole-repository measurements **may include** tests, fixtures and tooling. First-party/non-test LoC is not measured by this view. `--first-party-divisor` supports an explicit caller-selected estimate from measured code, not a recovered stored fact. No value is produced when no repository is measured. NEED(decision, Shaun): choose either (a) adopt the legacy 2.5 divisor with an approved calibration population/methodology, or (b) retain measured-only default and retire the automatic heuristic. Until that decision, an estimate is opt-in only; this implementation does not claim owner approval for either default.

---

## Outputs

| File | Purpose |
|---|---|
| `lines-of-code.json` | The view's model: per-language totals and per-repo measured lines. |
| `lines-of-code.{md,html}` | Dashboard: summary, language breakdown, per-repo table, not-measured repositories, population block. |
| `loc-explorer.html` | Separate trusted local app for JSON imports, sortable/filterable repository exploration, corpus and size buckets, and language-mix strips. Not a portable report export. |

The dashboard ends with the standard population block (in scope, with findings reported, with a decision recorded) for cross-dashboard reconciliation.

---

## Integrations

- **Upstream:** traust-core's repository inventory and observed default-branch
  heads define scope; recorded code-facts scans at those commits supply the
  measured language counts. Audit-report estimates and the retired language
  cache are not inputs.
- **Downstream diagnostics:** `/executive-summary-findings` consumes
  `lines-of-code.json` from the same product/team/time scope when explaining
  unknown-language rows. It matches repository IDs and reads each
  `unmeasured` reason; the export is diagnostic evidence, not a replacement
  counting source for the executive view.
- **Local explorer:** `traust dashboard explore-loc` produces
  `loc-explorer.html`; the user imports `lines-of-code.json` into that page.
  Filters and sorting operate on the selected export only, offline, without
  writing back to traust-core or changing a published report.
- **Human reports:** the Markdown/HTML pair is terminal presentation for the
  user. `/refresh-dashboards` can render the same live LoC view from recorded
  facts; it does not ingest these files or perform a new measurement.

---

## Operational notes

- **Auth / rate limit:** *retired* — no GitHub API calls.
- **Idempotent:** safe to wire into `finalize_batch.sh` or a `/loop`; it reads, it stores nothing.
- **Tuning:** documentation languages remain traust-core's `LocView` policy. Byte-per-line estimates stay retired. First-party estimates require `--first-party-divisor`; there is no implicit 2.5 calibration.
- **GitLab repos** are measured by the code-facts scan like any other.

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Many "Not measured" rows | No observed default head or qualifying code-facts scan by the selected time | Run/record the scan and rebuild. Missing measurements remain unknown, not zero. |
| Exit 2: invalid timestamp/comparison | Missing time zone or comparison not earlier than the selected time | Supply zoned ISO timestamps and an earlier `--compare-as-of`. |
| Dashboard shows 0 repos | Unknown scope / empty inventory | Check `--product` against `traust products list`. |

## Trends

Use `--as-of` and `--compare-as-of` to compare recorded measurements under current policy. Each repository's change is `null` unless measured at both points; aggregate changes cover only comparable repositories, with the baseline totals and measured counts stated separately. Coverage changes never masquerade as growth. This recomputation is distinct from an immutable as-reported snapshot; archive a published view when the originally reported bytes and methodology must survive future policy changes.
