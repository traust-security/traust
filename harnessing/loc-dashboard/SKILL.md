---
name: loc-dashboard
description: Use when the user asks how many lines of code have been scanned/audited, wants a LoC breakdown by language or repo across the security-audit campaign, or asks to (re)build the LoC dashboard. Produces the lines-of-code view {json,md,html} from the code facts traust-core has measured.
metadata:
  harness.tier: "tertiary"
allowed-tools:
  - Read
  - Write
  - Bash(python3 -m traust.cli dashboard view loc:*)
  - Bash(open *lines-of-code.html:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# LoC Dashboard

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Report and visualise the lines-of-code coverage of the security-audit campaign from the lines traust-core has measured for each repository (the latest code-facts scan at its default-branch commit; traust-core's `LocView`), rendered as a single-file HTML dashboard.

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

---

## Procedure

### Step 1 — Locate the dashboards folder

*Retired:* the repositories come from traust-core's inventory, not the analysis-results manifests. Write the view to `progress-tracker/metrics/dashboards/` (or where the user asks).

### Step 2 — Run the command

```bash
python3 -m traust.cli dashboard view loc \
    [--product <slug>]... [--team-id <uuid>]... \
    --out <progress-tracker>/metrics/dashboards
```

What it does (traust-core's `LocView`, one `InsightService.publish`):

1. Takes every repository in scope from the inventory (unique rows; no manifests, no dedupe by URL).
2. For each, reads the languages the latest code-facts scan measured at its default-branch commit (`CodeFactsService.language_stats`). A repository with no measurement is listed under "Not measured" with the reason (no default-branch commit, no scan, languages not measured, scan not completed); GitLab repositories are measured like any other.
3. Counts measured lines, not byte estimates (the `BPL` table is retired).
4. Sums lines by language, documentation languages apart, and names each repository's primary language.
5. Writes:
   - `lines-of-code.{md,html,json}` in `--out` — the dashboard and its model. Nothing is cached or stored.

### Step 3 — Report back

Always tell the user:

- The output paths.
- Headline numbers: code-LoC, total-LoC, repo counts, not-measured count. (No door yet for the calibrated first-party figure.)

If `summary` was requested, also print the per-bucket and top-10-language tables to the conversation.

### Step 4 — Interpretation note (include once per session)

> The measured lines are whole-repository counts and **may include** tests, fixtures, and tooling. Audit reports that hand-state LoC typically cite *first-party non-test* code only. Spot-checking against reports that record both gave a median ratio of ~2.5× (legacy `FIRST_PARTY_DIVISOR`) — no door yet for the first-party figure, so the dashboard shows the measured one.

---

## Outputs

| File | Purpose |
|---|---|
| `lines-of-code.json` | The view's model: per-language totals and per-repo measured lines. |
| `lines-of-code.{md,html}` | Dashboard: summary, language breakdown, per-repo table, not-measured repositories. |

No door yet for the population block panel.

---

## Operational notes

- **Auth / rate limit:** *retired* — no GitHub API calls.
- **Idempotent:** safe to wire into `finalize_batch.sh` or a `/loop`; it reads, it stores nothing.
- **Tuning:** documentation languages are traust-core's `LocView` constant; `BPL` and `FIRST_PARTY_DIVISOR` are retired (lines are measured).
- **GitLab repos** are measured by the code-facts scan like any other.

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Many "Not measured" rows | No code-facts scan at the default-branch commit yet | Expected; they contribute 0 LoC. Run the scan, then rebuild. |
| Exit 2: takes no as_of | `--as-of` passed | The view reads the latest measurement only; drop `--as-of`. |
| Dashboard shows 0 repos | Unknown scope / empty inventory | Check `--product` against `traust products list`. |

## Trends

*Retired:* no metrics-ledger snapshot or trend banner. The view stores
nothing; it reads the latest measurement only (no `as_of` yet).
