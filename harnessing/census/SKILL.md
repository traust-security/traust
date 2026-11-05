---
name: census
description: Use when the user asks for the corpus census, the report population, "how many repos/reports do we actually have", how much duplication is in the numbers, the distinct-vulnerability count, ownership cuts (owned vs upstream vs external-BU), or asks to (re)build the census or corpus manifest. Deterministically resolves the report population via traust-core (`traust portfolio population`), quantifies the five duplication vectors, computes distinct vulnerabilities (fingerprint-deduped at HEAD, disposition-adjusted, FP-excluded, hardening separate) per ownership cut, and writes census.{json,md,html} — the denominator authority every other dashboard cites.
argument-hint: "[summary] [open] [<workspace-root-path>]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust* -m traust.cli portfolio population:*)
  - Bash(python3 *traust* -m traust.cli dashboard view census:*)
  - Bash(ls:*)
  - Bash(open *.html:*)
  - Read
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# Corpus Census — population, duplication, distinct vulnerabilities

> **Ported to traust-core in part** (progress-tracker skill port 09, census): the population is `traust portfolio population`, repo liveness `traust portfolio liveness` (refused until plan 15's decision 3), distinct vulnerabilities, ownership cuts and the census files `traust dashboard view census` (traust-core's census view).

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


One deterministic pass that answers "what do we actually have": the report
population per tree and ownership cut, the duplication vectors that inflate
naive counts, and the **distinct vulnerabilities** headline (Lens 2 of the
three-lens taxonomy — see
`progress-tracker/plans/metrics-improvement-plan.md`).

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Default run — resolve the corpus, write all four outputs. |
| `summary` | Also print the census Markdown to the conversation. |
| `open` | Open the HTML dashboard in the default browser when done. |
| `<path>` | Override the workspace root (directory containing `analysis-results/` and `progress-tracker/`). |

---

## Procedure

### Step 1 — Locate the workspace root

Resolution order:

1. A path passed in `$ARGUMENTS`.
2. The parent of the `traust` checkout (the normal sibling
   layout with `analysis-results/` and `progress-tracker/`).

If neither contains `analysis-results/`, ask the user for the path.

### Step 2 — Run the harness script

```bash
python3 -m traust.cli portfolio population \
    [--kind secure_code] [--as-of <ISO time>]
python3 -m traust.cli dashboard view census \
    --out <workspace-root>/progress-tracker/metrics/dashboards/census \
    [--product <slug>] [--team-id <id>] [--as-of <ISO time>]
```

What the script does:

1. Resolves the population (now done by `traust portfolio population`): every
   registered repository, per assessment kind the newest default-line
   assessment, the default-line count and the branch re-audit count, and the
   repositories never assessed. Symlink aliases and unregistered trees are
   *retired* (one assessment row per run, no tree walk); ownership is
   recorded per product in the corpus registry (`traust products add --ownership`)
   and the census view cuts by it (a repository takes the ownership of each
   product that ships it).
2. (now done by the census view) Reads every recorded finding with its
   current disposition and classifies
   each finding: false positives dropped, hardening bucketed separately,
   everything else a vulnerability keyed by its finding identity
   (repository + `fingerprint`, recorded at intake).
3. (now done by the census view) Computes **distinct vulnerabilities** per ownership cut: unique
   findings on the default line (branch re-audits excluded from the headline),
   severity = the finding's effective (disposition-adjusted) severity, open = not
   resolved/risk-accepted.
4. Branch re-audits are `population`'s `branches` count and the census view's
   branch line (confirmed on a branch, branch only); the other vectors
   are *retired* (one assessment row per run, no files to alias, restate or
   duplicate). Quantifies the five duplication vectors: symlink aliases (incl.
   ledgers attached to aliased reports), branch re-audits (findings that
   fingerprint-match a HEAD finding count as confirmations, not new
   exposure — strict tier-1 matching, so branch-only counts are an upper
   bound), layered-artifact restatement, cross-tree slug overlap, and
   duplicate basenames.
5. (now done by `traust dashboard view census --out <dir>`) Writes the three outputs. The
   metrics-ledger snapshot row and trend-vs-previous line are *retired*: the view
   is derived on demand, so a trend is the same view at an earlier `--as-of`.

### Step 2b — Refresh repo liveness (archive-awareness)

The census owns **repo liveness** — population metadata recording which
repos can still act on findings (metrics-improvement plan, Phase 7):

**Pending:** `traust portfolio liveness` refuses with "Liveness status needs a
traust-core decision (plan 15, decision 3)": the typed repo-liveness status (active,
archived, moved, missing, disabled, unknown) needs a newer traust-core contracts pin. It
never derives a status traust-core did not record, so there is no liveness artifact to
refresh until that decision. Report liveness as unavailable in the report-back; do not
substitute archived flags from another source.

### Step 2c — Rebuild the findings database (projection)

The census refresh is what keeps the queryable findings DB current
(C9 — `/findings-db`): rebuild it from the same corpus resolution so the
projection can never lag the denominator authority by more than one
census run:

*Retired with `findings.db`*: every `traust findings` read is derived
from the recorded decisions when it runs, so there is no projection to
rebuild. When a findings number and a census number disagree, trust the
census.

### Step 2d — Compliance-assessed coverage line

The compliance posture cut is traust-core's compliance view
(python3 -m traust.cli dashboard view compliance --out <dir>), read live
from the recorded assessments and boundary declarations. When reporting census results, include the
"compliance-assessed targets" line from that dashboard — it is a
coverage cut over this census's denominators, never a separate
population.

### Step 3 — Report back

Always tell the user:

- The executive view: distinct owned vulnerabilities (total + open, with
  C/H/M/L/I split), the adjacent upstream line, and the external-BU
  work-performed count.
- The duplication-vector summary (the five numbered lines).
- Any drift warnings (repositories no product with a registered ownership
  ships: the view's "Not in the registry").
- The three output paths.

If `open` was requested:
`open progress-tracker/metrics/dashboards/census/census.html`

---

## Outputs

`traust dashboard view census --out <dir>` writes the three census files;
`traust portfolio population` prints the population as JSON.

| File | Purpose |
|---|---|
| `census/census.md` | Executive view, ownership-cut and by-product tables, duplication vectors, drift, standard population block. |
| `census/census.html` | Self-contained dashboard: the same sections as the Markdown. |
| `census/census.json` | Machine-readable census: population, ownership cuts, products, branch line, cloud-config and container counts, unregistered repositories. |
| `findings.db` `repos` | *Retired with `findings.db`*: the resolved record list is `traust portfolio population`. |

---

## Reading the numbers

- **Distinct vulnerabilities (owned)** is the canonical Lens 2 headline:
  owned products only, HEAD only, fingerprint-deduped,
  disposition-adjusted. Never average it with occurrence counts from
  other dashboards — reconcile via each dashboard's population block.
- **Upstream (upstream products)** is reported adjacent to the owned
  headline and is never folded in.
- **External-BU trees** (ecoengg, OpenStack, future engagements)
  appear only as work performed (Lens 1).
- **Branch re-audit confirmations** are Lens 1 coverage evidence
  ("N HEAD findings confirmed present on release branches"), not new
  exposure.

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: <ws>/analysis-results not found` | Wrong workspace root | Pass the directory that contains `analysis-results/`. |
| Repository under "Not in the registry" | No product with a registered ownership ships it | Register it via `/corpus-intake` (`traust products add --ownership`). |
| Distinct counts moved sharply with no new audits | Decisions recorded | Expected — the census is disposition-aware by design. |
