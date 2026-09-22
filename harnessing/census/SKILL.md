---
name: census
description: Use when the user asks for the corpus census, the report population, "how many repos/reports do we actually have", how much duplication is in the numbers, the distinct-vulnerability count, ownership cuts (owned vs upstream vs external-BU), or asks to (re)build the census or corpus manifest. Deterministically resolves the report population via python3 -m traust.cli corpus + $TRAUST_CONFIG_HOME/corpus-config.yaml, quantifies the five duplication vectors, computes distinct vulnerabilities (fingerprint-deduped at HEAD, disposition-adjusted, FP-excluded, hardening separate) per ownership cut, and writes census.{json,md,html} — the denominator authority every other dashboard cites.
argument-hint: "[summary] [open] [<workspace-root-path>]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust/harnessing/census/scripts/build_census.py:*)
  - Bash(python3 *traust* -m traust.cli corpus findings-db:*)
  - Bash(python3 *traust/harnessing/census/scripts/check_repo_liveness.py:*)
  - Bash(ls:*)
  - Bash(open *.html:*)
  - Read
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# Corpus Census — population, duplication, distinct vulnerabilities

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
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
python3 harnessing/census/scripts/build_census.py \
    [--workspace-root <resolved-root>] \
    [--summary]
```

What the script does:

1. Resolves the population via `python3 -m traust.cli corpus resolve` against
   `$TRAUST_CONFIG_HOME/corpus-config.yaml`: depth-tolerant walk of every registered
   tree, symlink aliases mapped to canonical reports (never counted),
   branch-ref identity (declared `metadata.ref` preferred, legacy
   `__release-X.Y` slug fallback → base slug + ref; a compact per-ref
   breakdown table lands under "Population by tree"), ownership
   tags (owned / upstream / external-bu). Registered engagement trees
   (any registered `<engagement>-findings/`) activate automatically
   when they appear on disk; unregistered trees holding audit reports
   raise drift warnings.
2. Loads every report's preferred layer — `*-findings-current.json`
   (disposition-aware) when present, else the audit JSON — and classifies
   each finding: false positives dropped, hardening bucketed separately,
   everything else a vulnerability keyed by its `fingerprint` (computed
   via python3 -m traust.cli corpus finding-identity when absent).
3. Computes **distinct vulnerabilities** per ownership cut: unique
   fingerprints at HEAD (branch re-audits excluded from the headline),
   severity = max across occurrences, open = any occurrence not
   resolved/risk-accepted.
4. Quantifies the five duplication vectors: symlink aliases (incl.
   ledgers attached to aliased reports), branch re-audits (findings that
   fingerprint-match a HEAD finding count as confirmations, not new
   exposure — strict tier-1 matching, so branch-only counts are an upper
   bound), layered-artifact restatement, cross-tree slug overlap, and
   duplicate basenames.
5. Writes the four outputs and appends a snapshot row to the central
   metrics ledger (python3 -m traust.cli metrics history, source `census`;
   `--skip-ledger` to suppress), injecting a trend-vs-previous line into
   the Markdown.

### Step 2b — Refresh repo liveness (archive-awareness)

The census owns **repo liveness** — population metadata recording which
repos can still act on findings (metrics-improvement plan, Phase 7):

```bash
python3 harnessing/census/scripts/check_repo_liveness.py \
    --spine <workspace-root>/analysis-results/graph/repo-graph.json \
    --out <workspace-root>/progress-tracker/metrics/repo-liveness.json
```

One GitHub API call per repo (`gh` must be authenticated; ~10 minutes on
a full sweep) emitting a status per repo — `active | archived | moved |
missing | unknown` — with `status_since` ratcheted from the previous
artifact. Skip when `gh` is unauthenticated or the spine is absent, and
say so in the report-back; a stale liveness artifact means downstream
consumers (audit stamps, verify-remediation sweep flags, graph attrs,
dashboard segments) are reading old status. Include the non-`active`
counts in the report-back — archived-but-shipping components are a
distinct risk segment, not burndown residue.

### Step 2c — Rebuild the findings database (projection)

The census refresh is what keeps the queryable findings DB current
(C9 — `/findings-db`): rebuild it from the same corpus resolution so the
projection can never lag the denominator authority by more than one
census run:

```bash
python3 -m traust.cli corpus findings-db \
    --results-root <workspace-root>/analysis-results
```

Full deterministic rebuild (< 1 min), output
`analysis-results/graph/findings.db` (gitignored, rebuildable). The DB is
a **projection of this census** — its `meta` table records the build time
and the authority rule; when DB and census numbers disagree, rebuild the
DB and trust the census. Skip (and say so) only if the script or the
corpus config is unavailable.

### Step 2d — Compliance-assessed coverage line

The compliance posture cut lives in
`progress-tracker/metrics/dashboards/compliance/` (built by
python3 -m traust.cli compliance dashboard on the census's own corpus
resolver, so its population block reconciles with this census by
construction). When reporting census results, include the
"compliance-assessed targets" line from that dashboard — it is a
coverage cut over this census's denominators, never a separate
population.

### Step 3 — Report back

Always tell the user:

- The executive view: distinct owned vulnerabilities (total + open, with
  C/H/M/L/I split), the adjacent upstream line, and the external-BU
  work-performed count.
- The duplication-vector summary (the five numbered lines).
- Any drift warnings (unregistered trees, md-only parse gaps, parse
  errors).
- The four output paths.

If `open` was requested:
`open progress-tracker/metrics/dashboards/census/census.html`

---

## Outputs

| File | Purpose |
|---|---|
| `census/census.md` | Executive view, population-by-tree table, duplication vectors, parse gaps/drift, standard population block. |
| `census/census.html` | Self-contained dashboard: stat cards, ownership severity chips, tree + duplication tables, drift warnings. |
| `census/census.json` | Machine-readable census: population, ownership cuts, duplication vectors, warnings, timings. |
| `findings.db` `repos` | Full resolved record list — the denominator source other dashboards cite. Written by `traust_engine.corpus.findings_db`, not here; `corpus-manifest.json` was retired 2026-08-20 as a write-only artifact nothing read. |

---

## Reading the numbers

- **Distinct vulnerabilities (owned)** is the canonical Lens 2 headline:
  `findings/` only, HEAD only, fingerprint-deduped,
  disposition-adjusted. Never average it with occurrence counts from
  other dashboards — reconcile via each dashboard's population block.
- **Upstream (oss-findings/)** is reported adjacent to the owned
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
| Unregistered-tree warning | New campaign tree on disk not in `corpus-config.yaml` | Register it via `/corpus-intake` (until that skill ships: edit `$TRAUST_CONFIG_HOME/corpus-config.yaml`). |
| Distinct counts moved sharply with no new audits | Disposition ledgers landed (findings-current now preferred) | Expected — the census is disposition-aware by design. |
| `metrics-ledger append skipped` on stderr | progress-tracker not writable/missing | Census still writes all four outputs; fix the sibling checkout to restore trending. |
