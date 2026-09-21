---
name: executive-summary-findings
description: Use when the user asks for an executive summary, leadership roll-up, or cross-portfolio dashboard of security-audit findings — e.g. "summarise all findings", "how many criticals do we have", "credential leaks across the campaign", "findings by language", or "rebuild the executive summary". Aggregates every *security-audit.{json,md} report under analysis-results/ into a one-page Markdown brief and a self-contained HTML dashboard.
metadata:
  harness.tier: "secondary"
---

# Executive Summary — Findings

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Roll up every completed security-audit report into a leadership-ready summary: severity totals, top Critical/High findings, credential & secret leaks, common CWE risk themes, and a per-language breakdown. Outputs both a Markdown one-pager and an interactive HTML dashboard.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Standard run — scan `findings/` and `oss-findings/`, write both outputs. |
| `open` | Open the resulting HTML dashboard in the default browser when done. |
| `summary` | After building, print the severity table and top-5 themes/criticals to the conversation. |
| `by-segment` | Add a per-input-segment breakdown (one row per inventory segment), mapping each repo against the inputs inventory (`locations.inputs`). The `ansible` input is excluded by default (`--exclude-segment` to change). Pass `--by-segment` to the script. |
| `include-triage` | For repos without a `findings-current` disposition ledger, count from unconfirmed `/triage` verdicts (true positives only) instead of the raw audit. **OFF by default** — early /triage runs over-marked false positives (unreachable repos, hardening misfiled as FP), so counting TP-only silently trusts those bad FP exclusions. When enabled, every affected figure is labeled "unconfirmed triage" in both outputs (KPI card + warning note with FP-excluded and undetermined counts). Pass `--include-triage` to the script. |
| `exclude-branch-variants` | Skip `__`-slugged release-branch re-audits when the same product tree also carries the base-slug audit (the within-product duplicate case, e.g. `rhacm/search-v2-api` holding main + release-5.1 audits). Branch-only audits — per-release payload products like `openshift-4.14-payload`, where the branch audit is the only audit — always count: release branches are tracked per-branch by design. The excluded-report count is stated in both outputs. Pass `--exclude-branch-variants` to the script. |
| `<path>` | Override the analysis-results root (directory containing `findings/` and `oss-findings/`). |

---

## Procedure

### Step 1 — Locate the analysis-results root

The harness needs the directory that contains `findings/` and `oss-findings/`.

Resolution order:

1. A path passed in `$ARGUMENTS`.
2. `$AUDIT_RESULTS_ROOT` environment variable.
3. `../analysis-results` relative to the `traust` checkout (the normal sibling layout).
4. Walk upward from `$PWD` looking for a directory that contains `findings/_manifest/audit-manifest.csv`.

If none resolve, ask the user for the path.

### Step 2 — Run the harness script

The skill ships `build_executive_summary.py` alongside this file. Invoke it with Bash:

```bash
python3 "$SKILL_DIR/scripts/build_executive_summary.py" \
    --results-root <resolved-root> \
    [--open] [--include-triage] [--exclude-branch-variants] \
    [--by-segment [--inputs-root <inputs-inventory>] \
              [--exclude-segment SEG]...]
```

What the script does:

1. Walks `<results-root>/findings/` and `<results-root>/oss-findings/` for every `*security-audit.json` (preferred) or `*security-audit.md` (fallback when no JSON sibling exists). The `_manifest/` directory is skipped. When a sibling `*-findings-current.json` (cumulative report from the `track-findings` skill) exists, it is used **instead of** the audit by default: human-confirmed false positives are excluded from every figure, severity counts are recomputed from the surviving findings, and per-finding resolution status feeds a "Remediation Status" section (Markdown) / KPIs + cards (HTML): closure rate across dispositioned repos, a "Findings remediated" count broken down by severity, and a per-month remediation trend (stacked resolved / partially-resolved bar chart, bucketed by each finding's last disposition event date).
2. Loads `<results-root>/findings/_manifest/gh-languages-cache.jsonl` (produced by `/loc-dashboard`) to resolve each repository's primary language; falls back to `metadata.additional.resource_type` or the report's own language row.
3. Aggregates:
   - Per-severity totals (Critical / High / Medium / Low / Informational)
   - A **"unique repos" KPI** alongside the report count: reports deduplicated
     by canonical repository URL (identical across mirror products and branch
     re-audits), falling back to the component slug with any `__<branch>`
     suffix stripped — so "N reports across M unique repositories"
     reads correctly even though totals remain per-report occurrences
   - A **Distinct Vulnerabilities** section (Lens 2, the canonical exposure
     headline): unique finding fingerprints at HEAD across `findings/`,
     disposition-adjusted, FP-excluded, hardening separate — computed with
     census-identical semantics so the two tools can never diverge; the
     upstream (`oss-findings/`) cut is shown adjacent, never folded in, and
     release-branch re-audit findings that fingerprint-match a HEAD finding
     are reported as confirmations on shipped releases, not new exposure
   - Top Critical & High findings, deduplicated by fingerprint (fallback
     `(repo, title)`) and ranked by CVSS
   - Credential / secret-leak findings — matched on CWE-798/259/321/522/540/256/312/313/260/547/1392 **or** a title heuristic (hard-coded, committed secret, API key, `.env`, kubeconfig, etc.)
   - A dedicated **"Hardening Backlog (Posture Debt)"** section + KPI card:
     `validation_status: hardening` findings are excluded from the severity
     totals but never dropped — total count, CWE-theme breakdown, and the
     largest per-repo backlogs render in both outputs, with the framing that
     absent hardening amplifies co-located vulnerabilities (λ-weighted in
     findings-trends) and files via `/file-security-defect --hardening`
   - Common risk themes — CWE → bucket clustering (Injection, Path Traversal, Secrets, Crypto, AuthN/Z, SSRF, TLS, RBAC, Supply-Chain, XSS, DoS, …)
   - Per-language severity matrix and repo counts
   - With `--by-segment`: a per-input-segment severity matrix. Every `*-repos.csv` under every segment of the inputs inventory (`locations.inputs`; the `ansible` input and any `--exclude-segment` skipped; `owners*.csv` ignored) is read into a canonical-URL → segment map; each report's `metadata.repository` resolves to its first matching segment in priority order — the declaration order of `<inputs>/inventory.yaml`, undeclared segments after by name (totals stay additive; the multi-segment overlap count is reported), and repos absent from the inventories — including all of `oss-findings/` — land in `unmapped`. Renders as a Markdown table and an HTML stacked-bar card + table. `--inputs-root` defaults to `locations.inputs`.
4. Stamps the harness version (`VERSION` + short git SHA) into both outputs.
5. Writes:
   - `progress-tracker/metrics/dashboards/Executive-summary-findings.md` — leadership one-pager
   - `progress-tracker/metrics/dashboards/Executive-summary-findings.html` — self-contained dashboard (Chart.js via CDN: severity doughnut, theme bar, language stacked-bar, Critical/High table, credential-leak table, full per-language table)

### Step 2a — Trends

Each run appends a headline snapshot (source `executive-summary`) to the
central hash-chained metrics ledger (`progress-tracker/metrics/
metrics-history.jsonl`, see python3 -m traust.cli metrics history) — skipped
automatically when nothing changed — and renders a "Trend vs <previous
snapshot>" line under the Scope header in both outputs. The leadership
time-series view is `/traust-metrics` →
`progress-tracker/metrics/Executive-Trends.{md,html}`.

### Step 3 — Report back

Always tell the user:

- The two output paths (relative to the results root).
- Headline numbers: repos audited, total findings, Critical count, High count, credential-leak count, repos with ≥1 Critical.
- Top 3 risk themes.

If `summary` was requested, also print the full severity table and the top-10 Critical/High table to the conversation.

---

## Outputs

| File | Purpose |
|---|---|
| `Executive-summary-findings.md` | Markdown one-pager: severity table, top Critical/High, credential leaks, risk themes, per-language matrix. Suitable for pasting into a doc or Slack. |
| `Executive-summary-findings.html` | Self-contained dashboard with KPI cards, charts, and sortable tables. Suitable for sharing with leadership or attaching to a coordination meeting. |

Both files are written to `progress-tracker/metrics/dashboards/` (dashboards live with the metrics, separate from findings data; legacy location was the analysis-results root) and are overwritten on every run — the headline series lives in the metrics ledger. Both outputs embed the standard population block (roots, unit, filters, denominator — from python3 -m traust.cli corpus) as a final section/panel for cross-dashboard reconciliation.

---

## Operational notes

- **No network calls.** The script reads only local report files and the existing `gh-languages-cache.jsonl`. If the language cache is missing or stale, run `/loc-dashboard` first (or accept `Unknown` language buckets).
- **JSON preferred, MD fallback.** A `*security-audit.md` is parsed only when its `.json` sibling is absent. The MD parser is heuristic — it extracts the metadata table, the severity-count row/table, `### FIND-…` headers, inline `| Severity |` rows, and `CWE-\d+` references.
- **Triage verdicts are never a default counting source.** The trusted precedence is `findings-current.json` (ledger: live-validation, verify-remediation, countersigned decisions) → raw audit. `--include-triage` is the explicit opt-in, and its figures are always labeled. Schema trap if touching triage data: `severity` is the label, `severity_label` is the CVSS vector string (score in parentheses).
- **Dedup.** Critical/High and credential-leak tables deduplicate by the per-finding `fingerprint` (stable cross-scan identity embedding the canonical repo URL; recomputed via python3 -m traust.cli corpus finding-identity when the field is absent — findings-current ledgers predate the backfill), falling back to `(short-repo, title[:80])` for md-parsed findings. Raw occurrence counts are still shown alongside the unique counts.
- **Idempotent.** Safe to wire into `finalize_batch.sh` or a `/loop` after each audit batch lands.
- **Tuning.** Edit the constants at the top of `build_executive_summary.py`:
  - `CREDENTIAL_CWES` / `CREDENTIAL_TITLE_RX` — what counts as a secret leak
  - `THEME_MAP` — CWE → risk-theme bucket
  - `_LANG_CANON` — language-name normalisation

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: could not locate analysis-results root` | Wrong working directory / non-standard layout | Pass the path explicitly as `$ARGUMENTS` or set `$AUDIT_RESULTS_ROOT`. |
| `parsed 0 reports` | No `*security-audit.{json,md}` under `findings/` yet | Run audits first; this skill summarises *completed* reports only. |
| Most repos show language `Unknown` | `gh-languages-cache.jsonl` missing or stale | Run `/loc-dashboard` to (re)populate the cache, then re-run this skill. |
| HTML charts blank when opened offline | Chart.js loaded from `cdn.jsdelivr.net` | Open while online, or vendor `chart.umd.min.js` and update the `<script src>`. |

## Integrations

**Emits:** `Executive-summary-findings.{md,html}` — the human-facing
leadership pair — plus `Executive-summary-findings.metrics.json`, the
**machine sidecar** carrying every headline number (2026-07-31).

**Consumed by:** `/traust-metrics`
(`collect_harness_metrics.py`) reads the sidecar as scoreboard source
row #1 — the earlier "no skill reads it back" claim here was false
(docs-verification 2026-07-31, wiring c3), and worse, the collector
was regex-parsing the markdown *sentences*, so rewording the prose
silently blanked leadership metrics. The sidecar is now the contract:
change a headline number's meaning → update the sidecar key and the
collector together; the md/html prose can be reworded freely.

Upstream inputs are the findings corpus (via python3 -m traust.cli corpus) and
the census population blocks; regenerate after any batch that moves
those.
