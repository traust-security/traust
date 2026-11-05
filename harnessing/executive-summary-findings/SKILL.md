---
name: executive-summary-findings
description: Use when the user asks for an executive summary, leadership roll-up, or cross-portfolio dashboard of security-audit findings — e.g. "summarise all findings", "how many criticals do we have", "credential leaks across the campaign", "findings by language", or "rebuild the executive summary". Aggregates every finding recorded in traust-core into a one-page Markdown brief and a self-contained HTML dashboard.
metadata:
  harness.tier: "secondary"
---

# Executive Summary — Findings

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Roll up every recorded finding (traust-core's `ExecutiveSummaryView`) into a leadership-ready summary: severity totals, top Critical/High findings, credential & secret leaks, common CWE risk themes, and a per-language breakdown. Outputs both a Markdown one-pager and an interactive HTML dashboard.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Standard run — every repository in the inventory, write the outputs. |
| `open` | Open the resulting HTML dashboard in the default browser when done. |
| `summary` | After building, print the severity table and top-5 themes/criticals to the conversation. |
| `by-segment` | *Retired:* scope is product or team (`--product`, `--team-id`). Was: add a per-input-segment breakdown (one row per inventory segment), mapping each repo against the inputs inventory (`locations.inputs`). The `ansible` input is excluded by default (`--exclude-segment` to change). Pass `--by-segment` to the script. |
| `include-triage` | *Retired:* the decision fold is the one counting source; unconfirmed triage verdicts are never counted. Was: for repos without a `findings-current` disposition ledger, count from unconfirmed `/triage` verdicts (true positives only) instead of the raw audit. **OFF by default** — early /triage runs over-marked false positives (unreachable repos, hardening misfiled as FP), so counting TP-only silently trusts those bad FP exclusions. When enabled, every affected figure is labeled "unconfirmed triage" in both outputs (KPI card + warning note with FP-excluded and undetermined counts). Pass `--include-triage` to the script. |
| `exclude-branch-variants` | *Retired:* repositories are unique inventory rows. Was: skip `__`-slugged release-branch re-audits when the same product tree also carries the base-slug audit (the within-product duplicate case, e.g. `rhacm/search-v2-api` holding main + release-5.1 audits). Branch-only audits — per-release payload products like `openshift-4.14-payload`, where the branch audit is the only audit — always count: release branches are tracked per-branch by design. The excluded-report count is stated in both outputs. Pass `--exclude-branch-variants` to the script. |
| `<product slug>` | Only that product's repositories (`--product`, repeatable; `--team-id <uuid>` for a team). |
| `as-of <ISO time>` | The summary as it stood then (`--as-of`, with a zone). |
| `panel <name>` | Compose a retained domain panel with `--panel attack`, `--panel pqc`, `--panel isolation` or `--panel iac` (repeatable); results stay inside the executive Markdown, HTML and JSON. |

---

## Procedure

### Step 1 — Locate the dashboards folder

*Retired:* findings come from traust-core, not the analysis-results tree. Write the view to `progress-tracker/metrics/dashboards/` (or where the user asks).

### Step 2 — Run the command

```bash
python3 -m traust.cli dashboard view executive-summary \
    [--product <slug>]... [--team-id <uuid>]... [--as-of <ISO time>] \
    [--panel attack] [--panel pqc] [--panel isolation] [--panel iac] \
    --out <progress-tracker>/metrics/dashboards
```

What it does (traust-core's `ExecutiveSummaryView`, one `InsightService.publish`):

1. *Retired:* file discovery, MD/JSON parsing and the `findings-current` precedence; each finding's state comes from the decision fold (human-confirmed false positives, resolved, risk-accepted and hardening are counted apart from open). The view renders the "Remediation Status" closure rate and the remediated count by severity; *retired:* the per-month remediation chart (the trend is `traust dashboard view findings-trend`). Was: walks `<results-root>/findings/` and `<results-root>/oss-findings/` for every `*security-audit.json` (preferred) or `*security-audit.md` (fallback when no JSON sibling exists). The `_manifest/` directory is skipped. When a sibling `*-findings-current.json` (cumulative report from the `track-findings` skill) exists, it is used **instead of** the audit by default: human-confirmed false positives are excluded from every figure, severity counts are recomputed from the surviving findings, and per-finding resolution status feeds a "Remediation Status" section (Markdown) / KPIs + cards (HTML): closure rate across dispositioned repos, a "Findings remediated" count broken down by severity, and a per-month remediation trend (stacked resolved / partially-resolved bar chart, bucketed by each finding's last disposition event date).
2. Resolves each repository's primary language from the lines the code-facts scan measured (`CodeFactsService.language_stats`); an unmeasured repository is `unknown`.
3. Aggregates:
   - Per-severity totals (Critical / High / Medium / Low / Informational)
   - *Retired* (repositories are unique inventory rows; counts are per repository): a **"unique repos" KPI** alongside the report count: reports deduplicated
     by canonical repository URL (identical across mirror products and branch
     re-audits), falling back to the component slug with any `__<branch>`
     suffix stripped — so "N reports across M unique repositories"
     reads correctly even though totals remain per-report occurrences
   - *Retired* (the fold counts each finding once; the upstream cut is a product/team scope; a release branch is the same finding by repository fingerprint, so there are no separate confirmations): a **Distinct Vulnerabilities** section (Lens 2, the canonical exposure
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
   - *Retired* (scope is product or team): with `--by-segment`, a per-input-segment severity matrix. Every `*-repos.csv` under every segment of the inputs inventory (`locations.inputs`; the `ansible` input and any `--exclude-segment` skipped; `owners*.csv` ignored) is read into a canonical-URL → segment map; each report's `metadata.repository` resolves to its first matching segment in priority order — the declaration order of `<inputs>/inventory.yaml`, undeclared segments after by name (totals stay additive; the multi-segment overlap count is reported), and repos absent from the inventories — including all of `oss-findings/` — land in `unmapped`. Renders as a Markdown table and an HTML stacked-bar card + table. `--inputs-root` defaults to `locations.inputs`.
   - Top measured RBAC-surplus profiles, with the number scored; profiles without a tier-2 measurement remain unknown.
   - Per-advisory accountability joins canonical advisory identities (including aliases), impact counts when recorded, and scoped findings' filed/resolved clocks at the cutoff. Missing impact analysis is `null`, not zero affected.
   - Optional ATT&CK and PQC panels compose the retained domain models and reports. PQC retains its current-state/product-only boundary and refuses historical or team requests rather than silently mixing times or populations.
   - Optional isolation includes the latest completed default-line reviews, interface/gap counts, dimension results and the five weakest stated posture categories, plus modeled tenant boundaries. Optional declared IaC includes latest default-line target audits, suppressed/unsuppressed/needs-review counts, severity and ledger coverage; neither panel is evidence of live-cluster posture.
4. Stamps the traust-core version in the population block.
5. Writes `executive-summary-findings.{md,html,json}` in `--out`:
   - `.md` — leadership one-pager
   - `.html` — self-contained dashboard (summary, Critical/High table, credential-leak table, risk themes, per-language table)
   - `.json` — the view's model

### Step 2a — Trends

*Retired:* no metrics-ledger snapshot or "Trend vs" line; nothing is
stored. An earlier state is the same view with `--as-of`. *Retired:* the leadership
time-series view `progress-tracker/metrics/Executive-Trends.{md,html}`, with the metrics
history, and the as-reported snapshot archive (`dashboard capture`/`history`/`compare`:
traust-core stores no view).

### Step 2b — Explain missing language measurements

When the executive view contains unknown-language repositories, use
`/loc-dashboard` with the same product/team filters (the LoC view reads the latest
measurement only, so it takes no `--as-of`):

```bash
python3 -m traust.cli dashboard view loc \
    [--product <slug>]... [--team-id <uuid>]... \
    --out <loc-output-dir>
```

Read `lines-of-code.json` from that output directory. Match the executive
repositories by `repository_id` and carry their `unmeasured` reasons into
the report-back caveats (for example, no observed default head or no
qualifying scan). A missing measurement stays unknown, never zero lines
or evidence of an unsupported language. This is a diagnostic handoff only:
the executive view still computes its language matrix from recorded code
facts, not by parsing a dashboard export. After a missing scan is recorded,
regenerate the views rather than editing their generated rows.

The matching identities are in the executive JSON's
`rollup.repositories[]` and the LoC JSON's `repositories[]`. A recorded
empty language list with no `unmeasured` reason is a genuine measured
zero, not a missing scan; retain that distinction in the caveat.

For interactive drill-down, ask `/loc-dashboard explore` for
`loc-explorer.html`, open that trusted local page and import the same
`lines-of-code.json`. Use its "Not measured" size bucket to inspect
measurement gaps. Local filters never change the executive view's scope
or headline counts.

### Step 3 — Report back

Always tell the user:

- The two output paths (relative to the results root).
- Headline numbers: repositories in scope, total findings, Critical count, High count, credential-leak count, repos with ≥1 Critical.
- Top 3 risk themes.

If `summary` was requested, also print the full severity table and the top-10 Critical/High table to the conversation.

---

## Outputs

| File | Purpose |
|---|---|
| `executive-summary-findings.md` | Markdown one-pager: severity table, top Critical/High, credential leaks, risk themes, per-language matrix. Suitable for pasting into a doc or Slack. |
| `executive-summary-findings.html` | Self-contained dashboard with summary and tables. Suitable for sharing with leadership or attaching to a coordination meeting. |

Both files are written to `--out`, normally `progress-tracker/metrics/dashboards/` (dashboards live with the metrics, separate from findings data), and are overwritten on every run — the headline series is the view at an earlier `--as-of`. The view renders the standard population block.

---

## Operational notes

- **No network calls.** The view reads only traust-core's recorded state. Languages come from the code-facts scan; an unmeasured repository counts as `unknown`.
- **JSON preferred, MD fallback.** *Retired:* no report files are parsed.
- **Triage verdicts are never a counting source.** Each finding's state is the decision fold (live-validation, verify-remediation, countersigned decisions); `--include-triage` is retired.
- **Dedup.** Each finding is one record (its identity is the fingerprint), so the tables count it once; raw occurrence counts are retired.
- **Idempotent.** Safe to wire into `finalize_batch.sh` or a `/loop` after each audit batch lands.
- **Tuning.** The constants live in traust-core's `ExecutiveSummaryView`:
  - the credential CWE set and title pattern — what counts as a secret leak
  - the CWE → risk-theme map
  - `_LANG_CANON` is retired (languages come from the code-facts scan)

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Exit 2: product is not registered | Unknown `--product` slug | Check `traust products list`. |
| 0 open findings | No findings recorded in scope yet | Run audits first; this skill summarises *recorded* findings only. |
| Most repos show language `unknown` | No code-facts scan at their default-branch commit | Run the scan (see `/loc-dashboard`'s "Not measured" list), then re-run this skill. |

## Integrations

**Emits:** `executive-summary-findings.{md,html}` — the human-facing
leadership pair — plus `executive-summary-findings.json`, the view's
model, carrying every headline number (replaces the
`Executive-summary-findings.metrics.json` sidecar).

**Consumed by:** `/traust-metrics`
(traust-core's `ScoreboardView`) reads this view as scoreboard source
row #1 — the earlier "no skill reads it back" claim here was false
(docs-verification 2026-07-31, wiring c3), and worse, the collector
was regex-parsing the markdown *sentences*, so rewording the prose
silently blanked leadership metrics. The sidecar is now the contract:
change a headline number's meaning → update the sidecar key and the
collector together; the md/html prose can be reworded freely. (*Retired:*
the sidecar; traust-core's `ScoreboardView` composes this view
in-process.)

Upstream inputs are traust-core's recorded findings, code facts,
privilege profiles and impact analyses; regenerate after any batch that
moves those.

**Consumes:** `lines-of-code.json` from `/loc-dashboard` for the same-scope
missing-language diagnostic in step 2b. Its repository IDs and measurement
gaps explain the report-back caveats; neither the JSON nor its companion
prose is used to author or overwrite executive headline counts.
For interactive investigation it can also use `/loc-dashboard`'s
`loc-explorer.html` with that JSON; the page is not a new measurement or
a source of persisted findings.
