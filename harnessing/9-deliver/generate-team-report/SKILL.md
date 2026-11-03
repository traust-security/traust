---
name: generate-team-report
description: Use when the user asks to generate a shareable findings folder, executive summary, or team-specific security audit report for one or more products from traust-core's recorded findings.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# Generate Team Security Report

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Creates the executive-summary rollup (HTML dashboard + Markdown one-pager) for
a given set of products, and — **only when the user explicitly asks for a
self-contained/shareable folder** — a bundled copy of the component-level
findings to go with it. The default output is the rollup pair alone:
findings reports and evidence stay in their source of record
(`analysis-results/`), and the summaries link to them.

## When to Use

- User asks to "generate a report for [product/team]"
- User asks to "create a shareable folder of findings for [product]"
- User asks for an "executive summary" of findings for specific products
- User asks to "package findings" for coordination with a team

## Inputs

`$ARGUMENTS` is one or more **product names**, **team names**, or **operator names**.

The findings live in **traust-core**; products are registered by slug
(`traust products list`), teams by id (`--team-id`; no team-name lookup door yet).

Map user-provided names to product slugs. Common mappings:

| User says | Product slugs |
|-----------|-------------------|
| RHACM, ACM, Advanced Cluster Management | `rhacm/`, `advanced-cluster-management/` |
| MCE, Multicluster Engine | `multicluster-engine/`, `mce/`, `klusterlet-product/`, `placement-operator/` |
| Gatekeeper | `gatekeeper/`, `gatekeeper-operator-product/` |
| GlobalHub | `globalhub/`, `multicluster-global-hub-operator-rh/` |
| VolSync | `volsync/`, `volsync-product/` |
| OpenShift GitOps, ArgoCD | `openshift-gitops-operator/` |
| OpenShift Pipelines, Tekton | `openshift-pipelines-operator-rh/` |
| OpenShift AI, RHODS | `rhods-operator/` |
| Service Mesh v2 | `servicemeshoperator/` |
| Service Mesh v3 | `servicemeshoperator3/` |
| Kiali OSSM | `kiali-ossm/` |
| MCP Gateway | `mcp-gateway/` |

If the user names a product not in this table, search `traust products list`
for matching slugs or names (case-insensitive, partial match).

*Retired:* mirror directories. traust-core keeps one finding per fingerprint per
repository, and a product's repositories come from the portfolio, so there is no
canonical tree to pick and nothing to deduplicate.

## Procedure

### Step 1 — Locate the Analysis Results Repository

*Retired:* the findings are read from traust-core (`traust dashboard team-report`).

### Step 2 — Identify Source Directories

*Retired:* the product's repositories are its registered refs in the portfolio;
`traust dashboard team-report` reads them. (A bundle, Step 4, still copies the
report files from `analysis-results/`: no report-export door yet.)

### Step 3 — Extract Severity Data

Severity counts must be **disposition-aware** wherever the artifacts allow it —
raw audit reports overstate because they still contain findings later refuted or
resolved. (`traust dashboard team-report` counts this way, from each finding's
recorded decisions: false positives skipped; hardening routed to the Step 3a
backlog; resolved and risk-accepted counted separately (remediation progress,
not open exposure); the rest counted open by effective severity; execution-proven
findings badged, findings with no verdict yet counted as **"unverified"**.)

*Retired:* counting from triage TP/FP verdicts or raw audit files. A machine
verdict is one recorded decision among others in the fold, never a count source.

Report the excluded false-positive and resolved totals in the KPI tiles and
the Markdown one-pager
so readers see which counts are validated and which are raw audit output.
(The door's Summary section does.)

*Retired:* branch variants and the extraction script. Findings are counted once
per repository, whichever branch reported them; `extract_findings.py` and the
inline CVSS parsing are gone.

```bash
traust dashboard team-report --product <slug> [--product <slug>…] [--team-id <id>…] \
    [--as-of <ISO time>] --out <folder>
```

It prints the paths it wrote and the rollup model (totals, per product, per
repository, the critical and high findings).

### Step 3a — Extract the Hardening Backlog

Split confirmed weakness findings out of the vulnerability counts
(see `docs/disposition-ledger.md` §7). The recorded shape is
`validity: confirmed, kind: weakness`, not a new hardening validity.
Historical hardening decisions remain readable as backlog. Unknown kind
stays unknown; it is not a vulnerability default, and a kind alone never
confirms an undetermined or manual-review item. Consume the door's
disjoint backlog and vulnerability totals, not all confirmed findings as
exploitable exposure.

Collect per component: count, categories, titles + locations, and the
owner hint. These are **accurate defense-in-depth/benchmark gaps with no
demonstrated exploit path** — engineering hygiene and compliance work,
never presented as vulnerabilities, but never omitted: absent hardening
degrades posture and amplifies co-located vulnerabilities. In the
executive-summary HTML and Markdown one-pager (Steps 5-6), render a dedicated
**"Hardening Backlog"** section AFTER the severity tables (the door renders it):
per-component counts with category breakdown and a one-line framing ("posture debt —
λ-weighted in the portfolio risk index; file as regular engineering work
via `/file-security-defect --hardening`, not as security defects").

### Step 3b — Lift Attack Scenarios from Threat Models

When a component's `<component>-threat-model.md` contains a
`## 9. Attack scenarios` section (harness ≥ 0.33.0 emissions), lift it
**verbatim** into both executive-summary formats (HTML and Markdown) under an
"Attack scenarios" heading, attributed to the source threat model. These
narratives are written to the schema's bar — present tense, jargon-free,
readable by a non-technical VP — and are the single most effective
persuasion artifact in a team package; never paraphrase them into table
rows. Older threat models without section 9 get no such section (do not
synthesize one from the threat table). (`traust dashboard team-report` does:
each repository's latest threat model's `attack_scenarios`, verbatim and
escaped, one "Attack scenarios" section per scenario.)

### Step 4 — Create Output Folder

**Two output modes. Default is rollup-only.**

**Rollup-only (default).** Create
`progress-tracker/metrics/team-reports/<product-slug>-findings/` containing
ONLY the executive-summary pair from Steps 5–6
(`traust dashboard team-report … --out progress-tracker/metrics/team-reports/<slug>-findings/`):

```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Product>.html
└── Executive-Summary-<Product>.md
```

The progress-tracker repo carries rollups, dashboards, and summaries — never
copies of findings reports or evidence artifacts (owner directive,
2026-07-21: duplicating findings there widens access to embargoed material
and bloats the metrics repo). Both summary files must link to the
`analysis-results/` source paths for the detailed reports (e.g.
`analysis-results/findings/<product>/<component>/` or the engagement tree
such as `analysis-results/<engagement>-findings/<repo>/`), including
`fuzz-corpus/` evidence where present.

**Bundled (opt-in only).** Only when the user has explicitly asked for a
self-contained/shareable folder (e.g. "package the findings", "folder I can
email/drive-share"), additionally copy the component directories per the
layouts below — and **ask the user where the bundle should live before
writing it**. Never place bundles in progress-tracker (rollups only) and
never in the analysis-results repo (the aggregation dashboards scan its
trees — bundled copies double-count every component). A scratch export
directory or a drive-synced folder outside both repos is typical.
⚠️ Bundles contain EMBARGOED per-team findings — share them only with
Product Security + the affected teams.

Bundle layout for **single-product** reports:
```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Product>.html
├── Executive-Summary-<Product>.md
├── <ComponentA>/
│   ├── <ComponentA>-security-audit.md
│   ├── <ComponentA>-security-audit.json
│   ├── <ComponentA>-triage.json
│   ├── <ComponentA>-triage.md
│   └── <ComponentA>-threat-model.md      # if present
└── <ComponentB>/
    └── … (same set)
```

Bundle layout for **multi-product** reports, grouped by product:
```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Products>.html
├── Executive-Summary-<Products>.md
├── ProductA/
│   ├── componentX/
│   └── componentY/
└── ProductB/
    └── componentZ/
```

In bundled mode, **copy** the component directories (not symlink) so the
folder is fully self-contained and shareable. Use `cp -RL` so any
symlinked artifacts are dereferenced into real files. After copying, delete
pipeline scratch state from the package — it is internal checkpoint data, not
part of the deliverable:

```bash
find <slug>-findings -type d \( -name '.triage-state' -o -name '.threat-model-state' \) -exec rm -rf {} +
find <slug>-findings -name '.DS_Store' -delete
```

### Step 5 — Generate Executive Summary HTML

**Escaping is mandatory (CWE-79; assessment 2026-07-31 F12).** Every
value that originates in a finding — titles, impact text, action
descriptions, component names, theme labels — is attacker-influencable
(a hostile repo controls what its audit findings quote) and lands in an
HTML file opened from Drive/file:// beside embargoed content. Before
placing ANY finding-derived text into the HTML:

1. HTML-escape it (`&`, `<`, `>`, `"`, `'`). No exceptions — a finding
   title is never trusted markup.
2. The `<head>` MUST carry the CSP meta tag (in the reference
   template): `default-src 'none'; style-src 'unsafe-inline'` — the
   dashboard is fully self-contained, so any network fetch or script
   execution is hostile.
3. No remote subresources of any kind (no CDN scripts, no fonts, no
   images) and no `<script>` elements at all — the dashboard renders
   with inline CSS only.

(`traust dashboard team-report` renders the HTML through traust-core's
`HtmlRenderer`, which escapes every value and sets this CSP. The rules still
bind everything you add: banner, tracking reference, themes, actions, attack
scenarios, source links.)

*Retired:* the reference template and its exact structure and styling
(`references/executive-summary-template.html` is gone); the layout is core's
renderer. Sections 1–4 below now say what the door renders and what you add.

#### 1–4. Sections

| Section | Rendered by | Content |
|---------|-------------|---------|
| **Banner** | you | `RED HAT INTERNAL — EMBARGOED.` warning |
| **Header** | door (title, date); you (tracking reference) | Product name(s), date, the tracking reference from `traust.yaml` (`campaign.tracking_reference`, omitted when unset) |
| **KPI tiles** | door (Summary) | open by severity, execution-proven, unverified; false positives, resolved, risk accepted, hardening |
| **By product / By repository** | door | Component/product × severity tables |
| **Top findings table** | door (Critical and high findings) | repository, finding, severity, CVSS, proven, SLA due; sorted by severity then CVSS |
| **Hardening backlog** | door | Step 3a |
| **Themes** | you | §5 below |
| **Actions** | you | §6 below, with ≤7d / ≤30d / ≤90d horizons |
| **Footer** | you | Source references, methodology note |

#### 5. Theme Identification

Group Critical + High findings into recurring themes. Common themes observed:

- Multi-cluster trust collapse (hub↔spoke CSR/impersonate escalation)
- Over-privileged operator RBAC (secrets/rbac/exec cluster-wide)
- Confused-deputy SSRF → credential exfiltration
- Arbitrary container-image override → privileged execution
- Supply-chain integrity (unpinned refs, mutable tags, curl|sh)
- Auth bypass / hardcoded credentials / secret leakage
- Unauthenticated admin APIs / dashboards
- Code / config injection → RCE
- Approval-gate bypass (mutable thresholds)
- Multi-tenant boundary bypass (cross-namespace, cross-project)

Only include themes that have ≥1 Critical or High finding in the current data.

#### 6. Action Priorities

- **≤7d (`tag.now`)**: Critical findings — unauth RCE/admin, credential
  exfiltration, CSR bypass, system:authenticated over-grants
- **≤30d (`tag.d30`)**: High findings requiring code changes — RBAC reduction,
  confused-deputy fixes, auth hardening, approval-gate immutability
- **≤90d (`tag.d90`)**: Systemic hardening — supply-chain pinning, cipher
  upgrades, defense-in-depth, container hardening

### Step 6 — Generate the Markdown One-Pager

Name it as the HTML dashboard's pair — same basename, different extension:
`Executive-Summary-<Product>.md` (never a generic `README.md`; the Markdown
is the same executive summary in a paste-into-Slack/doc format, and the pair
must sort and share together). (`traust dashboard team-report` writes both.)

Include:
- `RED HAT INTERNAL — EMBARGOED` classification (you add)
- Date and the tracking reference from `campaign.tracking_reference` in `$TRAUST_CONFIG_HOME/traust.yaml` (omit the line when unset) (the door writes the date; you add the reference)
- Summary table: Component × Severity (Critical/High/Medium/Low/Info/Total) (the door)
- Folder structure tree (abbreviated) (you add, bundled mode)
- Top Critical findings with one-line impact descriptions (the door lists them; you add the impact lines)
- Source directory references (you add)

### Step 7 — Redact Secrets in Output

> **Canonical patterns:** python3 -m traust.cli util redact is now the single
> source for these patterns (plus Luhn-gated payment cards, SSNs, and
> URL credentials it added — VVAH plan P2). Prefer
> python3 -m traust.cli util redact over
> re-implementing the table below; the table remains as the
> human-readable contract.

Applies to both modes (summaries can quote finding evidence; bundles copy
whole reports). Scan every file in the output folder for secrets and partially redact them
in-place. The original files in `analysis-results/` are never modified.

For each match, keep the **first 5 characters** and replace the remainder
with `...REDACTED` (e.g., `AKIAI...REDACTED`, `xoxb-...REDACTED`).

#### Patterns to detect

| Category | Regex | Notes |
|----------|-------|-------|
| AWS access keys | `AKIA[0-9A-Z]{12,}` | |
| GitHub tokens | `gh[posru]_[a-zA-Z0-9]{30,}` | ghp_, gho_, ghs_, ghr_, ghu_ |
| GitHub fine-grained PATs | `github_pat_[a-zA-Z0-9_]{20,}` | |
| GitLab tokens | `glpat-[a-zA-Z0-9\-_]{20,}` | |
| Slack tokens | `xox[bpsa]-[a-zA-Z0-9\-]{10,}` | xoxb-, xoxp-, xoxs-, xapp- |
| OpenAI / LLM API keys | `sk-[a-zA-Z0-9]{20,}` | |
| Google API keys | `AIza[0-9A-Za-z_\-]{35}` | |
| Bearer tokens | `Bearer\s+[a-zA-Z0-9._\-]{20,}` | |
| JWT tokens | `eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}` | |
| PEM private key blocks | `-----BEGIN .*PRIVATE KEY-----` through `-----END .*PRIVATE KEY-----` | See special handling below |
| Password assignments | `(password\|passwd)\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| Secret assignments | `secret\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| Token assignments | `token\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| API key assignments | `api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |

#### PEM private key handling

Keep the `-----BEGIN` / `-----END` markers. Replace all lines between them
with a single line:

```
-----BEGIN PRIVATE KEY-----
[REDACTED — PEM key material removed]
-----END PRIVATE KEY-----
```

This applies to all PEM private key variants (`PRIVATE KEY`,
`RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, etc.).

#### Exclusions — do NOT redact

- **Git commit SHAs** — 40-character hex strings that appear after `commit`,
  `@`, `sha/`, `ref`, or inside a git/GitHub URL. These are not secrets.
- **CVSS scores** and version numbers.
- **Strings shorter than 8 characters** — too short to be a meaningful secret.
- **Pattern names used as examples** — lines that describe patterns rather than
  contain live values (e.g., `No AKIA…`, `scan for ghp_`). Use judgment: if
  the match is inside prose describing what to look for rather than a real
  credential, skip it.

#### Procedure

1. Use `grep -rn -P` with each pattern above against the output folder to
   identify matches.
2. For each match, apply the partial redaction using `sed -i` or the Edit
   tool.
3. After all redactions, report a summary: number of redactions, which files
   were modified, and a sample of redacted stubs.

### Step 7a — Snapshot the Package Metrics (trends)

*Retired:* the metrics-history snapshot. Every decision is timestamped, so the
previous package's numbers are the rollup as it stood then:

```bash
traust dashboard team-report --product <slug> --as-of <previous package date> --out <scratch>
```

When a previous package exists, render a "Trend vs previous package (<date>)" line in the
executive summary (HTML header + Markdown one-pager) using the deltas — e.g.
"Open findings ↓ 96 (improving) · Resolved ↑ 21".

### Step 8 — Verify

- Confirm file counts match expectations
- Report total size with `du -sh`
- Summarize output to user

## Output Format

Always present a final summary to the user with:
1. Output folder path and total size
2. Component × Severity table
3. Key critical/high findings highlighted

## Notes

- Report files follow an 8-section structure: Executive Summary, OWASP ASVS,
  K8s Top 10, CIS/STIG, Supply Chain, Detailed Analysis, Severity Summary,
  Remediation Roadmap.
- Finding IDs are sequential within each report (`FIND-001`, `FIND-002`, …).
- A repository several products ship counts under each product (the door's
  By product table says so); there are no mirror directories to reconcile.
- Some components have 0 CVSS-scored findings (stub reports from failed audits
  or org-URL manifest entries). These should still be included in the folder for
  completeness but will show 0 in the severity table.

## Integrations

**Consumes:** traust-core's findings rollup (`InsightService.publish`,
`findings-rollup`, through `traust dashboard team-report`), threat-model attack
scenarios (lifted verbatim into packages), and, for a bundle, the report files
under `analysis-results/findings/<product>/`.

**Emits:** self-contained findings packages under
`progress-tracker/processed-results/` (reports + executive-summary
HTML) — consumed by `/assign-findings-owners` (stage ⑨) and the Drive
sharing flow (delivery). Terminal for machine consumers by design: the
audience is the owning engineering team.
