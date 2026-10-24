# Campaign workflow

How the end-to-end scanning campaign runs across an organisation: the helper repositories it needs, the campaign-bound skills, and the runtime directory structure. For single-skill local use see [standalone-usage.md](standalone-usage.md); for the pipeline overview see the [README](../README.md#how-to-use-this-workflow-engine).

The campaign workflow uses the [standalone skills](standalone-usage.md), plus a few additional campaign-specific skills, and works against a few fixed and private (due to data sensitivity) repositories that enable an automated data-flow from inventory through scanning to remediation.  These helper repositories are:

* **Inventory Repository** - this forms the _inputs_ to the security scan.  For operators of a campaign, this is the *-inputs repository(ies). This contains a structured inventory of all repositories in active projects/products to scan.  
* **Traust Workflow Engine** - this repository!  This contains all of the skills used throughout the campaign stages

## Campaign-bound skills

These skills are specific to the scanning campaign. They consume the full `*-results/` and/or `*-inputs/` trees as aggregate input and produce cross-portfolio dashboards or rollups.

| Skill | Stage | What It Does | Min Model |
|-------|-------|--------------|-----------|
| `census` | — | Corpus census: report population per ownership cut, five duplication vectors, the **distinct-vulnerabilities** canonical headline, repo liveness — the denominator authority every other dashboard cites (`findings.db `repos``) | opus-class |
| `add-inputs` | ① | Ad-hoc registration of repos or whole orgs into the inputs inventory (`locations.inputs`) — the lightweight counterpart of `inventory-repositories` | opus-class |
| `inventory-repositories` | ① | Discovers every source repo shipped in a release payload image or an OLM operator bundle (segment kinds `release-payload` / `catalog` in `<inputs>/inventory.yaml`) writes the per-segment CSV inventory and registers the repositories and owner teams in traust-core | opus-class |
| `corpus-intake` | — | The only supported write path for traust-core's corpus registry — interview-driven registration of corpus trees/engagements with ownership tags (owned / upstream / external-bu), validated writes in one transaction, census refresh | opus-class |
| `financial-tracking` | — | Campaign cost over time: per-lane spend, **per-business-unit** split (bridged from transcript paths via findings.db `business_unit`; partial coverage, always stated), unit economics ($/repo, $/finding), month-over-month trend, and an `--invoice` seam. All figures are **list-price estimates, never invoiced actuals** | opus-class |
| `executive-summary-findings` | — | Cross-portfolio leadership roll-up dashboard (deterministic builder + machine sidecar for the scoreboard) | haiku-class (`render-narrate` floor) |
| `loc-dashboard` | — | Lines-of-code coverage dashboard (also reads the inputs inventory) | haiku-class (`render-narrate` floor) |
| `insecure-patterns` | — | Cross-portfolio insecure-coding-pattern roll-up (CWE → OWASP ASVS taxonomy) | mythos-class |
| `findings-trends` | — | Up/down trend dashboard by ledger replay: burndown, headline risk signals (`owasp_high_plus_pct`, `mean_cvss_open`), velocity, MTTR, accepted-risk register | haiku-class (`render-narrate` floor) |
| `validation-fuzz-dashboard` | — | Combined live-validation + fuzzing results dashboard | opus-class |
| `threat-register` | — | Fleet-wide threat roll-up from every threat-model file: open-threat exposure by product, stable `<slug>:<Tn>` keys, class-closing quick wins | opus-class |
| `isolation-review` | — | Service-level tenant-isolation review (PEACH cited by reference only): interface inventory from the portfolio graph + existing findings, per-interface complexity, five hardening dimensions with cited evidence, posture + prioritized gaps | mythos-class |
| `traust-metrics` | — | Campaign metrics scoreboard + append-only hash-chained metrics-history ledger and Executive-Trends dashboard under `progress-tracker/metrics/` | opus-class |
| `rbac-tenancy-rollup` | — | RBAC + multi-tenancy misconfiguration rollup: executive one-pager, top-misconfigurations detail, HTML dashboard, MITRE ATT&CK candidate inference | opus-class |
| `attack-coverage` | — | Fleet-wide MITRE ATT&CK coverage rollup joining observed (live-validation), modeled (threat-model), and derived (category-mapped) technique IDs into a Navigator layer | opus-class |
| `compliance-check` | — | Evidence-gated per-control compliance assessment (PCI DSS, NIST 800-53, FedRAMP, SOC 2, GDPR slice); deterministic verdicts the agent cannot override | mythos-class |
| `property-test` | ⑦ | Authors a property test for a patched sink with an algebraic shape (codec, parser, normaliser, comparator, validator, bounds) and runs it against the unpatched and patched revisions; emits `property` evidence only when it fails before the fix and passes after. Says "an example test is the right answer here" when the sink has no such shape | opus-class |
| `fleet-fix` | ⑦ (fleet) | Remediates one systemic pattern across every affected repo via a schema-validated transform spec with mandatory golden tests; MRs only after human batch approval | opus-class |
| `sla-view` | — | Per-severity resolve clocks replayed from the disposition ledgers against a schema-validated SLA policy (default: Red Hat PSIRT VMWM) — breach counts, overdue lists | opus-class |
| `findings-db` | — | Queryable SQLite projection of the findings corpus for ad-hoc leadership questions; a projection, never an authority (ledgers stay the source of truth) | opus-class |
| `drift-watch` | — | Staleness/drift report over the harness's own derived artifacts and source pairs (feeds, findings.db, graphs vs inputs) | sonnet-class |
| `refresh-dashboards` | — | One-command rebuild of every deterministic dashboard in dependency order (projections → consumers → scoreboard); packages the weekly "Dashboards rebuild" job | sonnet-class |
| `recall-benchmark` | — | Ground truth for the auditor itself: re-audits pinned pre-fix refs of repos with known-real findings and measures detection recall | mythos-class |

## Campaign Directory Structure
Alongside runtime requirements (infrastructure requirements, orchestration), the campaign requires a very specific runtime file structure.

```
workspace/                              # Run the agent from here
├── traust/                # This repository (skills, schema, tooling)
├── *-inputs/                           # Repository inventories (CSVs, Markdown, owners)
│   ├── openshift/                      #   — campaign-bound skills only
│   ├── operator-catalog/
│   └── services/
│       └── <service>/
│           ├── <service>-repos.csv
│           └── <service>-repos.md
└── *-results/                          # Audit output
    ├── findings/
    │   ├── _manifest/                  # Campaign manifests, progress tracking
    │   │   ├── *-manifest.csv
    │   │   └── rescan-worklist.json
    │   ├── <product>/
    │   │   └── <repo>/
    │   │       ├── <repo>-security-audit.{md,json}
    │   │       ├── <repo>-findings-layer.json       # disposition ledger (track-findings)
    │   │       ├── <repo>-findings-current.{md,json}
    │   │       ├── <repo>-threat-model.md
    │   │       ├── <repo>-triage.{md,json}
    │   │       ├── <repo>-attack-plan.yaml          # validate-findings
    │   │       ├── <repo>-validation.{md,json}      # validate-findings
    │   │       ├── validation-audit.jsonl           # validate-findings
    │   │       ├── artifacts/                       # validate-findings evidence
    │   │       └── <image>-container-audit*.{md,json}  # secure-container-audit report +
    │   │                                            # its full-stem ledger artifacts
    │   └── <stream>/                    # dist-git streams (c10s, c9s) — secure-rpm-audit
    │       └── <component>/<component>-security-audit.{md,json}
    ├── oss-findings/
    │   └── <org>/<repo>/<repo>-security-audit.{md,json}
    └── validations/
        └── <slug>/                     # Per-operator/CO validation runs
```
