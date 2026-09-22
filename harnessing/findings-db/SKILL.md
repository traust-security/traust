---
name: findings-db
description: Use when the user asks an ad-hoc question over the findings corpus that reads like a query — "open criticals by business unit", "which repos have the most confirmed findings", "distinct CWE-1104 exposure across products", "how many findings were validated live" — or asks to build/refresh/query the findings database. Queries the storage/v1 SQLite store (analysis-results/graph/findings.db) through the contract's views instead of walking 8k JSON files.
metadata:
  harness.tier: "secondary"
---

# Findings DB — storage/v1 on SQLite

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


One SQLite file answering ad-hoc leadership questions in a query instead
of a JSON walk. **It is the traust-contracts storage/v1 store on SQLite**:
the same tables and views a database adopter reads on PostgreSQL,
populated from the artifact tree by the same corpus resolution `/census`
counts. **It is a projection, never an authority**: `/census` owns the
denominators, the disposition ledgers (`*-findings-layer.json`) remain the
source of truth and the only write path, and this DB is rebuilt from them
— deleting it loses nothing.

ONE schema, TWO backends. An adopter who keeps artifacts in git gets this
file; an adopter on PostgreSQL gets the same views populated at submit
time. A query written against a view here runs unchanged there
(`traust-contracts/storage/v1/{sqlite,postgres}/views/`), and the Go SDK
exposes every consumption view as a typed `Query*` method.

## Build / refresh

```bash
python3 -m traust.cli corpus findings-db   # <analysis-results>/graph/findings.db
```

A full rebuild ingests every artifact through the contract (validating
each against its schema) and takes minutes, not seconds; the file is
several GB because the store retains the exact bytes of every artifact,
as the contract specifies. It is written to a sibling `.building` file
and renamed into place, so a reader never sees a half-built store. The
census (Step 2c) rebuilds it on every run; rebuild manually whenever
freshness matters. **Always check staleness before answering from it:**

```sql
SELECT value FROM meta WHERE key='built_at';
```

If the ledgers changed since `built_at`, rebuild first. When a DB number
contradicts a census/dashboard number, the census wins — rebuild and
re-query rather than reconciling by hand.

**An artifact the contract rejects is in none of the contract tables.**
`meta` says how many and why:

```sql
SELECT key, value FROM meta
WHERE key IN ('ingest_accepted', 'ingest_rejected', 'ingest_reasons');
```

That is a data-quality queue for the producers, not something to
reconcile around.

## Schema

The contract's tables and views — `traust-contracts/storage/v1` — plus
five harness-defined tables that have no contract home yet.

**Read the views, not the tables.** The tables keep a row per binding,
including superseded restatements; the views resolve "current" and join
ownership. Every scoped view carries `scope_id` and, where it applies,
`subject_id` — the repo key — so a view joins to `repos` on
`repos.repo_key = <view>.subject_id`.

| View | Contents |
|---|---|
| `current_finding` | the spine: one row per CURRENT finding, both families (`code` from reports, `policy` from cloud-config), with `ownership`, `business_unit`, `tree`, `is_branch_audit`, `report_kind`, `cwes`, `effective_severity`, `cvss_score`. Unfiltered on disposition. |
| `open_findings` | open exposure: not affirmatively closed, not a false positive, **hardening excluded** |
| `hardening_findings` | the hardening/posture-debt class, separated |
| `distinct_exposure` | Lens 2: one row per fingerprint over owned HEAD open findings; `severity_example` is the highest by rank |
| `census_population`, `census_exposure`, `census_distinct`, `census_branch` | the census's denominators, exposure classes, per-cut distinct identities and branch confirmations |
| `finding_timeline`, `exposure_trend`, `finding_sla`, `sla_threshold` | the time dimension over `layer_event`: first seen, adjudicated, resolved; opened/closed per month; SLA state against the ingested policy |
| `validation_current`, `validation_exposure` | what happened when a finding was attempted live |
| `advisory_exposure` | blast radius: one row per repository an advisory reaches, with the evidence tier |
| `threat_current`, `threat_exposure`, `boundary_current` | modelled threats and tenant boundaries with their owner |
| `pattern_exposure`, `attack_coverage`, `compliance_posture`, `verification_current`, `verification_regression_current`, `remediation_current`, `operator_privilege`, `pqc_posture`, `pqc_readiness_rollup`, `doc_variance_current` | one view per dashboard aggregate |

| Table (harness-defined) | Contents |
|---|---|
| `repos` | one row per report record (corpus resolver identity): `repo_key` (= `subject_id`), tree, ownership, business_unit, label, product, ref, `report_kind`, the seven artifact refs |
| `graph_edges` | repo-graph edges (`ships`, `owned-by`, …) for product-reach joins |
| `provenance` | which external identifier (CVE, GHSA, Jira) a finding became — the ledger's `external_refs` |
| `decisions` | the ADR index, for `decision_refs` joins |
| `meta` | `built_at`, `schema_revision`, `storage_revision`, the ingest outcome, **the authority rule** |

Tables of the contract worth knowing by name: `report_finding` and
`cloud_config_finding` (one row per finding per report binding),
`layer_event` (every dated disposition transition, with the actor's
identity), `validation_finding`, `impact_repo`, `threat`,
`subject_ownership`. The full DDL is in
`traust-contracts/storage/v1/sqlite/schema/`.

## Query it

```bash
sqlite3 ../analysis-results/graph/findings.db "<SQL>"
```

Examples:

```sql
-- open criticals by business unit (Lens 1, occurrences)
SELECT business_unit, COUNT(*) FROM open_findings
WHERE severity='critical' GROUP BY 1 ORDER BY 2 DESC;

-- distinct owned exposure by primary CWE (Lens-2 approximation)
SELECT json_extract(cwes, '$[0]') AS primary_cwe, COUNT(DISTINCT fingerprint)
FROM current_finding
WHERE ownership='owned' AND is_branch_audit=0
  AND COALESCE(resolution,'open') NOT IN ('resolved','risk_accepted')
  AND COALESCE(validity,'confirmed') NOT IN ('false_positive','hardening')
GROUP BY 1 ORDER BY 2 DESC LIMIT 15;
-- (or read pattern_exposure, which fans every CWE out rather than the first)

-- live-validation outcomes
SELECT verdict, COUNT(*) FROM validation_current GROUP BY 1;

-- MTTA per severity: days from first ledger event (detection) to first
-- RESOLVED event backed by verification/validation evidence
WITH detected AS (
  SELECT b.subject_id, e.finding_ref, MIN(e.occurred_at) AS t0
  FROM layer_event e JOIN artifact_binding b ON b.binding_id = e.binding_id
  GROUP BY 1, 2
), fixed AS (
  SELECT b.subject_id, e.finding_ref, MIN(e.occurred_at) AS t1
  FROM layer_event e JOIN artifact_binding b ON b.binding_id = e.binding_id
  WHERE e.resolution = 'resolved'
    AND e.source_type IN ('verification_report', 'validation_report')
  GROUP BY 1, 2
)
SELECT c.severity, COUNT(*) n,
       ROUND(AVG(julianday(x.t1) - julianday(d.t0)), 1) AS mtta_days
FROM fixed x JOIN detected d USING (subject_id, finding_ref)
JOIN current_finding c ON c.subject_id = x.subject_id AND c.finding_id = x.finding_ref
GROUP BY c.severity ORDER BY mtta_days DESC;
-- (finding_timeline already carries days_to_resolve per fingerprint)

-- which products ship the repos with open criticals
SELECT ge.from_id AS product, COUNT(DISTINCT o.subject_id) AS repos
FROM open_findings o JOIN repos r ON r.repo_key = o.subject_id
JOIN graph_edges ge ON ge.rel = 'ships'
  AND ge.to_id = 'repo:' || REPLACE(REPLACE(r.repo_url,
                                            'https://', ''), '.git', '')
WHERE o.severity = 'critical'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- blast radius of one advisory, strongest evidence first
SELECT repo, classification, evidence_level, direct
FROM advisory_exposure WHERE advisory = 'CVE-…'
ORDER BY CASE evidence_level WHEN 'symbol' THEN 0 WHEN 'binary' THEN 1 ELSE 2 END;
```

## Constraints — read before presenting numbers

- **Label the lens.** `open_findings` counts occurrences (Lens 1);
  `COUNT(DISTINCT fingerprint)` and `distinct_exposure` are Lens 2. Never
  mix them in one sentence without saying so (PROCESS.md three-lens
  taxonomy).
- **Headline numbers come from the census/dashboards**, not from here.
  Use the DB for exploration, slicing, and answering questions the
  dashboards don't pre-compute; when a number will be quoted upward,
  reconcile it against the census first.
- **Filter by `report_kind` before blending.** Code audits, declared-layer
  IaC audits and container-image audits are different units.
- **Read-only.** Nothing updates the DB in place; the disposition
  ledger remains the only write path for finding state. To change a
  finding's disposition, emit a ledger event (track-findings flow) and
  rebuild.
- The DB file is **gitignored and local**; never commit it, never ship
  it as an artifact of record.

## Integrations

**Consumes:** the per-repo disposition ledgers `*-findings-layer.json`
and preferred reports (corpus resolution via python3 -m traust.cli corpus;
producer: `/track-findings` and the audit skills), every other artifact
family the contract declares (threat models, validations, verifications,
PQC facts, `/impact-analysis` artifacts under `analysis-results/impact/`,
operator privilege profiles), and repo-graph edges (`graph_edges`).

**Emits:** `analysis-results/graph/findings.db` (via
python3 -m traust.cli corpus findings-db) — the storage/v1 store, a
projection and never an authority (docs/disposition-ledger.md §11b).
Besides this skill, `/census` (Step 2c) and `/refresh-dashboards`
(projections stage) rebuild it; `/sla-view` and `/compliance-check`
rebuild-if-stale before reading.

**Consumers** (all read-only accelerators — none may author a verdict
or substitute for the ledger):

| Skill | Touchpoint |
|---|---|
| `/vuln-scan` | diff-mode baseline resolution (`resolve_baseline.py --db`, `repos`) |
| `/verify-remediation` | sweep scoping / accelerator queries |
| `/dependency-watch` | `advisory_exposure` + `repos` baselines |
| `/compliance-check` | `findings_db` collector — `open_findings` joined to the spine |
| `/sla-view` | python3 -m traust.cli metrics sla clock inputs (`layer_event`, `current_finding`) |
| `/fleet-fix` | optional candidate listing (`open_findings` + `graph_edges`) |
| `/mine-ledger` | optional cluster-shape pre-queries (DB for scoping; the miner stays file-based) |
| `/traust-metrics` | cloud-config lane (`collect_harness_metrics.py`, `current_finding`) |
| `/refresh-dashboards` | downstream dashboard builders read the views |
| `/drift-watch` | staleness sentinel (`built_at` vs newest ledger/report mtime) — watches the DB, never queries findings from it |

The daily rescan router (python3 -m traust.cli build rescan-worklist) also reads
it (`open_findings` + `repos`) when assembling the diff-lane worklist.
