---
name: findings-db
description: Use when the user asks an ad-hoc question over the findings corpus that reads like a query — "open criticals by business unit", "which repos have the most confirmed findings", "distinct CWE-1104 exposure across products", "how many findings were validated live" — or asks to build/refresh/query the findings database. Queries the SQLite projection (analysis-results/graph/findings.db) instead of walking 8k JSON files.
metadata:
  harness.tier: "secondary"
---

# Findings DB — Queryable Projection of the Findings Corpus

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


One SQLite file answering ad-hoc leadership questions in a query instead
of a JSON walk. **It is a projection, never an authority**: `/census`
owns the denominators, the disposition ledgers (`*-findings-layer.json`)
remain the source of truth and the only write path, and this DB is
rebuilt from them — deleting it loses nothing.

## Tables of note

Alongside the findings/events/validations core, the DB projects
`/impact-analysis` artifacts (`analysis-results/impact/`) into an
`impact` table — `SELECT repo_id, classification, evidence_level FROM
impact WHERE cve = 'CVE-…'` answers blast-radius questions without a
JSON read. Projection only: the artifacts stay the source of truth, and
`/drift-watch` flags artifacts older than the graph they queried.

## Build / refresh

```bash
python3 -m traust.cli corpus findings-db   # <analysis-results>/graph/findings.db
```

Full deterministic rebuild (< 1 min, 8k+ repos). The census (Step 2c)
rebuilds it on every run; rebuild manually whenever freshness matters.
**Always check staleness before answering from it:**

```sql
SELECT value FROM meta WHERE key='built_at';
```

If the ledgers changed since `built_at`, rebuild first. When a DB number
contradicts a census/dashboard number, the census wins — rebuild and
re-query rather than reconciling by hand.

## Schema

| Table / view | Contents |
|---|---|
| `repos` | one row per report record (corpus resolver identity): tree, ownership (`owned`/`upstream`/`external-bu`), business_unit, label, product, branch ref, md-only flag |
| `findings` | one row per finding in each repo's preferred report: severity, primary CWE, CVSS, fingerprint, disposition (validity/resolution/assurance), paths |
| `events` | disposition-ledger events (recorded/occurred timestamps, source, actor, disposition) |
| `validations` | live-validation verdicts from `validations/**/*-validation.json`, joined to repos best-effort |
| `graph_edges` | repo-graph edges (`ships`, `owned-by`, …) for product-reach joins |
| `v_open` | open exposure (not affirmatively closed, not a false positive, **hardening excluded** per dashboard convention) with repo context columns |
| `v_hardening` | the hardening/posture-debt class, separated like the dashboards |
| `v_distinct_owned` | Lens-2-style distinct fingerprints over owned HEAD audits (approximation — census parity rules are stricter) |
| `meta` | `built_at`, harness version, **the authority rule** |

## Query it

```bash
sqlite3 ../analysis-results/graph/findings.db "<SQL>"
```

Examples:

```sql
-- open criticals by business unit (Lens 1, occurrences)
SELECT business_unit, COUNT(*) FROM v_open
WHERE severity='critical' GROUP BY 1 ORDER BY 2 DESC;

-- distinct owned exposure by CWE (Lens-2 approximation)
SELECT primary_cwe, COUNT(DISTINCT fingerprint) FROM v_open
WHERE ownership='owned' AND is_branch_audit=0
GROUP BY 1 ORDER BY 2 DESC LIMIT 15;

-- live-validation outcomes for confirmed findings
SELECT v.verdict, COUNT(*) FROM validations v GROUP BY 1;

-- MTTA per severity (VVAH plan P7): mean days from first ledger event
-- (detection) to first RESOLVED event backed by verification/validation
-- evidence — the "discovery -> validated fix" clock leadership will be
-- asked to compare against other harnesses
WITH detected AS (
  SELECT repo_key, finding_id, MIN(occurred_at) AS t0
  FROM events GROUP BY repo_key, finding_id
), fixed AS (
  SELECT repo_key, finding_id, MIN(occurred_at) AS t1 FROM events
  WHERE resolution = 'resolved'
    AND source_type IN ('verification_report', 'validation_report')
  GROUP BY repo_key, finding_id
)
SELECT f.severity, COUNT(*) n,
       ROUND(AVG(julianday(x.t1) - julianday(d.t0)), 1) AS mtta_days
FROM fixed x JOIN detected d USING (repo_key, finding_id)
JOIN findings f USING (repo_key, finding_id)
GROUP BY f.severity ORDER BY mtta_days DESC;

-- which products ship the repos with open criticals
SELECT ge.from_id AS product, COUNT(DISTINCT o.repo_key) AS repos
FROM v_open o JOIN repos r USING (repo_key)
JOIN graph_edges ge ON ge.rel = 'ships'
  AND ge.to_id = 'repo:' || REPLACE(REPLACE(r.repo_url,
                                            'https://', ''), '.git', '')
WHERE o.severity = 'critical'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
```

## Constraints — read before presenting numbers

- **Label the lens.** `v_open` counts occurrences (Lens 1);
  `COUNT(DISTINCT fingerprint)` is Lens 2. Never mix them in one
  sentence without saying so (PROCESS.md three-lens taxonomy).
- **Headline numbers come from the census/dashboards**, not from here.
  Use the DB for exploration, slicing, and answering questions the
  dashboards don't pre-compute; when a number will be quoted upward,
  reconcile it against the census first (`v_distinct_owned` is an
  approximation — census exclusion rules are stricter).
- **Read-only.** Nothing updates the DB in place; the disposition
  ledger remains the only write path for finding state. To change a
  finding's disposition, emit a ledger event (track-findings flow) and
  rebuild.
- The DB file is **gitignored and local**; never commit it, never ship
  it as an artifact of record.

## Integrations

**Consumes:** the per-repo disposition ledgers `*-findings-layer.json`
and preferred reports (corpus resolution via python3 -m traust.cli corpus;
producer: `/track-findings` and the audit skills), `/impact-analysis`
artifacts under `analysis-results/impact/` (projected into the `impact`
table), and repo-graph edges (`graph_edges`).

**Emits:** `analysis-results/graph/findings.db` (via
python3 -m traust.cli corpus findings-db) — a projection, never an authority
(docs/disposition-ledger.md §11b). Besides this skill, `/census`
(Step 2c) and `/refresh-dashboards` (projections stage) rebuild it;
`/sla-view` and `/compliance-check` rebuild-if-stale before reading.

**Consumers** (all read-only accelerators — none may author a verdict
or substitute for the ledger):

| Skill | Touchpoint |
|---|---|
| `/vuln-scan` | diff-mode baseline resolution (`resolve_baseline.py --db`) |
| `/verify-remediation` | sweep scoping / accelerator queries |
| `/dependency-watch` | `impact` table + `repos` baselines |
| `/compliance-check` | `findings_db` collector — pre-shaped views over ledger conclusions |
| `/sla-view` | python3 -m traust.cli metrics sla clock inputs |
| `/fleet-fix` | optional candidate listing (`v_open` + `graph_edges`) |
| `/mine-ledger` | optional cluster-shape pre-queries (DB for scoping; the miner stays file-based) |
| `/traust-metrics` | cloud-config lane (`collect_harness_metrics.py`) |
| `/refresh-dashboards` | downstream dashboard builders read the fresh projection |
| `/drift-watch` | staleness sentinel (`built_at` vs newest ledger/report mtime) — watches the DB, never queries findings from it |

The daily rescan router (python3 -m traust.cli build rescan-worklist) also reads
it when assembling the diff-lane worklist.
