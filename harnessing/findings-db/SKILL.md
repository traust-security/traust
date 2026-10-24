---
name: findings-db
description: Use when the user asks an ad-hoc question over the findings corpus that reads like a query — "open criticals by business unit", "which repos have the most confirmed findings", "distinct CWE-1104 exposure across products", "how many findings were validated live" — or asks to build/refresh/query the findings database. Queries traust-core's finding doors (traust findings summary / timeline / baseline) instead of walking 8k JSON files.
metadata:
  harness.tier: "secondary"
---

# Findings DB — Queryable Findings Corpus

One command answering ad-hoc leadership questions in a query instead
of a JSON walk. **It is a read, never an authority**: `/census`
owns the denominators, the recorded decisions (`traust findings decide`)
remain the source of truth and the only write path, and every answer is
derived from them on read — there is nothing to rebuild.

## Tables of note

Blast-radius questions are `/impact-analysis`'s recorded `impact`
assessments — `traust impact analyze <advisory-id>` answers them without a
JSON read (`ExposureService`, not this skill's doors).

## Build / refresh

*Retired:* every `traust findings` read is derived from the recorded
decisions when it runs, so there is no projection to build, refresh or go
stale. `--as-of <ISO time>` reads the corpus as it stood at a time.
When a number here contradicts a census/dashboard number, the census wins —
re-query rather than reconciling by hand.

## Schema

| Was (table / view) | Now | Contents |
|---|---|---|
| `repos` | `traust products list` (business unit, ownership); repositories and teams are the inventory skills' doors | registered repositories, their products and owning teams |
| `findings` | `traust findings baseline --repo-url <url>` / `status <id>` | one finding per fingerprint per repository: effective severity, primary CWE, CVSS, disposition (validity/resolution/assurance), SLA due, locations |
| `events` | `traust findings history <id>` | every decision on a finding (occurred time, source, actor, disposition) |
| `validations` | *another skill's door* (`ValidationService`, the validate-findings port) | live-validation verdicts |
| `graph_edges` | `/generate-team-report`'s rollup (per product and repository) | product reach |
| `v_open` | `traust findings summary … ` state `open` | open exposure (not affirmatively closed, not a false positive, **hardening excluded** per dashboard convention) |
| `v_hardening` | `traust findings summary …` state `hardening` | the hardening/posture-debt class, separated like the dashboards |
| `v_distinct_owned` | `traust findings summary --group-by cwe` | one finding per fingerprint per repository already, so counts are distinct within a repository |
| `meta` | *retired* | no projection: the doors are the authority |

## Query it

```bash
traust findings summary  --repo-url <url> --group-by <severity|cwe|category|label|origin|validity|resolution|repository> [--open|--closed] [--validity <v>] [--as-of <ISO>]
traust findings timeline --repo-url <url> [--bucket day|week|month] [--as-of <ISO>]
```

Each read is one repository; a portfolio question runs it per repository
and adds the rows up, or uses `/generate-team-report`'s per-product rollup.

Examples:

```bash
# open criticals by business unit (Lens 1, occurrences): per repository of the unit
traust findings summary --repo-url <url> --group-by severity --open

# distinct owned exposure by CWE (Lens 2)
traust findings summary --repo-url <url> --group-by cwe --open

# live-validation outcomes for confirmed findings
traust findings summary --repo-url <url> --group-by validity

# MTTA (VVAH plan P7): mean days from first report (detection) to fix, per
# bucket — the "discovery -> validated fix" clock leadership will be
# asked to compare against other harnesses (`mttr_days`; overall, not per severity)
traust findings timeline --repo-url <url> --bucket month

# which products ship the repos with open criticals
# -> /generate-team-report (open findings by severity per product and repository)
```

## Constraints — read before presenting numbers

- **Label the lens.** `open` counts occurrences (Lens 1);
  one finding per fingerprint (`--group-by cwe`) is Lens 2. Never mix them in one
  sentence without saying so (PROCESS.md three-lens taxonomy).
- **Headline numbers come from the census/dashboards**, not from here.
  Use the DB for exploration, slicing, and answering questions the
  dashboards don't pre-compute; when a number will be quoted upward,
  reconcile it against the census first (`--group-by cwe` is an
  approximation — census exclusion rules are stricter).
- **Read-only.** Nothing here updates a finding; recorded decisions
  remain the only write path for finding state. To change a
  finding's disposition, record a decision (track-findings flow:
  `traust findings decide`) and re-query.

## Integrations

**Consumes:** traust-core's recorded findings and decisions through
`FindingService` (`traust findings summary / timeline / baseline / history`;
producer: `/track-findings` and the audit skills) and the portfolio's
repositories and products.

**Emits:** nothing — a read, never an authority
(docs/disposition-ledger.md §11b).

**Consumers** (all read-only accelerators — none may author a verdict
or substitute for the ledger):

| Skill | Touchpoint |
|---|---|
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
