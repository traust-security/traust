---
name: threat-register
description: >-
  Use when the user asks for a fleet-wide or portfolio-wide view of threats
  (not findings) — "how many unmitigated critical threats do we have",
  "threat register", "which products carry the most open threat exposure",
  "what class-closing mitigations would pay off fleet-wide" — or asks to
  (re)build the threat register. Deterministically lists every threat the
  registered repositories' latest recorded threat models state (traust
  assessments threats), each keyed by a stable id per model and <Tn>.
argument-hint: "[--status <status>] [--technique <attack-id>]"
user-invocable: true
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Read
  - Glob
  - Bash(python3 *-m traust_engine.reporting.lint:*)
  - Bash(python3 *-m traust.cli assessments threats:*)
  - Bash(python3 *-m traust.cli dashboard view:*)
  - Bash(ls:*)
  - Bash(wc:*)
---

# threat-register

> **Ported to traust-core** (progress-tracker skill port 13, threat-register): build_threat_register.py retired with the traust-core hub (it ran on the old ledger / corpus code). Run lists the register's threats from traust-core; Output's roll-ups and json/md/html register are traust-core's threat-register view (`traust dashboard view threat-register`). The parts marked *Retired* or NEED don't run.

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


The fleet-wide roll-up of **threats** — the durable, survives-a-patch
abstractions from `/threat-model` artifacts — complementing the dashboards
that roll up **findings**. Findings answer "what defects exist at this
commit"; the threat register answers "what standing exposure does the
portfolio carry, what state is it in, and where would one control buy the
most".

## Identity model

Threat IDs are document-scoped (`T1`, `T2`, …) by design — a threat must
not be SHA-pinned, and the disposition ledger tracks findings, not
threats. The register derives a **stable id** from the recorded model's
assessment and the threat's `<Tn>` (`label`), with the `repository` it
belongs to; it is durable because schema.md forbids renumbering or
reusing threat IDs, so ids are globally unique. Threats cite canonical finding IDs in their `evidence` column —
that is the join to the ledger, and it runs in that direction only.

## Run

```bash
python3 -m traust.cli assessments threats [--status unmitigated] [--technique T1190]
```

One deterministic read (`--status` repeats). It reads each registered
repository's latest completed threat model recorded by `/threat-model`
(`traust reporting record`), which passed the contract gate on the way
in, so nothing is skipped; a repository whose model isn't recorded has no
rows. It never edits a model.

## Output

```bash
python3 -m traust.cli dashboard view threat-register \
    [--product <slug>]... [--team-id <uuid>]... [--as-of <ISO time>] \
    --out <progress-tracker>/metrics/dashboards/threat-register
```

`progress-tracker/metrics/dashboards/threat-register/threat-register.{json,md,html}` (traust-core's `ThreatRegisterView`: each repository's latest threat model as of `--as-of`, else now). *Retired* (a point in time is `--as-of`; nothing is stored): the legacy fallback `<root>/threat-register/` and the `threat-register` snapshot appended to the central hash-chained metrics ledger with its trend-vs-previous banner in the md/html.

- **json** — full register (every threat with id, repository, label,
  actors, surface, asset, severity, band, crosswalked, likelihood, impact,
  status, controls, evidence, techniques, mitigations) plus the open
  doc variances and quick wins.
- **md** — leadership summary: status/severity totals, how many threats are
  rated with OWASP, top-25 open threats,
  top quick wins, risk acceptances, repositories by open-threat severity,
  open documentation variances.
- **html** — self-contained dashboard, no external assets.

*Retired* (scope is product or team: `--product`, `--team-id`): The md/html outputs embed the standard population block (roots, unit,
filters, denominator) for cross-dashboard reconciliation, and include an
Ownership cuts table splitting models/threats/open/open-critical
between owned (`findings/`, Hybrid Platforms) and upstream (`oss-findings/`)
— upstream is never folded into the owned cut.

**Ranking.** Threats are ranked by their **OWASP Risk Rating Methodology**
severity (<https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>),
then status, then repository and `<Tn>`. A threat whose
model hasn't been re-rated yet still carries legacy labels. It is ordered
by a fixed crosswalk onto the OWASP severity table
(traust-core's `RatingPolicy.threat_rating`) and marked
`crosswalked`, shown as "(legacy crosswalk)". The
crosswalk orders rows and is never reported as a rating. A threat with
neither is `unknown` and ranks last. Repositories are
ordered by their counts of open critical, then high, and so on: counts,
never a weighted sum. None of this is CVSS, and none of it feeds the
portfolio risk index, which remains the ledger's job
(`docs/risk-rating-methodology.md`). Statuses are reported exactly as the
models state them; the register draws no conclusions.

**Quick wins** = section 8 mitigations with `closes_class: yes` and
effort XS/S that cover at least one `unmitigated` threat of high or
critical severity — the highest-leverage engineering asks in the fleet.

## Tenant-isolation columns (optional; multi-tenant models only)

Threat models of multi-tenant services may carry the optional
tenant-boundary lens (threat-model `schema.md` section 10 + the trailing
`isolation_dimensions` threat-table column — PEACH referenced by name/URL
only, wording original; vocabulary shared with
`contracts/schemas/isolation-review.schema.json`). The register passes it through as
**optional per-row fields** — absent on every row of a model without the
lens, so registers built from boundary-free portfolios are unchanged:

- `isolation_dimensions` — which of the five hardening dimensions
  (`privilege`, `encryption`, `authentication`, `connectivity`, `hygiene`)
  the threat stresses;
- `boundary_ids` — the section 10 boundary/interface id(s)
  (`IF-n`) whose `threat_ids` tag the threat;
- `isolation_review_ref` — the `analysis-results/isolation/<service-slug>/`
  artifact of the full `/isolation-review`, when one exists.

**Aggregation — which tenant boundaries are weakest.** When any model
carries boundaries, the JSON gains a `tenant_boundaries` list (and the md
a "Weakest tenant boundaries" table), keyed by repository and `<IF-n>`
and ordered weakest-first: failed (`no`) dimensions weigh 2, `partial`
weighs 1, ties broken by interface complexity and tagged open threats.
Like the threat ranking, this ordering is an aid, not a conclusion — dimension
results are reported exactly as the models state them, and the evidence
lives in the linked isolation review, never here.

## Keeping it current

The register is a projection: it is read from the latest recorded
models on every call, so `/threat-model` runs, reviews, or updates show
up once they are recorded. Downstream: `/generate-team-report` and the
executive summary may cite per-product rows; `/threat-model review`
verdicts change `status` fields, which the next read picks up.
