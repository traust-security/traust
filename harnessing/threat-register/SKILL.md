---
name: threat-register
description: >-
  Use when the user asks for a fleet-wide or portfolio-wide view of threats
  (not findings) — "how many unmitigated critical threats do we have",
  "threat register", "which products carry the most open threat exposure",
  "what class-closing mitigations would pay off fleet-wide" — or asks to
  (re)build the threat register. Deterministically aggregates every
  *-threat-model.md (and legacy THREAT_MODEL.md) under analysis-results into
  progress-tracker/metrics/dashboards/threat-register/threat-register.{json,md,html}, keyed by the stable
  compound key <model-slug>:<Tn>.
argument-hint: "[--root <analysis-results>] [--out <dir>]"
user-invocable: true
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Read
  - Glob
  - Bash(python3 *harnessing/threat-register/scripts/build_threat_register.py:*)
  - Bash(python3 *-m traust_engine.reporting.lint:*)
  - Bash(ls:*)
  - Bash(wc:*)
---

# threat-register

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
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
threats. The register derives a **stable compound key**
`<product>/<model-slug>:<Tn>` for every threat; it is durable because
schema.md forbids renumbering or reusing threat IDs, and the builder
requalifies any colliding slug with its full path, so keys are globally
unique. Threats cite canonical finding IDs in their `evidence` column —
that is the join to the ledger, and it runs in that direction only.

## Run

```bash
python3 <skill-dir>/build_threat_register.py --root <analysis-results>
```

One deterministic pass (seconds, even for a corpus of thousands). The builder reuses
python3 -m traust.cli reporting lint's parser, so it reads exactly what the
contract gate enforces; models that do not conform are skipped and
counted (`models_skipped_nonconforming`) — if that count is nonzero,
run the linter to find them, fix, and rebuild. It never edits a model.

## Output

`progress-tracker/metrics/dashboards/threat-register/threat-register.{json,md,html}` (legacy fallback `<root>/threat-register/` when the progress-tracker sibling is absent). Each run also appends a `threat-register` snapshot (threat models, total/unmitigated/partially-mitigated/open threats, quick wins) to the central hash-chained metrics ledger — no-op when unchanged — and injects a trend-vs-previous banner into the md/html, so threat trends are visible per-register and in Executive-Trends:

- **json** — full register (every threat with key, product, model,
  actors, surface, asset, impact, likelihood, status, controls, evidence,
  rank score) plus totals, per-product roll-up, and quick wins.
- **md** — leadership summary: status/impact totals, top-25 open threats,
  top quick wins, products by open-threat exposure.
- **html** — self-contained dashboard, no external assets.

The md/html outputs embed the standard population block (roots, unit,
filters, denominator) for cross-dashboard reconciliation, and include an
Ownership cuts table splitting models/threats/open/open-critical+existential
between owned (`findings/`, Hybrid Platforms) and upstream (`oss-findings/`)
— upstream is never folded into the owned cut.

**Rank score** is a fixed ordinal product (impact weight × likelihood
weight, documented in `meta.scoring`); it orders rows and nothing else —
it is not CVSS and never feeds the portfolio risk index, which remains
the ledger's job (`docs/risk-rating-methodology.md`). Statuses are reported
exactly as the models state them; the register draws no conclusions.

**Quick wins** = section 8 mitigations with `closes_class: yes` and
effort XS/S that cover at least one `unmitigated` high/critical/
existential threat — the highest-leverage engineering asks in the fleet.

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
- `isolation_boundaries` — the section 10 boundary/interface id(s)
  (`IF-n`) whose `threat_ids` tag the threat;
- `isolation_review_ref` — the `analysis-results/isolation/<service-slug>/`
  artifact of the full `/isolation-review`, when one exists.

**Aggregation — which tenant boundaries are weakest.** When any model
carries boundaries, the JSON gains a `tenant_boundaries` list (and the md
a "Weakest tenant boundaries" table), keyed `<product>/<model-slug>:<IF-n>`
and ordered weakest-first: failed (`no`) dimensions weigh 2, `partial`
weighs 1, ties broken by interface complexity and tagged open threats.
Like the rank score this ordering is an aid, not a conclusion — dimension
results are reported exactly as the models state them, and the evidence
lives in the linked isolation review, never here.

## Keeping it current

The register is a projection: regenerate after any batch of
`/threat-model` runs, reviews, or updates (it is cheap enough to rebuild
on every consumption). Downstream: `/generate-team-report` and the
executive summary may cite per-product rows; `/threat-model review`
verdicts change `status` fields, which the next rebuild picks up.
