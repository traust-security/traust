---
name: attack-coverage
description: Use when the user asks for MITRE ATT&CK coverage of the portfolio — "which ATT&CK techniques/tactics do our threats or validated chains cover", "build the ATT&CK Navigator layer", "ATT&CK heat map", or after updating threat models/validations to refresh the coverage roll-up. Deterministically joins observed and attempted bound validation chains, threat-model attack_refs and finding-category-derived candidates against the pinned ATT&CK table; emits Navigator JSON and a tactic/technique coverage report.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# ATT&CK Coverage Roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Fleet-wide MITRE ATT&CK coverage from artifacts the pipeline already
produces. **Fully deterministic** — every number is a table lookup or a
count; no agent authors, adds, or reinterprets a technique reference.

## Evidence classes (never blended)

| Class | Source | Meaning |
|---|---|---|
| **observed** (score 3) | `ValidationService.reports`: bound reports' confirmed chains with a sound confirmed step and valid target attestation | adversary behavior demonstrated against a live target |
| **attempted** (score 0 when no stronger evidence exists) | executed chains not meeting observed requirements | an attempt, never evidence of exploitation |
| **modeled** (score 2) | each repository's latest recorded threat model: its threats' ATT&CK techniques (`AssessmentService.threats`) | behavior an owner/bootstrap pass named as a threat |
| **derived** (score 1) | recorded findings' categories (`FindingService.summary`) → [`tables/attack-mapping.json`](tables/attack-mapping.json) `category_map` | candidate techniques implied by a weakness class — potential, not behavior |

Each technique counts once per chain, even when a chain repeats its reference.
Reports shared across source bindings count once per recording run. `--as-of`
uses recorded assessment time; chain-only runs remain visible. Target-invalid or
unattested runs cannot become observed. Every reference is checked against the
pinned live technique catalog; invalid IDs are counted in the dropped report.

## Shared assets (used by other skills)

- [`tables/attack-techniques.json`](tables/attack-techniques.json) — distilled technique/mitigation table
  from ONE sha256-pinned ATT&CK release (`build_attack_table.py`; pin in
  [`tables/attack-bundle.sha256`](tables/attack-bundle.sha256)). The single source every harness
  component validates technique IDs against.
- [`tables/attack-mapping.json`](tables/attack-mapping.json) — harness vocabulary → candidate technique
  IDs (`capability_map` feeds `validate-findings/chain.py`; `category_map`
  feeds this roll-up). Schema: `contracts/schemas/attack-mapping.schema.json`.
- `attack_refs.py` — loader + validator, through traust-core's catalog. CLI:
  `traust attack validate <ids…>` (used by threat-model authors);
  referential integrity is checked by traust-core on every catalog load.

## Run

(traust-core's `AttackCoverageView` joins the classes.)

```bash
traust dashboard view attack-coverage \
    --out progress-tracker/metrics/dashboards/attack-coverage
```

Outputs to `progress-tracker/metrics/dashboards/attack-coverage/`:

| File | Contents |
|---|---|
| `attack-coverage.json` `navigator_layer` | ATT&CK Navigator layer (format 4.5) — load at <https://mitre-attack.github.io/attack-navigator/>; score 0/1/2/3 = attempted-only/derived/modeled/observed |
| `attack-coverage.md` (and `.html`) | per-tactic and per-technique coverage tables, population block, dropped-reference report |

*(Retired: the metrics append to the shared ledger; trends come from `--as-of`.)*

## Hard rules

- Technique IDs are **selected, never authored**: anything not present and
  live in the pinned table is dropped *and listed* in the "Dropped
  references" section — no silent loss.
- `derived` counts never masquerade as observed behavior; the three
  classes stay separate in every output.
- Upgrading the ATT&CK release is a deliberate act: bump `ATTACK_VERSION`
  in `build_attack_table.py`, run with `--refresh-pin`, review the diff
  (revocations!), fix any mapping fallout flagged by
  traust-core's catalog load (`traust attack validate` refuses), commit.
- ATT&CK® is © The MITRE Corporation, used with attribution under the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/);
  the attribution statement travels in the vendored table and every
  emitted layer.
