# Model Routing — Registry, Tiers, Escalation

How the harness decides *which model does what*. Policy home:
[config/model-registry.yaml](../config/model-registry.yaml), schema-gated by
`model-registry.schema.json` in traust-contracts. A deployment may place
its own copy in `TRAUST_CONFIG_HOME`, which then takes precedence — the
procedure, the per-role granularity and the schema requirements are in
[model-classes.md](model-classes.md#configuring-your-own-models).

## The one rule

**Concrete model identifiers live only in the registry.** Skills, docs, and
scripts name *tier classes* (`mythos-class`, `opus-class`, `sonnet-class`,
`haiku-class`); anything that needs a real model ID resolves it:

```bash
python3 -m traust.cli registry models resolve <role>            # at the role floor
python3 -m traust.cli registry models resolve <role> --tier opus-class   # escalated
```

What each class is *for*, the eleven role floors, and the per-skill index:
[model-classes.md](model-classes.md).

Alignment rule **A12** (pre-commit) fails any skill or script that hardcodes a
model ID outside the registry. This is the lock-in firewall: changing vendors
or tiers is a reviewed data change, never a prose hunt.

## Roles and floors

Roles map to the work the harness does (deep-audit, triage-verifier,
fact-judge, patch-author/reviewer, validation-planner, render-narrate, …).
Each role declares:

- **floor** — the minimum tier; `resolve` refuses anything below it
  (tier-downs below the floor are never allowed, silently or otherwise);
- **approved** — models cleared for use;
- **candidates** — awaiting eval-gated promotion: recall-benchmark within
  tolerance of the baseline, consistency thresholds, redaction/injection
  spot-check;
- **ledger_validity_writer** — roles that write the disposition ledger's
  validity axis; cross-vendor is forbidden here until two consecutive
  benchmark cycles pass;
- **claude_code_only** — runtime features the role currently depends on
  (subagent fan-out, effort control); a cross-runtime pilot must replace or
  forgo them.

### Where the floor is enforced — and where it is not

Three layers, none of them runtime:

1. **Resolution time (hard):** `resolve` computes the wanted tier as
   `--tier or floor` and raises on any tier-down below the floor; only
   `approved` models at the wanted tier are returnable.
2. **Commit time (hard):** the registry is schema-gated
   (`python3 -m traust.cli registry models validate`, approved-below-floor
   flagged) and alignment rule A12 fails the pre-commit for any concrete model
   ID outside the registry — code cannot bypass the resolver by hardcoding.
3. **Provenance (soft):** reports stamp
   `metadata.additional.model_routing {role, model}`, batch templates pin the
   resolved ID at batch start, and spend declarations record the model used —
   a below-floor run is visible after the fact.

**Known gap:** nothing enforces the floor at execution time. An interactive
session runs whatever model it was launched with, and the ledger emit scripts
do not check the writing model — `ledger_validity_writer` is contract
documentation, not a runtime gate. Closing it means a pre-flight in batch
templates (resolve the role, refuse launch on a below-floor session model)
and the equivalent check in orchestrator job specs.

## Escalation ladder

Drivers start at the role floor and escalate one tier when a trigger fires
(dual-pass disagreement, citation-gate failure, ≥high severity proposed by a
sub-floor tier, consistency-monitor flip). Escalations are recorded, never
silent: reports carry

```json
"model_routing": {"role": "fact-judge", "model": "…",
                   "registry_sha": "…", "floor": "sonnet-class"}
```

in `metadata.additional` (emit with
`python3 -m traust.cli registry models stamp`). The registry file's short
sha ties every routed decision to the exact policy revision that made it.

## Spend declaration

Every model-consuming batch declares a spend event in traust-core (priced from the registry;
an unknown or unpriced `--model` exits 1 and records nothing):

```bash
python3 -m traust.cli registry models spend --skill secure-code-audit \
    --model <id> --tokens-in N --tokens-out N [--batch <batch-id>] \
    [--repo <slug> --loc <size>]
```

`--repo`/`--loc` attribute the row to one audited target — the calibration
tuple `(spend, repo, size)` the scan estimator fits against (*not stored* yet:
the spend event has no column for them, nor for `--batch`/`--note`; the command
says so on stderr). Batch drivers
SHOULD pass both on per-repo rows; batch-level rows omit them. Every
model-heavy per-target skill carries a "Spend declaration (calibration tuple)"
section instructing the row; any other skill that consumes model tokens should
declare too — an unknown `--skill` name falls to the budget policy's `default`
ceiling. Estimator calibration is **per skill**.

Two properties of declared rows to keep in mind:

- **They are routing markers, not cost claims.** An agent cannot observe its
  own token usage mid-run, so the token fields are best-effort and often zero.
  Actual cost is measured from the runtime's own usage records by the
  deployment's spend-collection chain, which is deployment tooling, not part
  of this contract.
- **The registry is required.** A config home without `model-registry.yaml`
  (a platform worker that records usage itself) still copies the shipped one
  — `scripts/install_traust` does — and `traust registry models spend` refuses,
  naming the fix, rather than silently recording an unpriced declaration.

Cost, where a dashboard shows one, comes from the registry rate card
(`price_per_mtok_*`); verify it against the current published prices before
treating a dashboard figure as billing truth.

## Batch lane

Registry models carry `batch_eligible`. Non-interactive sweep classes (L2
re-scores, backfills, projection narration) should prefer the provider's batch
lane; the flag and the routing policy are in place so drivers can declare
intent, and the submission client lands with its first consumer.

## Adding a model or vendor

1. **Data-handling and licensing intake first** ([external-dependencies.md](external-dependencies.md)
   discipline) — embargoed findings leave the boundary only to approved
   processors; cost never overrides the embargo boundary.
2. Add under `providers` with tier and prices; add to the target role's
   `candidates`.
3. Run the eval gate and record results under the role's `evals`.
4. Promotion to `approved` is a reviewed change touching only the registry.
