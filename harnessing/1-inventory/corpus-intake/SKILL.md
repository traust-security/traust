---
name: corpus-intake
description: Use when the user wants to register, update, or review a corpus tree or scan engagement — "add a new BU engagement", "register this tree", "onboard <name> scanning work", "why is this tree unregistered", "update the ownership of X" — or when any census/dashboard run reports an unregistered-tree drift warning. Interactively interviews for the registration fields (or takes them as arguments), validates and records them in traust-core (products and the corpus registry) through `traust products`, then re-runs /census so the corpus manifest reflects the change immediately.
argument-hint: "[add|update|list] [<name>] [field=value ...]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(traust products list:*)
  - Bash(traust products add:*)
  - Bash(traust products update:*)
  - Bash(ls:*)
  - Read
---

# Corpus Intake — register trees and engagements

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


traust-core's products and corpus registry are the single source of truth for which trees
under `analysis-results/` are in the report corpus and who owns them.
This skill is its only supported write path: interview → validate →
recorded (product, then registry) → census refresh.

## Input

`$ARGUMENTS` may be empty (full interview), `list`, or a partial
registration (`add contoso tree=contoso-findings ...`) whose missing
fields the interview fills in.

---

## Procedure

### Step 1 — Show current state

```bash
traust products list
```

Present the registered trees/engagements (DRIFT warnings *retired*: status derives from assessments). If the
user only asked to review ("list", "what's registered"), stop here.

### Step 2 — Interview for the registration fields

Collect, one question at a time, anything not already provided:

1. **Kind** — *retired*: trees and engagements are both products in core.
2. **Name** — the config key (engagement codename or tree directory
   name). Letters/digits/`._-` only.
3. **Tree** — *retired*: the name is the tree.
   Convention: name it `<engagement>-findings`, one tree per engagement.
4. **Ownership tag** — exactly one of:
   - `owned` — the organization's remediation backlog (Lens 2 headline);
   - `upstream` — community code the organization relies on; adjacent line, never
     folded into the owned headline;
   - `external-bu` — scan work for another BU; Lens 1 (work performed)
     only, excluded from the organization's executive risk numbers.
   - `harness-qa` — harness self-measurement artifacts (probes,
     benchmarks, side-by-side sweeps); registered so drift-watch knows
     the tree is vetted, but excluded from EVERY metrics lens —
     `corpus.resolve()` never walks it.
   Probe the semantics, not just the label: "Does the organization own
   the remediation backlog for this code?" (owned) / "Do we ship or
   depend on it?" (upstream) / "Are we only performing the scanning
   work?" (external-bu) / "Is this the harness measuring itself, where
   counting the findings would double-count or distort?" (harness-qa).
5. **Business unit** — the human-readable BU/initiative name shown on
   dashboards.
6. **Inventory** (*retired*: core keys the corpus by ids, not paths) — path to the input inventory CSV in
   the inputs inventory (`locations.inputs`) if one exists.
7. **Notes** (NEED(contracts: a `notes` field on the corpus-registry subject; the schema's subject allows no other field, so nothing records them)) — anything non-obvious, especially product-vs-BU
   dualities (see the `ansible` entry: catalog operators inside
   `findings/` stay owned while the BU engagement is external).

If the answers reveal a BU boundary cutting through an existing tree
(some products owned, some not), do NOT force a tree-level tag — flag it
to the user (recording the exception in notes: NEED(contracts: corpus-registry subject `notes`), flag only until then); per-product `overrides`
support lands with a later phase.

### Step 3 — Apply

```bash
traust products add <name> \
    --label <label> --ownership <tag> --business-unit "<BU>"
# or targeted field changes
traust products update \
    <name> [--label ...] [--ownership ...] [--business-unit ...]
```

The tool validates before writing (ownership enum, name syntax) and
records the product, then the registry; adding a registered name with the same fields changes nothing,
with different fields is refused (use `update`), and a concurrent edit is refused rather than overwritten. Exit 2 = validation
error: relay the message, fix the field, retry.

### Step 4 — Refresh the census

```bash
python3 -m traust.cli dashboard view census \
  --out <progress-tracker>/metrics/dashboards/census
```

Confirm the new product's registration with `traust products list` and its
assessment population with `traust portfolio population`. The census view counts
recorded assessments; a product with no assessed repositories has no exposure rows yet.

### Step 5 — Remind about inventory

If the engagement has repos to scan and no inventory registered, remind
the user to run `/add-inputs` to add them to the inputs inventory.

---

## Outputs

- Products and the corpus registry in traust-core (validated).
- Refreshed `census.{json,md,html}` under
  `progress-tracker/metrics/dashboards/census/`. The resolved record list
  lives in findings.db `repos`.

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `ConflictError: '<name>' is already registered` | The name is registered with other fields | Update the existing entry instead. |
| `ConflictError` | Another edit landed between read and write | Re-run `traust products list`, then retry. |
