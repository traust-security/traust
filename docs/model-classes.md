# Model classes — what each level is for, and which skill runs at which

[`config/model-registry.yaml`](../config/model-registry.yaml) is the
authority for every class, role and floor. This document explains that file
and indexes the per-skill assignment; it introduces nothing of its own.

Three questions get confused with each other, so they are answered separately:

1. **What are the classes?** Four capability bands. Below.
2. **What decides which class a step gets?** A *role*, not a skill. A skill can
   use several roles at different points.
3. **Which class does skill X run at?** The per-skill index at the end.

Related: [model-routing.md](model-routing.md) is the mechanism — how a class is
resolved at run time, stamped into a report, and escalated.
[requirements.md](requirements.md) is the operator's view — what you need
installed and licensed to run each band.

---

## The four classes

Names are deliberately **not** model IDs. A class is a capability band; which
model fills it changes as models are released, and alignment rule **A12**
fails any commit that hardcodes a model ID in a skill or script.

| Class | What it is for | Why the band exists |
|---|---|---|
| `mythos-class` | frontier reasoning — verdict-writing and deep-audit floors | A wrong verdict here becomes a finding someone acts on, or a false refutation that closes a real vulnerability |
| `opus-class` | strong general reasoning — most orchestration and authoring | Work where being wrong costs a rerun, not a bad security decision |
| `sonnet-class` | fast/cheap — mechanical judgment over deterministic anchors | Judgment that a deterministic tool has already constrained; the anchor does the deciding |
| `haiku-class` | cheapest — routing, extraction, narration | No judgment at all: reshaping text that something else decided |

The ordering is a **floor**, not a preference. A role's floor is the weakest
class allowed to do that work; running above it is always permitted (and is
what escalation does), running below it is a routing bug.

## Roles are what carry a floor

A skill is not a single model call. `/secure-code-audit` fans out subagents,
judges facts, and narrates a report — different work with different exposure.
So the floor attaches to a **role**, and the skill resolves the role it needs
at the moment it needs it:

```bash
python3 -m traust.cli registry models resolve <role>
python3 -m traust.cli registry models resolve <role> --tier opus-class   # escalated
```

The twelve roles, their floors, and whether the role may write a validity
verdict into the disposition ledger:

| Role | Floor | Writes ledger validity? |
|---|---|---|
| `deep-audit` | `mythos-class` | **yes** |
| `triage-verifier` | `mythos-class` | **yes** |
| `validation-planner` | `mythos-class` | **yes** |
| `verification-verdict` | `mythos-class` | **yes** |
| `threat-model` | `mythos-class` | no |
| `patch-author` | `mythos-class` | no |
| `patch-reviewer` | `mythos-class` | no |
| `remediation` | `mythos-class` | no |
| `fuzz-author` | `opus-class` | no |
| `vuln-scan` | `opus-class` | no |
| `fact-judge` | `sonnet-class` | no |
| `render-narrate` | `haiku-class` | no |

Two patterns are worth reading off that table.

**Every ledger-validity writer floors at `mythos-class`.** The four roles that
can record "this finding is real" or "this finding is refuted" are the four
with the highest floor. That is the whole design: the cost of being wrong is
measured in someone's security decision, not in tokens.

**`fact-judge` floors at `sonnet-class` despite judging findings.** It is the
deliberate exception, and the reason is the anchor: it adjudicates against a
deterministic pre-scan result that already exists, so the judgment is bounded
rather than open-ended. See
[deterministic-inferential-mix.md](deterministic-inferential-mix.md) — the
split is "let the deterministic half decide what it can, and put the model
only where judgment is unavoidable".

## Escalation

A run may move *up* from a floor automatically. The registry names four
triggers:

- dual-pass disagreement
- citation-gate failure on first-pass output
- a finding of severity >= high proposed by a sub-floor tier
- a judge flip detected by the consistency monitors

Escalation is recorded, not silent: the routed decision is stamped into
`metadata.additional.model_routing` along with the registry SHA and the floor
that applied, so a report says which class actually produced it.

---

## Configuring your own models

`model-registry.yaml` is a **shipped default that is also seeded**:
`install_traust` copies it into `$TRAUST_CONFIG_HOME`, and **the copy there
wins**. An adopter edits that copy and never touches the harness tree. Nothing
about the classes above is hardcoded — they are that file's content.

```bash
$EDITOR "$TRAUST_CONFIG_HOME/model-registry.yaml"
python3 -m traust.cli registry models validate        # schema + semantic checks
python3 -m traust.cli registry models resolve deep-audit
```

### The override is per role, not all-or-nothing

Repointing one role leaves the rest on their shipped defaults, so a deployment
can move the work it cares about without re-declaring eleven roles:

Add your provider, then **edit the `approved` list of the role(s) you want to
move** — do not replace the role block, which would drop keys the schema
requires (`candidates` and `ledger_validity_writer` are mandatory on every
role):

```yaml
providers:
  adopter-inc:
    data_handling: zero-retention under our own MSA
    models:
      adopter-local-model-x:
        tier: mythos-class
        batch_eligible: false

roles:
  patch-author:
    floor: mythos-class            # keep
    approved: [adopter-local-model-x]   # <- the line you change
    candidates: []                 # keep
    ledger_validity_writer: false  # keep
```

With that in place, `resolve patch-author` returns `adopter-local-model-x`
while `resolve deep-audit` still returns the shipped default.

### It is schema-gated, so a broken override fails loudly

The registry validates against `model-registry.schema.json` in
traust-contracts before anything resolves. A malformed entry is rejected with
the offending object printed — it does not silently fall back to the shipped
copy or resolve to nothing. The shape the schema requires:

| Level | Required keys |
|---|---|
| `providers.<name>` | `data_handling`, `models` |
| `providers.<name>.models.<model-id>` | `tier`, `batch_eligible` (optional: `price_per_mtok_in`, `price_per_mtok_out`) |
| `roles.<role>` | `floor`, `approved`, `candidates`, `ledger_validity_writer` (optional: `claude_code_only`, `note`, `evals`; no other keys) |

Beyond the schema, `registry models validate` cross-checks that every model's
`tier` is a declared class and that each role's `approved` list actually
satisfies its `floor` — so you cannot quietly approve a sub-floor model for a
role that writes ledger validity.

### No vendor is assumed

Provider and model names are opaque strings. A provider called `adopter-inc`
with a model called `adopter-local-model-x` resolves exactly like the shipped
Anthropic entries, because skills name *roles* and only the registry names
models (rule **A12**). Swapping vendors is a config edit, not a code change.

Prices are optional; supply `price_per_mtok_in` / `price_per_mtok_out` if you
want `registry models spend` to compute cost for your own models rather than
recording tokens alone.

### Keeping track of your divergence

Your config-home `model-registry.yaml` is yours to maintain: `install_traust
--force` refreshes it from the shipped default (discarding local edits, so
re-apply your overrides after a force refresh). Divergence is intended for an
adopter who has repointed roles; the drift to watch is the reverse one —
`traust admin doctor` names a missing registry (it is required), and a stale
copy simply resolves roles to the models it names.

---

## Per-skill index

**This index is hand-maintained, and that is a known weakness.** Nothing in the
tree mechanically links a skill to a class: skill frontmatter carries
`harness.tier` (`primary` / `secondary` / `tertiary` / `ci`), which is a
*different axis* — how central the skill is, not what model it needs. Only one
skill currently names a role in its own text. So the classes below come from
the two usage tables, and a skill can drift from its documented class without
any gate noticing.

The two source tables are **complementary, not duplicates** — they partition
the corpus by how a skill is invoked, which is why neither is complete on its
own:

- [campaign-workflow.md](campaign-workflow.md) — 21 skills, the pipeline lanes
- [standalone-usage.md](standalone-usage.md) — 27 skills, invocable on any checkout

Between them they cover 47 of the 51 skills. The lists below are extracted
from those two tables rather than maintained separately, so they cannot
disagree with them; a docs-gate check enforces that. The four skills with no
documented class are listed at the end with the role that governs them.

### `mythos-class` — 16 skill(s)

Audits, threat models, triage, validation, remediation, verification — the roles that write ledger validity, or author and review patches.

`compliance-check` · `crypto-analysis` · `insecure-patterns` · `isolation-review` · `patch` · `pqc-readiness` · `recall-benchmark` · `remediate-finding` · `secure-code-audit` · `secure-rpm-audit` · `security-audit-phased` · `threat-model` · `triage` · `validate-browser-finding` · `validate-findings` · `verify-remediation`

### `opus-class` — 25 skill(s)

Orchestration, inventory, graphs, dashboards and rollups: work whose failure mode is a rerun, not a bad security decision.

`add-inputs` · `attack-coverage` · `census` · `cloud-config-audit` · `corpus-intake` · `dependency-watch` · `financial-tracking` · `findings-db` · `fleet-fix` · `generate-team-report` · `impact-analysis` · `inventory-repositories` · `mine-ledger` · `operator-priv-profile` · `portfolio-graph` · `property-test` · `secure-container-audit` · `sla-view` · `threat-register` · `track-findings` · `traust-metrics` · `validation-fuzz-dashboard` · `vuln-scan`

### `sonnet-class` — 6 skill(s)

Judgment anchored to a deterministic result — doc drift, licensing, alignment, security posture.

`check-alignment` · `check-harness-docs` · `check-licensing` · `check-skill-security` · `drift-watch` · `refresh-dashboards`

### Not classed in either usage table

Four skills carry no class in either table. The governing role is the better
answer for them anyway, since that is what actually decides the floor:

| Skill | Governing role | Effective floor |
|---|---|---|
| `create-fuzzing` | `fuzz-author` | `opus-class` |
| `executive-summary-findings` | `render-narrate` over deterministic aggregates | `opus-class` in practice; the narration step may drop to `haiku-class` |
| `findings-trends` | deterministic replay + narration | `opus-class` |
| `loc-dashboard` | deterministic, reads stored code facts | `opus-class` |

### Making this mechanical

The honest fix is for each skill to declare the role(s) it resolves in its own
frontmatter, so this index can be generated the way
[skills.md](skills.md) is and drift becomes impossible rather than merely
correctable. That is a change to 51 skills and a new alignment rule, so it is
recorded here as the known gap rather than done quietly.
