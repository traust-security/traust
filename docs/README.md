# Docs

A reader's map to the 34 documents in this directory. Three audiences — **operators** setting up and running the harness, **analysts** reading and acting on its output, and **contributors** changing the harness — are grouped separately below. Reference material shared across all three follows.

---

## Start here

| Doc | What it covers |
|-----|----------------|
| [getting-started.md](getting-started.md) | From zero to a first audit — install, configure, run, check output |
| [requirements.md](requirements.md) | What you need before you start (OS, Python, agents, optional scanners) |
| [setup.md](setup.md) | Complete setup reference: env vars, workspace layout, toolchain, sibling repos |
| [standalone-usage.md](standalone-usage.md) | Using individual skills locally, outside the automated campaign workflow |

---

## Operators — running the harness

For people deploying and operating Traust across a portfolio.

| Doc | What it covers |
|-----|----------------|
| [campaign-workflow.md](campaign-workflow.md) | End-to-end scanning campaign: helper repos, campaign-bound skills, runtime directory structure |
| [continuous-operations.md](continuous-operations.md) | The standing rescan loop: routing lanes and cadences, spend guard, dashboard jobs, credentials for autonomous runs |
| [sla-policy.md](sla-policy.md) | Configuring remediation deadlines — SLAs are policy data, never code |
| [model-routing.md](model-routing.md) | Which model does which role, the budget escalation ladder, and the registry contract |
| [model-classes.md](model-classes.md) | Per-skill model assignments and what each class is for |
| [external-dependencies.md](external-dependencies.md) | Every external tool the harness depends on and why |

---

## Analysts — reading and acting on results

For security engineers triaging findings, verifying exploitability, and tracking remediation.

| Doc | What it covers |
|-----|----------------|
| [artifacts.md](artifacts.md) | Every artifact the pipeline produces: what it contains, where it lands, who consumes it |
| [report-structure.md](report-structure.md) | Field-by-field reference for the security audit report JSON |
| [findings-routing.md](findings-routing.md) | How a finding gets from a producer report into the disposition ledger |
| [disposition-ledger.md](disposition-ledger.md) | Design and rationale behind the tamper-evident findings ledger |
| [validation-process.md](validation-process.md) | What a verdict must survive before it enters the ledger (trust gates, fail-closed stack) |
| [error-model.md](error-model.md) | Type I / Type II error policy — how the harness handles false positives and negatives |
| [risk-rating-methodology.md](risk-rating-methodology.md) | How per-finding scores become portfolio risk metrics |
| [reachability.md](reachability.md) | Reachability engines, what each may conclude, and per-language coverage |
| [adversarial-content-doctrine.md](adversarial-content-doctrine.md) | The standing rule for any agent reading content it did not write (prompt-injection defence) |

---

## Contributors — changing the harness

For engineers editing skills, scripts, schemas, or any of the five component repos.

| Doc | What it covers |
|-----|----------------|
| [architecture.md](architecture.md) | Pipeline shape, skill anatomy, adapter system, config & context model, code placement |
| [components.md](components.md) | The five component repos: what each owns, dependency order, version pinning, release procedure, and "which repo do I change?" |
| [deterministic-inferential-mix.md](deterministic-inferential-mix.md) | Where deterministic tooling belongs and where the LLM does the work — the boundary and its rationale |
| [signing.md](signing.md) | Ledger signing: key management, the verification flow, optional vs. enforced |
| [safe-exec.md](safe-exec.md) | The `safe_exec` sandbox: profiles, blocked constructs, gate rule S10 |
| [tooling-and-structure-files.md](tooling-and-structure-files.md) | All schemas, packaged CLIs, and key entry-point scripts in one index |
| [storage.md](storage.md) | Where each kind of data lives and which variable places it |
| [storage-v1-ddl-model.md](storage-v1-ddl-model.md) | Storage v1 DDL table model — *generated from traust-contracts; do not edit by hand* |
| [language-support.md](language-support.md) | Per-language coverage across the agentic core, reachability engines, fuzz harnesses, and rule packs |

---

## Reference

Lookup docs used across roles during normal work.

| Doc | What it covers |
|-----|----------------|
| [skills.md](skills.md) | All 52 skills: description, stage, tier, slash command — *generated; regenerate with `python3 -m traust.cli build skills-reference`* |
| [cli-reference.md](cli-reference.md) | Every `traust <group> <op>` command |
| [graphs.md](graphs.md) | The six graphs the harness builds or reads: which question each answers and who consumes it |
| [routers.md](routers.md) | The seven kinds of routing in the harness: what each does and which components implement it |
| [sarif.md](sarif.md) | The SARIF 2.1.0 emitter and importer: field mappings in both directions |

---

## Notes

- `continuous-scanning.md` — redirects to [continuous-operations.md](continuous-operations.md); kept to preserve inbound links.
- `storage-v1-ddl-model.md` and `skills.md` are generated files. Edits to them are overwritten on the next run.
- The docs gate (`python3 -m traust.cli check docs-consistency`) enforces count assertions, dead links, enum discipline, and version sync. Run it after editing.
