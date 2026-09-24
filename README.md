# Traust

[![skillsaw grade](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fopenshift%2Ftraust%2Fmain%2F.skillsaw-badge.json)](https://skillsaw.org/)

Traust is a workflow engine for the automated, multi-framework security assessment of software portfolios, including; source repositories, container images, RPM packages, Kubernetes operators, infrastructure-as-code and the services built from them. This repository holds the skills, slash commands, schemas and prompt engineering that let an AI coding agent run consistent, repeatable audits, then triage and validate what it finds. It records every disposition in a signed ledger, and drives remediation at scale rather than one review at a time. Traust was developed by Red Hat's Hybrid Platforms team and is published under Apache License 2.0.

## Purpose

Manual security review does not scale to hundreds of repositories across dozens of product releases. This workflow engine equips AI coding agents with structured methodologies to perform consistent, repeatable security audits — applying industry-standard frameworks to every repository in the portfolio.

Traust is designed to be agent-agnostic in principle, with the current implementation supporting Anthropic models using Claude Code and Crush (via shared skills and slash commands).

## Components

This repository is the **agent-facing layer** of a five-component stack, not the
whole system. Skills, slash commands and CLIs live here; the Traust engine, the ledger, the contracts, and the SDK are separately
versioned repositories, installed as pip dependencies pinned by git tag.

- [traust-engine](https://github.com/traust-security/traust-engine) — scanner adapters, corpus, metrics, reporting, validation
- [traust-ledger](https://github.com/traust-security/traust-ledger) — finding identity, Merkle integrity, signing, ledger writes
- [traust-contracts](https://github.com/traust-security/traust-contracts) — schemas, enums, shared models
- [traust-sdk](https://github.com/traust-security/traust-sdk) — typed SDKs for invoking Traust workflows

```
  traust     skills, slash commands, agent-facing CLIs   ← this repo
        ▼
  traust-engine          scanner adapters, corpus, metrics, reporting, validation
        ▼
  traust-ledger             finding identity, Merkle integrity, signing, ledger writes
        ▼
  traust-contracts   schemas · enums · shared models             (leaf)

  traust-sdk (Go)    typed SDK for non-Python consumers — imports the contracts,
                          calls the harness; not a dependency of it
```

Dependencies point one way, downward. The practical consequence: **a schema or
enum change belongs in `traust-contracts`, not here.** There is no local
`schemas/` directory — the `schemas/v1/…` paths referenced throughout this README
resolve inside the installed contracts package
(`traust_contracts`), and changing them means releasing that repo
and pulling the new tag up the chain.

Which repo to change for a given fix, how the git-tag pinning works (and the
`uv lock` "conflicting URLs" failure it produces when pins disagree), and the
bottom-up release order are all in **[docs/components.md](docs/components.md)**.

## How to Use this workflow engine

**Start here:** `scripts/install_traust` sets up `TRAUST_CONFIG_HOME` (the directory
holding your operational configuration, created from the `config/*.example.*`
templates), optionally installs the scanner toolchain, and `install_traust --doctor`
checks the install. Nothing runs without it — see [docs/setup.md](docs/setup.md).

**New here?** Start with [docs/getting-started.md](docs/getting-started.md) — zero to first audit report. What you need to run it (platform, agent/model tier, tools, network access) is in [docs/requirements.md](docs/requirements.md).

This harness is primarily used as an end-to-end workflow to index, scan, validate, and remediate all repositories across an organization.  That workflow looks roughly like this:
```
  Inputs ─▶ ① Inventory ─▶ ② Threat model ─▶ ③ Audit ─▶ ④ Triage ─┬─▶ ⑧ Package ─▶ ⑨ Assign ─▶ Share/Notify ─▶ File defects
 (inputs)                                    (analysis-results)    │   (progress-tracker → Drive, Slack, Jira)
                                                                   ├─▶ ⑤ Live validation  (validate-* / deploy-operator)
                                                                   ├─▶ ⑥ Fuzzing          (create-fuzzing)
                                                                   └─▶ ⑦ Remediation      (remediate-finding / patch / property-test / verify)

  Stages ③–⑦ feed the append-only disposition ledger (track-findings), gated by human countersign;
  follow-up scans (vuln-scan, verify-remediation regressions, dependency-watch) enter it directly.
  Dashboards (exec summary, trends, LoC, census …) render under progress-tracker/metrics/dashboards/.

  Standing loop (daily, after the first pass — docs/continuous-operations.md):
  fleet refresh ─▶ router ─▶ lanes: diff-scan │ deps (/dependency-watch) │ IaC │ verify treadmill │ rule mining (/mine-ledger)
                              └─ findings re-enter ④ Triage / the ledger; dashboards & drift-watch rebuild on cadence
```

Portions of the harness can be executed independently and locally. Both workflows, and the skills each one uses, are described in [docs/standalone-usage.md](docs/standalone-usage.md) and [docs/campaign-workflow.md](docs/campaign-workflow.md).

Findings interchange is standards-based, in both directions: `/triage` imports **SARIF 2.1.0** from any scanner (`harnessing/4-triage/triage/scripts/normalize_input.py`, which also takes Dependabot alert exports and native govulncheck streams), and every report exports to SARIF for the adopter's own dashboard or viewer (python3 -m traust.cli reporting sarif). See [docs/sarif.md](docs/sarif.md).

Note: if you just want an index of all skills in this repository, ask your agent or see [docs/skills.md](docs/skills.md).

### Standalone usage and the campaign workflow

Two ways to run the engine, each with its own guide:

- **[docs/standalone-usage.md](docs/standalone-usage.md)** — use any skill locally against a codebase or report you supply, outside the automated workflow: the standalone skills table (stage, inputs, environment requirements, minimum viable model).
- **[docs/campaign-workflow.md](docs/campaign-workflow.md)** — the end-to-end organisation-wide campaign: helper repositories, the campaign-bound skills table, and the runtime directory structure.

## Documentation

| Guide | Description |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | **Start here** — from zero to your first audit report: install, point your agent, run an audit, check the output |
| [docs/requirements.md](docs/requirements.md) | **What you need** — baseline platform/agent/model requirements, CLI tools by capability, network & access tiers, campaign extras |
| [docs/setup.md](docs/setup.md) | Setup reference — `install_traust`, workspace, toolchain, storage variables, tests, contributor gates |
| [docs/standalone-usage.md](docs/standalone-usage.md) | **Standalone usage** — run any skill locally outside the campaign: the standalone skills table with stage, inputs, environment requirements and minimum viable model |
| [docs/campaign-workflow.md](docs/campaign-workflow.md) | **Campaign workflow** — the end-to-end organisation-wide run: helper repositories, campaign-bound skills, and the runtime directory structure |
| [docs/cli-reference.md](docs/cli-reference.md) | **CLI command reference** — every `traust <group> <operation>`, the deprecated spellings to avoid, and the gate that enforces both |
| [docs/tooling-and-structure-files.md](docs/tooling-and-structure-files.md) | **Tooling and structure files** — every schema from `traust-contracts`, the packaged CLIs and key scripts, and what each is for |
| [docs/language-support.md](docs/language-support.md) | **Language support matrix** — the language-agnostic agentic core vs per-language deterministic depth (rule packs, CVE reachability engines and their soundness, fuzzers, manifests, crypto census), current gaps, and the pattern for adding a language |
| [docs/external-dependencies.md](docs/external-dependencies.md) | **Every external requirement** — CLI tools, Python libraries, MCP servers, data feeds, and framework content licenses, each with verified license + citation, plus the commercialization risk assessment (CIS flagged; PEACH resolved by the v0.54.2 original-text rewrite) |
| [docs/skills.md](docs/skills.md) | Detailed reference for all 52 skills |
| [docs/validation-process.md](docs/validation-process.md) | **How live validation reaches a trustworthy verdict** — the three-purpose mission, the fail-closed gate stack (attestation → positive controls → differential probing → soundness → ledger discipline), and artifact flow |
| [docs/graphs.md](docs/graphs.md) | **Every graph the harness builds or reads** — repo-graph, portfolio-graph, the ATT&CK Navigator layer, per-finding attack chains, and the transient Joern Code Property Graph / govulncheck call graph; what each answers, who consumes it, and what staleness costs |
| [docs/model-classes.md](docs/model-classes.md) | **Model classes** — what each of the four tier classes is for, the eleven role floors and which of them may write a validity verdict, escalation triggers, and the per-skill class index |
| [docs/model-routing.md](docs/model-routing.md) | **Model routing** — the model registry, tier classes and role floors, the A12 no-hardcoded-model rule, escalation stamping, the spend-declaration command |
| [docs/components.md](docs/components.md) | **The five-component stack** — what `traust-engine` / `traust-ledger` / `traust-contracts` / `traust-sdk` each own, which repo to change for a given fix, git-tag pinning and its "conflicting URLs" failure mode, and the bottom-up release order |
| [docs/architecture.md](docs/architecture.md) | Code internals — pipeline flow, adapter system, data model |
| [docs/artifacts.md](docs/artifacts.md) | Artifacts — what each stage produces, which skills consume it, where it lands, and the one-way projections (Markdown, findings.db, SARIF, GitLab) |
| [docs/sarif.md](docs/sarif.md) | **SARIF emitter and importer** — how a harness report projects to SARIF 2.1.0 (field mapping, suppressions, fingerprints, degraded-run signal, batch sweep) and how third-party SARIF is normalised into triage claims |
| [docs/continuous-operations.md](docs/continuous-operations.md) | **The standing rescan loop** — the daily router (python3 -m traust.cli build rescan-worklist), lane cadences, the arrival-channel coverage model with measured residuals, event injection via `rescan-events.jsonl`, the advisory budget guard, and the **weekly-drain orchestrator contract** (harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py + one headless diff scan per tranche row) |
| [docs/continuous-scanning.md](docs/continuous-scanning.md) | Redirect stub — renamed to `continuous-operations.md` on 2026-08-17 (it carries cost routing, spend cadence and credentials, not only scanning); kept so external links resolve |
| [docs/error-model.md](docs/error-model.md) | **Type I & Type II error handling** — where false positives and false negatives enter, the asymmetric-caution doctrine (machines confirm, humans dismiss), the measured error rates behind each control, self-measurement mechanisms, the improvement loop (how measured misses become the next rules/enumerators — coverage-gap rollup, rule-candidate capture), and the residual risks a consumer should know |
| [docs/disposition-ledger.md](docs/disposition-ledger.md) | **The ledger, from first principles** — why it is append-only and event-sourced, the two disposition axes, evidence-class precedence, the five-layer false-positive discipline, replay/assurance views, and a worked finding timeline |
| [docs/deterministic-inferential-mix.md](docs/deterministic-inferential-mix.md) | How deterministic and inferential tooling are mixed — CPU for enumeration and fact-retrieval, inference for judgment and novelty; deterministic tools route, gate, tag, or index, never conclude |
| [docs/report-structure.md](docs/report-structure.md) | Shared report-structure reference for all three audit profiles (code/rpm/container) — sections, deterministic_steps conventions |
| [docs/adversarial-content-doctrine.md](docs/adversarial-content-doctrine.md) | The single-source CWE-1427 doctrine every untrusted-content-reading skill references |
| [docs/risk-rating-methodology.md](docs/risk-rating-methodology.md) | How per-finding scores become portfolio risk metrics (findings-trends) |
| [docs/signing.md](docs/signing.md) | **Ledger signing** — what is signed (format-4 payload), when (every write, stamp then sign), who needs the key, configuration variables, the `ledger` CLI, cosign v3 behaviour, rotation |
| [docs/sla-policy.md](docs/sla-policy.md) | **Configuring your own service levels** — SLAs are policy data, never code: per-severity deadlines, multiple profiles, which timestamp starts the clock, and the three states that are not "compliant" |
| [docs/storage.md](docs/storage.md) | Where each kind of data lives — ledgers in git, results local or in object storage, roll-ups, projections, operational config — and the variables that place them |
| [docs/routers.md](docs/routers.md) | **Authoritative index of all seven router kinds** (work/rescan, cost/budget-guard, model, findings, owner, defect, feed) plus the five worklist builders — what each may write, and links to the detail |
| [docs/findings-routing.md](docs/findings-routing.md) | **Canonical:** how a finding gets into the ledger — the findings routers, idempotence, id minting, and the baseline-ownership rule. Disambiguates the other three kinds of routing (work/rescan, owner, defect) |
| [docs/safe-exec.md](docs/safe-exec.md) | The target-build sandbox: profiles, env scrubbing, modes/bypass, gate rule S10 |
| [docs/reachability.md](docs/reachability.md) | **Reachability** — every engine (govulncheck, Joern Java/C tiers, ELF scans, taint enumerator), the evidence ladder and its soundness rules, consumers, and guardrails; pending build-out lives in `progress-tracker/plans/reachability-integration-plan.md` |
| [PROCESS.md](PROCESS.md) | End-to-end 9-stage campaign workflow |

## Versioning

The harness is versioned via the `VERSION` file using semantic versioning (`MAJOR.MINOR.PATCH`). At report time, the short git SHA is appended (e.g. `0.32.1-4dd9796`). See `AGENTS.md` for bump guidelines.

## Security and authorisation

All security testing performed by this harness is authorised. The `AGENTS.md` file establishes the following constraints:

- Only analyse repositories the user has explicitly authorised
- Analyse the exact branch or commit ref specified in the input data
- Implement scope validation before execution
- Maintain audit trails for all agent actions
- Findings are for defensive purposes only

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Portions are derivative works of third-party projects (the `triage`, `threat-model`, `patch`, and `vuln-scan` skills and python3 -m traust.cli admin checkpoint derive from Anthropic's Apache-2.0-licensed defending-code-reference-harness; parts of `vuln-scan` are adapted from the MIT-licensed claude-code-security-review). See [`NOTICE`](NOTICE) for attributions and `LICENSES/` for the full third-party license texts.
