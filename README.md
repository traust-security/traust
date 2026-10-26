# Traust

[![skillsaw grade](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ftraust-security%2Ftraust%2Fmain%2F.skillsaw-badge.json)](https://skillsaw.org/)

Traust is an AI-native workflow engine for the automated security assessment of software. It equips adopters with a structured methodology to run consistent, repeatable multi-framework audits across repositories that include source code, container images, RPM packages, Kubernetes operators, or infrastructure as code (IaC). It provides machine triage of findings and live validation of exploits to drive remediation, recording every event in a signed, tamper-evident ledger. Traust is built to simplify the process of application security, with the ability to scale to hundreds of repositories across dozens of product releases if needed.

This repository holds Traust's agent-facing security skills, slash commands, CLI entry points, and workflow policy. Shared platform capabilities are being consolidated in [traust-core](https://github.com/traust-security/traust-core); adoption by the existing components is in progress. Traust is agent-agnostic in principle, with current implementations for Claude Code and Crush. Developed by Red Hat's Hybrid Platforms team and published under Apache License 2.0.

## Quick start

```bash
git clone <your-forge>/traust.git && cd traust
uv sync
scripts/install_traust           # set up TRAUST_CONFIG_HOME from the config/ templates
scripts/install_traust --doctor  # confirm the install end to end
```

Then start your agent from the workflow engine's root directory and type `/` to see available commands.

- New here? → [docs/getting-started.md](docs/getting-started.md) — zero to first audit report
- Requirements → [docs/requirements.md](docs/requirements.md)
- Full setup reference → [docs/setup.md](docs/setup.md)

## Pipeline

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

You can run Traust in either of the following ways: 

- **[standalone](docs/standalone-usage.md)** (one skill, one repo, locally) 

- **[campaign](docs/campaign-workflow.md)** (end-to-end, org-wide). [PROCESS.md](PROCESS.md) explains the full nine-stage workflow.

Findings interchange is standards-based in both directions: `/triage` imports **SARIF 2.1.0** from any scanner (also Dependabot alert exports and govulncheck streams), and every report exports to SARIF for the adopter's own dashboard or viewer (`python3 -m traust.cli reporting sarif`). See [docs/sarif.md](docs/sarif.md).

## Components

Traust separates security workflow policy, deterministic processing, shared platform capabilities, ledger operations, and data contracts into dedicated repositories.

| Repository | Responsibility |
|---|---|
| **traust** (this repo) | Security skills, prompts, slash commands, CLI entry points, and workflow policy |
| **[traust-core](https://github.com/traust-security/traust-core)** | Shared Python platform API (`traust_core.v1`): domain models, repositories, services, artifact publishing, configuration/context, and provider interfaces; migration in progress |
| **[traust-engine](https://github.com/traust-security/traust-engine)** | Existing deterministic processing: scanner adapters, corpus processing, reporting, metrics, and validation |
| **[traust-ledger](https://github.com/traust-security/traust-ledger)** | Finding identity, signed event history, Merkle integrity, signing, verification, and ledger entry points |
| **[traust-contracts](https://github.com/traust-security/traust-contracts)** | Canonical artifact/config schemas, controlled vocabularies, shared bindings, and database DDL |
| **[traust-sdk](https://github.com/traust-security/traust-sdk)** | Go-facing integration and typed access; a sibling consumer, not a dependency of the Python harness |

**Current integration:** the harness installs `traust-engine`, `traust-ledger`, and `traust-contracts`. These components do not yet declare a dependency on `traust-core`. Core's repositories are implemented, but its domain services are mostly stubs; see its [implementation status](https://github.com/traust-security/traust-core#domain-services-stubs). The intended direction is for execution and CLI adapters to call shared core services, with security workflow policy remaining here. The core REST API route for non-Python consumers is planned, not an available SDK integration.

**Contracts defines data; core supplies shared access and behavior.** A schema, enum, or DDL change belongs in `traust-contracts`, not in this repository. The installed contracts revision determines its resource layout; do not hard-code paths from a different revision.

Python code dependencies are pinned by commit `rev` in `pyproject.toml` and resolved in `uv.lock`. Component ownership, current dependencies, migration boundaries, and dependency update order: **[docs/components.md](docs/components.md)**.

## Documentation

**[docs/README.md](docs/README.md)** — all docs organised by audience (operators, analysts, contributors) with one-line descriptions.

| | |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | Zero to first audit report |
| [docs/standalone-usage.md](docs/standalone-usage.md) | Run any skill locally outside the campaign |
| [docs/campaign-workflow.md](docs/campaign-workflow.md) | End-to-end org-wide campaign |
| [docs/skills.md](docs/skills.md) | All 52 skills: stage, tier, slash command |
| [docs/artifacts.md](docs/artifacts.md) | Every artifact the pipeline produces and who consumes it |
| [docs/components.md](docs/components.md) | Which repo to change for a given fix |
| [traust-core platform API](https://github.com/traust-security/traust-core) | Shared models, persistence, services, and implementation status |
| [PROCESS.md](PROCESS.md) | Full 9-stage campaign workflow |

## Versioning

The workflow engine is versioned via the `VERSION` file using semantic versioning (`MAJOR.MINOR.PATCH`). At report time, the short git SHA is appended (e.g. `0.32.1-4dd9796`). See `AGENTS.md` for bump guidelines.

Dependency pins are separate from the harness release version: `[tool.uv.sources]` selects git commits, not release tags. Core's `traust_core.v1` namespace is an evolving API, not a guarantee that every domain service is implemented or frozen; core documents commit-based consumption rather than tagged releases.

## Security and authorisation

All security testing performed by this workflow engine is authorised. The `AGENTS.md` file establishes the following constraints:

- Only analyse repositories the user has explicitly authorised
- Analyse the exact branch or commit ref specified in the input data
- Implement scope validation before execution
- Maintain audit trails for all agent actions
- Findings are for defensive purposes only

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Portions are derivative works of third-party projects (the `triage`, `threat-model`, `patch`, and `vuln-scan` skills and python3 -m traust.cli admin checkpoint derive from Anthropic's Apache-2.0-licensed defending-code-reference-harness; parts of `vuln-scan` are adapted from the MIT-licensed claude-code-security-review). See [`NOTICE`](NOTICE) for attributions and `LICENSES/` for the full third-party license texts.

<!-- build nudge: force a push event so Konflux rebuilds main -->
