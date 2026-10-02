# Traust

[![skillsaw grade](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fopenshift%2Ftraust%2Fmain%2F.skillsaw-badge.json)](https://skillsaw.org/)

Traust is an agent harness for automated security assessment of software portfolios at scale. It equips an AI coding agent with structured methodology to run consistent, repeatable multi-framework audits across hundreds of repositories — source code, container images, RPM packages, Kubernetes operators, and IaC — then triage findings, validate exploitability on live systems, drive remediation, and record every disposition in a signed, tamper-evident ledger. Manual review does not scale to hundreds of repositories across dozens of product releases; Traust does.

This repository holds the skills, slash commands, schemas and prompt engineering that drive the harness. Traust is agent-agnostic in principle, with current implementations for Claude Code and Crush. Developed by Red Hat's Hybrid Platforms team and published under Apache License 2.0.

## Quick start

```bash
git clone <your-forge>/traust.git && cd traust
uv sync
scripts/install_traust           # set up TRAUST_CONFIG_HOME from the config/ templates
scripts/install_traust --doctor  # confirm the install end to end
```

Then start your agent from the harness root and type `/` to see available commands.

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

Two ways to run it: **[standalone](docs/standalone-usage.md)** (one skill, one repo, locally) or **[campaign](docs/campaign-workflow.md)** (end-to-end, org-wide). The full 9-stage workflow is in [PROCESS.md](PROCESS.md).

Findings interchange is standards-based in both directions: `/triage` imports **SARIF 2.1.0** from any scanner (also Dependabot alert exports and govulncheck streams), and every report exports to SARIF for the adopter's own dashboard or viewer (`python3 -m traust.cli reporting sarif`). See [docs/sarif.md](docs/sarif.md).

## Components

This repository is the **agent-facing layer** of a five-component stack, not the whole system. Skills, slash commands and CLIs live here; the engine, ledger, contracts, and SDK are separately versioned repositories installed as pip dependencies pinned by git tag.

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

- [traust-engine](https://github.com/traust-security/traust-engine)
- [traust-ledger](https://github.com/traust-security/traust-ledger)
- [traust-contracts](https://github.com/traust-security/traust-contracts)
- [traust-sdk](https://github.com/traust-security/traust-sdk)

**A schema or enum change belongs in `traust-contracts`, not here** — there is no local `schemas/` directory; the `schemas/v1/…` paths resolve inside the installed contracts package. Which repo to change for a given fix, how git-tag pinning works (and the `uv lock` "conflicting URLs" failure it produces when pins disagree), and the bottom-up release order: **[docs/components.md](docs/components.md)**.

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
| [PROCESS.md](PROCESS.md) | Full 9-stage campaign workflow |

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
