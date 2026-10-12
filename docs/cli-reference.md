# CLI Command Reference

<!-- The group/operation table below is verified against the live GROUPS
     registry by the "CLI reference drift" check in check_docs_consistency.py.
     Add a group or operation in code and this table fails the docs gate
     until it matches — do not hand-wave it. -->

The harness CLI is grouped: **`traust <group> <operation>`**, or
`python3 -m traust.cli <group> <operation>` from the harness venv. Both are the
same entry point (`[project.scripts] traust = "traust.cli.__main__:main"`).

```bash
traust check skill-alignment
python3 -m traust.cli check skill-alignment      # equivalent
```

## Command groups

18 groups (plus the deprecated `tools` group below).

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `checkov`, `crypto-audit`, `crypto-probe`, `gitleaks`, `govulncheck`, `joern`, `opengrep`, `osv`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `countersign`, `query-index`, `scan-internal-refs`, `toolchain` |
| `build` | Deterministic builders | `cumulative`, `rescan-worklist`, `skills-reference`, `symbol-index` |
| `observe` | Repository observations | `repo-state` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `report-digests`, `skill-alignment`, `skill-security` |
| `compliance` | Compliance reporting | `dashboard`, `scope` |
| `corpus` | Corpus management | `finding-identity`, `findings-db`, `precedent`, `resolve`, `summary` |
| `dashboard` | Dashboard rebuilds | `refresh` |
| `feeds` | Feed management | `fetch`, `reconcile-cve-provenance` |
| `impact` | Impact analysis | `analyze`, `calibrate-rule-pack`, `cluster-state-diff`, `resolve-advisory-symbols`, `sweep` |
| `ledger` | Ledger emission | `doc-variance`, `emit-triage`, `emit-validation`, `emit-verification`, `pull` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `history`, `sla`, `spend` |
| `portfolio` | Portfolio graph | `artifacts`, `build`, `deps-multi`, `freshness`, `interfaces`, `parsers`, `query`, `stats`, `symbols` |
| `registry` | Model/product registry | `models`, `products` |
| `reporting` | Report validation & rendering | `lint`, `rate-threats`, `render`, `sarif`, `validate` |
| `route` | Finding routing | `impact-findings`, `regressions` |
| `sweep` | Class-generalization sweep | `benchmark`, `collect`, `draft`, `emit`, `mine`, `rule-lane`, `sweep` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |

## Observe repository state

`traust observe repo-state` records one repository's forge facts through Core,
then prints its current assembled state as JSON.

```sh
traust observe repo-state --repo https://github.com/example/project \
  --core-config /path/to/traust.yaml --db /path/to/graph/findings.db
```

`--core-config` is required. Configure the output database and forge access:

```yaml
database:
  url: sqlite:////path/to/core.db
process:
  allowed_binaries: [gh, glab]
  keep_env: [PATH, HOME, LANG, LC_ALL, TMPDIR, GH_TOKEN, GITLAB_TOKEN]
  timeout_seconds: 120
```

Provision or migrate the database using the pinned
[Contracts storage schema](https://github.com/traust-security/traust-contracts/blob/main/storage/v1/README.md#migrations)
before running the command. Core rejects uninitialized storage and output SQLite
databases that coincide with an input projection. PostgreSQL requires its Core
driver and a corresponding `database.url`.

The repository must exist in the audit/inventory views. Use `--repo-key` instead
of `--repo` for an audit filing, including one without a URL. `--no-network`
prevents forge calls. `--graph-db` and `--designations` override inventory and
exposure inputs; these and `--db` otherwise use the deployment's existing paths.
Findings and inventory are read-only inputs. Only forge facts are stored;
age, churn, finding counts, risk and exposure are derived when state is assembled.
Expected forge failures appear as JSON statuses with exit code 0; input,
configuration and storage errors exit 2.

Legacy worklist keys map to JSON fields as follows: `tier` → `risk_tier`,
`C` → `changed_lines`, `R` → `churn_ratio`, `S` → `sensitive_changed`,
`S_lines` → `sensitive_lines`, `changed` → `push_changed`, and
`truncated` → `compare_truncated`. Unknown measurements are null;
a measured empty diff remains zero/false.

## Deprecated forms

Two older spellings still work and must not be used in docs, skills, or
command wrappers:

| Form | Example | Use instead |
|---|---|---|
| Pre-grouping module invocation | `python3 -m traust.cli.check_skill_alignment` | `python3 -m traust.cli check skill-alignment` |
| `tools` group alias | `python3 -m traust.cli tools check-skill-alignment` | `python3 -m traust.cli check skill-alignment` |

The dot-separated form keeps working because each `src/traust/cli/<module>.py`
carries an `__main__` delegate that forwards to the grouped parser — which is
exactly why a stale example drifts silently. `src/traust/cli/groups/tools.py`
self-describes as "deprecated aliases for migrated command groups".

Both are enforced: the **CLI invocation syntax** check in
[`check_docs_consistency.py`](../src/traust/cli/check_docs_consistency.py) fails
the docs gate on any dot-separated invocation in `README.md`, `AGENTS.md`,
`PROCESS.md`, `docs/*.md`, `config/*`, `harnessing/*/SKILL.md`, or
`.claude/commands/*.md`.

> Not every `traust.cli.*` module is a CLI. `traust.cli.budget_shadow`, for
> instance, has no argparse or `__main__` — refer to it as a module path, never
> as `python3 -m`.

See [tooling-and-structure-files.md](tooling-and-structure-files.md) for what
each packaged CLI does, and [skills.md](skills.md) for the skills that call them.
