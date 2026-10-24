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

21 groups (plus the deprecated `tools` group below).

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `checkov`, `crypto-audit`, `crypto-cluster`, `crypto-image`, `crypto-probe`, `crypto-source`, `gitleaks`, `govulncheck`, `image-packages`, `image-sbom`, `joern`, `opengrep`, `osv`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `query-index`, `scan-internal-refs`, `toolchain` |
| `assessments` | The audit skills' doors on traust-core | `coverage`, `prepare`, `threats` |
| `auth` | Who you act as, over traust-core's identity provider | `local`, `login`, `logout`, `refresh`, `service-account`, `status`, `token` |
| `build` | Deterministic builders | `rescan-worklist`, `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `skill-alignment`, `skill-security` |
| `cloud-config` | The cloud-config-audit skill's doors on traust-core | `check`, `record`, `run` |
| `compliance` | Compliance reporting; boundary doors on traust-core | `dashboard`, `declare`, `resolve`, `scopes` |
| `dashboard` | Dashboard rebuilds, the team report and one insight view | `refresh`, `team-report`, `view` |
| `feeds` | Security feed snapshots (traust-core) and the product-definitions cache | `fetch`, `fetch-products` |
| `findings` | track-findings' and findings-db's doors on traust-core | `baseline`, `confirm`, `decide`, `find`, `history`, `import`, `queue`, `refuted`, `reject`, `sarif`, `status`, `summary`, `surfaces`, `tickets`, `timeline` |
| `impact` | Impact analysis | `analyze`, `calibrate-rule-pack`, `cluster-state-diff`, `find`, `package`, `sbom`, `sweep`, `symbols` |
| `ledger` | Ledger audit (traust-core) and the doc-variance register | `audit`, `doc-variance` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `history`, `sla`, `spend` |
| `portfolio` | Portfolio graph; `observe` is the `repo_state` materializer; `plan` / `onboard` / `owner-hints` / `import-owners` are add-inputs' doors on traust-core | `artifacts`, `build`, `deps-multi`, `freshness`, `import-owners`, `interfaces`, `observe`, `onboard`, `owner-hints`, `parsers`, `plan`, `population`, `query`, `stats`, `symbols` |
| `products` | corpus-intake's doors on traust-core: products and their corpus ownership | `add`, `list`, `update` |
| `registry` | Model/product registry | `models`, `products` |
| `reporting` | Report validation, rendering & recording | `lint`, `rate-threats`, `record`, `render`, `sarif`, `validate` |
| `triage` | The triage skill's doors on traust-core | `check`, `intake`, `prepare`, `record`, `render` |
| `sweep` | Class-generalization sweep; recall-benchmark answer key | `benchmark`, `benchmark-targets`, `collect`, `draft`, `emit`, `mine`, `rule-lane`, `sweep` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |

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
