# Observe one repository through Core

`traust observe repo-state` asks Core to record the selected repository's forge facts, then prints its current assembled state as JSON. It does not select a lane or dispatch a job.

```sh
traust observe repo-state --repo https://github.com/example/project \
  --core-config /path/to/traust.yaml \
  --db /path/to/graph/findings.db \
  --graph-db /path/to/graph/portfolio-graph.db \
  --designations /path/to/findings/_manifest/exposure-designations.json
```

`--repo-key` selects an existing audit filing, including one without a usable URL. `--no-network` prevents forge calls. The findings, inventory and designation paths default from the existing deployment locations. The repository must be present in the available audit/inventory views.

## Configuration and storage

Core configuration is explicit and required. For example:

```yaml
# traust.yaml; choose the database location for your deployment.
database:
  url: sqlite:////path/to/core.db
process:
  allowed_binaries: [gh, glab]
  keep_env: [PATH, HOME, LANG, LC_ALL, TMPDIR, GH_TOKEN, GITLAB_TOKEN]
  timeout_seconds: 120
forge_hosts:
  github.com: github
  gitlab.com: gitlab
```

Provision or migrate this database with the pinned Contracts storage/v1 schema before running the command. Core checks the table shape and refuses uninitialized storage. PostgreSQL can be selected with `database.url` and Core's PostgreSQL driver installed. Credentials remain deployment inputs; only explicitly forwarded environment variables reach forge commands.

The command no longer has `--state-db` or a default `graph/repo-state.db`. It never creates a `security_repo_state` table. Core stores only `portfolio_forge_facts` in its configured database. Findings and inventory projections are opened read-only, and configuring either input as the output SQLite database is rejected.

`PortfolioService.repo_state()` assembles state on every call: current audit baseline, stored forge facts, live findings, designation and current time. Age, churn, risk tier and exposure are not persisted. A comparison measured against a different audit baseline is not reused. Expected forge failures are recorded as statuses and the command exits zero after recording them; invalid input/configuration or storage failures remain command errors.

## Source for each ownership change from PR #58

The October 9, 2026 placement sections of [XWING-2205](https://redhat.atlassian.net/browse/XWING-2205) and [XWING-2214](https://redhat.atlassian.net/browse/XWING-2214) supersede earlier pack-based sketches. [Shaun's review of this PR](https://github.com/traust-security/traust/pull/58#issuecomment-6069412172) explains the ownership change; the updated ticket further clarifies that only forge facts are stored.

| Earlier #58 component | New owner | Source |
|---|---|---|
| `traust_pack_security.models` and `ComparisonStatus` | Core `models.portfolio` | XWING-2214: Core models; assembled RepoState |
| `traust_pack_security.observe` and private ForgeClient | Core PortfolioService and existing SourceProvider extended with compare/quota | XWING-2214: observation/stage1/stage2, breaker/quota in Core |
| `traust_pack_security.repos.repo_state` | Core PortfolioRepository, storing only ForgeFacts | XWING-2214: never persist RepoState |
| Pack-owned SQL DDL | Contracts storage/v1 SQLite and PostgreSQL DDL | XWING-2205 and XWING-2214: DDL ownership |
| LegacyObservationInputs, audit/inventory/findings reads | Core repositories, AssessmentService and PortfolioService | XWING-2214 removes this adapter; [XWING-2213](https://redhat.atlassian.net/browse/XWING-2213) assigns these reads to Core |
| Risk/exposure, audit freshness and diff metrics | Core PortfolioPolicy / AssessmentService | XWING-2214's named ownership and existing worklist formulas |
| CLI orchestration | Stays here; Context → record facts → return assembled state | XWING-2214 CLI acceptance criterion; [Core PR #4](https://github.com/traust-security/traust-core/pull/4) wiring pattern |
| Lane and EventSource vocabulary | Stays in `traust_pack_security.vocab` | XWING-2214: routing vocabulary is pack-owned |
| Observation fixtures and domain tests | Core; CLI/batch tests remain here | XWING-2214: keep recorded fixtures, field mapping and batch parity |

The Core change contains a fuller [source and implementation-choice map](https://github.com/traust-security/traust-core/blob/feat/repository-observation/docs/repository-observation.md). API signatures, legacy lookup keys, baseline matching and the explicit configuration flag are implementation choices for review, not claims that Jira prescribed their exact spelling.

## Existing batch behavior and field mapping

`build_rescan_worklist.py` remains the batch entry point. Its forge and portfolio-policy helpers delegate to Core. Its thread pools, shared ban breaker, index-based quota allocation, routing decision table, companion work and output flow remain in the existing command pending their own migration. Individual Core observations use live remaining quota and do not reserve fleet capacity.

The output retains the earlier observation field mapping: `tier` → `risk_tier`, `C` → `changed_lines`, `R` → `churn_ratio`, `S` → `sensitive_changed`, `S_lines` → `sensitive_lines`, `changed` → `push_changed`, and `truncated` → `compare_truncated`. Unknown measurements are null; a measured empty diff remains zero/false. GitHub paths normalize case and tree/blob suffixes; GitLab subgroup paths remain intact. Missing URLs retain distinct filing keys. Legacy abbreviated audit SHAs remain supported.

This implements the observation reads needed by XWING-2214, including XWING-2213's open-count prerequisite. It does not complete all of XWING-2213, the new Router (XWING-2215), engine scheduling or dispatch.

## Verification and dependencies

Run `uv sync --locked` and the test suite. The Core and Contracts pins form a review stack: Contracts first, then Core, then this PR. The Contracts override unifies the newer Core dependency with the older engine/ledger dependency pins. Reconcile the pins after upstream PRs merge if their commit IDs change.

Core tests replay all thirteen retained observation references and cover statuses, live state recomputation, baseline invalidation and memory/SQLite/PostgreSQL storage. `tests/test_repo_observation.py` exercises the real command through Context, checks no-network with a transport that raises if invoked, replays the recorded forge response, and checks storage/configuration failures. Existing worklist tests exercise the batch path. Fixture expectations are not regenerated by this move; routing parity tracked by XWING-2216 is separate.
