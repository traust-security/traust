---
name: refresh-dashboards
description: >-
  Use when the user asks to refresh, rebuild, or update all the dashboards — "refresh the dashboards", "rebuild every dashboard", "update the derived views", "run the weekly dashboards job" — or on the weekly orchestration cadence. Runs python3 -m traust.cli dashboard refresh, the packaged "Dashboards rebuild" job from docs/continuous-operations.md: traust-core's insight views first (InsightService.refresh), then the per-dashboard builders (executive summary, trends, insecure-patterns, validation-fuzz, RBAC/tenancy rollup, SLA view, compliance, ATT&CK coverage, LoC cache-only); the leadership scoreboard is a core view. Deterministic, ~$0, no agents.
argument-hint: "[--only <stage...>] [--skip <stage>] [--spend-actuals] [--view <name>] [--out <dir>]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust* -m traust.cli.refresh_dashboards:*)
  - Read
---

# Refresh Dashboards — the one-command derived-views rebuild

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Every dashboard is a rebuildable view of traust-core's recorded findings
and decisions. This skill rebuilds all of them in dependency order
as **one sequential deterministic job** — the same chain
`docs/continuous-operations.md` schedules weekly ("Dashboards rebuild"),
packaged so an operator, cron leg, or orchestrator fragment can fire it
as a single command.

Ordering is the whole point:

1. **Core views** — `DashboardsMaterializer`: one `InsightService.refresh`
   renders every view traust-core has built (`traust dashboard view --help` lists them)
   to `<out>/<view>/<stem>.{md,html,json}`. Reads are live, so there is
   no projection to go stale; a view that fails is reported degraded and
   the others still render.
2. **Consumers** — executive summary,
   insecure-patterns, validation-fuzz dashboard, RBAC/tenancy rollup,
   LoC dashboard (cache-only). (*Retired* here:
   dependency-exposure, now the `exposure` and `dependency-reach` core views;
   ATT&CK coverage rollup, now the `attack-coverage` core view; the spend
   dashboard, now `dashboard view spend`.)
   Each continues on error; failures are collected.
3. **Scoreboard last** — *retired:* the scoreboard is traust-core's
   `ScoreboardView`, rendered in step 1; it composes the other views in-process,
   so it needs no place in the order
   (it writes no history row: a trend is the view built at an earlier `as_of`).

## Procedure

1. Run the chain (deterministic; from the harness root):

   ```bash
   python3 -m traust.cli dashboard refresh \
       [--workspace-root <path>] [--results-root <path>] \
       [--only <stage...>] [--skip <stage>] \
       [--spend-actuals] [--view <name>] [--out <dir>] [--run-id <id>] \
       [--list] [--dry-run]
   ```

   `--list` prints the stage names; `--only`/`--skip` select stages
   (canonical order is always preserved); `--view` renders one core view
   in the `views` stage, `--out` is where views are written (default
   `progress-tracker/metrics/dashboards/`).

2. **Read the summary table back.** Report which stages ran, which
   failed, and the elapsed time. The `views` stage prints its JobResult:
   each degraded view is named with its reason. Consumer failures don't block the others; report each
   failed stage with its builder so the user can rerun it alone
   (`--only <stage>`).

3. **Commit the rebuilt artifacts** in `analysis-results/` and
   `progress-tracker/` per the workspace convention (dashboards are
   derived views — regenerating them is always safe; history is the
   view built at an earlier `as_of`).

## What it does NOT cover

- **Spend actuals** (python3 -m traust.cli metrics collect-spend --append) reads
  Claude Code session transcripts on the operator's workstation, so the
  default job skips it to stay orchestrator-portable. Pass
  `--spend-actuals` when running on a workstation that has transcripts;
  the `dashboards:spend-actuals` drift row guards this leg either way.
- **LoC measurement** — the `views` stage renders `loc` from the
  lines the code-facts scan already stored; measuring them is the
  scan's job, not this one's.
- **Agent-built views** — the threat register (`/threat-register`)
  involves judgment, not just aggregation, and is rebuilt by its owning
  skill on its own cadence. The scoreboard composes the threat-register view.
- **Campaign-lane artifacts** that live in the same dashboards folder —
  pqc views, operator-least-priv, rbac-openshift-platform, fuzz,
  benchmark — are outputs of their campaign runs (`/pqc-readiness`,
  `/operator-priv-profile`, `/create-fuzzing`, `/recall-benchmark`),
  not aggregation dashboards; they update when those lanes run.
- **Deciding when to rebuild** — that's `/drift-watch`; its
  `dashboards:*` rows remain the dead-timer backstop (scoreboard >7d,
  spend >4d).

## Stages

| Stage | Tier | Builder |
|---|---|---|
| `views` | core | `InsightService.refresh` via `DashboardsMaterializer` (every view traust-core has built) |
| `exec-summary` | — | *retired:* rendered by the `views` stage (`ExecutiveSummaryView`) |
| `insecure-patterns` | — | *retired:* rendered by the `views` stage (`InsecurePatternsView`, core#301) |
| `validation-fuzz` | — | *retired:* rendered by the `views` stage (`ValidationFuzzView`) |
| `rbac-tenancy` | — | *retired (with its skill):* the `views` stage renders the rollup (`FindingsRollupView`), category-scoped on demand via `ViewFilter.categories`; the axis taxonomy returns with Q5 |
| `sla` | — | *retired:* rendered by the `views` stage (`SlaView`, on the recorded SLA policy, else the security pack's) |
| `compliance` | — | *retired:* rendered by the `views` stage (`ComplianceDashboardView`) |
| `attack-coverage` | — | *retired:* rendered by the `views` stage (`AttackCoverageView`) |
| `loc` | — | *retired:* rendered by the `views` stage (`LocView`) |
| `dependency-exposure` | — | *retired:* rendered by the `views` stage (`ExposureView` for advisory, MAL- and product exposure; `DependencyReachView` for per-ecosystem coverage and shared-package blast radius) |
| `spend-actuals` | consumer, opt-in | python3 -m traust.cli metrics collect-spend --append |
| `spend` | — | *retired:* the legacy spend dashboard; `dashboard view spend` reads traust-core's recorded spend |
| `scoreboard` | — | *retired:* rendered by the `views` stage (`ScoreboardView`) |

## Integrations

- **Emits no artifact of its own** — every output is owned by the
  builder that writes it (the core views and the dashboard files
  under `progress-tracker/metrics/dashboards/`, the
  scoreboard among them). Consumers are documented in each
  owning skill.
- **docs/continuous-operations.md** names this script as the "Dashboards
  rebuild" scheduled job (orchestrator target: weekly; spend ≤4d); the
  security pack's `dashboards` asset runs it.
- **/drift-watch** routes attention here: when `dashboards:*` rows go
  stale, the refresh command is this script.
- **/traust-metrics `--refresh-sources`** — *retired:* the scoreboard
  composes live views (`--only views --view scoreboard` renders it alone);
  this skill is the full chain.
