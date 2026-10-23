---
name: dependency-watch
description: >-
  Use on the daily continuous-operations cadence, or when the user asks to "check for new dependency CVEs", "run the deps lane", "watch dependencies", or "file dependency vulnerabilities" — runs the advisory-driven dependency chain end to end: refresh the vulnerability feeds, sweep new advisories against the audited fleet, run /impact-analysis reachability on hits, and route affected repos' findings into their disposition ledgers as event-carried findings (gate A15 — the baseline is never written), so a newly disclosed dependency CVE becomes an owned, SLA-clocked finding the same day. Orchestrator-neutral — invocable identically from an operator session, cron, Source Code Intelligence, or any enterprise scheduler.
argument-hint: "[CVE-ID | --since <date>] [--include-likely] [--dry-run]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  # Scoped per A11 — exactly the chain's scripts, never a bare interpreter.
  - Bash(python3 *-m traust.cli feeds fetch:*)
  - Bash(python3 *-m traust.cli impact analyze:*)
  - Bash(python3 *-m traust.cli route impact-findings:*)
  - Bash(python3 *harnessing/3-audit/dependency-watch/scripts/fleet_sweep.py:*)
  - Read
  - Glob
  - Grep
---

# Dependency Watch — the advisory-driven deps lane, end to end

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Closes the loop the coverage model calls "new CVE disclosed in a
dependency" (docs/continuous-operations.md): from advisory publication to
an **accountable finding** — owner, SLA clock, Jira path, UI visibility —
in one pass, the same day. Before this skill the chain's pieces all
existed but stopped at analysis: `affected` classifications reached
findings.db's `impact` table and no further (no baseline entry, no
ledger event — the filing gap named 2026-07-28).

Orchestrator-neutral by design: any scheduler that can start a harness
session runs this identically — operator daily session, cron, the
Source Code Intelligence worker, Konflux, or an enterprise-native tool.
Nothing here assumes or requires a particular front-end; every output
lands in the one per-repo baseline + disposition-ledger pipeline that
all reporting surfaces (findings-current, SLA view, team reports,
executive summaries, SCI) already read.

## Procedure

1. **Refresh feeds** (deterministic):
   `python3 -m traust.cli feeds fetch` — the cached feeds (EPSS, CISA KEV,
   vendor CVE and VEX data). OSV is not cached: it is queried live
   through the shared OSV client. A feed the fetch reports `STALE` is
   named in the run's report; `/drift-watch` flags stale caches
   independently.

2. **Determine the advisory set.** With a `CVE-ID` argument, that CVE
   only. Otherwise: advisories newly published/modified since the last
   run (`--since <date>`, default = the previous run's stamp from the
   worklist/ledger context). Skip advisories already fully routed
   (their artifact exists AND `route_impact_findings.py` reports
   0 targets outstanding — re-runs are idempotent regardless).

   **Bootstrap / full-baseline mode (`bootstrap` argument, first run,
   quarterly re-baseline, or after portfolio-graph rebuilds):** run
   `python3 traust/harnessing/3-audit/dependency-watch/scripts/fleet_sweep.py`
   — clone-free fleet inventory (graph `depends_on` pairs × the OSV
   batch API, deduped by advisory display id — CVE alias when present,
   else the OSV id itself, so CVE-less malicious-package (`MAL-`)
   advisories are never dropped — the Shai-Hulud class — severity-banded,
   with `malicious` rows forced CRITICAL and sorted first) persisted to
   `analysis-results/impact/fleet-osv-worklist-<date>.json` with a staged
   worklist of ready-to-run impact/filing commands. `--ecosystem` defaults
   to `all` and sweeps every ecosystem present in the graph per-ecosystem
   against OSV (Go plus npm, PyPI, Maven, Cargo, RubyGems, NuGet, GitHub
   Actions); pass a comma list (e.g. `--ecosystem Go,npm`) to scope a run
   to specific ecosystems. Docker and Helm carry blast-radius edges in the
   graph but have no OSV-by-name lane (no ecosystem covers a base-image
   tag or a chart version) — they are graph-only and skipped from the OSV
   sweep by design, logged rather than silently dropped. Staging discipline is built in: CVEs whose in-range blast radius exceeds
   `--deep-scan-cap` (default 100 repos) get graph-only impact
   artifacts (exposure dashboard-visible immediately) with deep scans
   left to explicit operator staging; bounded CVEs get deep-scan +
   filing commands. Worklist rows carry **argv arrays**
   (`impact_argv`/`route_argv`) — module names originate in target
   repos' go.mod and versions in OSV, both attacker-influenceable, so
   rows are executed as argument vectors exactly as given (one Bash
   call per array, no shell string joining, no edits) in order
   (severity, then blast radius). Inputs failing the charset gates are
   listed under `rejected_inputs` — review them, never hand-repair
   them into commands (assessment 2026-07-31 H1). Each command's
   `--fixed-version` is the fix for the installed version's own span
   (the highest across the installed versions it covers; per-version
   targets are in `fixed_by_version`). An advisory with no fix still
   gets a row: `fix_available: false`, no `--fixed-version`, and the
   range bounded by `last_affected` when known, else `*`. An advisory
   can hit packages in several ecosystems: each command carries its
   module's own `ecosystem` (used for its gates and `--ecosystem`), and
   the row lists them all in `ecosystems`. Commit the sweep artifact.

   **A degraded sweep is not a quiet day.** Exit 3 with
   `status: degraded` means some (name, version) pairs were never
   answered (`pairs_unanswered`, listed in `unanswered_pairs`) or some
   advisory details are missing. Report the counts; the unanswered pairs
   are re-run, never read as "no advisories". Exit 2 with
   `status: failed` means OSV could not be used at all (`failure` says
   why, including `air-gapped`: the sweep needs the OSV API): nothing was
   checked, the worklist is empty, and the day is reported as not swept.

   **Auto-verify malicious hits (`--verify`, opt-in).** OSV flags a
   malicious package purely by name+version match, which is blind to npm
   aliasing: a manifest line `"legacy-swc-helpers": "npm:@swc/helpers@0.4.14"`
   declares the *legitimate* `@swc/helpers` under a local alias name, not
   the malicious registry package — an OSV name-match false positive that
   historically only manual source inspection caught. With `--verify`, each
   `malicious` worklist hit is checked against its recorded `manifest`
   provenance BEFORE emission (`harnessing/3-audit/dependency-watch/scripts/verify_dep_provenance.py`): the exact
   source manifest is fetched and re-parsed (npm aliases resolved to their
   real package), and each row is annotated `verification: {status,
   evidence, checks}`. A **positively refuted** hit (present only as an alias
   to a different package, or genuinely absent from every recorded manifest,
   with no confirmation anywhere) is moved out of the actionable worklist
   into `refuted_findings` with its reason — an alias/false-positive is
   auto-dropped *with a paper trail*, never silently and never as a live
   finding. Confirmed hits and `unverifiable` ones (no provenance recorded,
   or fetch/parse failed) stay actionable (fail-safe — a finding is never
   dropped for lack of data). `--verify` is **off by default** (preserves
   the deterministic offline sweep); it adds `gh api
   repos/<org>/<name>/contents/<path>` raw fetches — the sweep's only
   network egress, routed through the same vetted argv-list fetcher the
   portfolio-graph build uses (no shell string, no secret in argv). Enable
   it when a run surfaces malicious hits worth confirming before they page
   an owner.

3. **Blast radius + reachability** per advisory affecting a module the
   portfolio uses: run `/impact-analysis` (or its script directly):
   `python3 -m traust.cli impact analyze <CVE>
   --module <m> --vulnerable-range '<r>' --fixed-version <v> ...` —
   writes `analysis-results/impact/<cve>-impact-analysis.json`.
   **Precondition:** a fresh portfolio graph — the graph is the blast
   radius; check `/drift-watch`'s `portfolio-graph` item first and say
   so if stale rather than silently analyzing against old topology.

4. **Severity from the advisory, never invented:** take severity from
   the OSV/advisory record (CVSS mapping: 9.0+ critical / 7.0+ high /
   4.0+ medium / else low), noting KEV listing in the rationale if
   present (KEV escalates dispatch urgency, not severity).

5. **File** (deterministic, idempotent):
   `python3 -m traust.cli route impact-findings
   analysis-results/impact/<cve>-impact-analysis.json --severity <s>
   [--include-likely] [--dry-run]` — for every `affected` repo with a
   baseline: campaign-ID finding carried on its ledger event (`event.finding`, contracts >= 0.4.4; the baseline is never written — gate A15)
   (`origin: impact-analysis`, `category: supply-chain`,
   `validation_status: not_verified`), claim hash pinned, ledger birth
   event (`source.type: impact_report`, machine-static class 3),
   cumulative `*-findings-current.{json,md}` rebuilt. Repos without a
   baseline are listed, never silently dropped — they are unaudited
   inventory, which is a census matter, not a filing one.

6. **Report** what was routed: per CVE — affected/filed/already-filed/
   no-baseline counts and the finding IDs, so the run's output is
   reviewable at a glance. Criticals routed here inherit the standing
   SLA (validated-or-blocked ≤7d) like any other critical.

## Constraints

- Deterministic steps route and record; **the affectedness judgment is
  /impact-analysis's** (evidence ladder) and downstream adjudication is
  /triage and /validate-findings' — this skill never overrides either.
- Severity comes from the advisory record; when no CVSS exists, file at
  `medium` with the uncertainty named in the description rather than
  guessing high or suppressing.
- Never file `likely_affected` by default; `--include-likely` is an
  explicit operator choice (precision posture).

## Integrations

Consumes: advisory feed caches (producer: python3 -m traust.cli feeds fetch);
`analysis-results/impact/*-impact-analysis.json` (producer:
`/impact-analysis` — python3 -m traust.cli impact analyze); portfolio graph
(producer: `/portfolio-graph`; freshness gated via `/drift-watch`);
findings.db `repos` baselines (producer: python3 -m traust.cli corpus findings-db).

Produces: `analysis-results/impact/fleet-osv-worklist-<date>.json` —
terminal beyond this skill (a staging inventory consumed by the same
run's worklist execution and by operator review of deep-scan staging;
no downstream skill reads it; carries a `refuted_findings` list of
malicious hits auto-refuted against their source manifests under
`--verify`, via `harnessing/3-audit/dependency-watch/scripts/verify_dep_provenance.py`); baseline appends +
disposition-ledger birth events via
python3 -m traust.cli route impact-findings (consumers: `/track-findings`
cumulative rebuild, `/triage` adjudication, `/verify-remediation`
(resolution), owner routing / SLA view / team reports /
`/executive-summary-findings` / `/file-security-defect`, and any ledger
front-end such as Source Code Intelligence). The per-run routing report
is terminal (human review of the day's filings).

Related: the change-triggered manifest path (rule 3b in the rescan
router) covers dependency *changes on our side*; this skill covers
advisory arrival on *their* side. The router's `cve` event lane
(`rescan-events.jsonl`) queues ad-hoc CVE requests into the same chain.
