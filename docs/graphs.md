# Graphs — every graph the harness builds or reads

Six graphs, built by different skills for different questions. Reaching for
the wrong one is the usual mistake, so each entry below states the question it
answers and who consumes it.

Sizes and node counts depend entirely on your inventory. `repo-graph-stats.md`
and the native `dependency-reach` view report yours after a build.

| Graph | Artifact | Question it answers | Built by |
|---|---|---|---|
| **repo-graph** | `repo-graph.{json,dot,gexf,html}` + `repo-graph-stats.md` | repository relationships, ownership, assessment coverage and highest-degree hubs | `traust portfolio graph`, over native portfolio/assessment/finding services and optional input hierarchy |
| **portfolio-graph** | `portfolio-graph.db` (SQLite) + `portfolio-graph-summary.json` | what the code depends on, and what a change reaches | *retired*: traust-core records each commit's and image's SBOM ([`/portfolio-graph`](../harnessing/portfolio-graph/SKILL.md)); nothing builds the file |
| **ATT&CK coverage layer** | `attack-coverage.json` `navigator_layer` (Navigator format 4.5) | which adversary techniques the portfolio's findings and validated chains cover | [`/attack-coverage`](../harnessing/attack-coverage/SKILL.md) |
| **attack chains** | `attack_chains[]` inside validation reports | how a confirmed finding chains from entry point to terminal asset | [`/validate-findings`](../harnessing/5-validate/validate-findings/SKILL.md) |
| **Joern Code Property Graph** | transient (temp dir, discarded with the run) | does an advisory's vulnerable symbol actually get called in this repo — the evidence that promotes a finding to `affected` | `adapters joern` (Java, C/C++) |
| **govulncheck call graph** | transient, internal to the tool | the same question for Go, and the most precise reachability tier the harness has | `adapters govulncheck` |

Graph artifacts land in `analysis-results/graph/` under the configured
`analysis-results` root — except the call graphs, which are per-run and never
persisted, and attack chains, which live inside the validation reports that
produce them.

Every one is a **derived artifact**, not a system of record. All are
rebuildable, and when a number from a graph disagrees with `/census`, the
census is the denominator authority
([census SKILL](../harnessing/census/SKILL.md)).

---

## repo-graph — coverage and ownership

The retired graph database and builder are not restored. `traust portfolio graph --out <dir>`
derives presentation artifacts from `PortfolioService` products,
releases, components, repositories, refs, upstreams and temporal owners;
`AssessmentService.population` supplies latest default-line assessment coverage,
and `FindingService` supplies disposition-aware open severity and counts.

```bash
traust portfolio graph --out <analysis-results>/graph
# Optional hierarchy source and scope:
traust portfolio graph --inputs <inputs> --product <slug> --out <dir>
# The same view through the generic dashboard door:
traust dashboard view repository-graph --out <dir>
```

The optional `InputSegments` source preserves declared segment, release, product,
version, category and branch relationships without persisting graph rows.
Inventory-only repositories stay visible as unassessed; a tool scan or repo-state
observation alone is not audit coverage. Inventory labels describe the current
source snapshot even when `--as-of` limits recorded facts. The default segment
exclusion follows the dashboard scope; repeat `--exclude-segment` to choose it.

JSON contains every typed node/edge and `stats`, including node/relation counts,
coverage, and deterministic top-20 hubs. `has_ref` / `ships_ref` preserve branch
queries without inflating repository hub degrees. The CLI writes DOT for
GraphViz, GEXF for Gephi, an offline self-contained HTML explorer, and
`repo-graph-stats.md`; the generic dashboard uses `repo-graph.md` for its report.

The HTML view inherits the native report's restrained light visual system.
Search and segment focus reduce the map, pointer dragging and keyboard arrows
pan, zoom controls/scroll/+/- scale, and Home fits. Select a repository in the
keyboard-accessible list for relationships; double-click opens a safe source
URL. Version/category/ref/artifact nodes remain in the full export and node
details while the overview contracts them. No remote script, font or network
dependency is needed.

Exports are human/machine-terminal snapshots, never input to routing, ingestion
or dispatch. Native services remain the authoritative relationship and coverage
queries; the retired `/repo-graph` skill need not be revived.

## portfolio-graph — the code-level layers

The SQLite `portfolio-graph.db` remains retired. Dependencies come from each
commit's manifest SBOM (`impact sbom`) and each image's SBOM
(`adapters image-sbom`). Package import/export and interface scans are recorded
as typed code-facts assessments by `portfolio facts-collect`.

`drift-watch` names `portfolio-graph.db` only in its retired `pqc-backfeed`
history. It does not reopen that database: native PQC reads use recorded facts,
so there is no graph-enrichment copy for a rebuild to clobber.

| Layer | Native question |
|---|---|
| L0 | `portfolio graph`: inventory/release/ref/owner/coverage relationships |
| L1 | `portfolio dependencies` / `dependents`: recorded SBOM blast radius |
| L2 | `portfolio crd-consumers`: API-group owners, consumers, RBAC and webhooks |
| L3 | `portfolio ships-module`: images shipping a module in their recorded SBOM |
| L4 | `portfolio imports-package` / `exports-of`: cited package and symbol facts |

`portfolio internal-coupling` ranks packages with declared producing-repository
provenance by distinct dependent repositories, not dependency rows. Missing
scans remain unmeasured. `dependency-reach` retains the SBOM coverage denominator.
Presence or an import is never exploitability; `/impact-analysis` owns affectedness.

## Not a graph: `findings.db`

`findings.db` sits in the same directory and is **not** a graph — it is a
relational projection of the findings corpus (`findings`, `events`,
`decisions`, `validations`, `repos`, `impact`, `provenance`, plus views),
queried via [`/findings-db`](../harnessing/findings-db/SKILL.md).

It is called out here only because its location invites the assumption. One
table inside it, `graph_edges`, *is* imported from repo-graph so findings can
be joined to what ships them — but a single borrowed edge table does not make
the database a graph, and nothing treats it as one.

## attack-coverage navigator_layer — ATT&CK coverage

Joins three sources into one Navigator layer, scored by evidence strength:
**observed** (3) from confirmed `attack_chains[].mitre_attack_refs` in
validation reports (not yet recorded in traust-core), **modeled** (2) from threat-model `attack_refs`, and
**derived** (1) from finding categories.

The scoring is the point: a technique covered only by category inference is
not the same claim as one demonstrated against a live target.

## attack_chains[] — per-finding attack paths

Not a standalone file. Each validation report carries `attack_chains[]` with
`chain_id`, `name`, `entry_point`, `terminal_asset`, `mitre_attack_refs[]`,
`steps[]` and a `verdict`. This is the graph that says *how* an attacker gets
from an entry point to an asset, and it is the input the ATT&CK layer scores
as "observed".

## Transient reachability graphs

**What they are for:** deciding whether an advisory actually reaches *your*
code. A manifest pin says a vulnerable package is present; it does not say
anything calls the vulnerable function. These graphs answer that, and the
answer promotes or withholds an `affected` classification.

**Used by** [`/impact-analysis`](../harnessing/3-audit/impact-analysis/SKILL.md)
as its strongest evidence tier, and by
[`/secure-rpm-audit`](../harnessing/3-audit/secure-rpm-audit/SKILL.md).

### `adapters joern` — Code Property Graph (Java, C/C++)

Builds a CPG of the repo's first-party sources — Joern's model, combining AST,
control flow and data flow in one queryable graph — with the frontend named
explicitly per language (`javasrc2cpg` for Java source, `c2cpg` for C/C++,
`jimple2cpg` when compiled artifacts are present). Reachability is then a
CPGQL query: filter `cpg.call` by `methodFullName` against the advisory's
vulnerable symbols or package prefixes.

Each resolved call site is reported with file, caller method, approximate line
and a `test_path` tag. The caller method is the authoritative anchor — line
attribution drifts in `javasrc2cpg`, so exact lines are verified by reading
the file.

**The evidence rule is asymmetric, deliberately:**

- a resolved first-party call to the vulnerable symbol promotes evidence to
  `symbol` and classification to `affected`, with the witness cited
- package-level calls promote `manifest` → `symbol-usage`
- **an absent call path never demotes anything.** Java DI (Spring/CDI),
  reflection and MethodHandles hide edges from static analysis, so
  `no_call_sites_found` is recorded honestly and the classification stays
  where the cheaper tiers put it

It is gated on the cheap tiers — it runs only when a manifest pins the module
in range or textual usage was found — because building a CPG is expensive. If
Joern is absent the tier records `skipped: joern not on PATH` and is forgone,
never faked.

### `adapters govulncheck` — call graph (Go)

The same question for Go, using the Go toolchain's own call-graph analysis,
reporting `symbol_reachable` and related classifications. This is the
strongest reachability tier in the harness because the Go analysis is precise;
the Joern tier is its analogue for Java and C/C++.

### Neither is persisted

`joern.py` builds the CPG inside a temporary directory and discards it when
the run ends; govulncheck keeps its graph internal. What survives is a
per-candidate classification with its witness, recorded in the impact-analysis
artifact.

So these are the richest graphs the harness touches and the only ones you
cannot query after the fact. To re-examine reachability, re-run the adapter —
there is no stored graph to open.

---

## Freshness

Native graph views read current owners on demand. Exported files are dated
snapshots: regenerate them after inventory, ownership, assessments or findings
change. A stale export may mislead a reader, but is never a routing or dependency
authority. The retired portfolio SQLite graph is not revived as a freshness gate.

A stale relationship export misstates coverage and ownership. A stale manifest
SBOM understates dependency reach, which can read as good news. Regenerate the
presentation and refresh source facts through their respective owners; never
repair an export by editing graph rows.
