# Graphs — every graph the harness builds or reads

Six graphs, built by different skills for different questions. Reaching for
the wrong one is the usual mistake, so each entry below states the question it
answers and who consumes it.

Sizes and node counts depend entirely on your inventory. `repo-graph-stats.md`
and `portfolio-graph-summary.json` report yours after a build.

| Graph | Artifact | Question it answers | Built by |
|---|---|---|---|
| **repo-graph** | `repo-graph.{json,dot,gexf,html}` + `repo-graph-stats.md` | which repos exist, who owns them, what has been audited | [`/repo-graph`](../harnessing/repo-graph/SKILL.md) |
| **portfolio-graph** | `portfolio-graph.db` (SQLite) + `portfolio-graph-summary.json` | what the code depends on, and what a change reaches | [`/portfolio-graph`](../harnessing/portfolio-graph/SKILL.md) |
| **ATT&CK coverage layer** | `attack-navigator-layer.json` (Navigator format 4.5) | which adversary techniques the portfolio's findings and validated chains cover | [`/attack-coverage`](../harnessing/attack-coverage/SKILL.md) |
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

Built from the inputs inventory (segment CSVs + `owners.csv`) cross-referenced
against the findings tree.

Hierarchy: `segment` → `release`/`product` → `product-version` → `category` →
`repo` → `findings`, plus `owner-team` → `repo` and `repo` → `repo-ref` for
the branch-awareness layer.

Edges: `contains` (hierarchy), `ships` (an inventory row ships this repo),
`owned-by` (from `owners.csv`), `has-findings` (a findings directory exists),
and `has_ref` / `ships_ref` for the ref layer.

Repo nodes are coloured by max triaged severity across linked findings
directories and carry `attrs.tp_total`, `attrs.findings_dirs` and
`attrs.findings`. That is what makes it the coverage answer: *which repos have
no audit at all* is a query over these nodes.

Four outputs for four audiences: `.json` is canonical and machine-readable,
`.dot` for GraphViz, `.gexf` for Gephi, `.html` a self-contained pan/zoom page.

**Read by:** `/census` (report population, and repo liveness),
`/portfolio-graph` (as its L0 spine), `/secure-code-audit` (CVE enrichment),
`/fleet-fix` (target selection), `/drift-watch` (staleness), plus
`ops/build_crown_jewel_tiers` (tiering) and
`migrations/resolve_docs_version_refs` (doc-version resolution).

## portfolio-graph — the code-level layers

| Layer | Holds |
|---|---|
| **L0** | the repo-graph spine |
| **L1** | module dependencies — Go (`go.mod`) plus npm, PyPI, Maven, Cargo, RubyGems, NuGet |
| **L2** | Kubernetes interfaces (CRDs, API groups) |
| **L3** | artifacts / SBOM, built during a shallow clone→extract→delete sweep, cached per repo |
| **L4** | symbols, via tree-sitter extraction |

All four are implemented. L1's non-Go half (`deps-multi`) is tree-driven and
resumable from a disk cache, which matters because a full rebuild is not cheap.

**`repo-graph.json` is the L0 layer this builds on**, so repo-graph is a
prerequisite rather than an alternative — a stale spine yields a
portfolio-graph over the wrong repo set.

This is the graph behind blast-radius questions: *which products depend on
module X*, *what does this CVE reach*, *top shared libraries*, *internal
library coupling*.

**Read by:** `/impact-analysis` (advisory blast radius, before per-language
reachability), `/pqc-readiness` (product rollups, vendor tracker,
crypto-dependency scans), `/isolation-review` (resolving a service's repo
set), `/fleet-fix` (every repo affected by one systemic pattern),
`/dependency-watch` (fleet advisory sweep), `/refresh-dashboards` (dependency
exposure), `/drift-watch` (staleness), plus `cli/build_rescan_worklist`
(rescan routing) and `ops/build_crown_jewel_tiers` (tiering).

## Not a graph: `findings.db`

`findings.db` sits in the same directory and is **not** a graph — it is the
traust-contracts storage/v1 store on SQLite: the contract's tables and views
(`report_finding`, `layer_event`, `validation_finding`, `impact_repo`,
`current_finding`, `open_findings`, …) populated from the artifact tree, plus
the harness-defined `repos`, `graph_edges`, `provenance`, `decisions` and
`meta`. Queried via [`/findings-db`](../harnessing/findings-db/SKILL.md);
the same views serve a PostgreSQL adopter unchanged.

It is called out here only because its location invites the assumption. One
table inside it, `graph_edges`, *is* imported from repo-graph so findings can
be joined to what ships them — but a single borrowed edge table does not make
the database a graph, and nothing treats it as one.

## attack-navigator-layer.json — ATT&CK coverage

Joins three sources into one Navigator layer, scored by evidence strength:
**observed** (3) from confirmed `attack_chains[].mitre_attack_refs` in
validation reports, **modeled** (2) from threat-model `attack_refs`, and
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

`/drift-watch` watches repo-graph and portfolio-graph, reporting `stale` when
a graph predates the inputs inventory's HEAD, because inventory or ownership
may have changed underneath it. Neither is rebuilt automatically — drift
routes attention and a human decides.

Staleness costs differ by graph, and one of them is dangerous:

- **A stale repo-graph** misstates coverage and ownership. Findings route to
  the wrong team, and "repos with no audit" omits repos added since the build.
- **A stale portfolio-graph** *understates* blast radius. An advisory sweep
  against an old dependency layer reports fewer affected repos than exist,
  which reads as good news.
