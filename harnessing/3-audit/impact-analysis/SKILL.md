---
name: impact-analysis
description: Use when determining which portfolio repositories are affected by
  an advisory (CVE, GHSA, MAL-/malicious-package, or another OSV-native id).
  Walks the commits' recorded SBOMs for blast radius, then runs language-specific
  analysis (govulncheck reachability for Go, the strongest tier;
  manifest-level analyzers for npm, PyPI, Maven, Cargo, RubyGems, and NuGet;
  manifest-level evidence for the universal Docker/GitHub
  Actions/Helm surfaces) to classify every importing repo. Records a
  schema-validated artifact per commit in traust-core, consumed by /triage
  and /verify-remediation. New unjudged findings omit validity assertions;
  affectedness evidence does not author a Core validity judgment.
argument-hint: "<advisory-id> [--repo-url <url> --sha <commit>] [--symbols <s1,s2>] [--feature-desc '...'] [--scan]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(python3 *-m traust.cli impact find:*)
  - Bash(python3 *-m traust.cli impact sbom:*)
  - Bash(python3 *-m traust.cli impact symbols:*)
  - Bash(python3 *-m traust.cli impact analyze:*)
  - Bash(python3 *-m traust.cli impact export:*)
  # (Bash(git:*) dropped 2026-07-31 P1-W4: no git invocation in this skill's flow)
  - Bash(jq:*)
  - Bash(python3 *-m traust.cli impact document:*)
---

# Impact Analysis

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Determine per-repo CVE affectedness across the portfolio. Takes a CVE
identifier, walks the commits' recorded SBOMs for the blast radius, runs
language-specific analysis, and classifies every importing repo. Output
is a structured artifact per commit, recorded in traust-core, that feeds
`/triage` Phase 2f and `/verify-remediation` full-sweep scoping.

## How it works

python3 -m traust.cli impact analyze does all the work, on traust-core's
`ExposureService`:

1. **Blast radius** — walks the recorded SBOMs for every commit that holds
   the advisory's packages, directly, through a base image or through an
   internal library. Each commit's version is then checked against the
   advisory's version ranges.
2. **L4 refinement** — *retired:* the model has no package-import edges;
   the deep scan's govulncheck and source-import tiers answer it.
3. **Deep scan** — with `--scan`, for commits still classified
   `likely_affected` or `inconclusive`, clones the commit at its sha and
   runs the language-specific analyzer.
4. **Classification** — each repo gets a classification based on the
   accumulated evidence.
5. **Artifact emission** — records an `impact` assessment with its
   `impact-analysis` document per commit in traust-core.

### Language analyzers

Analysis is **per-ecosystem**: the analyzer is selected from the
advisory's package ecosystem, not from a single-language guess of the
clone. A non-Go ecosystem (`npm`/`pypi`/`cargo`/`maven`/`ruby`/`nuget`, or a
manifest surface) gets its analyzer regardless of what language the repo
looks like — so a Go module that also ships a JS UI subdir, analyzed for an
npm advisory, scans its `web/ui/react-app/` sources instead of being
misrouted to the Go analyzer by `go.mod`-wins language precedence. The
blast radius is already per-ecosystem (packages are ecosystem + name), so
the analyzer matches it. Each analyzer owns the full tool chain for its
ecosystem.

**Go** (symbol-level — the strongest tier):
- `govulncheck` source mode → symbol reachability
- ELF string scan → package path presence in shipped binaries (*retired:*
  it read extracted image binaries nothing produced, so it never ran)
- Unsafe/reflect detection → flags repos needing manual trace

**GitHub Actions, Docker, Helm** (manifest surfaces, no reachability tier):
the commit's SBOM says whether the action/base-image/chart is declared, and
whether the declared version is in the advisory's range. There is no package-manifest language or call-graph tool for these
surfaces to deep-scan, so the classification ceiling is `likely_affected`,
never `affected`, regardless of how confirmatory the manifest match is.

**Python, Rust, JavaScript, Java, Ruby, NuGet** (manifest-level):
the lockfile/manifest pins in the commit's SBOM (syft reads
`requirements*.txt`/`Pipfile.lock`/`poetry.lock`, `Cargo.lock`,
`package-lock.json`/`yarn.lock`, `pom.xml`/gradle, `Gemfile.lock`,
`packages.lock.json`/`*.csproj`) with version-range comparison, plus a
source import scan. **The ceiling for
manifest evidence is `likely_affected`** — a lockfile pin proves the
dependency is present at a vulnerable version, never that the vulnerable
symbol is reachable. A pin outside the range yields
`version_not_in_range`; module absent from manifests AND no source
imports yields `not_observed` (at manifest level).

**C/C++** (binary + source level): header-include grep
(`#include <lib/…>`) plus a DT_NEEDED linked-library scan of shipped
image binaries (*retired:* it read extracted image binaries nothing
produced, so it never ran). `linked` caps at `likely_affected`;
`not_linked` with no includes yields `not_observed`.

**Assurance boosters (all languages):**
- **Symbol-usage scan** — when the advisory names vulnerable symbols
  (published by its source, mined from its fix commits by
  `traust impact symbols`, or passed with `--symbols`), source is grepped
  for calls to them (`symbol_usage_scan`), and for C/C++ the shipped
  binary's strings are scanned for the symbol names (`binary_symbol_scan`,
  *retired* with the other binary tiers) — the binary references the
  vulnerable *function*, not just the library. Textual
  usage is stronger than a pin, weaker than reachability: evidence
  level `symbol-usage`, ceiling still `likely_affected`.
- **SBOM cross-check** — the SBOMs of images built from the commit
  (recorded in traust-core) are checked for the module: `sbom_scan`/`sbom_shipped_version` record
  what the **delivered image** actually contains, vs what the lockfile
  intended. Evidence only, never a verdict by itself.
- **Joern call-site reachability (Java v0.231.0, C/C++ v0.232.0)** —
  the analogue of govulncheck's symbol tier. *Not run today:* the Java
  tier was withdrawn (interface dispatch, zero promotions); the C/C++
  tier returns once the impact-analysis schema carries its evidence
  fields. The rules below hold when it does.
  python3 -m traust.cli adapters joern builds a CPG of the repo's
  first-party sources (joern-parse/javasrc2cpg, external pinned tool —
  see docs/external-dependencies.md) and reports resolved call sites
  matching the advisory's vulnerable symbols (`class#method`) or
  package prefixes, each with file + caller method + approximate line
  and a `test_path` tag (line attribution drifts in javasrc2cpg —
  the caller method is the authoritative anchor; exact lines are
  verified by reading the file, per citation-gate discipline). Gated on the cheap tiers (runs only when the manifest pins the
  module in-range or textual usage was found). **Evidence asymmetry,
  by design and stated on every artifact**: a resolved first-party
  call to the vulnerable symbol promotes to evidence level `symbol`
  and classification `affected` (witness cited in `joern_witness`);
  package-level calls promote `manifest` → `symbol-usage`; an absent
  path NEVER demotes anything — Java DI (Spring/CDI), reflection, and
  MethodHandles hide edges from static analysis, so `no_call_sites_found`
  is recorded honestly and the classification stays where the cheaper
  tiers put it. Joern absent → `skipped: joern not on PATH` in the
  evidence, tier silently forgone, never faked. **C/C++**: the same
  wrapper with `--language c` (c2cpg frontend, exact function-name
  matching — prefix matching on short C identifiers would over-match);
  gated on include/linked evidence AND advisory-named symbols; the
  same promotion-only asymmetry (C function pointers hide edges the
  way Java DI does). Validated 2026-07-31
  against the 2026-07 Java engagement corpus: audit-confirmed sink METHODS
  re-found (dnsjava TSIG.verify at the exact audited SHA; jline3
  CursorSupport.getCursorPosition at upstream HEAD; jackson's actual
  Class.forName choke point correctly resolved to
  TypeFactory.classForName) — record in
  analysis-results/scan-testing/joern-validation/.

Every repo entry records `evidence.evidence_level`
(`symbol > symbol-usage > binary > manifest > none`) so downstream
consumers weigh a govulncheck reachability verdict above a lockfile
pin. Adding a new language means an `ImpactAnalyzer` provider in
traust-core (`providers/impact.py`).

**Assurance promotion beyond static:** `affected` is machine-static
evidence (ledger class 3). To reach execution evidence (class 1), feed
the affected list to `/create-fuzzing` (input form 2b — harness entry
point from `govulncheck_trace`, corpus from `feature_description`); a
reproducing input flips the finding to `confirmed` through the
disposition ledger. Live validation (`/validate-findings`) is the
end-to-end gold standard for shipped products. Triage's Phase 2f
attacker-influence judgment ranks which `affected` verdicts deserve
that investment first.

## Input

Parse from `$ARGUMENTS`:

- `<advisory-id>` (positional, required) — `CVE`/`GHSA`/`MAL`/`PYSEC`/`GO`/
  `RUSTSEC`/`OSV`-prefixed, e.g. `CVE-2026-33186` or a `MAL-` malicious-package
  advisory. A CVE whose record names no package takes the packages its
  GHSA/GO/PYSEC aliases name.
- The affected module, its ecosystem, the vulnerable packages, the
  vulnerable range (every span, lower and upper bounds) and the fixed
  version come from the advisory's record (`traust impact find`), not
  from arguments.
- `--symbols <s1,s2>` — vulnerable symbols you identified (Step 1); they
  join any the advisory publishes or its fix commits yield.
- `--feature-desc "..."` — what capability must be in use.
- `--repo-url <url> --sha <commit> [--branch <branch>]` — assess one commit instead of every
  commit the advisory reaches.
- `--scan` — clone undecided commits and run the deep scan; without it,
  SBOM evidence only, no cloning or scanning.
- `--advisory-file <path>` — repeatable exported raw OSV JSON input for
  `find`, `symbols`, and `analyze` (also `sweep` for offline feed sweeps).
  When supplied, advisory lookup uses only these documents, never the live
  OSV provider. An absent requested advisory is an error, not a network fallback.

## Procedure

### Step 1: Parse CVE and identify attack surface

Fetch the advisory to extract affected module, version range, vulnerable
symbols/packages, and feature description. `traust impact find` returns the
OSV record `analyze` itself works from:

All advisory fetches go through the scoped fetcher — the skill's only
network egress (the hosts registered in the feeds registry traust-core ships, default TLS; a raw `curl` grant
would be an arbitrary-destination exfiltration channel under
injection — audit D7):

```bash
# OSV (the record analyze uses)
python3 -m traust.cli impact find <ADVISORY-ID>
# Offline alternative: pass the same exported OSV records to find, symbols and analyze
python3 -m traust.cli impact find <ADVISORY-ID> --advisory-file <osv-export.json>

# NVD
python3 -m traust.cli impact document nvd <CVE-ID>

# Red Hat CSAF VEX (CVE-keyed)
python3 -m traust.cli impact document vex <cve-id>
```

When symbols aren't in the advisory, read the fix commit diff to identify
the affected API surface (`python3 -m traust.cli impact symbols
<ADVISORY-ID>` mines the fix commits first; read the diff when it reports
`no_symbols_in_diff`, `no_fix_commit` or `degraded`) and pass what you find
with `--symbols`.

**The vulnerable range and fixed version come from a fetched advisory or
an explicitly supplied raw OSV export, never from memory.** If neither
source supplies the advisory, stop and report it as not assessed. Pass
the same repeatable `--advisory-file` inputs to `symbols` and `analyze`
when operating offline. `advisory_sources` retains the sources used;
`--scan` may still require repository checkout access.

### Step 2: Run the analysis

```bash
python3 -m traust.cli impact analyze <CVE-ID> \
    --symbols <s1,s2> \
    --feature-desc 'description of the vulnerable feature' \
    --scan
```

The script handles everything: blast radius, cloning, language-specific
analysis, classification, artifact recording, and filing a dependency
finding for each `affected` commit/package. Every affected ecosystem,
module and held version gets its own document with its own range and fix.

Leave out `--scan` for a fast SBOM-only pass (no cloning). A commit
with no recorded SBOM is not in the blast radius. The SBOM's source decides
what its silence means:

- **A manifest scan of the commit**
  (`python3 -m traust.cli impact sbom --repo-url <url> --sha <commit> [--branch <branch>]`,
  no file: syft over that commit's manifests) records the SBOM with its coverage, so
  a package it lacks is `not_imported`, unless a manifest it couldn't resolve leaves
  that ecosystem `inconclusive`. The `manifest_sbom` asset (`impact manifest-sbom --repo <url>`)
  does the same, but only for the repository's observed default head.
- **An SBOM given as a document**
  (`python3 -m traust.cli impact sbom <file> --repo-url <url> --sha <commit> [--branch <branch>]`)
  has no scan behind it, so its coverage is unknown. A package it lacks is
  `inconclusive`, never `not_imported`. Its pins still classify (`likely_affected`,
  `version_not_in_range`). For absence evidence on that commit, rerun `impact sbom`
  for it without the file, or use `--scan`.

### Step 3: Validate and review

Each document is validated against the schema when it is recorded.

Review the summary: how many affected vs not_observed? Do the numbers
make sense given what the CVE is about?

Repos classified `inconclusive` with `needs_manual_trace: true` have
unsafe pointer or reflection usage that may hide reachability — these
need human review.

### Step 4: Export the fleet view for consumers

```bash
python3 -m traust.cli impact export <ADVISORY-ID> \
    --out <output-dir>/<advisory-id>-impact-analysis.json
```

Use the configured `locations.analysis_results` output root when choosing
`<output-dir>`. Export reads the already recorded artifacts, including
non-affected and undecided classifications; it does not fetch or re-analyze.
Its `commits` count is distinct commits; `analyses` counts the exported
commit/ecosystem/module/version rows. Each row carries the exact complete
native document under `document`, plus classification, evidence, repository
URL, SHA and recorded assessment/artifact/finding identifiers. Export selects
the latest complete preparation scope. Preserve each native document's
`metadata.preparation_scope`: its digest and full member set identify the
package/version snapshot prepared together. An incomplete newer scope cannot
clear a previous complete result; a complete corrected SBOM snapshot replaces
obsolete modules and versions. Distinct members within that snapshot remain
separate. Summary and timeline count its worst verdict once per commit/advisory,
not whichever safe package packet happened to finish last.

## Classification rubric

| Classification | Meaning | Evidence |
|---|---|---|
| `affected` | Vulnerable symbol reachable or feature in use | govulncheck `symbol_reachable` or feature-pattern match |
| `likely_affected` | Package imported, no deep scan yet | manifest pin in range, imports found or symbols used + no govulncheck result |
| `not_observed` | Vulnerable package/symbol not observed | govulncheck `*_not_observed`, or not in manifests and no imports |
| `version_not_in_range` | At safe version | SBOM version ≥ fix |
| `not_imported` | Module not in dep graph | blast-radius miss against a manifest-scanned SBOM (coverage known) |
| `inconclusive` | Analysis hit limits | clone failed, non-Go repo, unsafe/reflect, a Go pin in range not yet scanned (`--scan`), a package absent from an SBOM given as a document (coverage unknown) |

`not_observed` means "not observed by the tools we ran" — same vocabulary
discipline as govulncheck. It is evidence for a human decision, not a
machine verdict.

## Extending to new languages

To add support for a new ecosystem:

1. Add an `ImpactAnalyzer` provider in traust-core (`providers/impact.py`).
2. Implement `evidence()` with the language's tool chain:
   - What's the equivalent of govulncheck? (cargo-audit for Rust,
     pip-audit for Python, etc.)
   - What binary analysis applies? (JAR inspection for Java,
     statically-linked binary scan for Rust, etc.)
   - What indicates inconclusive results needing manual trace?
3. Wire it in `Context.services()` with the ecosystems it covers.

The classification rubric and artifact schema are language-agnostic —
only the analysis path varies.

## Output schema

Each native per-commit/package document follows the installed
`impact-analysis` contract schema. Key structure:

```json
{
  "metadata": {
    "cve": "CVE-2026-33186",
    "module": "google.golang.org/grpc",
    "vulnerable_range": "< v1.64.1",
    "tiers_executed": ["L1", "govulncheck"],
    ...
  },
  "summary": {
    "repos_in_blast_radius": 1,
    "affected": 0,
    "not_observed": 1,
    ...
  },
  "repos": [
    {
      "repo": "repo:github.com/openshift/foo",
      "classification": "not_observed",
      "evidence": { "govulncheck": "package_imported_not_observed", ... }
    }
  ]
}
```

## Downstream consumption

Every run records native commit/package artifacts in traust-core (an
`impact` assessment each). `traust impact export` produces the portable
advisory-wide `ImpactExport` view described in Step 4, not a second
persisted report or a native artifact to re-import. Consumers of its
`.repos` use `repository_url` and `sha`; native metadata and all original
fields remain under each row's `document`. The view includes every
classification, not only the findings that `analyze` filed.

- **`/dependency-watch` → python3 -m traust.cli impact analyze** — the
  filing leg (harness ≥ 0.197.0): every `affected` repo's dependency
  finding is filed through traust-core's intake — never written to the
  baseline (gate A15) — with unauthored `validation_status` omitted
  (`source.type: impact_report`, class-3 machine-static), making the
  classification an owned, SLA-clocked finding — not just analysis.
  Preserve the affectedness/reachability rationale as evidence; validity
  judgments belong to Core's decision services and installed contracts
  registry, per [Validity authoring](../../../docs/report-structure.md#validity-authoring).
- **`/triage` Phase 2f** — triage reads the impact-analysis artifact to
  give verifiers portfolio-wide context.
- **`/verify-remediation` full-sweep** — pass the exported JSON as
  `traust remediation verify-sweep --impact-filter <path>` to scope
  verification to `affected`/`likely_affected` repositories. The adapter
  intersects any explicit repository/product scope and deduplicates URLs;
  no matching rows mean an empty worklist, never the full fleet.
- **SBOMs** — the commits' recorded SBOMs are this skill's backbone;
  keep them current (`traust impact sbom`) or the blast radius lies.
- **`/secure-container-audit`** — sbom-grype CVE hits check the impact
  artifact for the repo's classification before promotion (a
  `not_observed` at symbol level is dismissal evidence with citation).
- **`/secure-code-audit`** — K07 vulnerable-dependency findings cite the
  repo's classification + evidence block when an artifact covers the CVE.
- **`/fleet-fix`** — the `affected`/`likely_affected` repo list is a
  ready-made worklist for a dependency-bump transform spec.
- **`/file-security-defect`** — defects cite the classification and
  evidence; `not_observed` justifies downgraded urgency, never
  auto-closure.
- **Tracker evidence** — per-repo classification + evidence block is
  machine evidence for closing OCPBUGS trackers.
- **`/findings-db`** — query kept impact analyses through Core exposure
  services or consume the exported view; never rebuild a parallel impact table.
- **`/secure-rpm-audit`** — vendored-dependency CVE hits cite the source
  repo's classification (same convention as secure-code-audit K07).
- **`/validate-findings`** — `affected` + `attacker_influence: plausible`
  repos are prioritized live-validation candidates; the trace names the
  interface to drive. Confirmed exploitation = class-1 evidence.
- **`/remediate-finding`** — dependency-bump remediations consult the
  trace for fix placement; upstream fixes verify consumption via
  `traust check fix-propagation` + `/verify-remediation --fix-repo`.

## Hard rules

- The SBOMs are the backbone — the blast radius alone separates
  the handful of affected repos from the hundreds of unaffected ones,
  without cloning anything.
- `not_observed` never auto-closes a tracker.
- Every classification carries its evidence provenance.
- The script owns the analysis — the skill invokes it, doesn't
  reimplement it.
