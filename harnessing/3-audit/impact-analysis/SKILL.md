---
name: impact-analysis
description: Use when determining which portfolio repositories are affected by
  an advisory (CVE, GHSA, MAL-/malicious-package, or another OSV-native id).
  Queries the portfolio graph for blast radius, then runs language-specific
  analysis (govulncheck + ELF reachability for Go, the strongest tier;
  manifest-level analyzers for npm, PyPI, Maven, Cargo, RubyGems, and NuGet;
  a manifest-level SurfaceAnalyzer for the universal Docker/GitHub
  Actions/Helm surfaces) to classify every importing repo. Emits a
  schema-validated artifact consumed by /triage and /verify-remediation.
argument-hint: "<advisory-id> --module <mod> [--ecosystem go|npm|pypi|maven|cargo|ruby|nuget|actions|docker|helm] [--packages <p1,p2>] [--feature-desc '...'] [--advisory-file <osv.json>] [--skip-scan] [--jobs N]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(python3 *-m traust.cli impact analyze:*)
  - Bash(python3 *-m traust.cli portfolio:*)
  - Bash(python3 *-m traust.cli reporting validate:*)
  # (Bash(git:*) dropped 2026-07-31 P1-W4: no git invocation in this skill's flow)
  - Bash(jq:*)
  - Bash(python3 *harnessing/3-audit/impact-analysis/scripts/fetch_advisory.py:*)
  - Bash(sqlite3:*)
---

# Impact Analysis

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Determine per-repo CVE affectedness across the portfolio. Takes a CVE
identifier, queries the portfolio graph for the blast radius, runs
language-specific analysis, and classifies every importing repo. Output
is a structured artifact that feeds `/triage` Phase 2f and
`/verify-remediation` full-sweep scoping.

## How it works

The script python3 -m traust.cli impact analyze does all the work:

1. **Blast radius** — queries portfolio-graph.db for all repos that
   `depends_on` the affected module. Filters by version range.
2. **L4 refinement** — queries `imports_package` edges to see which repos
   actually import the vulnerable *package* (not just the module).
3. **Deep scan** — for repos still classified `likely_affected` or
   `inconclusive`, clones and runs the language-specific analyzer.
4. **Classification** — each repo gets a classification based on the
   accumulated evidence.
5. **Artifact emission** — writes `<cve>-impact-analysis.json`.

### Language analyzers

Analysis is **per-ecosystem**: the analyzer is selected from `--ecosystem`,
not from a single-language guess of the clone. When `--ecosystem` names a
specific non-Go ecosystem (`npm`/`pypi`/`cargo`/`maven`/`ruby`/`nuget`, or a
`SurfaceAnalyzer` surface), that analyzer runs regardless of what language
the repo looks like — so a Go module that also ships a JS UI subdir,
analyzed with `--ecosystem npm`, scans its `web/ui/react-app/package.json`
(the lockfile analyzers rglob manifests anywhere in the tree) instead of
being misrouted to the Go analyzer by `go.mod`-wins language precedence. The
default/unspecified ecosystem `go` keeps the legacy `detect_language`
routing (byte-identical: a Go repo detects `go` and runs the Go analyzer).
The blast-radius seed is already per-ecosystem (`blast_radius_seed`), so the
analyzer matches it. Each analyzer owns the full tool chain for its
ecosystem.

**Go** (symbol-level — the strongest tier):
- `govulncheck` source mode → symbol reachability
- ELF string scan → package path presence in shipped binaries
- Unsafe/reflect detection → flags repos needing manual trace

**GitHub Actions, Docker, Helm** (manifest surfaces, no reachability tier):
a `SurfaceAnalyzer` re-checks the clone's `.github/workflows/*.y{,a}ml` /
`Dockerfile*` / `Chart.yaml` manifests with the same parsers that put the
`depends_on` edge in the portfolio graph — is the action/base-image/chart
still declared, and (when a range is given) is the declared version in
range. There is no package-manifest language or call-graph tool for these
surfaces to deep-scan, so the classification ceiling is `likely_affected`,
never `affected`, regardless of how confirmatory the manifest match is.

**Python, Rust, JavaScript, Java, Ruby, NuGet** (manifest-level):
lockfile/manifest pin extraction (`requirements*.txt`/`Pipfile.lock`/
`poetry.lock`/`pyproject.toml`, `Cargo.lock`/`Cargo.toml`,
`package-lock.json`/`yarn.lock`, `pom.xml`/gradle, `Gemfile.lock`/
`Gemfile`, `packages.lock.json`/`*.csproj`) with version-range
comparison, plus a source import scan. **The ceiling for
manifest evidence is `likely_affected`** — a lockfile pin proves the
dependency is present at a vulnerable version, never that the vulnerable
symbol is reachable. A pin outside the range yields
`version_not_in_range`; module absent from manifests AND no source
imports yields `not_observed` (at manifest level).

**C/C++** (binary + source level): header-include grep
(`#include <lib/…>`) plus a DT_NEEDED linked-library scan of shipped
image binaries via python3 -m traust.cli util elf. `linked` caps at
`likely_affected`; `not_linked` with no includes yields `not_observed`.

**Assurance boosters (all languages):**
- **Symbol-usage scan** — when the advisory names vulnerable symbols
  (`--symbols`), source is grepped for calls to them
  (`symbol_usage_scan`), and for C/C++ the shipped binary's strings are
  scanned for the symbol names (`binary_symbol_scan`) — the binary
  references the vulnerable *function*, not just the library. Textual
  usage is stronger than a pin, weaker than reachability: evidence
  level `symbol-usage`, ceiling still `likely_affected`.
- **SBOM cross-check** — syft SBOMs persisted by
  `/secure-container-audit` (`analysis-results/graph/sboms/`) are
  checked for the module: `sbom_scan`/`sbom_shipped_version` record
  what the **delivered image** actually contains, vs what the lockfile
  intended. Evidence only, never a verdict by itself.
- **Joern call-site reachability (Java v0.231.0, C/C++ v0.232.0)** —
  the analogue of govulncheck's symbol tier.
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
pin. Adding a new language means subclassing `LanguageAnalyzer` (or
`LockfileAnalyzer` for manifest ecosystems) in the script and
registering it in `ANALYZERS`.

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
  advisory.
- `--module <module-path>` (required) — affected module.
- `--ecosystem <eco>` — package ecosystem of `--module`: `go` (default),
  `npm`, `pypi`, `maven`, `cargo`, `ruby`, `nuget`, `actions`, `docker`,
  `helm`. Seeds the blast-radius query's node-id resolution and
  version-parsing semantics, so an advisory against a non-Go package
  resolves against the multi-ecosystem portfolio-graph L1 layer the same
  way Go does; `actions`/`docker`/`helm` route to the manifest-level
  `SurfaceAnalyzer` (no reachability tier, ceiling `likely_affected`).
  OSV publishes no `docker` or `helm` advisories, so those are not
  assessed (the range has no record to come from).
- `--packages <p1,p2>` — vulnerable packages within the module.
- `--symbols <s1,s2>` — vulnerable symbols (informational).
- **No range or fixed-version flags.** `analyze` fetches the advisory's OSV
  record through the feeds registry (`config/feeds.yaml`, the `osv` source)
  and decides every version on the record's spans, lower bounds and separate
  release lines included. The record's URL goes into `advisory_sources`; the
  artifact's `vulnerable_range` renders the spans and `fixed_version` is the
  highest fix. An ID OSV doesn't serve for the package (a CVE whose records
  are GHSA/PYSEC entries) is found through the package's advisories, and
  every record used is recorded. A record that can't be fetched, or that
  names no affected version of `--module`, exits 2: the advisory is **not
  assessed**.
- `--advisory-file <osv.json>` — the advisory's OSV record, exported on a
  connected host. Required when the `osv` source is `access: air-gapped`;
  its `file://` path is the recorded source.
- `--verified-version <v>` (repeatable) with `--verified-by <verdicts.json>`
  — dependency-watch's below-range lane only: versions two blind reviews
  and a judge verified affected although the record leaves them out. Each
  needs a final `applicable` verdict in the file for that package, version
  and advisory; the file joins `advisory_sources`.
- `--feature-desc "..."` — what capability must be in use.
- `--db <path>` — portfolio-graph.db (default:
  `analysis-results/graph/portfolio-graph.db`).
- `--skip-scan` — graph queries only, no cloning or scanning.
- `--jobs N` — parallel clone+analyze workers (default 4).
- `--out <path>` — output file (default: `<cve>-impact-analysis.json`).

## Procedure

### Step 1: Parse CVE and identify attack surface

Fetch the advisory to extract affected module, version range, vulnerable
symbols/packages, and feature description:

All advisory fetches go through the scoped fetcher — the skill's only
network egress (three fixed hosts, default TLS; a raw `curl` grant
would be an arbitrary-destination exfiltration channel under
injection — audit D7):

```bash
# OSV (Go ecosystem)
python3 harnessing/3-audit/impact-analysis/scripts/fetch_advisory.py osv <module> --ecosystem Go

# NVD
python3 harnessing/3-audit/impact-analysis/scripts/fetch_advisory.py nvd <CVE-ID>

# Red Hat CSAF
python3 harnessing/3-audit/impact-analysis/scripts/fetch_advisory.py csaf <cve-id>
```

When symbols aren't in the advisory, read the fix commit diff to identify
the affected API surface.

**The vulnerable range and fixed version come from the fetched OSV record,
never from memory.** Step 2 fetches it itself and records it in
`advisory_sources`; the fetches above are for reading the advisory (affected
packages, symbols, the feature in question), not for supplying a range. If
`analyze` exits 2 because the record is unavailable, report the CVE as not
assessed.

### Step 2: Run the analysis

```bash
python3 -m traust.cli impact analyze <CVE-ID> \
    --module <module> \
    --packages <p1,p2> \
    --feature-desc 'description of the vulnerable feature' \
    --db analysis-results/graph/portfolio-graph.db \
    --jobs 4
```

The script handles everything: graph queries, cloning, language-specific
analysis, classification, and artifact emission.

Use `--skip-scan` for a fast graph-only pass (no cloning).

### Step 3: Validate and review

```bash
python3 -m traust.cli reporting validate <cve>-impact-analysis.json
```

Review the summary: how many affected vs not_observed? Do the numbers
make sense given what the CVE is about?

Repos classified `inconclusive` with `needs_manual_trace: true` have
unsafe pointer or reflection usage that may hide reachability — these
need human review.

## Classification rubric

| Classification | Meaning | Evidence |
|---|---|---|
| `affected` | Vulnerable symbol reachable or feature in use | govulncheck `symbol_reachable` or feature-pattern match |
| `likely_affected` | Package imported, no deep scan yet | L4 import + no govulncheck/ELF result |
| `not_observed` | Vulnerable package/symbol not observed | govulncheck `*_not_observed`, L4 no import (Go only: an installed PyPI/npm/… dependency is loaded by other libraries without a first-party import, so there the manifest scan decides), or binary scan negative |
| `version_not_in_range` | At safe version | L1 version ≥ fix |
| `not_imported` | Module not in dep graph | blast-radius miss |
| `inconclusive` | Analysis hit limits | clone failed, non-Go repo, unsafe/reflect |

`not_observed` means "not observed by the tools we ran" — same vocabulary
discipline as govulncheck. It is evidence for a human decision, not a
machine verdict.

## Extending to new languages

To add support for a new ecosystem:

1. Subclass `LanguageAnalyzer` in python3 -m traust.cli impact analyze.
2. Implement `analyze()` with the language's tool chain:
   - What's the equivalent of govulncheck? (cargo-audit for Rust,
     pip-audit for Python, etc.)
   - What binary analysis applies? (JAR inspection for Java,
     statically-linked binary scan for Rust, etc.)
   - What indicates inconclusive results needing manual trace?
3. Register in the `ANALYZERS` dict.
4. Add `detect_language()` check if needed.

The classification rubric and artifact schema are language-agnostic —
only the analysis path varies.

## Output schema

See `contracts/schemas/impact-analysis.schema.json`. Key structure:

```json
{
  "metadata": {
    "cve": "CVE-2026-33186",
    "module": "google.golang.org/grpc",
    "vulnerable_range": "< v1.64.1",
    "tiers_executed": ["L1", "L4", "govulncheck_source"],
    ...
  },
  "summary": {
    "repos_in_blast_radius": 1412,
    "affected": 4,
    "not_observed": 876,
    ...
  },
  "repos": [
    {
      "repo": "repo:github.com/openshift/foo",
      "classification": "not_observed",
      "evidence": { "l4_package_imported": false, ... }
    }
  ]
}
```

## Downstream consumption

Campaign runs write the artifact to the canonical location
`analysis-results/impact/<cve>-impact-analysis.json` so consumers can
discover it without being told (pass `--out` accordingly).

- **`/dependency-watch` → python3 -m traust.cli route impact-findings** — the
  filing leg (harness ≥ 0.197.0): every `affected` repo's dependency
  finding is routed into its disposition ledger — carried on the event, never written to the baseline (gate A15) — at
  `validation_status: not_verified` (direct-entry convention,
  `source.type: impact_report`, class-3 machine-static), making the
  classification an owned, SLA-clocked finding — not just analysis.
- **`/triage` Phase 2f** — triage reads the impact-analysis artifact to
  give verifiers portfolio-wide context.
- **`/verify-remediation` full-sweep** — accepts `--impact-filter` to
  scope verification to `affected`/`likely_affected` repos only.
- **`/portfolio-graph`** — the graph is this skill's backbone (L1
  `depends_on` + L4 `imports_package`); keep the graph fresh
  (`/drift-watch` flags staleness) or the blast radius lies.
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
- **`/findings-db`** — artifacts are projected into the `impact` table
  on every DB rebuild, so per-CVE affectedness is queryable via SQL.
- **`/secure-rpm-audit`** — vendored-dependency CVE hits cite the source
  repo's classification (same convention as secure-code-audit K07).
- **`/validate-findings`** — `affected` + `attacker_influence: plausible`
  repos are prioritized live-validation candidates; the trace names the
  interface to drive. Confirmed exploitation = class-1 evidence.
- **`/remediate-finding`** — dependency-bump remediations consult the
  trace for fix placement; upstream fixes verify consumption via
  `check_fix_propagation.py` + `/verify-remediation --fix-repo`.

## Hard rules

- The portfolio graph is the backbone — L1 + L4 queries alone separate
  the handful of affected repos from the hundreds of unaffected ones,
  without cloning anything.
- `not_observed` never auto-closes a tracker.
- Every classification carries its evidence provenance.
- The script owns the analysis — the skill invokes it, doesn't
  reimplement it.
