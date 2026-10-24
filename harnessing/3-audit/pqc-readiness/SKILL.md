---
name: pqc-readiness
description: >-
  Assess a repository's post-quantum TLS readiness. Use when asked whether a
  repo can negotiate ML-KEM hybrid TLS, who controls that choice, or to emit
  a pqc-readiness report. Walks the TLS control chain from platform down to
  app, consulting capability notes for version meaning.
argument-hint: "<repo-dir-or-url> [--from-facts PATH]"
user-invocable: true
metadata:
  harness.tier: "primary"
---

# PQC Readiness

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Assess **one repository**: can it negotiate post-quantum TLS today, and who
actually decides that?

Precursor: `/crypto-analysis` gathers crypto facts and builds governance
chains (who owns each crypto decision). This skill **consumes** that work
and answers the PQ question on top of it. If no prior analysis exists,
gather facts first (step 1), then reason.

Write for a reader who is not a PQC expert
([language notes](notes/language.md)).

---

## The control chain

Readiness is not "Go version ≥ 1.24." It is a control chain from the
outside in. Walk it until you know which link **sets** TLS crypto and which
links only **inherit** it.

```
platform TLS governance  (cluster, cloud LB, managed service)
     ↓ may govern
mesh / ingress / sidecar termination
     ↓ may govern
builder / base image  (toolset, FIPS, injected OpenSSL)
     ↓ may replace
language / toolchain defaults  (Go, JDK, Node, …)
     ↓ may link
crypto library  (OpenSSL, BoringSSL, rustls, …)
     ↓ may be overridden by
app / middleware pins, kill-switches, namedGroups
```

Name the outermost link that still **decides**. Judge whether that link can
do PQ TLS (consult capability notes). Say who should change what next.

---

## Outputs

| File                        | Who                         | Contract                                                                                                               |
| --------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `<slug>-pqc-facts.json`     | L1 scanner (`pqc_facts.py`) | `pqc-facts.schema.json` in traust-contracts — gated at write time; `--validate-facts` re-checks |
| `<slug>-cbom.json`          | L1 scanner                  | CycloneDX                                                                                                              |
| `<slug>-pqc-readiness.json` | **you**                     | `pqc-readiness.schema.json` in traust-contracts                                                                                         |
| `<slug>-pqc-readiness.md`   | **you**                     | human companion                                                                                                        |

This is a **posture assessment**, not a vulnerability report. The output
does not enter the findings ledger or the triage/patch pipeline.
`/secure-code-audit` already spot-tags PQC-relevant findings in its own
reports — this skill goes deeper on the readiness question.

---

## Procedure

### 1. Gather facts

If the pinned scanner binary needs to be built or rebuilt, follow
[build_pqc_scan.sh](build_pqc_scan.sh); it pins the source revision and
records the binary checksum for the readiness checks.

If facts already exist (`--from-facts`), load them. Otherwise run the
deterministic scanner:

```bash
python3 <skill-base>/scripts/pqc_facts.py \
  --repo-dir <checkout> --repo-url <URL> \
  --out <slug>-pqc-facts.json --cbom-out <slug>-cbom.json
```

**Zero-hit gate:** empty facts without `coverage.no_crypto_detected_assertion`
means the scan failed — stop. Do not call a broken scan "ready."

Facts give you: provider versions, rule IDs, `pqc_capable` hints,
`fips_mode`, IR 8547 clocks, provenance hints. They do **not** contain the
readiness verdict — you produce that.

### 2. Walk the control chain

Work **outside → in**. At each layer ask: does this layer choose TLS crypto,
or only inherit?

**A. Platform TLS governance**

Some platforms centrally govern TLS for workloads — Kubernetes clusters
with TLS profiles, cloud load balancers with cipher policies, managed
services that terminate TLS on behalf of apps. When facts show
platform-level governance signals (profile consumers, policy
enforcement, managed TLS termination), the **platform** decides TLS for
that path.

- `who_sets_tls: platform`
- App readiness follows the platform config, not go.mod.
- `do_next` for platform: name the config surface that controls TLS.
- `do_next` for app: keep consuming the platform config; do not hard-code curves;
  watch the profile and adapt when the customer changes it (operators: reload
  operands on change). Distill `how` from the matching remediation playbook
  (for Go: `SecurityProfileWatcher` / `ObserveTLSSecurityProfile` / direct
  APIServer fetch + operand reload) — never cite the playbook path in the report.
- The platform itself is not a capability note — no version floor to cite.
  Score what the platform _uses_ (its OpenSSL, its proxy stack).
- Wording help: [notes/platform-governance.yaml](notes/platform-governance.yaml).

**Inverse check — the app runs a server the platform can't govern.** When
the platform offers a managed TLS profile AND first-party
`HP_TLS_LISTENER_*` / `HP_TLS_SERVER_CONFIG_*` facts show the app
terminates TLS in-process, look for first-party profile consumption
(`HP_GOV_PLATFORM_*` facts — first-party only; vendored API types are not
consumption). Listener present + consumption absent means the app seized
the decision without honoring the platform contract:

- `who_sets_tls: this_app` (not `language_defaults` — a static server
  config is a pin on the _profile_ dimension even when no curve is pinned).
- Emit a remediation: the server's TLS config does not follow the
  platform TLS profile; `do_next` for the app = derive the listener's
  config from the profile and reload on change, distilled from the
  matching `tls-ke-server` playbook, with `locations` anchored at the
  listener facts.
- Absence of listener facts is only meaningful when the scan covered the
  repo's language (`coverage.rules_in_pack`, listener rules are
  Go/Py/JS/Rust today) — otherwise say so rather than concluding
  delegation.

**B. Mesh / ingress / sidecar**

TLS terminates outside the app process → `who_sets_tls: mesh_or_ingress`.
Judge the proxy stack, not the app's language.

**C. Builder / base image**

FROM / FIPS toolset / explicit OpenSSL install can **replace** the crypto
the language version implies.

- Multi-stage builds: which stage ships? Builder ≠ runtime.
- golang-fips / boringcrypto / RPM NEVRA → the **injected library** version
  is what you score, not the language default.
- When the image swaps the backend, language-runtime floors are secondary.

**D. Language / toolchain**

go.mod toolchain, JDK release, Node major — only decisive when nothing
outer owns TLS and the app does not pin.

Open the matching **capability note** ([notes/capabilities/](notes/capabilities/))
to see what that version means. Never invent a floor.

**E. Crypto library**

OpenSSL, rustls, … — especially when a language `depends_on` the library
(Python → OpenSSL). Score the library note when that is the real negotiator.

**F. App pins and feature overrides**

`CurvePreferences`, `namedGroups`, `ssl_ecdh_curve`,
`GODEBUG=tlsmlkem=0` → the **app** seized control.
`who_sets_tls: this_app`. Often `why_not: curves_pinned` or
`feature_turned_off` even if the toolchain is PQ-capable.

**G. External peers**

DB/LDAP/SMTP client TLS to a server this repo does not run →
`who_sets_tls: external_server`. Client toolchain alone cannot make
`quantum_ready: yes_by_default`.

A repo may have **several** decision points. Resolve each; the report's
primary `who_sets_tls` is the dominant / worst path for PQ TLS.

### 3. Consult notes for meaning

When you need a version judgment or ownership seed, open the relevant
note — the answer is in the note, not in this procedure.

Hard rule: **never invent a version floor.** Cite only what appears in
the capability note. Record `capabilities[]` for stacks you judged.

### 4. Emit the report

Lead with plain language:

| Field           | Rule                                                                                |
| --------------- | ----------------------------------------------------------------------------------- |
| `summary`       | ≤20 words                                                                           |
| `status`        | `ready` / `needs_work` / `blocked` / `not_applicable`                               |
| `who_sets_tls`  | from step 2                                                                         |
| `quantum_ready` | `yes_by_default` / `yes_if_configured` / `no` / `only_with_fips_curves` / `unknown` |
| `why_not`       | short codes                                                                         |
| `do_next`       | `[{ "who", "do", "how", "locations"? }]` — see contract below                       |
| `capabilities`  | card hits from step 3                                                               |

**`do_next` contract (owner-facing):**

| Field       | Rule                                                                                                                                                                                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `who`       | `platform` / `app` / `language` / `unknown`                                                                                                                                                                                                                                           |
| `do`        | ≤25 words, imperative — _what_ to change                                                                                                                                                                                                                                              |
| `how`       | 1–3 sentences distilled from the matching remediation playbook — _how_ to resolve. Self-contained. **Never** cite `remediation/…`, `notes/…`, or `harnessing/…` paths (owners do not have the harness).                                                                               |
| `locations` | Repo-relative `file:line` (or `file`) anchors from the cited facts so the owner can open the right place. Required whenever the action maps to first-party code, lockfiles, manifests, or config in _this_ repo. Empty/omit only for pure external/platform waits with no local file. |

Consult playbooks under `remediation/` (table below) to write `how`; those files are **agent-only**. `/patch` loads them via [`remediation/index.yaml`](remediation/index.yaml) as DOMAIN KNOWLEDGE — do not rely on report paths for that.

Example:

```json
{
  "who": "app",
  "do": "Remove CurvePreferences pin to allow ML-KEM negotiation.",
  "how": "Delete CurvePreferences from the tls.Config at the cited site. With CurvePreferences unset, Go 1.24+ negotiates X25519MLKEM768 by default.",
  "locations": ["pkg/server/tls.go:88"]
}
```

Keep the primary surface plain — technical IDs and standards jargon go
under `evidence` only ([notes/language.md](notes/language.md)).

Scorecard compat (`scores`, `flags`, `provenance_summary`,
`readiness_bucket`) — fill from facts, never invent from `quantum_ready`.
Thresholds: [notes/scoring.yaml](notes/scoring.yaml).

### 5. Validate

```bash
python3 <skill-base>/scripts/pqc_facts.py \
  --validate-readiness <slug>-pqc-readiness.json
```

One-line recap: status, who sets TLS, quantum_ready, top do_next.

**`remediations` section (mandatory for new reports, harness ≥ 0.153.0)** —
the structured, machine-readable counterpart of the Markdown companion's
"What you need to do" sections. Entry ids are **globally unique**,
mirroring the `/secure-code-audit` finding-id convention:
`<SLUG_UPPER max 24>-<short sha>-REM-NNN` — slug uppercased with
non-alphanumerics as `_`, the 7-hex short form of `metadata.commit`
(or `u` + 6 hex of `sha256(metadata.repository)` when no commit is
pinned), and a per-report 3-digit sequence (e.g.
`HELMET-f1b2984-REM-001`). Never emit bare `REM-NNN` ids — two repos'
entries must never collide in cross-report tooling. One entry per
actionable item,
`category` following exactly the routing rules below (`fix-now` /
`upgrade` / `waiting-on-upstream`), plus one `deadline` entry per
`clock_items[]` group that is not already covered by a fix-now/upgrade
entry. Each entry carries the `locations` from those facts (repo
`file:line` anchors — the owner-facing map), reuses the clock item's
`remediation_effort`/`blast_radius`
where one exists, names the concrete `target` (version, mechanism, or
policy value), and sets `recipe` to the matching playbook under
`harnessing/3-audit/pqc-readiness/remediation/` (per [`remediation/index.yaml`](remediation/index.yaml)
matching semantics; `null` when no recipe applies). `recipe` is
**machine metadata for `/patch`** — never print it as a user-facing
Playbook link in the Markdown companion.
**Do not put `fact_ids` on `remediations[]` or `do_next[]`** — those
arrays are owner-facing. Fact ids (`F0008`) stay only on
`scores.*.checks[]` / `clock_items[]` (and the sibling facts file) as
machine citations; owners navigate via `locations`.
`waiting-on-upstream` entries must name `blocked_on`. The validator
checks the section whenever present. Reports written before 0.153.0 are
backfilled deterministically with
`python3 harnessing/3-audit/pqc-readiness/scripts/backfill_remediations.py` (derives
entries from the existing MD sections + clock_items; idempotent).

**Markdown companion format (`<slug>-pqc-readiness.md`)** — this file is
read by developers and engineering leads who are NOT PQC experts. Write it
for that audience:

**Status mapping** (bucket → status line):

- `ready` → "Ready — no action needed"
- `partial` → "Almost ready — minor changes needed (score X/100)"
- `not-ready` → "Needs work (score X/100)"
- `blocked-external` → "Waiting on upstream — nothing for you right now"
- `not-applicable` → "No crypto detected — nothing to do"

**Routing rules** — which items go in which section:

- **Fix now**: `HP_GROUPS_*` pins, `HP_ENV_*` kill-switches, explicit
  curve/group lists, `NO-PQ` crypto-policy — anything that _actively
  prevents_ PQC negotiation
- **Upgrade**: `HP_CHAIN_*` rules where `pqc_capable: false` (Go < 1.24,
  old base images, Node < 22, JDK < 24) — version bumps that flip PQC on
- **Waiting on upstream**: `remediation_effort: blocked-external`, or
  dominant provenance is `delegated-dependency`/`vendored`/`externalized`
  and the dependency lacks PQC support
- **Deadlines**: items from `clock_items[]` — `deprecated_after: 2030`
  means "stop using for new work by 2030"; `disallowed_after: 2035`
  means "must remove entirely by 2035" (per NIST IR 8547)

Every Fix now / Upgrade bullet **leads with a repo `file:line`** (or
lockfile/manifest path) so the owner can jump to the site. Put the
distilled `how` under Action — never a harness Playbook path.

```
# <repo-name> — PQC Readiness

**Status:** <use mapping above>

## What you need to do

### Fix now (these actively block PQC)
- `file:line` — <what's wrong in plain English>
  Action: <one sentence — what to change>
  How: <1–3 sentences distilled from the playbook; no harness paths>

### Upgrade (version bumps that enable PQC automatically)
- `file:line` — <what's outdated>
  Action: <what version to target>
  How: <how to bump / where the pin lives>

### Waiting on upstream (nothing for you to do)
- <item> — blocked on <vendor/library>
  (cite local evidence file if any, e.g. `bundle-hack/rpms.lock.yaml`)

## Deadlines (NIST post-quantum transition schedule)
- By 2030 (deprecated — stop using for new work): <what>
- By 2035 (disallowed — must remove): <what>

## Remediations
- **<SLUG>-<sha7>-REM-001** (<category label>): <the entry's action, verbatim>
  Locations: `<file:line>, …`
<one bullet per entry of the JSON remediations section, same order and
 same globally-unique ids; show Locations when set; never Playbook paths;
 "None — no remediation actions identified." when the section is empty>

## Scores
| Domain | Score | Meaning |
|---|---|---|
| Vulnerability (VULN) | X | <"Fully exposed" / "Some exposure" / "No quantum-vulnerable crypto"> |
| Agility (AGIL) | X | <"Hardcoded" / "Mostly configurable" / "Fully agile"> |
| PQC Adoption (PQCA) | X | <"No PQC yet" / "Partial" / "Adopted"> |
| Harvest Risk (HNDL) | X | <"High harvest risk" / "Some risk" / "No risk"> |

### What the domains mean
<the standard domain legend, verbatim from
 backfill_remediations.py LEGEND — question each domain answers, its
 0–100 scale, the Overall weighting (VULN 40% / AGIL 25% / PQCA 20% /
 HNDL 15%), and the bucket thresholds. Mandatory on every report that
 shows scores; omit only on minimal ready/not-applicable pages with no
 scores displayed.>
```

**Minimal examples** (ready / not-applicable repos):

```
# cluster-version-operator — PQC Readiness
**Status:** Ready — no action needed.
```

```
# console-docs — PQC Readiness
**Status:** No crypto detected — nothing to do.
```

Rules for the `.md`:

- Lead with action items, scores at the bottom (people stop reading)
- **Never put fact ids (`F0001`-style) anywhere in the `.md`** — not in
  columns, not in parentheses on deadline lines, not in Remediations
  bullets. Owners navigate via `file:line` under Locations / Fix now.
  Machine citations live only in `<slug>-pqc-readiness.json`
  (`scores.*.checks[].fact_ids`, `clock_items[].fact_ids`) and
  `<slug>-pqc-facts.json` — never on `remediations[]` / `do_next[]`.
  (Existing MD was scrubbed of Facts columns by
  `backfill_remediations.py --refresh-md`; re-scrub prose leaks the
  same way.)
- The `## Remediations` section mirrors the JSON `remediations` array
  one-for-one (ids included, so a developer can reference REM-002 in a
  ticket); it complements — never replaces — the plain-English
  "What you need to do" routing above
- No acronyms without immediate plain-English explanation
- "GODEBUG flag" → "GODEBUG flag (Go runtime switch that disables PQC)"
- "CurvePreferences" → "CurvePreferences (pinned TLS groups blocking PQC)"
- Translate internal check IDs to plain English (e.g. `VULN-1` → describe
  what it means; `infra_mlkem_unverified` → "server-side PQC not yet confirmed")
- Group items by what the developer can actually do (fix now / upgrade / wait)
- If the repo is `ready` or `not-applicable`, the `.md` can be 2–3 lines

### 6. Optional runtime

Cluster available → `/crypto-analysis` cluster probe with ML-KEM groups can
**confirm** negotiation. Runtime promotes confidence; it does not invent
floors. No cluster → `runtime_verification_required: true`.

---

## Notes (reference — consult, don't memorize)

| Note                             | When to open                                       |
| -------------------------------- | -------------------------------------------------- |
| `notes/capabilities/<id>.yaml`   | Need a version floor or FIPS meaning               |
| [`notes/who-sets-tls.yaml`](notes/who-sets-tls.yaml)        | Need an ownership seed from fact signals           |
| [`notes/language.md`](notes/language.md)              | Writing the report (glossary, caps, banned jargon) |
| [`notes/scoring.yaml`](notes/scoring.yaml)             | Bucket thresholds, effort labels                   |
| [`notes/platform-governance.yaml`](notes/platform-governance.yaml) | Wording when a platform governs TLS                |

## Remediation playbooks (agent-only — distill into `how`; `/patch` loads full text)

Open the matching guide to write `do_next.how` and to set
`remediations[].recipe`. **Do not emit these paths in owner-facing
JSON/MD.** `/patch` re-resolves them via [`remediation/index.yaml`](remediation/index.yaml) and
injects the markdown as DOMAIN KNOWLEDGE.

| Guide                                             | When it applies                                                    |
| ------------------------------------------------- | ------------------------------------------------------------------ |
| [`remediation/tls-ke-server/go.md`](remediation/tls-ke-server/go.md)                 | Go service needs to honor platform TLS or enable ML-KEM            |
| [`remediation/tls-ke-server/python.md`](remediation/tls-ke-server/python.md)             | Python service TLS config                                          |
| [`remediation/tls-ke-server/nodejs.md`](remediation/tls-ke-server/nodejs.md)             | Node.js service TLS config                                         |
| [`remediation/tls-ke-server/rust.md`](remediation/tls-ke-server/rust.md)               | Rust service TLS config                                            |
| [`remediation/tls-ke-client/go.md`](remediation/tls-ke-client/go.md)                 | Go client restricts TLS negotiation (CurvePreferences, MaxVersion) |
| [`remediation/tls-ke-client/generic.md`](remediation/tls-ke-client/generic.md)            | Non-Go client restricts TLS negotiation                            |
| [`remediation/config-blockers/crypto-policy.md`](remediation/config-blockers/crypto-policy.md)    | System crypto-policy blocks PQC                                    |
| [`remediation/config-blockers/runtime-switches.md`](remediation/config-blockers/runtime-switches.md) | GODEBUG / env vars disable PQC                                     |
| [`remediation/config-blockers/curve-pins.md`](remediation/config-blockers/curve-pins.md)       | Explicit classical-only group configuration                        |
| [`remediation/digital-signatures/checklist.md`](remediation/digital-signatures/checklist.md)     | PQ signature agility                                               |

Capability / ownership notes (`notes/capabilities/`, [`notes/who-sets-tls.yaml`](notes/who-sets-tls.yaml),
…) are the same class: consult to score, never cite in the report.

---

### Worklist (sweep mode)

`bulk_prescan.py --refresh` (v0.132.3+) re-runs Layer 1 across the corpus
after a rules/adapter change: stamp-aware (re-scans only facts whose
adapter_version/rules_sha256 differ from the current pack), idempotent
and resumable. `l2_prepass.py` (v0.132.4) then routes the Layer-2
re-score deterministically — tiers `full` (governance/DB/FIPS facts
fired, or 2030-clock/HNDL/not-ready stakes), `light` (governance labels +
PQCA-3 ceiling check only), `skip` (zero-hit n/a or vendor/test-only
facts: re-derive bucket, no agent) — into
`pqc/_manifest/l2-worklist-adapter-<ver>.json` so migration agent fleets
visit the affected population instead of every scored repo. Routes only;
never authors a verdict.

`build_pqc_dashboard.py --results-root <dir>` regenerates the live
campaign dashboard after every batch —
`progress-tracker/metrics/dashboards/pqc/pqc-dashboard.{md,json}`
(executive summary, org-grouped repos worst-first, bucket distribution,
2030-clock burndown, HNDL harvest-risk list, effort mix, provenance
breakdown, "What the scores mean" guide, human-readable FIPS/provenance
labels) plus `pqc-readiness` metrics in the shared hash-chained ledger
(charted on Executive-Trends).

`build_pqc_worklist.py --analysis-results <dir>` writes
`findings/_manifest/pqc-worklist.{json,md}`: one entry per unique repository
URL (normalized), priority-tiered chokepoint → crypto-CWE ground truth →
tail, with the unreachable-triage residual routed `sbom-only` /
`access-request`.

`build_pqc_rollup.py --results-root <dir>` synthesizes the completed sweep
into the portfolio migration plan:
`progress-tracker/metrics/dashboards/pqc/pqc-portfolio-rollup.{md,json}` +
5 CSV exports (2030-clock burndown, HNDL ranking, hybrid-TLS blockers
with file:line, go-directive quick wins, per-product roll-up via the
graph's `ships` edges). Uses plain-English section headings and
human-readable FIPS/provenance labels; the Go PQC threshold is consumed
at runtime from the [`notes/reference/pqc-version-matrix.yaml`](notes/reference/pqc-version-matrix.yaml) input
table. Read-only full
rebuild; re-run after mop-up or probe passes change the reports.

`build_pqc_vendor_tracker.py --results-root <dir>` (Phase 3 handoff) merges
the curated vendor registry (`<results-root>/pqc/inputs/vendor-registry.json`
— dated status claims, curated org data held in the corpus; override with
`PQC_VENDOR_REGISTRY`) with live fleet counts into
`progress-tracker/metrics/dashboards/pqc/pqc-vendor-roadmap.{md,json}`;
review the registry, then re-run.

`build_xcrypto_tracker.py --results-root <dir>` regenerates the OCP
"x/crypto usage tracking" workbook rows from the corpus:
`progress-tracker/metrics/dashboards/pqc/xcrypto-tracker.{csv,md}` in the
tracker's column order (Product/Org, Repository, Entrypoint, Crypto module
used, Status, Comment, Dependency Graph), best evidence tier first per
repo×package (callgraph-reachable → first-party import → vendored
presence from the facts). Status is a **suggestion** from the per-package
IR 8547 table — teams own the final call. `--push-sheet <spreadsheet-id>
[--tab <title>]` upserts the tab directly via a Drive-scoped
`gcloud auth print-access-token` bearer (run
`gcloud auth login --enable-gdrive-access` once per host).

`build_pqc_product_reports.py --results-root <dir>` writes one per-product
report + worst-first index under
`progress-tracker/metrics/dashboards/pqc/products/` (graph ships edges ×
pqc repo attrs × clock detail); re-run with the dashboard/roll-up. Each
per-product report also carries an additive **Cross-language crypto
dependencies** section — the product's repos' graph-discovered crypto-library
hits (package / version / ecosystem / manifest / PQC posture) with a
per-product posture rollup whose `classical-only` count is the
migration-relevant total. It reuses `scan_crypto_deps_graph.discover()` and
the `ships` repo→product mapping so it stays consistent with the roll-up's
portfolio-level section, routes repo/package/manifest cell text through
traust_engine.escaping (`md_cell`), and degrades to a "no data" line (never a
crash) when the graph or its multi-ecosystem `depends_on` layer is absent.

`scan_pqc_dependencies.py --results-root <dir>` backfeeds the portfolio
graph from the already-emitted facts: L1 `crypto-dep` nodes (library ×
version) + `uses_crypto_dep` edges, L3 `crypto-usage` nodes (ir8547
usage × qclass) + `uses_crypto` edges, and a `pqc` attrs block on each
repo node (bucket/overall/HNDL/2030 flags). Deterministic full rebuild —
re-run after each sweep batch alongside the dashboard; "show all repos
using RSA key exchange" becomes a SQL lookup over
`analysis-results/graph/portfolio-graph.db`.

`scan_crypto_deps_graph.py --results-root <dir>` goes the OTHER direction:
it **reads** the portfolio graph's multi-ecosystem `depends_on` edges
(`repo -[depends_on {version, ecosystem, manifest}]-> pkg:<eco>/<name>`,
built by `python3 -m traust.cli portfolio build` for npm / pypi / maven /
cargo / ruby / nuget) to discover crypto-relevant dependencies **across
languages**, not just the Go/TLS surface `pqc_facts.py` covers. The set
of crypto packages it looks for is a **curated STARTER seed list**,
[`notes/crypto-packages.yaml`](notes/crypto-packages.yaml) — keyed by ecosystem, each package carries a
PQC `posture` (`classical-only` / `pqc-capable` / `inherits` +
`capability_card` / `unknown`) and a one-line note. **Extend it there:**
add a package under its ecosystem key using the exact `pkg:<eco>/<name>`
node name (npm scoped names keep `@scope/name`; maven uses
`group:artifact`), give it a posture, and set `capability_card` when a
`notes/capabilities/<id>.yaml` card governs its real crypto backend; mark
anything uncertain `posture: unknown`. The scan emits, per ecosystem, the
repo + crypto package + version + `manifest` provenance path(s) from the
edge + mapped posture into
`analysis-results/pqc/_manifest/crypto-deps.{json,md}`, and
`build_pqc_rollup.py` imports its `discover()` to render a cross-language
crypto-dependency section in the portfolio roll-up. READ-ONLY against the
graph (opened `mode=ro`), NO network; a missing or legacy graph db is a
clean logged skip (`graph_present: false`), never a crash.

## Two-layer probe model

```
Layer 1 (census):   python3 -m traust.cli adapters crypto-probe    → CRYPTO_* facts
                     ↓ imported by
                    pqc_facts.py                → HP_CHAIN_* PQC facts + pqc_capable flag

Layer 2 (TLS/code): pqc-scan rules (opengrep)  → CWE/algorithm-level crypto usage
                    novel.py PQC probes         → runtime TLS negotiation, crypto-policy

Chain reasoning:    crypto-analysis SKILL.md    → governance chains (who owns the decision)
```

| Tool                    | Location                                         | Purpose                                                                                                                                                                          |
| ----------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crypto_probe.py`       | python3 -m traust.cli adapters crypto-probe                        | Provider census: Go, Node, JDK, Python, Rust, .NET, Ruby, C/C++ crypto stacks, base images, RPM locks, GODEBUG, crypto-policies                                                  |
| `crypto_audit.py`       | python3 -m traust.cli adapters crypto-audit                        | Unopinionated data collector — `cluster` tier with `--groups` provides raw TLS negotiation facts for PQC probing                                                                 |
| `pqc_facts.py`          | `harnessing/3-audit/pqc-readiness/scripts/pqc_facts.py`          | Imports crypto*probe, maps `CRYPTO*_`→`HP*CHAIN*_`, adds PQC capability assessment via `\_pqc_capable_version()`(reads thresholds from[`notes/reference/pqc-version-matrix.yaml`](notes/reference/pqc-version-matrix.yaml)) |
| `scan_xcrypto_usage.py` | `harnessing/3-audit/pqc-readiness/scripts/scan_xcrypto_usage.py` | golang.org/x/crypto evidence: first-party import sites, go.mod versions, optional callgraph reachability (somepath witness)                                                      |
| `build_pqc_blockers.py` | `harnessing/3-audit/pqc-readiness/scripts/build_pqc_blockers.py` | Projects readiness `remediations[]` into the findings-shaped `<slug>-pqc-blockers.json` (contracts/schemas/pqc-blockers.schema.json) for `/patch` and other findings consumers              |
| `novel.py`              | `harnessing/5-validate/validate-findings/novel.py`          | Runtime probes: `pqc-tls-negotiation`, `pqc-cert-algorithm`, `pqc-crypto-policy`, `pqc-backend-tls`                                                                              |
| `crypto-analysis`       | `harnessing/3-audit/crypto-analysis/SKILL.md`            | Governance chain reasoning — traces who decides crypto config from OS through platform to app code                                                                               |

PQC version thresholds live in [`notes/reference/pqc-version-matrix.yaml`](notes/reference/pqc-version-matrix.yaml) (single source of
truth); `pqc_facts.py` `_pqc_capable_version()` reads them at runtime. Current:
Go >= 1.24, Node >= 22 (OpenSSL 3.5 backport), JDK >= 24, OpenSSL >= 3.5,
rustls >= 0.23.27, GnuTLS >= 3.8 (experimental), NSS >= 3.105. Runtime behavior
is confirmed by probing — never by static data alone.

## Integrations

- `<slug>-pqc-facts.json` (contract: `pqc-facts.schema.json` in
  traust-contracts, gated at write time by `pqc_facts.py`;
  `--validate-facts` re-checks an
  existing file) — consumed by this skill's Layer 2 scoring
  (`l2_prepass.py`, `bulk_prescan.py`), by `/patch`'s pqc ingest
  (actionable first-party blockers → candidate diffs), and by
  `build_pqc_rollup.py` + `build_xcrypto_tracker.py`.
- `<slug>-pqc-readiness.json` (schema-gated, `--validate-readiness`) —
  consumed by `build_pqc_dashboard.py`, `build_pqc_rollup.py`,
  `build_pqc_product_reports.py`, and `build_pqc_blockers.py`.
- `<slug>-pqc-blockers.json` (contract: `pqc-blockers.schema.json` in
  traust-contracts, gated at write time) — **Emits:**
  `build_pqc_blockers.py --readiness
<slug>-pqc-readiness.json` (or `--results-root` for batch backfill), a
  deterministic projection of the readiness report's `remediations[]`
  into the security-audit findings _vocabulary_ (same field names and
  semantics; deliberately parallel to `report.schema.json`, not
  conformant — shape convergence is a planned separate feature).
  Remediations without `locations[]` are excluded and recorded in
  `metadata.additional.excluded_remediations`. Consumed by `/patch` as a
  findings-shaped input (preferred over raw `*-pqc-facts.json` filtering
  when both exist). Emit it whenever the readiness report carries
  remediations.
- `<slug>-xcrypto-usage.json` — consumed by `build_xcrypto_tracker.py`.
- `pqc/_manifest/crypto-deps.{json,md}` — **Emits:** written by
  `scan_crypto_deps_graph.py` from the portfolio graph's multi-ecosystem
  `depends_on` edges (input: `analysis-results/graph/portfolio-graph.db`
  produced by `/portfolio-graph`; seed list [`notes/crypto-packages.yaml`](notes/crypto-packages.yaml)).
  **Consumes:** none authored here beyond the graph. Consumed by
  `build_pqc_rollup.py` and `build_pqc_product_reports.py` (both import
  `discover()`) for the roll-up's portfolio-level and the per-product
  cross-language crypto-dependency sections.
- `<slug>-cbom.json` (CycloneDX) and `<slug>-pqc-readiness.md` are
  terminal: interchange/compliance evidence and the human companion.

## Hard rules

- Facts are deterministic; agents never add, remove, or reword facts.
- `inherited-platform` is conditional — always pair with the provider census.
- Vendor-path facts appear in the CBOM but are excluded from scoring.
  **`path_class: test_docs` facts likewise** —
  tests/docs/examples are posture-irrelevant; they stay in the CBOM for
  completeness only.
- Verify-only classical signature use scores Partial, not Yes.
- SBOM-only assessments mark unassessable checks `na`, never `yes`.

---

## Sibling skills

| Skill                | Relationship                                       |
| -------------------- | -------------------------------------------------- |
| `/crypto-analysis`   | Precursor — governance chains, crypto probes       |
| `/secure-code-audit` | Spot-tags PQC-relevant findings in its own reports |

## Spend declaration (calibration tuple)

After this skill's report/artifact is written, declare the run's spend
against the target so `estimate_scan` can calibrate per-skill cost
models (contract: docs/model-routing.md; analysis:
progress-tracker/metrics/estimate-calibration-analysis.md §F5):

```bash
python3 -m traust.cli registry models spend --skill pqc-readiness \
    --model <resolved model id> [--tokens-in <N>] [--tokens-out <N>] \
    --repo <target-slug> --loc <target size, if known> [--batch <batch-id>]
```

Token counts are OPTIONAL and best-effort: pass them when the
orchestrator has them (Task results carry per-subagent usage),
otherwise omit them — an agent cannot observe its own usage mid-run.
**This row is a routing marker, not a cost claim**; actual per-lane
cost is attributed from session transcripts by
python3 -m traust.cli metrics attribute-spend. Never skip the row: an
unattributed run is a calibration gap.
