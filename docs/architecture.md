# Architecture

> **Scope.** This page covers code internals — pipeline flow, adapters, data
> model — across the whole stack, and freely references modules that live in
> *other repositories* (`traust_engine.*`, `traust_ledger.*`). For which
> repository owns what, how the packages are pinned, and which one to change for
> a given fix, see **[components.md](components.md)**.

## Pipeline shape

The harness operates as a 9-stage pipeline (see [PROCESS.md](../PROCESS.md) for the full workflow — stage numbering is shared verbatim with README.md and docs/skills.md). Skills map to pipeline stages:

```
① Inventory   ② Threat model  ③ Audit        ④ Triage
inventory-    threat-model    secure-code-   triage
repositories                  audit (+rpm/
add-inputs                    container/IaC
                              /vuln-scan)

⑤ Validate                                   ⑥ Fuzz          ⑦ Remediate
├── validate-findings (any authorized target) create-fuzzing  remediate-finding
│   └── deploy-operator (stands up the                        patch / fleet-fix
│       operator under test)                                  verify-remediation
└── validate-browser-finding (browser-borne
    findings, Playwright)

⑧ Package     ⑨ Assign       Delivery (post-⑨)
generate-     assign-        team report → owner assignment →
team-report   findings-      file-security-defect
              owners
```

Supporting skills (e.g. `executive-summary-findings`, `loc-dashboard`, `insecure-patterns`, `findings-trends`, `track-findings`, `reassign-findings-owners`, `threat-model`, `patch`, `remediate-finding`) run outside or alongside the main pipeline.

**Storage.** Where each kind of data lives and which variable places it:
[storage.md](storage.md).

## Skill anatomy

Each skill is a self-contained directory under `harnessing/`. Workflow
skills sit under their pipeline stage; everything else (gates, dashboards,
graphs, corpus QA) sits at the root, because it is not a stage:

```
harnessing/<N>-<stage>/<name>/   # workflow skill, e.g. 4-triage/triage/
harnessing/<name>/               # gate, dashboard, graph, corpus-QA skill
├── SKILL.md              # Agent prompt (the skill definition)
├── scripts/, *.py, *.sh  # Implementation scripts (optional)
├── templates/            # Report/tracker templates (optional)
└── procedures/           # Sub-procedures (optional)
```

`SKILL.md` is the canonical prompt that the agent reads to perform the skill. Some skills are prompt-only (e.g., `secure-code-audit`); others have substantial implementation code (e.g., `validate-findings`, a multi-module Python pipeline). Agents see a flat name regardless of stage through the `.claude/skills/` and `.crush/skills/` symlink trees; code enumerates skills through `skill_dirs()` in `traust.paths`, never by globbing one level.

## validate-findings pipeline

> Verdict trustworthiness — the fail-closed gate stack (target
> attestation, positive controls, differential probing, soundness
> signatures) and how verdicts reach the disposition ledger — is
> documented end-to-end in [validation-process.md](validation-process.md).


The most complex skill internally. Seven modules are described below — a pipeline of five modules with two supplementary modules feeding into the plan stage. Two further modules sit outside the pipeline diagram: `soundness.py`, the refutation-soundness gate that blocks `refuted` verdicts whose probes never actually tested the claim, and `credential_liveness.py`, read-only liveness probes for leaked-credential candidates.

```
                          ┌──────────┐
                          │  chain   │ attack-chain DFS
                          └────┬─────┘
                               │
ingest ──► scope ──► plan ──► execute ──► report
                       ▲
                  ┌────┴─────┐
                  │  novel   │ gap-hunting probes
                  └──────────┘
```

### ingest (`ingest.py`)

Parses `*-security-audit.json`, `*-threat-model.md`, and `*-triage.json` into a unified in-memory model (`Normalized`). Classifies attack surfaces (`ci-build`, `host`, `tooling`, `runtime`) to route non-cluster findings away from the k8s adapter.

### scope (`scope.py`)

Defines and enforces what the harness is authorized to touch. Scope sources are additive (high-to-low precedence): explicit `targets.yaml` > CLI flags > inferred from report metadata.

Safety mechanisms:
- Hard-deny `off_limits` rules that override all other scope
- Control-plane namespace lock (`kube-system`, `openshift-etcd`, etc.) — only explicit `targets.yaml` entries can unlock
- Engagement expiry check
- Per-context verb deny lists

### plan (`plan.py`)

Builds an ordered list of `Step` objects organized as: recon → replay → adapted → chained → novel. Steps carry adapter, verb, payload/cmd, expected outcome, rollback hint, and classification (`safe`/`mutating`/`destructive`).

Key logic:
- PoC language detection (YAML manifests, kubectl/curl/podman commands, WASM)
- CWE-to-probe mapping for findings without literal PoCs
- Destructive steps blocked unless `--destructive` flag
- Each step scope-checked before emission

### chain (`chain.py`)

Builds a directed graph over entry-points, findings, and assets. DFS searches for kill-chains from external entry to high-sensitivity assets. Uses an 18-capability vocabulary (e.g., `sa-token`, `cluster-admin`, `host-exec`) with CWE-to-capability mapping and transitive closure, plus 7 PQC posture capabilities (`PQC_CAPS`) that are observation-only and never enter the closures.

Scalability guards: max 200 findings graphed, max 8 edges/node, max 100 chains, max depth 6.

### novel (`novel.py`)

Generates deterministic recon steps (read-only kubectl/podman/wasm-tools commands) to inventory what's actually running, then diffs against the threat model to find gaps. Produces probe steps for unexamined surfaces (CRD cross-ns references, SSRF, webhook bypass, hostpath access, SA token reach, WASI preopen).

### execute (`execute.py`)

Walks the plan, dispatches steps to the appropriate adapter, captures evidence, and writes an append-only audit log. Re-checks scope at runtime (not just at plan time). Immediate rollback of mutating steps. Second-pass novel step materialization after recon completes.

### report (`report.py`)

Produces `*-validation.json` and `*-validation.md`. Per-finding verdict rollup uses precedence: `confirmed` > `refuted` > `inconclusive` > `blocked_by_scope` > `not_attempted`. Includes SHA-256 of the audit log for tamper detection.

## Adapter system

Three adapters implement a common interface (`AdapterBase`):

| Adapter | Target | Key verbs |
|---|---|---|
| `k8s` | Clusters, operators, pods | `apply-manifest`, `exec`, `rbac-can-i`, `port-forward+http`, `patch-cr`, `raw` |
| `container` | Running containers | `exec`, `inspect`, `network-probe`, `cp` |
| `wasm` | WASM modules | `capability-probe`, `invoke-export`, `instantiate`, `fuzz-import` |

All adapters share:
- **Verb classification** — each verb is tagged `safe`, `mutating`, or `destructive`; kube argv is additionally analyzed server-side (`adapters/kubeargv.py`: denied flags, subcommand classification as the verb-table floor)
- **safe_exec step vetting** — string-form PoC steps never reach a shell: they are validated and executed through python3 -m traust.cli util safe-exec under the `validation-step` profile (argv allowlist, scrubbed env, shell-free pipelines; blocked steps exit 126 → `inconclusive`, never a silent pass). See [safe-exec.md](safe-exec.md)
- **Credential redaction** — Core's public `models.redaction.SecretDetector` owns shared credential shapes; the validation adapter renders strict no-prefix markers and recursively scrubs arbitrary Secret-map values before saving any artifact or observed transcript (including container/wasm). See [validation-process.md](validation-process.md#credential-safe-execution-evidence).
- **Rollback** — mutating steps track what they created/modified for cleanup

## Model routing & spend

Which model runs which role — and what it costs — is **policy data**, not
prose: `config/model-registry.yaml` (schema-gated) is the only place
vendor/model identifiers live, python3 -m traust.cli registry models resolves roles
with floor enforcement, and spend is tracked from two sources (driver-
declared + session actuals) into traust-core's spend events and the
spend view. Full contract, real-time view command, and escalation
ladder: [model-routing.md](model-routing.md). Gate: alignment rule A12.

## SARIF interchange

Findings cross the harness boundary as SARIF 2.1.0, the standard JSON format
for static-analysis results, in both directions. The **importer**
(`traust triage intake`, on traust-core) records SARIF from any scanner as an
assessment of the commit and its findings, which `/triage` then verifies, so
third-party results enter the same adversarial pipeline as audit-born ones. The **emitter**
(python3 -m traust.cli reporting sarif) projects any harness report,
dispositions included, into SARIF for whatever dashboard, viewer or aggregator
the adopter runs. Neither is a store: the harness report and the disposition
ledger stay authoritative, and an export is a derived view. Field mappings in
both directions: [sarif.md](sarif.md).

## Security-posture gate

python3 -m traust.cli check skill-security runs in the
pre-commit hook and in CI as a peer of the alignment gate
(python3 -m traust.cli check skill-alignment). Its S-rule
series makes the safe patterns mechanical for every skill: tool
confinement, the adversarial-content doctrine, git-transport gating,
shell-exec constructs, secrets in argv, fixed temp paths, unpinned
installs, raw-egress grants, repo-config isolation for headless agents,
and target-build routing through the `safe_exec` sandbox
([safe-exec.md](safe-exec.md)). Grandfathered exemptions each cite the
item that will remove them. The rules are enumerated in the
`check-skill-security` skill.

## Impact analysis

`harnessing/3-audit/impact-analysis/` plus `traust impact analyze` (traust-core's
`ExposureService`) answer "which commits does this advisory actually affect": a
blast-radius walk over the commits' SBOMs followed by per-ecosystem affectedness analysis
(for Go: govulncheck source and binary modes, then an ELF string scan of
shipped images). Artifacts validate against
`schemas/v1/impact-analysis.schema.json` and feed `/triage` Phase 2f and
`/verify-remediation --impact-filter`.

## Configuration & context

All runtime configuration is **config-owned and injected** — one directory, read
once at the entry point, threaded down. There are no environment overrides for
deployment values (the AWS/SSH model: one place you edit, not a scatter of env
vars). Three layers, each owning exactly one thing:

| Layer | Repo / package | Owns |
|-------|----------------|------|
| **Contract** | `traust_contracts` | The config *mechanism*: the MANIFEST (what files exist), the `config/v1/*` JSON schemas, the typed section models, and the one loader — `load_context()` (full) / `load_section()` (narrow). No estate data. |
| **Resolution** | `traust` (this app) | The *source + composition root*: templates, shipped defaults, `install_traust` seeding, and resolving the context **once** at each entry point (`traust.context.load`, traust-core's `Context`), then injecting it. |
| **Consumer** | `traust_engine` | A pure *consumer*: `HarnessEngine.load()` builds from a `HarnessContext`; ops namespaces (`h.metrics`, `h.corpus`, …) hold the ctx and resolve values; stateless functions receive resolved values. **The engine never loads config itself** — no env, no cwd, no workspace-shaped guessing. |

### The one config directory

Everything lives under `$TRAUST_CONFIG_HOME` (default `~/.traust/config`).
`make install` (→ `scripts/install_traust`) seeds it with `traust.yaml` (from
`config/traust.example.yaml`) and the shipped `model-registry.yaml`; `make doctor`
runs a `load()` smoke that names exactly what still needs filling. Tool pins,
safe-exec profiles and the feeds registry ship with traust-core. Runtime *paths*
(workspace, analysis results, progress tracker, feed cache, scanner-ruleset
overrides, product registry endpoint) live in `traust.yaml` under **`locations:`** — see
[storage.md](storage.md). Operator setup: [setup.md](setup.md).

### The runtime flow

```
entry point (CLI main / app)
   └─ traust.context.load()                 # resolve config ONCE, here
        ├─ Context.register_*(paths)         # core's providers; config read on first use
        └─ Context.services()                # core's domain services
```

A required-but-absent (or still-a-template) config file raises
`DeploymentConfigMissing` **at the entry point** — fail once, loudly, with the
fix named, never deep in a module at an unpredictable moment. Signing is
optional: with no `ledger.public_key_path`, the ledger records unsigned and
verification is skipped (set `traust.yaml` → `ledger.required` to enforce).
Signing and token verification are `traust.yaml`'s `ledger:` and `identity:`
sections (optional); ledger layers are contract tables in the record store.

**What stays environment-driven** (deliberately, not config): secrets
(`GITHUB_TOKEN`, LDAP bind-password file, signing key *paths*), OS/tool
standards (`XDG_*`, `JAVA_OPTS`), and the safety switch `SAFE_EXEC_DISABLED`.
Everything else that is a deployment value is a file in `$TRAUST_CONFIG_HOME`.

Why this shape: the engine is reusable by any caller that supplies a context
(it has zero app coupling and no hidden config reads), config resolution has a
single implementation so no two callers can disagree about “what the config is,”
and an operator has one directory to reason about. Which repo to change for a
given config concern: [components.md](components.md).

## Where the code lives

Deterministic tooling is split by how many skills use it (the placement
rule in AGENTS.md): a single skill's helpers sit in that skill's
`scripts/`; CLIs shared across skills are package modules under
`src/traust/cli/`. Ops runners remain in the app; adopter-portable migrations
stay with their owning package and deployment-specific one-shots stay private.
Core owns scanner providers, canonical intake/reporting, safe execution and the
model catalogue behind its public Context/services API. The engine runs orders
through that API; the ledger library supplies pure integrity/signing primitives
to Core's ledger service. Skills invoke their app CLIs from
the harness venv. Per-language deterministic coverage (reachability
engines, fuzzers, rule packs) is mapped in
[language-support.md](language-support.md).

There is no hand-maintained catalogue of scripts. The list of skills is
generated ([skills.md](skills.md)); each CLI documents itself in its
module docstring and `--help`; which repository owns a module, and which
one to change for a given fix, is [components.md](components.md).

## Core cutover compatibility decisions

The current adapters expose domain use cases through Core; a removed private
script is not a permission to remove its supported use case. These decisions
describe this implementation and are proposed for review with the cutover PR,
not attributed retroactively to an earlier owner approval.

| Capability | Owner and compatibility decision |
|---|---|
| Configuration and identity | Core owns the typed deployment configuration and authenticated caller. Adapters resolve explicit configuration before choices or execution; they do not invent login state or read a second configuration store. |
| Static code facts | Core enumerators own static expansion and explicit coverage gaps. CLI metadata, configurable matrix limits, offline facts and serialized field names remain supported; static candidates never become findings merely by enumeration. |
| Finding intake and correction | Core owns canonical intake, report bindings and disposition precedence. A ticketed human correction changes the existing claim without manufacturing a new assessment or validity decision. |
| Validation | Source labels are not database UUIDs. Machine recording uses explicit bindings; scope, attestation, controls and differential evidence retain their distinct failure states. Probe observations, not helper names or prose, determine soundness. |
| Compliance | Typed checks retain preconditions, uncertainty and evidence provenance. Per-control Markdown, OSCAL stability comparison and field precision are different outputs and remain separate from aggregate posture. Official documentation requires declared source coordinates. |
| Dependency exposure | Advisory providers own source ranges and fixes, including exported offline records. Same-vulnerability aliases retain every contributing package, version, source and fix. Ordinary unfixed advisories remain visible; fix availability is metadata, not a silent retention gate. |
| Exposure history | One complete preparation scope may produce several package packets. Partial replacement evidence cannot clear the last complete snapshot; a completed corrected snapshot can remove obsolete package versions. Historical queries select the complete evidence available at their cutoff. |
| Remediation and verification | Core owns work items, fork policy, progress and verification evidence. Explicit rollup targets and branch scope remain supported; impact filters intersect requested scope and never widen an empty selection. Replays do not imply another verification run. |
| Detection quality | Recorded misses and pre-intake campaign candidates are separate populations. Bootstrap emits unadmitted candidates, not answer-key truth. Replay presence, detection, review and missed outcomes remain distinct; sanitizer execution still requires its approved boundary. |
| Inventory references | Service labels, ownership provenance, contact and tracker routing are declared outside-authoritative facts. Missing values remain unknown. Corpus caveats use the existing registry note instead of a new database field. |
| Repository topology | Native inventory, relationships and recorded package/interface facts feed graph queries and exports. Unregistered declared URLs stay visible. An unsigned crown-jewel proposal does not change an approved designation. |
| Repository availability | The portfolio liveness owner distinguishes unqueried, unknown, moved and missing. Failed observations do not invent a commit or erase the last genuine successful ref. |
| PQC | Package discovery does not require the readiness assessment it is meant to trigger. Historical repair preserves supplied evidence; ranked/bulk workflows use explicit selectors and checkpoints, not fabricated readiness or guessed external fixes. |
| Report composition | Executive, scoreboard, validation/fuzz, trend and pattern views preserve their supported domain cuts and detail. A link to an unrelated view is not a substitute for an embedded use case. Unmeasured values are not zero. |
| Temporal metrics | Captured as-reported bytes are separate from recomputation at `as_of`. Optional current-rate repricing never rewrites settled dollars. First-party estimates require an explicit calibration input; no automatic global divisor is asserted. |
| Review overrides | Suppressed scanner results remain excluded by default; an explicit review override can include them. Optional signature verification reports integrity failures without conferring finding validity or authorization. |
| Operational freshness | Provider readiness, upstream release age, registry age, schema compatibility and measured-language coverage answer different questions. The surviving worklist retains its age backstop. |
| Interim rescan population | Native input inventory replaces the graph bootstrap. The registered rescan builder still consumes its explicit legacy findings projection for population, report paths and IaC-baseline selection; this is not a claim that the whole router has migrated or that its projection is Core's authoritative finding store. |
| Retired layer export | Legacy layer-store replay/export remains retired. Native layer/event reads are distinct from importing external source statements; `findings import` is not described as a snapshot-export replacement. |

Rendering and transport do not create authority: structured untrusted text is
escaped by its format's existing renderer, unknown metadata is not guessed, and
reference declarations do not establish execution evidence. Existing approved
retirements remain retired; the compatibility work restores their actual retained
consumers rather than adding deprecated aliases or parallel stores.
