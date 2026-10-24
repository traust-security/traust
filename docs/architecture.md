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
- **Credential redaction** — the shared write-time redaction patterns (`traust_engine._util.redact`, plus adapter-local ones) scrub PEM keys, cloud credentials, bearer tokens, JWTs, and registry auth from all artifacts before they hit disk (all adapters, including container/wasm)
- **Rollback** — mutating steps track what they created/modified for cleanup

## Model routing & spend

Which model runs which role — and what it costs — is **policy data**, not
prose: `config/model-registry.yaml` (schema-gated) is the only place
vendor/model identifiers live, python3 -m traust.cli registry models resolves roles
with floor enforcement, and spend is tracked from two sources (driver-
declared + session actuals) into the hash-chained metrics ledger and the
spend dashboard. Full contract, real-time view command, and escalation
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
| **Resolution** | `traust` (this app) | The *source + composition root*: templates, shipped defaults, `install_traust` seeding, and resolving the context **once** at each entry point (`traust.context.load_engine`), then injecting it. |
| **Consumer** | `traust_engine` | A pure *consumer*: `HarnessEngine.load()` builds from a `HarnessContext`; ops namespaces (`h.metrics`, `h.corpus`, …) hold the ctx and resolve values; stateless functions receive resolved values. **The engine never loads config itself** — no env, no cwd, no workspace-shaped guessing. |

### The one config directory

Everything lives under `$TRAUST_CONFIG_HOME` (default `~/.traust/config`).
`make install` (→ `scripts/install_traust`) seeds it from `config/*.example.*`
templates plus the shipped filled defaults (`model-registry.yaml`, `feeds.yaml`,
`external-tools.yaml`); `make doctor` runs a `load_context()` smoke that names
exactly which files still need filling. Runtime *paths* (workspace, analysis
results, progress tracker, feed cache, scanner-ruleset overrides, product
registry endpoint) live in one file, **`locations.yaml`** — see
[storage.md](storage.md). Operator setup: [setup.md](setup.md).

### The runtime flow

```
entry point (CLI main / app)
   └─ traust.context.load_engine()          # resolve config ONCE, here
        └─ HarnessEngine.load(ctx)           # traust_engine, from a frozen HarnessContext
             ├─ h.metrics / h.corpus / …     # ops namespaces bind ctx, derive paths
             └─ stateless fns(resolved args)  # never re-read config
```

A required-but-absent (or still-a-template) config file raises
`DeploymentConfigMissing` **at the entry point** — fail once, loudly, with the
fix named, never deep in a module at an unpredictable moment. Signing is
optional: with no `ledger-signing-key.pub`, the ledger records unsigned and
verification is skipped (set `ledger.yaml` → `signing.required` to enforce).
Ledger mode, signing and token verification are `ledger.yaml` (optional): with a
`dsn` the Ledger database is the authority and layer files are read-only
snapshots; every ledger CLI then takes `--ledger-layer` / `--product-repo`.

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
`src/traust/cli/` (ops runners and one-shot migrations under
`ops/` and `migrations/`); scanner adapters, the corpus resolver,
reporting, safe-exec and the model registry live in the sibling
`traust_engine` package; ledger integrity, identity and signing live in
`traust_ledger`. Skills invoke all of them as `python3 -m <module>` from
the harness venv. Per-language deterministic coverage (reachability
engines, fuzzers, rule packs) is mapped in
[language-support.md](language-support.md).

There is no hand-maintained catalogue of scripts. The list of skills is
generated ([skills.md](skills.md)); each CLI documents itself in its
module docstring and `--help`; which repository owns a module, and which
one to change for a given fix, is [components.md](components.md).
