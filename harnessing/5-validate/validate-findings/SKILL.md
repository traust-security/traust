---
name: validate-findings
description: Use when the user asks to validate, reproduce, exploit, red-team, or live-test security findings against a Kubernetes/OpenShift cluster, operator, WASM module, container, pod, or cluster component. Ingests *-security-audit, *-threat-model, and *-triage reports, builds an attack plan (replay + chained + novel), executes it against an authorized live target under a hard scope guard, and emits a schema-validated *-validation.{json,md} report. Records explicitly bound existing findings through core-owned soundness and evidence gates; novel-finding intake remains a separate port.
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - AskUserQuestion
  # scope.py is fail-closed and the adapters' step vetting is the exec
  # gate (audit C2/D6, plan P2.13/P2.14); oc/kubectl reach the LAB
  # cluster the ROE names. Never widen to a bare interpreter.
  - Bash(oc:*)
  - Bash(kubectl:*)
  - Bash(jq:*)
  - Bash(ls:*)
  - Bash(grep:*)
  - Bash(head:*)
  - Bash(python3 *harnessing/5-validate/validate-browser-finding/scripts/run.py:*)
  - Bash(python3 *ingest.py:*)
  - Bash(python3 *plan.py:*)
  - Bash(python3 *execute.py:*)
  - Bash(python3 *harnessing/5-validate/validate-findings/run.py:*)
  - Bash(python3 *harnessing/5-validate/validate-core-ocp/scripts/gen_targets.py:*)
  - Bash(python3 *credential_liveness.py:*)
  - Bash(python3 *-m traust.cli reporting validate:*)
  - Bash(traust findings refuted:*)
  - Bash(traust validation record:*)
  - Bash(python3 *-m traust.cli validation record:*)
  - Bash(python3 *-m traust.cli admin attest-target:*)
---

# Validate Findings — Live Validation & Attack-Chain Harness

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Take the static outputs of `secure-code-audit`, `threat-model`, and `triage` and **prove or refute them against a live authorized environment**. Then go further: chain confirmed findings into multi-step kill-chains and hunt for novel attacks the static analysis missed.

> **Authorization**: This skill executes potentially state-changing actions against live infrastructure. It MUST only be run against targets you own or have explicit written authorization to test. Every action is gated by the scope guard (`scope.py`) — out-of-scope steps are refused and logged, never silently skipped.

---

## Input

`$ARGUMENTS` is parsed as whitespace-separated tokens. The **first non-flag token** is the findings source; remaining tokens are flags.

### Findings source (required — one of)

| Form | Resolution |
|---|---|
| `<dir>/` | Directory containing `*-security-audit.{json,md}`, `*-threat-model.md`, `*-triage.{json,md}` |
| `<file>.{md,json}` | A single report file; siblings auto-discovered in the same directory |
| `<product>/<repo>` | Shorthand resolved to `../analysis-results/findings/<product>/<repo>/` |
| `<slug>-findings` | Product package from `../progress-tracker/processed-results/<slug>-findings/`. All repos in the package are ingested into a single model; each finding is tagged with its source repo. The bare `<slug>` form (without `-findings`) is also accepted. |
| `<slug1>,<slug2>,…` | **Multiple packages** merged into one model — used when a logical product spans several `processed-results` entries (see the Deduplication Map in `progress-tracker/VALIDATION-PRIORITY-LIST.md`, e.g. ODF → 12 packages). Findings are tagged `<package>:<repo>` and de-duplicated by `(repo, id)` so a repo appearing in two packages contributes once. |
| `all-confirmed` | Every triage-confirmed finding across `../analysis-results/findings/**` (use with `--dry-run` first) |

**Refuted findings stay in scope.** Read core's current refuted findings with
`traust findings refuted --repo-url <repository-URL>`. A retained
`<repo>-refuted-register.json` is historical evidence, not an exclusion or a
current projection; its emitter is retired. A finding dismissed as a false
positive — even human-countersigned — remains a falsifiable claim.
Explicit E0–E3 evidence grades, not the report kind or a machine identity,
govern precedence. `traust validation record` admits bound existing findings;
sound refutations remain open pending verified human signoff. Include refuted
findings in planning when scope and budget allow; a human signature is not
execution proof and a null grade never overrides E0.

**Impact-analysis artifacts as target selection.** When
`analysis-results/impact/<cve>-impact-analysis.json` (from
`/impact-analysis`) covers the finding's CVE, use it two ways: (a)
prioritization — repos classified `affected` with triage's
`attacker_influence: plausible` are the validation candidates worth
cluster time first; (b) attack planning — the repo's
`evidence.govulncheck_trace` names the call path caller-first, so the
first in-repo frame identifies which interface the attack plan should
drive. A confirmed exploitation here is execution evidence (class 1):
it flips the finding to `confirmed` in the disposition ledger and is
the terminal answer to "is this repo actually affected".

**Product packages** (`*-findings/` directories) contain sub-directories grouped by repo or by sub-group/repo (1–2 levels). The harness auto-detects the package layout: if the source directory has no audit reports at the top level but has sub-directories with audit reports, it is treated as a package and all repos are ingested. Findings from each repo carry a `source_repo` tag for traceability in the plan, execution log, and validation report.

### Scope binding (at least one mode; modes are additive)

| Flag | Mode | Effect |
|---|---|---|
| `--targets <file.yaml>` | **1 — explicit** | Load a rules-of-engagement scope file (see `targets.example.yaml`). Highest precedence. |
| `--context <name>` | **2 — inline** | Kubeconfig context to bind (repeatable). Implies the cluster at that context is in scope. |
| `--ns <name>` | 2 | Namespace allowlist (repeatable, glob OK). |
| `--image <ref>` | 2 | Container image allowlist (repeatable, glob OK). |
| `--pod <selector>` | 2 | Pod label selector allowlist (repeatable). |
| `--container <name>` | 2 | Running container name/ID for the container adapter (repeatable, glob OK). |
| `--wasm <path>` | 2 | WASM artifact path for the wasm adapter (repeatable). |
| `--infer-scope` | **3 — inferred** | Derive scope from report `metadata` + threat-model `entry_points`. Lowest precedence; **never** infers `kube-system`, `openshift-*` control-plane, or `default` namespaces. |

If no scope mode is given, the harness runs `--dry-run` implicitly and warns.

### Execution control

| Flag | Effect |
|---|---|
| `--dry-run` | Stop after Phase 2. Emit `attack-plan.yaml` only; nothing touches the target. |
| `--auto` | Skip the Phase 3 review gate. Use **only** in isolated lab environments. |
| `--replay-only` | Validate existing findings only; skip chaining and novel hunting. |
| `--novel-only` | Skip replay; run recon + chain synthesis + novel probes only. |
| `--destructive` | Permit steps the adapter classifies as `destructive` (data loss, DoS, irreversible mutation). Without this flag such steps are recorded as `not_attempted` with reason `destructive-not-permitted`. |
| `--max-novel <N>` | Cap novel-attack hypotheses (default 10). |
| `--out <dir>` | Override output directory (default: alongside the source reports). |

---

## Scope Binding — Resolution & Enforcement

Run `python harnessing/5-validate/validate-findings/scope.py` semantics:

1. **Load** mode-1 file if `--targets` given; merge mode-2 inline flags on top; if `--infer-scope`, call `ingest.infer_scope()` and merge with **lowest** precedence.
2. **Compile** into a `Scope` object exposing `is_in_scope(action: Action) -> (bool, reason)` where `Action = {adapter, verb, context, namespace, resource, name, image, extra}`.
3. **Hard denies** (always refused regardless of flags or `--auto --destructive`):
   - Any entry in `targets.yaml#off_limits`.
   - Any namespace matching `kube-system`, `openshift-etcd`, `openshift-kube-apiserver*`, `openshift-authentication*` **unless explicitly listed** in mode-1 `clusters[].namespaces`.
   - `expires` date in the past.
4. **Preflight** every bound target via the adapter's `preflight()` to capture a fingerprint (cluster version, node count, image digest, WASM sha256). The fingerprint goes into `validation.json#metadata.target_fingerprint` so results are reproducible.

Every executed step is logged with the scope-check outcome. A `blocked_by_scope` verdict is a **result**, not an error — it tells the reader the PoC would have crossed a boundary the engagement does not permit.

---

## Benchmark mode (P7)

`analysis-results/scan-testing/validation-benchmark/benchmark-findings.json`
(from python3 -m traust.cli sweep benchmark plan) is a first-class input:
validate its claims against the deployed fixtures exactly like campaign
findings, then score the report with
`python3 -m traust.cli sweep benchmark score --variant vuln|safe`. Benchmark runs
live in the harness-QA tree and never touch campaign metrics.

## Phase 0b — Target attestation (fail-closed, P2)

After scope loads and before ANY probe executes, attest the target and
write `target-attestation.json` into the validation output dir:

```bash
python3 -m traust.cli admin attest-target --out <out-dir>/target-attestation.json \
    --namespace <operand-ns> [--csv <operator-csv>] [--selector <pods>] \
    [--version <deployed> --affected-range '<vX.Y.Z'] \
    [--kubeconfig <path>] [--context <ctx>]
```

Retain the full object in `metadata.target_attestation` or supply the full
artifact to `traust validation record --target-attestation`. Core owns the
run-level gate: explicit `attested: false` voids EVERY verdict at any age.
Current recording requires attestation regardless of the reset harness version;
missing evidence becomes review with `attestation_missing`. Flags and raw
observations remain retained even when no validity decision can be written.

## Phase 0c — Positive-control pairing (assay validity, P1)

Every **refutation-capable** probe step carries paired positive
controls in its plan entry, executed in the same session and recorded
in the step's `controls[]` (schema `positive_control`):

| Probe class | Paired control (kind) |
|---|---|
| RBAC "subject X cannot do Y" | same client performs an action X is KNOWN to be allowed (`must_succeed`) — proves auth worked, enumeration non-empty, API reachable |
| Secret-exposure "secret not readable" | read a planted canary secret the probe SHOULD see (`must_succeed`) — proves the oracle observes the right store |
| Network/exposure "endpoint not reachable" | reach a known-open endpoint on the same path (`must_succeed`) and a known-closed one (`must_deny`) |

Rules (enforced by the soundness gate + ledger emitter):
- A `refuted` verdict with a **failed** control is quarantined as
  `failed-positive-control` — any report age: the assay demonstrably
  didn't work.
- A `refuted` verdict with **no passing control**, on reports at/after
  harness 0.177.0, quarantines as `missing-positive-control`.
- Controls never substitute for the probe: they prove the assay could
  have detected the claim, converting "absence of evidence" into
  "evidence of absence, with the assay proven live."

## Phase 0d — Differential probing for authz claims (P3)

For every "role/subject can(not) do X" refutation, probe the **pair** in
the same session and record it in the step's `differential` block:

- the claimed action, AND
- a neighbor action with a **known-different expected outcome** (same
  subject → a verb it IS allowed; same verb → a subject that IS
  authorized).

If both outcomes are identical, the oracle cannot discriminate allowed
from denied — the refutation is unsound **regardless of which way it
pointed** (`non-discriminating-oracle`, quarantined at any report age).
Post-0.178.0, an authz-class refutation without a discriminating
differential quarantines as `missing-differential-probe`. One extra
request per probe; catches wrong-oracle failures without knowing *why*
the oracle is wrong.

## Phase 0e — Severity validation on confirmations (P9)

Every `confirmed` finding records `severity_validation`: the CVSS
components the exploit ACTUALLY demonstrated (attack vector used,
privileges the probe identity held at success, user interaction, scope
crossing observed from the E0 artifact, impact axes evidenced) and the
signed delta vs the claimed score. When |delta| >= 1.0 **and** the
evidence grade is E0/E1/E2 (never E3), emit a `proposal` in the validation
artifact. `traust validation record` retains it and requests human review;
machines never write severity overrides. OWASP risk rating remains the
methodology; CVSS observation fields do not replace it. A demonstrated DOWNGRADE
("exploitation required cluster-admin") is exactly as valuable as an
upgrade. Findings that are constituents of a demonstrated attack chain
also record `chain_context` (chain id, chain severity, role) — chain
membership is severity evidence and belongs in the proposal rationale.

## Phase 6 pointer — discovery sweeps & replay artifacts (P5/P8)

**Replay (P8, required on every probe):** record a self-contained
replay script per executed step in `artifacts/replay/<step_id>.sh`
(+ inputs file when the probe posts data) and reference it in the
step's `replay` block with the attestation fingerprint sha. A
countersign human re-runs the exact probe instead of trusting the
transcript.

**Discovery sweeps (P5, optional phase after replay/chained/novel):**
outputs are NEW finding candidates with `origin: validation-discovery`,
routed to `/triage` generic ingest — never straight to the ledger:

1. *State diffing (implemented):* python3 -m traust.cli impact cluster-state-diff
   snapshot before the sweep and after it; `diff` turns unexpected
   deltas (new/mutated RBAC, SCC changes, webhook mutations, deleted
   NetworkPolicies, new exposure) into candidates, excluding declared
   probe side-effects (`--expected`).
2. *Anonymous-surface sweep* — unauthenticated reachability vs an
   authenticated baseline (per-sweep increment, not yet implemented).
3. *Privilege-escalation chain search* — seeded from
   operator-priv-profile + the RBAC graph; attempt the cheapest link
   under the scope guard (not yet implemented).
4. *Browser role×route matrix + IDOR probing* (browser lane; not yet
   implemented).

All sweeps inherit the hard scope guard unchanged.

## Phase 1 — Ingest & Normalize

```bash
python harnessing/5-validate/validate-findings/ingest.py <findings-source> > /tmp/normalized.json
```

1. Locate the three report types in the source directory. JSON is preferred; fall back to Markdown parsing when JSON is absent.
2. Build a unified `Finding` list. For each finding merge:
   - `security-audit`: `id`, `title`, `severity`, `cwes`, `locations`, `evidence[]`, `attack_pattern`, `cvss`
   - `triage` (if present): `verdict`, `verify_verdict`, `confidence`, `preconditions[]`, `first_links[]`, `severity_label`, `owner_hint`
   - `threat-model` (if present): linked `threat_id`, `entry_point`, `asset`, `controls`
3. Build a `ThreatGraph` skeleton: assets (with sensitivity), entry points (with trust level + reachable assets), threats (with status + linked finding evidence).
4. Extract **embedded PoCs**: scan `evidence[]` code blocks and `attack_pattern` text for fenced `yaml`/`bash`/`json`/`curl` blocks and the triage `rationale` STEP narratives. Tag each as `{lang, body, source_field}`.

Findings with triage `verdict == false_positive` are carried through but default to `technique: skip` in the plan (override with `--include-fp`). Findings with triage `verdict == needs_review` (evidence not statically locatable; never proven false) are **not** skipped — they are planned like `true_positive` and the resulting step is tagged `triage_was_needs_review: true`.

---

## Phase 2 — Attack Planning

```bash
python harnessing/5-validate/validate-findings/plan.py /tmp/normalized.json --scope <scope.json> > <out>/<repo>-attack-plan.yaml
```

The plan is an ordered list of **steps**, each:

```yaml
- id: step-007
  finding_ref: ODR-2026-004        # or novel_ref / chain_ref
  technique: replay                # replay | adapted | chained | novel | recon
  adapter: k8s
  verb: apply-manifest
  target: {context: lab-spoke-1, namespace: ramen-ops}
  payload: |                       # the literal manifest / command / wasm-invoke
    apiVersion: ramen.openshift.io/v1alpha1
    kind: Recipe
    ...
  classification: mutating         # safe | mutating | destructive (from adapter.classify)
  expected: "pods/exec succeeds in namespace outside tenant scope"
  rollback: "kubectl --context lab-spoke-1 -n ramen-ops delete recipe pwn"
  preconditions: [step-003]        # steps that must succeed first
```

### 2a. Replay steps

For each non-FP finding, convert extracted PoCs into one or more steps:

| PoC form | Adapter / verb |
|---|---|
| YAML manifest (Kind present) | `k8s / apply-manifest` |
| `kubectl …` / `oc …` literal | `k8s / raw` |
| `curl` / `http` against a Service | `k8s / port-forward+http` (or `container / network-probe` if no cluster) |
| `podman exec` / `docker exec` | `container / exec` |
| Shell against a pod | `k8s / exec` |
| WASM invoke / hostcall | `wasm / invoke-export` |
| No literal PoC | `technique: adapted` — synthesize a minimal probe from `cwes` + `locations` (e.g. CWE-918 ⇒ SSRF callback to a harness-controlled listener) |

### 2b. Chained steps (`chain.py`)

Build the attack graph and emit one `chain_ref` step-group per discovered path:

- **Nodes**: findings, threat-model entry points, threat-model assets, recon-discovered resources (added in Phase 4 second pass).
- **Edges**:
  - `entry_point → finding` when the finding's `preconditions` are satisfiable at that entry point's trust level.
  - `finding_A → finding_B` when A's expected impact (token theft, ns escape, RBAC grant, file write, network position) satisfies any of B's preconditions. Use the capability vocabulary in `chain.py:CAPABILITIES`.
  - `finding → asset` when the finding's impact references the asset.
- **Search**: DFS from every entry point to every asset with sensitivity ≥ high. Deduplicate by node-set. Cap path length at 6.
- For each chain, emit ordered steps reusing the replay steps where they exist, inserting `technique: chained` glue steps (e.g. "extract SA token from step-003 evidence and set KUBECONFIG for step-004").
- Annotate with **MITRE ATT&CK** technique IDs from the shared pinned tables (`harnessing/attack-coverage/tables/`, loaded via `attack_refs.capability_map()`; IDs validated against the pinned ATT&CK release at import).

### 2c. Novel steps (`novel.py`)

1. **Recon plan**: emit `technique: recon` steps for the bound target type(s) — these are always `classification: safe`:
   - **k8s/operator/component**: `kubectl get crd,clusterrolebinding,rolebinding,networkpolicy,validatingwebhookconfiguration,mutatingwebhookconfiguration,svc,ep -A -o json`; `kubectl auth can-i --list --as=<each in-scope SA>`; `kubectl get pods -o jsonpath` for securityContext, hostPath, SA mounts, capabilities.
   - **container**: `inspect`; `cat /proc/self/status` (CapEff), `/proc/mounts`, env, listening sockets.
   - **wasm**: `wasm-tools dump --imports --exports`; component-model world inspection.
2. **Diff** recon output against threat-model `entry_points` + `controls`. Surfaces present live but absent from the model are **candidate novel entry points**.
3. **Crypto posture probes** — when findings include `category: cryptography` or
   `pqc_classification` and a cluster context is bound, run runtime data
   collection:
   ```bash
   python3 -m traust.cli adapters crypto-cluster --context <ctx> --namespaces <ns> [--discover] [--groups "..."]
   ```
   This emits the runtime crypto census with raw TLS negotiation
   data, crypto-policy state, and OpenSSL/Go versions. For source and image
   tier crypto analysis, delegate to the `crypto-analysis` skill.

   These facts feed the PQC PROBE_CATALOGUE entries and
   `chain.pqc_caps_from_probe()` for capability mapping. Record each run
   in `metadata.tools` and `deterministic_steps`.

4. **Pattern probes** — for each candidate, emit a probe step from the catalogue in `novel.py:PROBE_CATALOGUE` keyed by target type and surface class:
   - *Operator*: confused-deputy (cross-ns `*Ref` fields in CRD schema), SSRF (URL-typed CRD fields → harness listener), TOCTOU (status-subresource race), webhook bypass (label/annotation that skips admission), over-broad RBAC (`auth can-i --list` shows `* * *`).
   - *Pod / container*: writable hostPath, `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` presence, `/var/run/docker.sock` or CRI socket mount, SA token with cluster-admin reachability, procfs breakout, shared PID/net namespace.
   - *Cluster component*: unauth metrics/pprof/healthz with side-effects, anonymous-auth on kubelet, insecure-port residue, etcd client cert reuse.
   - *WASM*: unrestricted WASI preopen dirs, hostcall import without capability check, linear-memory OOB on exported function, missing fuel/epoch limits.
5. **AI-assisted hypotheses** — after recon executes (Phase 4 first pass), reason over: recon output, unexploited threat-model threats (`status: unmitigated` with no linked finding), and the CWE distribution of confirmed findings. Propose up to `--max-novel` additional attack hypotheses. Each becomes a `technique: novel` step with a clear `expected` outcome that distinguishes confirmed from refuted.

### 2d. Ordering & classification

Order: all `recon` → all `replay` (severity desc) → `chained` → `novel`. Run `adapter.classify()` on every step; if `destructive` and `--destructive` not set, mark `skip: destructive-not-permitted`.

Write the plan to `<out>/<repo>-attack-plan.yaml`.

---

## Phase 3 — Review Gate

Unless `--auto` or `--dry-run`:

1. Print a summary table: step count by `{technique × classification}`, every `mutating`/`destructive` step's verb + target, and every step that `scope.is_in_scope()` would refuse.
2. Ask the user to approve. Accept: `yes` (run all permitted), `edit` (open `attack-plan.yaml`, re-read, re-summarize), `skip <id...>` (mark listed steps `not_attempted: user-skip`), or `no` (exit, plan kept on disk).
3. Record the approval (who, when, mode) in `validation.json#metadata.approval`.

If `--dry-run`: stop here. The plan on disk is the deliverable.

---

## Phase 4 — Execute

```bash
python harnessing/5-validate/validate-findings/execute.py <out>/<repo>-attack-plan.yaml --scope <scope.json> --out <out>
```

For each step in plan order:

1. `scope.is_in_scope(step.action)` — if false, record `verdict: blocked_by_scope` with reason; continue.
2. Check `preconditions` — if any referenced step did not yield `verdict: confirmed`, record `verdict: not_attempted` with reason `precondition-failed:<id>`; continue.
3. Dispatch to `TARGET_ADAPTERS[step.adapter].execute(step, scope, audit)`:
   - Capture stdout/stderr/exit, plus adapter-specific evidence (resource YAML before/after, HTTP response body, WASM trap).
   - Write artifacts to `<out>/artifacts/step-<id>.*` and compute sha256.
   - Compare observed outcome to `step.expected` → `verdict ∈ {confirmed, refuted, inconclusive}`.
   - **Refutation-soundness gate** (`soundness.py`, applied deterministically by `execute.py` — never bypass it when composing verdicts by hand): `refuted` is **un-emittable** when (a) the probe transcript matches an error signature (`Forbidden`/validator-RBAC denial, `command not found`, jsonpath errors, `NotFound`, `does not exist`, `Could not connect`, an unsubstituted `{ns}`/`{sa}` template), (b) an RBAC-style probe enumerated zero concrete subjects (empty `vf-rbac-tried:` list) or carries a literal `system:serviceaccount:{ns}:{sa}` placeholder, or (c) the run directory contains `install-failure.yaml` (whole run — the operand never deployed). Gated verdicts downgrade to `inconclusive` and carry a machine-readable `soundness_flag` (`error-signature:<name>` | `rbac-zero-subjects` | `rbac-template-placeholder` | `target-not-deployed`). `traust validation record` passes these observations to core's soundness policy, retaining detailed causes in immutable evidence and routing canonical review items — never a false-positive dismissal. `/track-findings` exposes the full observations through `traust findings review-cases`.
4. Append one JSONL line to `<out>/validation-audit.jsonl`:
   ```json
   {"ts":"<iso8601>","step_id":"...","adapter":"...","verb":"...","target":"...","scope_check":"pass","classification":"...","verdict":"...","evidence":["artifacts/step-007.log"],"rollback":"..."}
   ```
5. If `classification: mutating` and the adapter provides `rollback()`, run it immediately after evidence capture and record `rollback_performed: true|false` with output.
6. **Two-pass for novel**: after recon steps complete, re-invoke `novel.py` with live recon artifacts to materialize the AI-assisted hypotheses (Phase 2c-4) into concrete steps, append them to the plan, and continue execution.

Rate-limit: ≤ 1 mutating step per 2 s per cluster context; back off ×2 on 429/503 from the API server.

---

## Phase 5 — Report and record

`report.py` is the in-process producer (`build_validation_json`, then `write`),
not a standalone CLI. Its final serialized bytes are checked as core's typed
`ValidationArtifact` before either report companion is written. Preserve actual
controls/differential observations in `StepResult`; explicit grades and severity
review proposals can be supplied as `finding_assessments` keyed by planner ID.
Absent grades stay null; no adapter or report class infers proof strength.

The existing unattended lab runner now performs report generation AND recording:

```bash
python3 harnessing/5-validate/validate-findings/run.py <source>[,<source>...] \
  --targets <authorized-targets.yaml> --out <out-dir> \
  --target-attestation <out-dir>/target-attestation.json \
  --record-bindings <source-bindings.json> [--finding-assessments <grades.json>] \
  [--install-failure <explicit-install-failure.yaml>] [--config-home <private-config>]
```

This runner requires `environment: lab`, an unexpired authorized scope, explicit
target attestation and current-policy bindings. It establishes a real run UUID
and start time before execution, passes that typed provenance directly, and calls
the same record door as the standalone invocation below. This is not the full
plan24 service port: prepare/plan/authorize/execute still use existing local
owners and their scope guard. Never use this runner to bypass interactive
approval outside an explicitly authorized isolated lab.

For an already-produced report (no live probing):

```bash
traust validation record --report <out-dir>/<repo>-validation.json \
  --bindings <source-bindings.json> --provenance <run-provenance.json> \
  --target-attestation <out-dir>/target-attestation.json \
  [--install-failure <explicit-install-failure.yaml>] [--config-home <private-config>]
```

Use the exact typed [binding/provenance protocol](../../../docs/cli-reference.md#machine-validation-recording).
Bindings explicitly map every report source reference and original finding label
to stored core assessment/artifact/finding UUIDs, including multi-source reports.
Core validates membership, repository, baseline and any source digest; neither
source references nor finding labels are guessed from paths or interpreted as UUIDs.
Raw report bytes, target environment, full attestation and supplied install-failure
text remain evidence. Replays are idempotent; different targets/runs stay distinct.
The receipt identifies recorded artifacts, decisions and review items, not a
local layer, refuted-register or cumulative-file mutation.

The schema's `not_attempted_reason` carries skip causes. Surface/credential/count
detail stays under `metadata.additional.validation_producer`; compact chain
entries include the required step context without copying all transcripts.
Authoritative structure is core's installed `ValidationArtifact` contract,
also selected by `traust reporting validate <report>-validation.json`.

**Novel findings:** preserve executed novel findings and their provenance in the
report. This recording slice judges only explicitly bound existing core findings;
it does not implement novel-finding intake or carried-event routing. Do not claim
novel findings were admitted, hand-write ledger events or append audit baselines.
Unexecuted discovery candidates still go through `/triage` intake.
- `execution_log_ref`: relative path to `validation-audit.jsonl`.
- `negative_results[]`: probes that ran clean (reuse `report.schema.json#/$defs/negative_result`).

The Markdown render mirrors the structure of `*-security-audit.md`: executive summary table, per-finding verdict cards with embedded evidence excerpts, an attack-chain section with ASCII path diagrams, a novel-findings section formatted identically to audit findings, and an appendix linking every artifact.

---

## Credential-liveness verification (gitleaks candidates)

When the findings under validation include committed-credential candidates
(a `<repo>-gitleaks.json` artifact from python3 -m traust.cli adapters gitleaks, or
secret findings whose evidence cites one), run the dedicated verifier
instead of hand-probing:

```bash
python harnessing/5-validate/validate-findings/credential_liveness.py \
    --candidates <repo>-gitleaks.json --repo <checkout> \
    --targets targets.yaml [--endpoint openshift=https://api.…:6443]
```

- **One read-only introspection call per credential** (GitHub `/user`,
  GitLab `/api/v4/user`, Slack `auth.test`, OpenShift `users/~`, AWS
  `sts get-caller-identity`) → `CONFIRMED_LIVE` / `REVOKED` /
  `UNTESTABLE(reason)`. Never a mutation: revocation and rotation are the
  finding owner's actions.
- **Explicit-only scope**: the `credential` adapter unlocks solely via
  `targets.yaml#credential_probes.classes` (see `targets.example.yaml`).
  Inline/inferred scope, `--auto`, and `--destructive` cannot unlock it;
  without a targets file every candidate verdicts UNTESTABLE. `--dry-run`
  plans probes (with scope decisions) without touching anything.
- **Secret hygiene**: the verifier re-reads credentials from the checkout
  (the candidates artifact is secret-free by construction), keeps them in
  memory only, masks to a 4-char prefix in outputs, and refuses to write
  an artifact that would contain a recovered secret. Its audit trail
  (`credential-liveness-audit.jsonl`) is append-only like
  `validation-audit.jsonl`.
- **Into the report**: fold each probed candidate into
  `validated_findings[]` — `CONFIRMED_LIVE` ⇒ `verdict: confirmed` with
  the introspection response (status + identity) retained as evidence; supply
  an explicit justified grade, never infer strength from this classification;
  `REVOKED` ⇒ `verdict: refuted` **scoped to exposure-now only** (the
  historical exposure finding stands — a secret that lived in git history
  was still exposed for its lifetime; say so in
  `deviation_from_claim`); `UNTESTABLE` ⇒ `verdict: inconclusive` with
  the reason.

---

## Bundled package and benchmark assets

[__init__.py](__init__.py) declares this package’s public module surface.
The [benchmark expectations](benchmark/expected.json) pair the safe and
vulnerable manifests in [benchmark/fixtures/](benchmark/fixtures/).
`tests/test_target_attestation.py` loads these expectations through
traust-core's `models.validation_benchmark` scorer to verify scorer semantics.
Consult the benchmark assets when maintaining the scorer; live execution
still requires the scope and review gates below.

## Safety Controls

- **Default-deny scope**: no action runs without a positive scope match. Inferred scope never includes control-plane namespaces.
- **Staged by default**: human reviews the plan unless `--auto`. `--auto` is refused if `metadata.approval.environment` is not `lab` in `targets.yaml`.
- **Destructive opt-in**: steps that delete data, kill pods, exhaust resources, or cannot be rolled back require `--destructive` AND must not match `off_limits`.
- **Rollback**: `apply-manifest` and `create-cr` auto-delete what they created; `patch-cr` captures pre-image and restores it; `exec`/`network-probe` have no rollback (classified accordingly).
- **Audit trail**: `validation-audit.jsonl` is append-only; the report embeds its sha256 so tampering is detectable.
- **Expiry**: `targets.yaml#expires` in the past aborts before Phase 1.
- **Listener isolation**: SSRF/callback probes bind a listener on `127.0.0.1` and reach it via `kubectl port-forward` reverse — no external egress required or permitted.

---

## Output Layout

```
<analysis-results>/findings/<product>/<repo>/
├── <repo>-security-audit.{json,md}     # existing
├── <repo>-threat-model.md              # existing
├── <repo>-triage.{json,md}             # existing
├── <repo>-attack-plan.yaml             # new — reviewed plan
├── <repo>-validation.json              # new — schema-validated
├── <repo>-validation.md                # new — rendered
├── validation-audit.jsonl              # new — append-only action log
└── artifacts/                          # new — evidence files
```

## Integrations

Consumed artifacts (producer named per artifact):

- `*-security-audit.json` (`/secure-code-audit`), `*-threat-model.md`
  (`/threat-model`), `*-triage.json` (`/triage`) — the findings sources
  ingested in Phase 1.
- `targets.yaml` rules-of-engagement — human-authored scope binding.
- `*-gitleaks.json` — produced by python3 -m traust.cli adapters gitleaks; input to
  the credential-liveness verifier.
- Core refuted findings (`traust findings refuted`, from triage and
  track-findings decisions) — targets for re-validation. Retained
  `*-refuted-register.json` files are historical inputs, not refreshed outputs.

Emitted artifacts:

- `*-validation.json` — consumed by `traust validation record` through core's
  `ValidationService.record`, and by `/validation-fuzz-dashboard`. Bound verdicts
  produce canonical decisions or review items only after core-owned soundness
  and attestation gates; grade is explicit or null.
- `target-attestation.json` — consumed by the report runner and
  `traust validation record --target-attestation`; full checks/fingerprint retained.
- `install-failure.yaml` — explicitly supplied to `traust validation record
  --install-failure`; core retains its text and gates unsound refutations.
- `*-validation.md`, `validation-audit.jsonl`, `artifacts/` (including replay
  scripts) — review/replay companions. Actual run provenance is passed directly
  to core and retained there, not written as a parallel authoritative sidecar.
- Executed novel findings remain in the report for the separate finding-intake
  port; never append them to immutable baselines by hand.
- Discovery-sweep candidates (`origin: validation-discovery`) —
  consumed by `/triage` generic ingest.

## Spend declaration (calibration tuple)

After this skill's report/artifact is written, declare the run's spend
against the target so `estimate_scan` can calibrate per-skill cost
models (contract: docs/model-routing.md; analysis:
progress-tracker/metrics/estimate-calibration-analysis.md §F5):

```bash
python3 -m traust.cli registry models spend --skill validate-findings \
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
