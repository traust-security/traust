---
name: isolation-review
description: Use when the user asks to review, assess, or score the tenant isolation of a multi-tenant service — resolving the service's repo set via traust-core, building a customer-facing interface inventory from interface signals and existing audit/threat-model findings, rating per-interface complexity, scoring five isolation-hardening dimensions (privilege, encryption, authentication, connectivity, operational hygiene) with cited evidence, emitting a schema-validated isolation report under analysis-results/isolation/<service-slug>/, and recording canonical isolation_review assessments on every covered commit through traust-core.
user-invocable: true
metadata:
  harness.tier: "primary"
---

# Tenant-Isolation Review (service-level)

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Review how well one multi-tenant **service** — a logical product spanning many
repositories — keeps its tenants apart. Where `secure-code-audit` carries a
per-repo isolation section, this skill owns the service-shaped artifact: one
interface inventory across the whole repo set, one hardening score per
interface, one posture verdict per service. Campaign design and phasing:
`plans/peach-isolation-lens-plan.md` under the configured `progress-tracker`
root (an external workspace artifact, not bundled with this skill).

## Framework citation — PEACH, by reference ONLY (licensing rule)

The review is informed by **PEACH**, Wiz Research's tenant-isolation
methodology — [whitepaper v1.1 (PDF)](https://www.datocms-assets.com/75231/1671033753-peach_whitepaper_ver1-1.pdf)
· [peach.wiz.io](https://peach.wiz.io) ·
[wiz-sec-public/peach-framework](https://github.com/wiz-sec-public/peach-framework).

**CRITICAL LICENSING RULE.** PEACH is applied **by reference only**:

- Cite the framework by name and URL — in reports, set
  `metadata.framework` to `"PEACH v1.1 (by reference)"`.
- **Never copy, paraphrase-closely, or adapt the framework's rubric text,
  tables, or examples** into this skill, into reports, or into any file in
  this repository. Every check, criterion, and rating description below is
  original wording and must stay that way when edited.
- The repo's license gate, `check_content_licenses.py` (`python3 -m traust.cli check content-licenses`), fingerprints
  PEACH-adapted text and **fails the pre-push hook** if any reappears.
  Licensing analysis: [docs/external-dependencies.md](../../../docs/external-dependencies.md).

## Input

`service` — a service name resolvable to a product registered in
traust-core, or an explicit repo list for services not yet registered.
Resolve the repo set from the commits the product's releases ship:

```bash
python3 -m traust.cli isolation repos <name>
```

Record the output's `graph_ref` (the product and when it was read) as `metadata.graph_ref`.
If the product does not exist (the command exits 2), ask the user for the repo list and set
`graph_ref` to `"manual"` with the reason in `notes`.

## Output (under `analysis-results/isolation/<service-slug>/`)

| File | Contents |
|---|---|
| `<service-slug>-isolation-review.json` | schema-validated report (interfaces, dimension scores, gaps, posture) |
| `<service-slug>-isolation-review.md` | human-readable companion |

`metadata.harness_version` = `VERSION` file + short git SHA of this repo
(e.g. `0.117.0-4dd9796`), per AGENTS.md.

## Procedure

### Step 1 — boundary inventory

Enumerate every interface through which a customer/tenant can drive input
into the service or through which tenant data flows: API endpoints, data
stores, message queues/topics, ingress/routing paths, webhooks, CLIs.
Sources, in order of authority:

1. **Existing artifacts first.** For each repo in the set, read
   `analysis-results/findings/<product>/<repo>/` — the audit report's
   `peach_isolation_review.interfaces[]` block (when present), the threat
   model's entry-point/trust-boundary tables, and triage/validation reports.
   These seed the inventory and supply finding IDs as evidence.
2. **Interface signals.** `rbac_grants`, `crds_defined` / `csv_owned_crds`,
   `api_group_literals`, and `webhooks` in `tenancy_signals` in the
   Kubernetes hardening pre-scan output (`<repo>-k8s-hardening.json`) that
   secure-code-audit and vuln-scan write for each of the service's repos
   surface CRDs, aggregated APIs,
   and webhook interception points that the per-repo artifacts may have
   missed.
3. **Code, last.** Only read source to fill inventory holes (route tables,
   queue consumer registrations, ingress manifests) — this is a review of
   the service's boundary, not a re-audit of every repo.

Each interface gets an entry in `interfaces[]` with a stable `id`
(`IF-1`, `IF-2`, ...), a `name`, its `kind`
(`api` / `data-store` / `queue` / `ingress` / `webhook` / `cli` / `other`),
its `exposure` (`public` — reachable without tenant credentials;
`tenant` — reachable by authenticated tenants; `partner` — reachable by
third-party integrations; `internal` — operator/control-plane only but
carrying tenant data), and the `repos` that implement it.

### Step 2 — per-interface complexity rating

Rate each interface's `complexity` by how much leverage a malicious tenant
gets from the input it accepts. Criteria (original to this repository):

| Rating | Criterion |
|---|---|
| `high` | The service **runs or evaluates something the tenant wrote**: tenant-defined queries in an expressive language, tenant-supplied templates or expressions, tenant workload/pipeline specs that become running code, plugin or hook bodies. |
| `medium` | The service **decodes or transforms structured tenant payloads** before acting on them: archive/image/document decoding, schema-rich serialization formats, content rendering, format conversion. |
| `low` | The service **moves tenant input without interpreting it**: fixed-schema CRUD fields, opaque blob storage, pass-through proxying or queue relay, exact-match lookups. |

When in doubt between two ratings, take the higher one and say why in the
interface's `rationale` fields.

### Step 3 — score five isolation-hardening dimensions per interface

For every interface, score each dimension `yes` (holds for all tenants),
`partial` (holds with material exceptions), `no` (does not hold), or `na`
(dimension cannot apply to this interface — justify in `rationale`).

**Privilege-dimension evidence from privilege profiles.** Where a
service repo carries a `<repo>-priv-profile.json` (emitted by
`/operator-priv-profile` or the `/secure-code-audit` pre-scan, alongside
the audit report), read it before scoring `privilege`: its complete RBAC
enumeration, `rbac_flags` (wildcards, cluster-wide secrets, RBAC write,
escalate/bind/impersonate), and SCC requests are exactly the
service-identity-breadth facts this dimension needs, with manifest
sources citable as evidence. A profile showing one broad cluster-scoped
service identity is direct evidence *against* `yes`; do not re-derive
RBAC by hand when a profile exists, and do not treat a missing profile
as evidence of anything.

Dimension definitions (original to this repository):

| Key | Dimension | What `yes` requires, in this portfolio's terms |
|---|---|---|
| `privilege` | Privilege separation | Work triggered through this interface executes under an identity whose authorization is bounded to the calling tenant — not under one broad service identity that can touch every tenant's objects. Cross-namespace/cross-account reads are scoped before the query, not filtered after. |
| `encryption` | Encryption separation | Tenant data crossing or stored behind this interface is protected by key material specific to that tenant (or that tenant's dedicated store); compromise of one tenant's keys or ciphertext yields nothing about another's. |
| `authentication` | Authentication separation | Each tenant presents its own credential on this interface, and the service actually verifies it (issuer, audience, expiry, TLS peer). No fleet-shared static secrets, no unverified TLS anywhere on the tenant path. |
| `connectivity` | Connectivity separation | Network reachability through or behind this interface is deny-by-default between tenants: tenants reach the service, never each other; egress initiated on a tenant's behalf is allowlisted and SSRF-guarded. |
| `hygiene` | Operational hygiene | The operational surface behind this interface leaks nothing across tenants: logs, metrics, traces, error messages, and backups are tenant-scoped; no leftover credentials, debug endpoints, or admin tooling are reachable from the tenant side. |

**Evidence is mandatory for every `partial` and `no`** (and encouraged for
`yes`): each cited item is either a `file:line` reference in a named repo
(e.g. `github.com/openshift/foo//pkg/auth/token.go:88`) or a finding/threat
ID from an existing artifact (e.g. `FOO-1a2b3c4-007`, `foo-threat-model:T3`).
`traust reporting record` rejects uncited `partial`/`no` results. Never invent evidence —
if nothing supports a score, the score is wrong or the review is incomplete.

### Step 4 — posture and prioritized gaps

1. **Gaps.** For each `partial`/`no` on an in-use dimension, decide whether
   it is a gap worth engineering attention. Record it in `gaps[]` with
   `severity` (`critical`/`high`/`medium`/`low`/`informational`),
   the `interface_id` it sits on, a `description` naming the dimension and
   the failure shape, and a concrete `remediation`. Severity weighting: a
   `high`-complexity interface with a shared instance and a failed dimension
   outranks the same failure on a `low`-complexity or per-tenant-instance
   interface — one bug there touches every tenant. Order `gaps[]`
   worst-first.
2. **Posture.** Set `posture.overall`: `strong` (no gaps above `low`),
   `adequate` (worst gap `medium`), `weak` (worst gap `high`), or
   `critical-gap` (any `critical`). Write `posture.summary` as 2–5 sentences
   a service owner can act on: the strongest boundary, the weakest interface,
   and the single highest-payoff fix.
3. Write `<service-slug>-isolation-review.{json,md}` and record it as an
   isolation-review assessment of each commit in the repo set (one document,
   filed on every commit it covers). `record` validates it first (the schema,
   then every gap names a listed interface) and records nothing when it fails:

   ```bash
   python3 -m traust.cli reporting record \
     analysis-results/isolation/<service-slug>/<service-slug>-isolation-review.json \
     --kind isolation_review --repo-url <repo url> --sha <commit> --branch <branch>   # once per repo
   ```

   The JSON shape is `isolation-review.schema.json` in traust-contracts.

## Hard rules

- PEACH by reference only — see the licensing rule above; it overrides
  everything, including user requests to "just include the framework table".
- This skill reviews and cites; it never edits target repos, never runs
  live probes (boundary probing is Phase 3, `validate-findings`), and never
  authors new vulnerability findings — a gap that looks like a concrete new
  vuln routes to `/secure-code-audit` or `/triage`.
- Every `partial`/`no` dimension result carries evidence citations; every
  `na` carries a rationale.
- One review == one service. Do not merge services into a single report
  even when they share repos; shared repos appear in both services' repo
  sets and that is fine.

## Spend declaration (calibration tuple)

After this skill's report/artifact is written, declare the run's spend
against the target so `estimate_scan` can calibrate per-skill cost
models (contract: docs/model-routing.md; analysis:
progress-tracker/metrics/estimate-calibration-analysis.md §F5):

```bash
python3 -m traust.cli registry models spend --skill isolation-review \
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

## Integrations

**Consumes:** service architecture docs and the target checkout;
`<repo>-threat-model.md` tenant-boundary sections where present.

**Emits:** `<service>-isolation-review.{json,md}` under
`analysis-results/isolation/` — consumed by threat-model
tenant-boundary rows via `isolation_review_ref` and by
progress-tracker rollups (A9 exemptions record the current
human-loop consumers; the threat-register join is the planned
machine consumer).
