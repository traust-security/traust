# Report Structure Reference (shared)

The single reference for `*-security-audit.json` reports. **All three** audit
skills — `secure-code-audit` (profile `code`), `secure-rpm-audit` (profile
`rpm`), and `secure-container-audit` (profile `container`) — emit this one
structure, validated by the one `schemas/v1/report.schema.json` +
python3 -m traust.cli reporting validate. The schema is the authoritative
source for types and constraints; this page is the human-readable companion.
Profile-specific deltas are at the bottom — everything above them is identical
across profiles, on purpose: the finding/severity/ID vocabulary must stay
unified so triage, the disposition ledger, verify-remediation, and every
dashboard work on every report kind unmodified.

Any report in this structure (including the disposition-aware
`*-findings-current.json`) projects to SARIF 2.1.0 via
python3 -m traust.cli reporting sarif for any SARIF consumer; see
[sarif.md](sarif.md) for the mapping and [artifacts.md](artifacts.md) for the
projections.

> Maintenance rule: this file is the ONLY place the structure tables live. The
> SKILL.mds reference it and state only their deltas — duplicated tables drift,
> and the alignment gate rejects a skill that restates them.

## Required top-level keys

| Key | Description |
|---|---|
| `title` | Report title. Must contain a security-related keyword: security, audit, assessment, review, finding, or analysis. |
| `metadata` | Object with required `date` (YYYY-MM-DD, the **audit execution date** — never a commit or CVE date) and `scope` (≥10 chars). Optional: `repository`, `commit`, `ref` + `ref_kind` (`branch` \| `tag` \| `default` \| `stream` — explicit ref provenance; stamp both together on code/rpm profiles, omit on container and for detached-SHA inputs; `stream` is the rpm profile's dist-git release stream, a mainline deliverable that is never a branch re-audit), `framework`, `auditor`, `methodology`, `tools` (array), `loc_reviewed` (integer preferred), `loc_breakdown`, `audit_profile` (`code` \| `rpm` \| `container` — set it; see deltas), `additional` (object). **Must include** `additional.harness_version` — the semver from the harness `VERSION` file plus the short git SHA (e.g. `0.51.0-370e5a2`); its presence marks the report as modern-producer output, which requires stamped finding identity. `additional.contracts_version` records the contracts package version the report was validated against. The schema does not allow `harness_version` as a direct `metadata` key; it lives under `metadata.additional`, which is where the validator reads it for version-gated checks. Routed model decisions are stamped as `metadata.additional.model_routing` (`{role, model, registry_sha, floor}`, emitted via python3 -m traust.cli registry models stamp — alignment rule A12; see [model-routing.md](model-routing.md)). |
| `executive_summary` | Object with `prose` (≥50 chars) and `severity_counts` (required `critical`, `high`, `medium`, `low`, `informational` integer counts). Optional: `key_risks`, `positive_observations`. |
| `severity_criteria` | Array of ≥4 entries, each with `level` (critical/high/medium/low/informational) and `definition` (≥20 chars). Must include at least critical, high, medium, low. |
| `findings` | Array of finding objects (below). |
| `findings_summary` | Array of ≥4 severity count entries (`severity`, `count`, `finding_ids`) — counts and IDs must match the findings. |
| `remediation_roadmap` | Array of ≥1 items (`priority`, `action` ≥10 chars, `addresses` finding-ID array). |

## Finding object fields

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Globally-unique **scan-scoped** ID `{REPO_SLUG}-{SHORTSHA}-{NNN}`. Provenance to an exact commit; unique across the corpus. Never reuse across scans. |
| `fingerprint` | No (script-set) | **Cross-scan identity**: `sha256(canonical repo URL \| sorted lineless location paths \| primary CWE)`. Computed by python3 -m traust.cli corpus finding-identity (`fingerprint`/`backfill`) — never authored by the model, and the only implementation: consumers read this stamp and fail closed when it is absent. Correlates the same vulnerability across re-scans; the `rebaseline` command maps a superseded report's IDs to their successors via layer `metadata.finding_aliases`. A change to the recipe is a change to `ALGO_VERSION` paired with a re-stamp migration, never a silent regeneration. |
| `title` | Yes | Short description (≥5 chars). |
| `severity` | Yes | `critical` \| `high` \| `medium` \| `low` \| `informational`. |
| `cwes` | Yes | ≥1 `CWE-NNN` identifiers; the first is the primary (feeds the fingerprint). |
| `locations` | Yes | ≥1 objects with required `path`, optional `lines`, `description`. |
| `description` | Yes | Detailed vulnerability description (≥50 chars). |
| `remediation` | Yes | Remediation guidance (≥10 chars). |
| `cvss` | No | `score` (0.0–10.0) + `vector`. |
| `capec` | No | `CAPEC-NNN` array. |
| `evidence` | No | Code blocks: required `code`, optional `language`, `caption`. |
| `attack_pattern` | No | Attack-scenario description. |
| `category` | No | Exactly one kebab-case token from the shared vocabulary: `injection`, `authentication`, `authorization`, `secrets-management`, `supply-chain`, `insecure-workload-config`, `network-exposure`, `cryptography`, `input-validation`, `path-traversal`, `cross-site-scripting`, `ssrf`, `resource-management`, `logging-monitoring`, `data-exposure`, `tenant-isolation`. Strict-mode validation warns on any other value. Framework mappings (OWASP Kubernetes K-IDs, CIS sections, STIG IDs, ASVS chapters) belong in `description`, `asvs_references`, and the CWE list — never in `category`. The `rpm` profile uses its own packaging taxonomy (see deltas). |
| `asvs_references` | No | ASVS requirement IDs. |
| `peach_references` | No | `PEACH-P/E/A/C/H` IDs (code profile, multi-tenant only). |
| `isolation_boundary` | No | Identifier of the tenant-facing interface this finding sits on — an interface name from `peach_isolation_review.interfaces[]` or an `IF-n` id from a service isolation review. |
| `isolation_dimensions` | No | Isolation-hardening dimension(s) the finding stresses; vocabulary shared with `isolation-review.schema.json`. Only set when the finding stresses a tenant boundary. |
| `passes` | No | Audit passes that independently surfaced this finding under dual-pass union-merge: `[1,2]` both passes, `[2]` second pass only. Single-pass reports omit it. |
| `dependency` | No | Supply-chain provenance for a dependency finding (ecosystem, package, version, advisory), so the finding is self-describing and does not depend on a sibling impact-analysis artifact. |
| `pqc_classification` | No | PQC relevance, assigned by table lookup against the PQC reference tables — never free-authored: `shor-key-establishment` \| `shor-signature` \| `clock-2030-parameter` \| `classically-broken` \| `hndl-exposure` \| `pqc-blocker-config` \| `pqc-adoption`. |
| `remediation_effort` | No | Contract vocabulary: [remediation effort enum](https://github.com/traust-security/traust-contracts/blob/main/enums/v1/remediation-effort.json). PQC values are derived deterministically per the PQC decision tree and emitted alongside `pqc_classification`. |
| `validation_status` | No | `confirmed` \| `corrected` \| `false_positive` \| `not_verified` \| `hardening` — **ledger-set, never at audit time**. |
| `disposition` | No | Present only on cumulative reports (`*-findings-current.json`): both disposition axes, conflict and awaiting-signoff flags, and event history, derived from the ledger. Never authored in a baseline. |
| `effective_severity` | No | Present only on cumulative reports: equals a human severity override from the ledger when one exists, else the original severity. The original `severity` is never rewritten. |
| `source_findings` | No | Source scanner finding IDs / provenance refs (for routed findings: the producer's own id — e.g. a `REG-*` regression id — plus the producing report's path). |
| `origin` | No | Producer of a finding that entered the ledger as an event rather than from the baseline audit: `verify-remediation` \| `vuln-scan` \| `create-fuzzing` \| `validate-findings` \| `validation-discovery` \| `impact-analysis`. Absent on findings authored by the baseline audit itself. |

## Optional top-level keys

| Key | Description |
|---|---|
| `dependency_audit` | `prose` + `entries[]` (`package`, `version`, `status`, `notes`). |
| `negative_results` | Areas verified clean: `area`, `result`, optional `files`. |
| `asvs_coverage` | ASVS chapter coverage entries. |
| `scanner_correlation` | Scanner tool results, including the judge decisions the rule-mining lane consumes. |
| `peach_isolation_review` | Always emitted on `code` and `container` profiles — see deltas. |
| `disposition_summary` | Cumulative reports only: counts per validity and resolution state, derived from the ledger. |
| `footer` | Free-text footer. |

## Profile deltas

### `code` — secure-code-audit (source/manifest audits)

- `metadata.audit_profile: "code"`.
- `metadata.additional.deterministic_steps` — an object recording the fate of
  every deterministic pre-scan so evidence quality is comparable across a
  batch. Keys: `k8s-hardening`, `opengrep`, `gitleaks`, `osv-scanner`,
  `sbom-grype`, `priv-profile`, `fork-advisory-lag`, `route-guards`,
  `config-matrix`; value `"ran"` or `"skipped: <reason>"` (e.g.
  `"skipped: opengrep not on PATH"`, `"skipped: no local checkout"`). A
  skipped step means that section of the audit ran on manual review alone —
  downstream consumers (`/mine-ledger` precision, `/verify-remediation`) must
  not read absence of scanner facts as "scanner found nothing". The other
  profiles record their own step keys under the same object (see below).
- `metadata.additional.precision_gates` — the Precision Gate pass record, on
  all four scanning skills: `crit_high_evaluated` counts every critical/high
  candidate (filed or gated) and `fired[]` lists each gate that changed a
  candidate's disposition
  (`{candidate, gate, action: downgraded|negative_results|dependency_audit}`).
  An empty `fired` list is legitimate; a report that files crit/high findings
  with **no** block is an incomplete run — the same contract as
  `deterministic_steps`. `/vuln-scan` stamps it on its supplement scans.
- `metadata.additional.repo_status` — repo liveness from the census
  (`active | archived | moved | missing | unknown: <reason>`, with
  `status_since`). Record-only: status never changes findings or severity;
  it exists so ledgers, dashboards, and sweeps can segment
  archived-but-shipping components instead of misreading them as
  unremediated backlog. The container profile records the *source* repo's
  status as `source_repo_status`.
- `peach_isolation_review` is **always emitted**: `{"applicable": false,
  "rationale": …}` for single-tenant components; full `interfaces[]` when
  multi-tenant. `peach_references` on findings only when applicable.
- `category` uses the shared kebab-case vocabulary above.
- `metadata.loc_breakdown` expected on all new reports.

### `rpm` — secure-rpm-audit (dist-git packaging audits)

- `metadata.audit_profile: "rpm"`.
- `metadata.additional.deterministic_steps` keys: `sbom-grype`, `yara`,
  `crypto-audit`.
- `metadata.repository` is the dist-git URL; record upstream `Source0`, spec
  `Version`/`Release`, and applied patches under `metadata.additional`.
- `metadata.ref` = the dist-git stream audited (e.g. `c10s`) with
  `metadata.ref_kind: "stream"` — never `"branch"`, which would misclassify
  the report as a branch re-audit and drop it from the census HEAD cuts.
  Reports land under `analysis-results/findings/<stream>/<component>/`, the
  stream playing the product role.
- `category` uses the packaging taxonomy `RPM01`–`RPM10` (e.g.
  `RPM02: Privileged File Modes & Capabilities`).
- Slug quirk: component names starting with a digit take an `RPM_` prefix
  (`389-ds-base` → `RPM_389_DS_BASE`) because the ID regex anchors on `[A-Z]`.
- `locations[].path` is the dist-git file (spec, patch, tekton) or a path in
  the prepared source tree.
- No `peach_isolation_review` (packaging repos are not tenant boundaries).

### `container` — secure-container-audit (registry image audits)

- `metadata.audit_profile: "container"`.
- `metadata.additional.deterministic_steps` keys: `k8s-hardening`,
  `priv-profile`, `yara`.
- `metadata.repository` is the full image reference **pinned by digest**
  (`<registry>/<namespace>/<image>@sha256:…`); the tag audited, source-repo
  labels (`vcs-url`, `vcs-ref`), and base image go under `metadata.additional`.
- `metadata.commit` carries the **manifest digest hex** (the 64 hex chars
  after `sha256:`) — the image analog of a git SHA. Finding-ID `SHORTSHA` =
  its first 7 chars, which satisfies the existing ID regex and the validator's
  SHORTSHA↔commit cross-check unchanged.
- `metadata.tools` must record `skopeo`/`syft`/`grype` versions **and the
  grype vulnerability-DB build date** — CVE results are only reproducible
  against a stated DB state.
- `locations[].path` is a package URL (`pkg:golang/…`, `pkg:rpm/…`) for
  dependency findings, or an image pseudo-path (`oci-config:User`,
  `oci-config:Env`, `layer:<sha256:…>`) for image-configuration findings.
- `category` uses the shared kebab-case vocabulary (typically `supply-chain`,
  `insecure-workload-config`, `secrets-management`, `data-exposure`).
- `dependency_audit` is **required in practice**: every grype match lands
  there (`package`, `version`, `status`, `notes` with fixed-in version); only
  reachable/shipping vulnerabilities are promoted to findings.
- No `metadata.loc_breakdown` (no source is measured); record SBOM package
  counts under `metadata.additional.sbom_packages` instead.
- `peach_isolation_review` is still always emitted (the validator requires it
  from harness 0.15.0): normally `{"applicable": false, "rationale":
  "image-level audit; tenant-isolation review lives in the source repo's
  code-profile report"}` with a pointer to that report.

## After writing a report

1. Validate: python3 -m traust.cli reporting validate <report.json> — 0
   errors required.
2. Fingerprint: python3 -m traust.cli corpus finding-identity fingerprint <report.json> --write
   (deterministic; safe — fingerprints are outside the claim-hash fields).
3. On a full re-audit of an already-audited repo:
   python3 -m traust.cli corpus finding-identity rebaseline <old.json> <new.json> <layer.json>
   so the disposition ledger's history transfers (fingerprint matches auto-map;
   looser matches queue for human confirmation; unmatched old findings queue as
   needs_review — never silently dropped). Rebaseline also migrates the layer's
   claim-hash pins to the new baseline (superseded old ids with an alias or a
   queued decision are unpinned; run
   `harnessing/4-triage/track-findings/scripts/baseline_claims.py record`
   afterwards to pin the new report's claims) and repoints
   `metadata.audit_commit`.
