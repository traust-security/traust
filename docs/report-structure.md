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

## Historical signature validation

`python3 -m traust.cli reporting validate <path> --signing-pubkey <cosign.pub>`
additionally verifies historical `*-findings-layer.json` documents against
their stored Merkle roots and public-key signatures. For other filenames,
name the contract with `--schema layer`. This is a read-only compatibility
check, not a new layer writer or a signature over an ordinary audit report.
Directory sweeps still validate other report families normally.

The full contract schema remains required. Explicit verification fails with
a nonzero status for changed event content, an invalid root, a wrong,
missing or malformed public key, a missing or malformed signature, or an
unavailable cosign verifier. Omitting `--signing-pubkey` preserves ordinary
schema/content validation and does not require signatures on unsigned
historical documents. Legacy signature formats retain the verifier's
warnings; an event-ID-only Merkle tree does not establish content integrity.
No report or layer bytes are rewritten.

## Required top-level keys

| Key | Description |
|---|---|
| `title` | Report title. Must contain a security-related keyword: security, audit, assessment, review, finding, or analysis. |
| `metadata` | Object with required `date` (YYYY-MM-DD, the **audit execution date** — never a commit or CVE date) and `scope` (≥10 chars). Optional: `repository`, `commit`, `ref` + `ref_kind` (`branch` \| `tag` \| `default` \| `stream` — explicit ref provenance; stamp both together on code/rpm profiles, omit on container and for detached-SHA inputs; `stream` is the rpm profile's dist-git release stream, a mainline deliverable that is never a branch re-audit), `framework`, `auditor`, `methodology`, `tools` (array), `loc_reviewed` (integer preferred), `loc_breakdown`, `audit_profile` (`code` \| `rpm` \| `container` — set it; see deltas), `additional` (object). **Must include** `additional.harness_version` — the semver from the harness `VERSION` file plus the short git SHA (e.g., `0.51.0-370e5a2`); it records producer provenance, not finding admission or a requirement to stamp finding identity. `additional.contracts_version` records the contracts package version the report was validated against. The schema does not allow `harness_version` as a direct `metadata` key; it lives under `metadata.additional`, which is where the validator reads it for version-gated checks. Routed model decisions are stamped as `metadata.additional.model_routing` (`{role, model, registry_sha, floor}`, emitted via python3 -m traust.cli registry models stamp — alignment rule A12; see [model-routing.md](model-routing.md)). |
| `executive_summary` | Object with `prose` (≥50 chars) and `severity_counts` (required `critical`, `high`, `medium`, `low`, `informational` integer counts). Optional: `key_risks`, `positive_observations`. |
| `severity_criteria` | Array of ≥4 entries, each with `level` (critical/high/medium/low/informational) and `definition` (≥20 chars). Must include at least critical, high, medium, low. |
| `findings` | Array of finding objects (below). |
| `findings_summary` | Array of ≥4 severity count entries (`severity`, `count`, `finding_ids`) — counts and IDs must match the findings. |
| `remediation_roadmap` | Array of ≥1 items with required explicitly authored `priority`, `action` ≥10 chars, and `addresses` finding-ID array. Optional `effort` and independent `blocked_external`; see [Remediation authoring](#remediation-authoring). |

## Finding object fields

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Globally-unique **scan-scoped** ID `{REPO_SLUG}-{SHORTSHA}-{NNN}`. Provenance to an exact commit; unique across the corpus. Never reuse across scans. |
| `fingerprint` | No (historical report field) | **Cross-scan identity** is computed by Core's supported finding intake from the canonical repo URL, sorted lineless location paths and primary CWE — never model-authored. Canonical secure-code/container/RPM recording admits findings and computes their stored identity; it never stamps this report field. Historical report fingerprints remain readable, but are not an admission receipt or a reason to revive report stamping or layer-based alias writers. |
| `title` | Yes | Short description (≥5 chars). |
| `kind` | No | Explicit finding classification from the installed [finding-kind vocabulary](https://github.com/traust-security/traust-contracts/blob/development/enums/v1/finding-kind.json). Use it to distinguish a vulnerability from a defense-in-depth weakness; omission remains unknown. Kind is not a validity answer or evidence grade. Core intake preserves it for a new finding without reclassifying an existing one. |
| `severity` | Yes | `critical` \| `high` \| `medium` \| `low` \| `informational`. |
| `kind` | No | Finding classification, independent of validity or proof. Use `weakness` for an explicitly established hardening classification; do not infer a validity answer from it. |
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
| `remediation_effort` | No | New findings: `xs` \| `s` \| `m` \| `l` \| `xl`, or `null` for unknown size, from traust-contracts `enums/v1/effort.json`. Omission also leaves size unknown. Historical effort labels remain readable, not valid choices for new authorship; see [Remediation authoring](#remediation-authoring). |
| `blocked_external` | No | Independent boolean: an external dependency blocks remediation (`true`) or is affirmatively known not to (`false`). Omit when unknown; absence is not `false`, and neither value establishes size or priority. |
| `validation_status` | No | Optional, non-null validity assertion. Omit when no validity answer has been authored; explicit new values must pass Core's installed [contracts validity registry](https://github.com/traust-security/traust-contracts/blob/development/enums/v1/validity.json). Historical reads retain compatibility; see [Validity authoring](#validity-authoring). |
| `disposition` | No | Present only on cumulative reports (`*-findings-current.json`): both disposition axes, conflict and awaiting-signoff flags, and event history, derived from the ledger. Never authored in a baseline. |
| `effective_severity` | No | Present only on cumulative reports: equals a human severity override from the ledger when one exists, else the original severity. The original `severity` is never rewritten. |
| `source_findings` | No | Source scanner finding IDs / provenance refs (for routed findings: the producer's own id — e.g. a `REG-*` regression id — plus the producing report's path). |
| `origin` | No | Historical/provider report provenance tag: `verify-remediation` \| `vuln-scan` \| `create-fuzzing` \| `validate-findings` \| `validation-discovery` \| `impact-analysis`. It remains readable in raw artifacts; Core source attribution comes from the first reporting assessment, not a candidate-field or CLI override. |

## Optional top-level keys

| Key | Description |
|---|---|
| `dependency_audit` | `prose` + `entries[]` (`package`, `version`, `status`, `notes`). |
| `negative_results` | Areas verified clean: `area`, `result`, optional `files`. |
| `asvs_coverage` | ASVS chapter coverage entries. |
| `review_surface_coverage` | One entry per review surface (the `review_surface` enum in traust-contracts), each with a status from `review_surface_status`; required on `code`-profile audits from traust 0.20.0 and `rpm`-profile audits from 0.21.0, and its `llm-integration` entry on audits dated from 2026-11-02 — see deltas. In a `*-findings-current.json` it is the audit's record merged with later scans' records ([review-surfaces.md](../harnessing/3-audit/secure-code-audit/review-surfaces.md#scans-that-follow-an-audit)). |
| `scanner_correlation` | Scanner tool results, including the judge decisions the rule-mining lane consumes. |
| `peach_isolation_review` | Always emitted on `code` and `container` profiles — see deltas. |
| `disposition_summary` | Cumulative reports only: counts per validity and resolution state, derived from the ledger. |
| `footer` | Free-text footer. |

## Validity authoring

These rules apply to new findings in the ordinary audit/report schema,
which exposes optional, non-null `validation_status`. **An unjudged
finding omits that field** — do not emit `null`, a legacy unknown marker,
or a blanket confirmation. Static evidence, scanner matches, confidence
scores, and report inclusion alone do not author a validity answer.

The installed traust-contracts validity registry owns the accepted vocabulary;
Core's report record service enforces it for explicit new assertions. Only carry an
explicit canonical assertion when its supporting execution evidence or
attributed reviewer determination actually exists and is referenced in the
finding's existing evidence/provenance fields. Do not create a local enum
mirror or infer a judgment from a tool/source label. Later judgments belong
to Core's existing authenticated decision doors, not baseline-file edits.

`corrected` describes a revision, not a validity answer. Preserve correction
rationale, evidence, and revision context in existing description, notes, and
provenance fields where the artifact supports them; do not turn them into a
status. Already stored claims use the existing authenticated restatement
workflow rather than an in-place rewrite. An explicitly known hardening
classification uses `kind: weakness`, independent of validity; when no
validity answer exists, still omit `validation_status`.

The base report schema remains historical-compatible, and historical reads,
cumulative projections, and exact stored-run replay keep their existing
semantics. Acceptance by that schema or a compatibility reader is not
permission to emit deprecated validity in a new report. Do not rewrite old
reports to satisfy new-authoring rules. The separate `vuln-findings`
finding schema and verification schema's `$defs/regression` have **no
`validation_status` property** and reject undeclared fields. Never add
that field to either source artifact, even for a supported canonical
judgment; subsequent judgments use Core's existing decision doors.
Triage artifact verdicts are a separate contract and are unchanged by
these rules.

## Severity authoring

A finding's `severity` is the band of a score, never a judgment. These rules
apply to new reports; historical reports are not rewritten.

- **The CVSS calculator computes every score and band.** You write a
  vector's metrics; never a score or a band. Before validating a report, run
  `python3 -m traust.cli reporting rate-cvss <report>`: it fills each
  finding's `cvss.score` and `severity` from its `cvss.vector` with
  traust-core's CVSS calculator (the `cvss` library, FIRST's 3.x and 4.0
  formulas), and `--check` reports any disagreement. `--vector "<vector>"`
  scores one vector. A vector you authored that it refuses is malformed:
  fix the metrics. An advisory's vector is copied, never fixed: when the
  selected authority states only a CVSS v2 vector, or none the calculator
  scores, the finding files at `medium` with no `cvss`, and the description
  quotes the published score and says the advisory is unscored in 3.x/4.0.
- **Every finding not backed by an advisory** (first-party code, image
  configuration, spec construct, IaC): `severity` is the calculator's band
  for the Base vector in the finding's `cvss`. A 0.0 score is not a
  vulnerability finding. Base metrics describe
  the vulnerability in the code. Deployment context, a control that lives
  elsewhere, and a chain step you could not show never lower them; name those
  in the description. An unscored posture or hygiene observation is
  `informational` and carries no `cvss`.
- **Advisory-backed finding** (a published CVE, GHSA or other OSV advisory
  matched to a dependency, package or image, including advisory-lag in a
  repository's own forked or vendored upstream code): `cvss.vector` is the
  advisory's selected authority vector, copied from the tool output, and
  `rate-cvss` computes its score and band. D2: for a Red Hat product, the selected score is Red Hat's CVSS
  for that product when Red Hat publishes one. A Red Hat product is one whose
  Core product record declares Red Hat CSAF product identifiers; never guess
  it from a name. Until Core keeps Red Hat's score per product, the normal
  order applies. Otherwise the order is NIST (NVD
  Primary), GitHub (GHSA), the CVE's CNA, ADP, Red Hat, then the scanner. A
  3.x score comes before 4.0; 4.0 is used only when no source has 3.x. Red
  Hat's severity word (Important, Moderate) is never a score. Quote every
  authority's score you have, with its source, in the description. An
  advisory that no source scores, the scanner included, files at `medium`
  with the description saying it is unscored.
- **Stated exceptions, pending an owner decision:** the severity floors
  (verification-disable and credential-transport findings at least `high`)
  and RPM06's mandated severities (a digest mismatch Critical, an unlisted
  tarball High) set severity by rule. Until the owner decides, those findings
  keep the floor, and the description names it as the reason the label
  differs from the calculator's band.
- **The audit never changes a severity.** Reachability, deployment context,
  restricted SCCs, a compensating control elsewhere, a required prior
  compromise or plain uncertainty never lower it. A Precision Gate decides
  only whether a candidate is filed: with affirmative evidence it moves to
  `dependency_audit` or `negative_results`; otherwise the finding is filed at
  its band, with the open question named in the description for `/triage`.
- **Who changes it later:** only `/impact-analysis`, `/triage` and live
  validation (`/validate-findings` and its siblings), through Core's decision
  doors, never by editing the report, and only on evidence. For an
  advisory-backed finding, evidence is a recorded artifact bound to the
  finding, its commit and its dependency version, or a code citation
  (`file:line` quoted from the checkout) that triage's citation lint
  verifies, bound to the same finding, commit, dependency version and
  environment. Inference is not evidence: uncited reasoning, vote counts,
  precondition counts, threat-model matches, deployment assumptions and
  prose. KEV and EPSS are exploitability inputs to ranking and the SLA; they
  never change a severity. The evidence decides the outcome:

  | Evidence | Outcome |
  |---|---|
  | `classification: version_not_in_range` or `not_imported`, or `not_observed` with `evidence_level: symbol` (govulncheck: the vulnerable symbol is unreachable); a vendor not-affected statement; a shipped NVR at or past the fixed NVR | not affected. In an audit, a `not_affected` entry; in triage, `false_positive` with `refute_reasons: ["bound_evidence"]` citing the artifact (triage's verdicts have no `not_affected` yet) |
  | Code citations showing a precondition or control that changes how the vulnerability can be exploited here | triage proposes a CVSS Environmental vector, each modified metric citing its evidence, in the rationale. The severity changes only when Core scores that vector with the CVSS calculator and admits the decision (remediation plan step 7); until then the band stands |
  | A live-validation result | the validation's verdict, at the band of the vector it records |

  An audit applies the first row itself, recording the match as not
  affected (see the next section); the code-citation and validation rows
  belong to triage and live validation. Symbol-usage or manifest-level
  `not_observed`, `likely_affected` and `inconclusive` are not evidence for
  any of these. Nothing raises a severity above its score's band either.
  The report's `severity` is never rewritten.

  A finding nobody disproves keeps its published band. When triage or live
  validation can't disprove it (a tool limit, no coverage, a split), the
  finding goes to a person through Core's review queue; it is never invalid
  by default.

## Dependency and advisory findings: affected or not affected

A scanner-matched CVE is either **not affected** (validity `not_affected`: the
issue exists but doesn't apply to this repository, version or deployment), on
the impact-analysis or vendor evidence below, and recorded as such with its
rationale; or it is **filed as a finding** at its published score and stays
until `/triage` or live validation disproves it (see the evidence table in
[Severity authoring](#severity-authoring)), or a person decides. Names below
are traust-contracts' own: the `finding.dependency` block, the
`impact-classification` and `dependency-evidence-level` enums.

1. **Where a match comes from.** An advisory match comes from a
   deterministic scanner: the OSV pre-scan, `sbom-grype`, govulncheck, or an
   image package list. Copy `advisory`, `module`, `ecosystem`,
   `installed_version`, `vulnerable_range`, `fixed_version` and scores from
   its output; never type them. A CVE you recall that no scanner matched
   goes in `dependency_audit` as a lead naming the missing scanner evidence.
   - **Correlate before filing:** matches with the same advisory (or alias),
     ecosystem, module and installed version are one match. File one
     finding, or one `not_affected` entry, citing every scanner's output.
   - **An installed version is required:** a candidate whose version isn't
     an installed version (OSV `version_basis: manifest-floor` or
     `resolved`) isn't a match yet. Record it in `dependency_audit` with a
     `coverage_gaps` entry naming the missing lockfile, SBOM or build. It
     becomes a match once a deterministic source establishes the installed
     version.
2. **Reachability: impact-analysis, single-commit mode.** For every match,
   run:

   ```bash
   python3 -m traust.cli impact sbom --repo-url <url> --sha <commit> [--branch <branch>]
   python3 -m traust.cli impact analyze <ADVISORY> --repo-url <url> --sha <commit> [--branch <branch>] --scan
   python3 -m traust.cli impact export <ADVISORY> --out <scratch-dir>/<advisory>-impact.json
   ```

   - `impact sbom` (no file argument) records the commit's manifest SBOM
     with its coverage, so Core holds the packages the analysis needs. Run
     it once per audited commit.
   - Read the export row for this repository, commit, ecosystem, module and
     installed version: its `classification` and `evidence`.
   - **A row counts only when its commit is the source the audited artifact
     ships:** the audited repository's commit, or an image's `vcs-ref`. A
     row for another commit, such as an RPM's upstream, is context only:
     downstream patches and bundled archives change what ships, so it never
     makes a match not affected.
   - **`impact analyze` writes to Core:** it records an impact assessment
     and, for an `affected` row, files Core's own dependency finding,
     identified by repository, advisory and package. Cite that finding id in
     the report finding's `source_findings`. Until Core's intake maps
     `finding.dependency` (remediation plan step 6), the same advisory and
     commit can appear under both ids.
   - The export is a scratch intermediate; never place it in the findings
     tree.
   - Record `deterministic_steps["impact-analysis"]` as `"ran: <n>
     advisories"`, or `"skipped: <reason>"` with a `coverage_gaps` entry.
3. **File by the evidence:**

   | Evidence | Outcome |
   |---|---|
   | `classification: version_not_in_range` or `not_imported` | **Not affected** |
   | `classification: not_observed` with `evidence_level: symbol` (govulncheck: the vulnerable symbol is unreachable) | **Not affected** |
   | A vendor not-affected statement for the shipped product, or a fixed NVR at or before the shipped NVR, in the tool data (grype's Red Hat security data, a VEX document impact-analysis recorded) | **Not affected** |
   | `classification: affected` | A finding at the published score, citing the row's evidence: its govulncheck trace when present, else what the row records (feature-pattern matches, for example) |
   | `classification: likely_affected` or `inconclusive`, or `not_observed` with `evidence_level` other than `symbol` | A finding at the published score, unverified |
   | Sources' ranges disagree for the installed version (a release-tag range against a Go-module range, for example) | A finding at the published score, unverified, citing both ranges |
   | No row (the run failed, the commit isn't the shipped source, or impact-analysis doesn't cover the ecosystem or surface) | A finding at the published score, unverified, with the gap named |

   Every filed advisory finding carries no validity answer (omit
   `validation_status`) and a `dependency` block. The block holds
   `advisory`, `module`, `ecosystem`, `installed_version`,
   `vulnerable_range` and `fixed_version`. When a row exists, it also holds
   the row's `classification`, `evidence_level` and an `impact_artifact`
   pointing at the row. When none exists, the description states the
   skipped or failed reason and the coverage gap. Test or dev scope and
   vendor data go in its description.
4. **Record every not-affected match** in the report's `not_affected`
   section: one entry each, with the same `dependency` block (its
   `classification` and `evidence_level` are the evidence), a `rationale`,
   and `reference` for a vendor statement. It is the paper trail that the
   CVE was identified and why it was eliminated; it isn't ingested as a
   finding. Until the installed contracts declare `not_affected`
   (traust-contracts#189), write each as a `dependency_audit` entry with
   `status: "not_affected"` and the same facts in `notes`.

Your own reading of the code ("unused", "dev-only", "not executed in this
image", "client-only symbol") is never evidence of non-applicability. It
goes in the finding's description for `/triage`.

## Remediation authoring

These rules apply to newly authored findings and roadmap items across all
three profiles and the audit reports produced for `/recall-benchmark`.
The installed traust-contracts report schema owns the vocabulary:
`$defs/canonical_finding` narrows finding effort; the findings and
`remediation_roadmap` subnodes of `$defs/canonical_write` narrow the
corresponding new-report fields. Historical full-schema validation and
stored-run replay remain unchanged; do not rewrite old reports or source
notes to make them look newly authored.

- **Size:** finding `remediation_effort` and roadmap `effort` use the
  same canonical effort scale above. If size is not explicitly established,
  use `null` when emitting the field, or omit the optional field. There are
  no defined duration thresholds or unconditional conversions from legacy
  effort labels. Existing prose, provenance, agility, pin counts, urgency,
  deadlines, severity, and external blocking do not establish size.
- **Priority:** every roadmap item requires an explicitly authored `p0`,
  `p1`, `p2`, `p3`, or `p4`, from traust-contracts
  `enums/v1/roadmap-priority.json` (`$defs/roadmap_priority` in the report
  schema). Preserve a supplied canonical priority. The labels are ordered;
  no severity, urgency, deadline, effort, or legacy-text mapping is defined.
  Never invent a default, use `null`, or omit the required priority. If an
  automated source cannot supply one, identify the source and intended
  consumer and obtain an explicit authoring decision before publishing.
- **Blocking:** assess `blocked_external` separately for each finding and
  roadmap item. Only emit a boolean supported by evidence; unknown blocking
  stays absent, not `false`. An unknown size can be externally blocked.
- **Reference data is producer input:** the PQC tagging pass reads
  [`pqc-readiness-decision-tree.json`](../harnessing/3-audit/pqc-readiness/notes/reference/pqc-readiness-decision-tree.json).
  Its effort rules return unknown size and only its explicit blocking rule
  establishes blocking; they supply no roadmap priority. Do not turn its
  readiness buckets or the IR8547 clocks into sizes or priorities.

Use `traust reporting record` for publication (below): Core owns admission
of newly recorded report fields. The compatibility validator and renderer
also read historical reports; their acceptance alone does not establish
that a new report is ready to record. Do not add a local vocabulary gate,
apply unrelated classifier policies, or recreate retired report writers.

## Profile deltas

### `code` — secure-code-audit (source/manifest audits)

- `metadata.audit_profile: "code"`.
- `metadata.additional.deterministic_steps` — an object recording the fate of
  every deterministic pre-scan so evidence quality is comparable across a
  batch. Keys: `k8s-hardening`, `opengrep`, `gitleaks`, `osv-scanner`,
  `sbom-grype`, `priv-profile`, `fork-advisory-lag`, `route-guards`,
  `config-matrix`, `impact-analysis`; value `"ran"` or `"skipped: <reason>"` (e.g.
  `"skipped: opengrep not on PATH"`, `"skipped: no local checkout"`). A
  skipped step means that section of the audit ran on manual review alone —
  downstream consumers (`/mine-ledger` precision, `/verify-remediation`) must
  not read absence of scanner facts as "scanner found nothing". The other
  profiles record their own step keys under the same object (see below).
- `metadata.additional.precision_gates` — the Precision Gate pass record, on
  all four scanning skills: `crit_high_evaluated` counts every critical/high
  candidate (filed or gated) and `fired[]` lists each gate that changed a
  candidate's disposition
  (`{candidate, gate, action}`). New reports use `negative_results` or
  `dependency_audit`: a gate never changes severity
  ([Severity authoring](#severity-authoring)); `downgraded` stays readable in
  historical reports.
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
- `review_surface_coverage` is **always emitted** (required from traust
  0.20.0): one entry per review surface. `finding` entries name existing
  findings in `finding_ids`, `negative` entries have a `negative_results`
  entry whose `area` starts with the surface ID, and `not_assessed` entries
  have a `coverage_gaps` entry with `tool: "review-surfaces"`. The
  validator checks each against the report. `llm-integration` is required
  for audits dated from 2026-11-02: `not_applicable` citing the LLM
  pre-scan when it finds no LLM use.
- `peach_isolation_review` is **always emitted**: `{"applicable": false,
  "rationale": …}` for single-tenant components; full `interfaces[]` when
  multi-tenant. `peach_references` on findings only when applicable.
- `category` uses the shared kebab-case vocabulary above.
- `metadata.loc_breakdown` expected on all new reports.

### `rpm` — secure-rpm-audit (dist-git packaging audits)

- `metadata.audit_profile: "rpm"`.
- `metadata.additional.deterministic_steps` keys: `sbom-grype`, `yara`,
  `crypto-audit`, `impact-analysis`.
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
- `review_surface_coverage` is **always emitted** (required from traust
  0.21.0), with the same evidence rules as the `code` profile.

### `container` — secure-container-audit (registry image audits)

- `metadata.audit_profile: "container"`.
- `metadata.additional.deterministic_steps` keys: `k8s-hardening`,
  `priv-profile`, `yara`, `impact-analysis`.
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
2. Record the report through `python3 -m traust.cli reporting record
   <report.json> --kind <kind> --repo-url <https source repository URL>
   --sha <audited source commit> [--branch <audited branch>]`.
   Use `secure_code`, `rpm`, or `container` for the corresponding audit
   skill; `/recall-benchmark` records public real-target reports as
   `benchmark_audit` with `--public`. Follow each skill's provenance
   instructions (container source labels identify its source commit).
   A new report is not published until Core accepts the record. An
   admission error is not a reason to guess a size or priority.
   Finding admission depends on the kind: canonical `secure_code`,
   `container` and `rpm` reports admit their findings atomically with
   recording. Use their returned assessment ID with `triage prepare` for
   native findings and any matching precedents; no separate intake receipt is
   required. Canonical `vuln_scan` documents likewise admit their findings when
   recorded. `benchmark_audit` reports are scored, not admitted. Plan 15's
   decision 5 may change whether `secure_code` recording admits findings.
   After admission, `findings find <report.json> --label <report-local-id>
   --repo-url <audited-source-url>` is an optional report-label diagnostic:
   exit 0 with `finding_id: null` means no match, not a completed identity check.
   An empty batch is not evidence of a clean audit. Do not invent an intake
   command, convert or rewrite the audit to imply admission, or stamp a
   caller-generated identity.
3. Preserve historical reports and raw notes. A re-audit is a new report
   and assessment, not a rewrite of the old report. Use the current Core
   finding doors for later decisions; the former layer emitters and
   cumulative-report rebuild are retired and must not be recreated.
