# End-to-End Process

This document describes the full workflow used to perform AI-assisted
security assessments across a portfolio of components, from repository
discovery through triage, validation, remediation, and defect filing —
and the standing loop that keeps it all current.

For a map of all documentation organised by audience, see **[docs/README.md](docs/README.md)**.

The stage numbering here is **the** campaign numbering — README.md's
pipeline diagram, docs/skills.md's Stage column, and this page all use
the same ①–⑨ (the 2026-07-31 docs-verification found three
incompatible schemes; this page was the worst offender, documenting
the retired pre-ledger campaign). Current campaign numbers are never
quoted here — they live in the dashboards
(`/census` for the population authority,
`progress-tracker/metrics/dashboards/` for the rest).

---

## Overview

```
  Inputs ─▶ ① Inventory ─▶ ② Threat model ─▶ ③ Audit ─▶ ④ Triage ─┬─▶ ⑧ Package ─▶ ⑨ Assign ─▶ Share/Notify ─▶ File defects
 (inputs)                                    (analysis-results)    │   (progress-tracker → Drive, Slack, Jira)
                                                                   ├─▶ ⑤ Live validation  (validate-* / deploy-operator)
                                                                   ├─▶ ⑥ Fuzzing          (create-fuzzing)
                                                                   └─▶ ⑦ Remediation      (remediate-finding / patch / verify)

  Stages ③–⑦ feed the append-only disposition ledger (track-findings), gated by human countersign;
  follow-up scans (vuln-scan, verify-remediation regressions, dependency-watch) enter it directly.

  Standing loop (daily, after the first pass — docs/continuous-operations.md):
  fleet refresh ─▶ router ─▶ lanes: diff-scan │ deps (/dependency-watch) │ IaC │ verify treadmill │ rule mining (/mine-ledger)
                              └─ findings re-enter ④ Triage / the ledger; dashboards & drift-watch rebuild on cadence
```

Each stage uses skills from this repository and produces artifacts that
feed the next; the disposition ledger and the metrics spine run across
all of them.

> **Model routing & spend:** every stage's model comes from
> `config/model-registry.yaml` and spend lands on the spend dashboard —
> see [docs/model-routing.md](docs/model-routing.md).

---

## Stage 1 — Repository Inventory

**Skill:** ``inventory-repositories`` (internal extension repo) (automated discovery) · [`add-inputs`](.claude/skills/add-inputs/SKILL.md) (ad-hoc registration)

Discover every source code repository belonging to each product segment
in the Hybrid Platforms portfolio: OpenShift release payloads, OLM
operator bundles, and managed services.

For repos or whole orgs outside those discovery paths, `add-inputs`
appends them (plus `owners.csv` rows) to a segment CSV directly —
default segment `adhoc/`. When the addition is a new scan engagement,
`corpus-intake` registers the matching *output* tree in
`$TRAUST_CONFIG_HOME/corpus-config.yaml` and records the inventory path, linking the
two sides. The full sequence — both registrations, census confirmation,
repo-graph rebuild — is a deployment procedure; each step is its own skill
(`/add-inputs`, `/corpus-intake`, `/census`, `/repo-graph`).

**Output:** CSV inventories, Markdown analysis reports, and `owners.csv`
files pushed to the **inventory repository** (see Repository Map).

---

## Stage 2 — Threat Model

**Skill:** [`threat-model`](.claude/skills/threat-model/SKILL.md)

Build the target's threat model before (or alongside) its first audit —
the map of what could go wrong independent of any specific bug.
`bootstrap` derives one from code plus past vulnerabilities; `interview`
walks an application owner through the four-question framework;
maintenance modes (`review`/`update`/`pr`) keep it current as the code
moves. The emitted `<repo>-threat-model.md` is copied into the
findings tree (`analysis-results/findings/<product>/<repo>/`) by
contract — that copy is what ③ Audit's coverage diff, `/vuln-scan`,
`/triage`, and `/threat-register` consume.

---

## Stage 3 — Security Audit

**Skill:** [`secure-code-audit`](.claude/skills/secure-code-audit/SKILL.md) · profile variants [`secure-rpm-audit`](.claude/skills/secure-rpm-audit/SKILL.md), [`secure-container-audit`](.claude/skills/secure-container-audit/SKILL.md), [`cloud-config-audit`](.claude/skills/cloud-config-audit/SKILL.md), [`vuln-scan`](.claude/skills/vuln-scan/SKILL.md) (supplement/diff scans)

Run multi-framework security audits against the inventoried
repositories. Each repository is assessed against **eight**
industry-standard frameworks: OWASP ASVS v5.0, OWASP Kubernetes Top 10
(2025), CIS Kubernetes Benchmark v2.0, DISA STIG V2R6, SLSA v1.2,
OpenSSF Scorecard, the SEI CERT coding standards
(language-conditional), and the PEACH tenant-isolation framework.
Dual-pass execution is the campaign default; deterministic pre-scans
(opengrep, gitleaks, osv-scanner, syft/grype, checkov, k8s-hardening)
seed both passes and are recorded under `deterministic_steps`.

Batch orchestration is driven by the continuous-operations router's
worklist and the findings manifest
(`analysis-results/findings/_manifest/`) — there is no fixed
parallel-agent width; the manifest system handles deduplication (one
canonical report per repo+ref, symlinks from sibling product
directories).

**Output:** schema-validated JSON reports (`<repo>-security-audit.json`,
with rendered Markdown companions via python3 -m traust.cli reporting render —
auditors never hand-write the Markdown) pushed to the **results
repository** (see Repository Map).

---

## Stage 4 — Triage

**Skill:** [`triage`](.claude/skills/triage/SKILL.md)

Adversarially verify every audit finding: N-vote verification with
cited evidence, duplicate collapse, derived-exploitability re-ranking,
and owner tagging. Verdicts land as `<repo>-triage.{json,md}` next to
the audit report and flow into the disposition ledger automatically
(Phase 6e → python3 -m traust.cli ledger emit-triage): true positives
become machine-`confirmed` events, false positives enter the tiered
countersign flow, hardening findings take the `hardening` validity.
The full contract: [docs/disposition-ledger.md](docs/disposition-ledger.md) §6b.

---

## Stage 5 — Live Validation

**Skills:** ``validate-operator-live`` (internal extension repo) (orchestration) → ``deploy-operator`` (internal extension repo) + [`validate-findings`](.claude/skills/validate-findings/SKILL.md) · [`validate-browser-finding`](harnessing/5-validate/validate-browser-finding/SKILL.md) (web UI vulns) · ``validate-core-ocp`` (internal extension repo)

Prove or refute audit findings against an **authorized live
environment**, then chain confirmed findings into multi-step
kill-chains and hunt for novel attacks the static analysis missed. For
OLM-layered operators the campaign runs on disposable ephemeral ROSA
HCP clusters (`provision_rosa.sh`, always torn down); for
browser-exploitable web vulnerabilities, `validate-browser-finding`
drives Playwright against lab targets.

The campaign manifest lives at `analysis-results/validations/_manifest/`
(`validation-manifest.csv` + `next_pending_validation.py` +
`update_validation_progress.py`; product resolution via
the internal extension's deploy-operator product map). Every verdict passes the
fail-closed gate stack in
[docs/validation-process.md](docs/validation-process.md); results emit
`<slug>-validation.{json,md}` + `validation-audit.jsonl` and enter the
ledger via python3 -m traust.cli ledger emit-validation (execution-graded
evidence — E0/E1 carries class-1 override power).

---

## Stage 6 — Fuzzing

**Skill:** [`create-fuzzing`](.claude/skills/create-fuzzing/SKILL.md)

Offline fuzz harnesses for parser/decoder/templater entry points
flagged in audit reports — Go-native by default, plus Python, JS/TS,
Rust, and Java templates. The refuted register is a standing input:
FP-dismissed findings in fuzzable classes are priority targets
(falsifiability discipline — see
[docs/disposition-ledger.md](docs/disposition-ledger.md) §6). Crashers
triage into follow-up findings through the same pipeline.

---

## Stage 7 — Remediation & Verification

**Skills:** [`remediate-finding`](.claude/skills/remediate-finding/SKILL.md) (fork-flow patches with the repo's own checks) · [`patch`](.claude/skills/patch/SKILL.md) (inert candidate diffs for human review) · [`fleet-fix`](.claude/skills/fleet-fix/SKILL.md) (one transform × N repos) · [`verify-remediation`](.claude/skills/verify-remediation/SKILL.md)

Produce fixes and verify them. `/patch` writes an inert human-review
packet (terminal by design — no auto-apply path exists);
`/remediate-finding` builds reviewable patches on private forks and
runs the repo's own build/test suite in containment;
`/verify-remediation` re-audits each original finding against the
patched code (single repo, or the weekly full-sweep treadmill) and its
verdicts resolve ledger entries via `/track-findings`.

**What a patch here has been proven to do depends on how it got here.**
`/patch`'s executable ladder — build → reproduce → regress → re-attack —
runs only in execution-verified mode, which needs `vuln-pipeline` input.
On the static path (audit, triage or `/vuln-scan` input) the strongest
executable evidence is the fact differential: the backing scanner, re-run
on a scratch worktree with the diff applied, no longer fires — pattern-level,
and only for scanner-backed findings. `/verify-remediation` is a re-audit,
so it is analysis rather than execution. None of this makes a patch
untrustworthy; it means "patched" and "proven" are different claims. The
per-path ceilings are tabulated in
[docs/disposition-ledger.md](docs/disposition-ledger.md) §8a.

---

## Stage 8 — Team Report Packaging

**Skill:** [`generate-team-report`](.claude/skills/generate-team-report/SKILL.md)

Generate self-contained report packages for each operator, product, or
service — the relevant component-level reports bundled with an
executive-summary HTML dashboard.

**Output:** findings folders under `processed-results/` in the
**tracker repository** (see Repository Map).

---

## Stage 9 — Assign Findings Owners

**Skill:** ``assign-findings-owners`` (internal extension repo)

For each findings package, identify two Red Hat lead developer owners
who will receive the findings and delegate remediation. The skill
resolves owners through a chain of data sources:

1. Product Security product registry (python3 -m traust.cli registry products)
   — non-authoritative context resolved first: Kerberos-ID candidate
   seeds, the accountable escalation contact, and the product lifecycle
   window, so an EOL or unreleased product is caught before the rest of
   the chain runs. Never names an owner.
2. `owners.csv` files from the inventory stage
3. Org repo team structures (`org/config/structures/` YAML)
4. OpenShift CI `OWNERS` files
5. Corporate directory identity verification (LDAP; see
   `HARNESS_LDAP_SERVER`)
6. Git commit email resolution as fallback

Confirmed assignments are recorded in
`progress-tracker/owners-mapping.md` and
`progress-tracker/tracking/routed-results.md`. Ownership changes after
initial routing go through
``reassign-findings-owners`` (internal extension repo),
which re-verifies via LDAP, re-resolves registry context, maintains the
`Escalation` column, and updates Drive permissions. Escalation contacts
receive the findings folder as commenters unless LDAP marks them
contingent (2026-07-30 decision), and never hold an owner slot.

---

## Delivery (after ⑨) — Share, Notify, File

**Google Drive.** The team's Shared Drive (id in the deployment's sharing config) carries
a copy of every findings folder from `processed-results/`, shared with
its assigned owners via `progress-tracker/scripts/drive/share_results.py`
(`commenter` grants, OAuth desktop-app credentials). Sharing plans are
YAML configs under `progress-tracker/configs/` (per-campaign files —
see that directory; escalation contacts share through
`configs/escalation-contacts-share.yaml`); folder IDs come from
`progress-tracker/tracking/drive-sharing-plan.md`, recipients from
`tracking/routed-results.md`.

```bash
python share_results.py --config configs/<campaign>.yaml --dry-run   # preview
python share_results.py --config configs/<campaign>.yaml             # share for real
```

**Slack.** Once Drive access is granted, each owner receives a DM via
the **Chai bot** directing them to their findings folder and the
engineering process document.

**Jira.** For each Critical (and optionally High) finding,
``file-security-defect`` (internal extension repo)
creates an embargoed Jira defect (finding data extracted from the audit
report, owning team/project resolved from `org/config/structures/`,
Security Level "Embargoed Security Issue"). Filed defects are tracked
in `progress-tracker/tracking/opened-tickets.md`.

---

## The Disposition Ledger & Countersign (cross-stage)

Everything from ③ on feeds one append-only evidence stream per repo
(`<repo>-findings-layer.json`), merged deterministically into
`<repo>-findings-current.{json,md}` by
[`track-findings`](.claude/skills/track-findings/SKILL.md). Machine
refutations pend until an LDAP-verified human signs them at the
[`countersign`](.claude/skills/countersign/SKILL.md) workbench
(two-person rule against execution proof; salted audit valve on the
auto-accept tier); every false positive enters a refuted register that
feeds ⑥ Fuzzing and ⑤ Live-validation target selection. Design
rationale: [docs/disposition-ledger.md](docs/disposition-ledger.md);
artifact chain: [docs/artifacts.md](docs/artifacts.md);
error doctrine: [docs/error-model.md](docs/error-model.md).

## Continuous Operation (cross-stage) — when stages re-run

The stages above describe one pass. After the initial baseline, **rescan
frequency is decided deterministically by the continuous-operations
router** (python3 -m traust.cli build rescan-worklist
→ `analysis-results/findings/_manifest/rescan-worklist.json`), not by a
calendar: heavy or security-sensitive code churn and injected events
(external reports, methodology releases, CVE reachability, artifact
releases) route repos back into ③ as full audits or
`/vuln-scan --diff` scans; age ceilings backstop slow drift; `/drift-watch`
flags a worklist older than 3 days. The full loop — lanes, cadences,
arrival-channel coverage, and budget knobs — is documented in
[docs/continuous-operations.md](docs/continuous-operations.md).
Dashboards rebuild on cadence via
[`refresh-dashboards`](.claude/skills/refresh-dashboards/SKILL.md).

## Metrics & Reporting Layer (cross-stage)

Every campaign number flows through one consistency spine
(`progress-tracker/plans/metrics-improvement-plan.md`):

- **`$TRAUST_CONFIG_HOME/corpus-config.yaml`** registers every output tree with an
  ownership tag — `owned` (`findings/`, Hybrid Platforms), `upstream`
  (`oss-findings/`, community code HP depends on; reported adjacent,
  never folded into the owned headline), `external-bu` (scan engagements
  for other business units; work-performed only). Updated only via
  `/corpus-intake`.
- **python3 -m traust.cli corpus** is the one implementation of report discovery,
  identity (branch-ref stripping, symlink aliasing), and dedup that every
  dashboard builder uses; **`/census`** publishes the resolved population,
  the five duplication vectors, repo liveness, and the
  **distinct-vulnerabilities** headline as the denominator authority
  (findings.db `repos`).
- **Three-lens taxonomy** — every reported number carries a lens: Lens 1
  work performed (occurrences/throughput; a defect shipped in N products
  counts N times), Lens 2 distinct exposure (unique finding fingerprints
  at HEAD, disposition-adjusted — the canonical headline), Lens 3
  systemic patterns (fleet leverage). Never average across lenses.
- **Ref semantics** (branch-awareness plan —
  `progress-tracker/plans/branch-awareness-plan.md`): a report's
  `metadata.ref`/`metadata.ref_kind` is the authoritative statement of
  the ref it was audited from; `__release-X.Y` slug suffixes are a
  legacy fallback only (corpus.py prefers declared refs and never
  extends the slug whitelist). The finding fingerprint stays
  branch-blind — that is what folds a release-branch confirmation into
  its HEAD finding — and Lens 2 stays HEAD-canonical: branch audits
  confirm shipped exposure, they never add headline units.
- Every generated dashboard embeds a **population block** (roots +
  ownership, unit, filters, denominator source) so any two headline
  numbers reconcile on paper.

## Repository Map

The process needs four repositories. Only the first is this one; the other
three hold output and are yours to create — on any forge, under any names.
They are checked out as siblings of the harness, and the names below are the
sibling directory names the tooling expects.

| Repository | Role in Process |
|---|---|
| `traust` | Skills, commands, and prompts that drive every stage |
| the inputs inventory (`locations.inputs`) | ① output — repository inventories and ownership data |
| `analysis-results` | ②–⑦ outputs — threat models, audit reports, triage, validations, ledgers |
| `progress-tracker` | ⑧–⑨ + delivery — packaged reports, owner assignments, sharing plans, filed defects, dashboards |
