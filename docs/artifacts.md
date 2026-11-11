# Artifacts — what each stage produces, where it lands, and what consumes it

This page maps legacy exchange artifacts and their intended consumers; it is
not a claim that every pipeline edge is implemented. Schemas supplied through
the pinned core dependency are the authority on artifact structure.
See [components.md](components.md) for current ownership and
[report-structure.md](report-structure.md) for fields.

The hub retired ledger emitters, findings routers and cumulative projection
builders. Those rows below describe historical or intended interfaces pending
their skill ports. Triage recording, bound machine-validation recording and the
human countersign workbench now use core and emit JSON receipts; they do not
regenerate legacy files or infer proof strength from the report kind.
Historical layer design is in [disposition-ledger.md](disposition-ledger.md)
and [findings-routing.md](findings-routing.md).

## The historical chain at a glance

```
 threat model (/threat-model)         -> the surface an audit checks itself against
   |
   v
 audit (/secure-code-audit, -rpm-, -container-) -> the baseline: claimed findings,
   |                                    canonical ids, severity, category
   v
 triage (/triage, N adversarial votes) -> verdicts: true_positive | hardening |
   |   citation gate, symbol index,      undetermined | false_positive | duplicate;
   |   verdict-evidence lint             derived severity, owner hint
   v
 execution evidence                   -> reproducing exploits, crashes, re-tested
   |   (/validate-findings,              fixes: class-1 evidence
   |    /create-fuzzing, /verify-remediation)
   v
 disposition ledger (/track-findings) -> append-only events; validity + resolution
   |                                    axes; countersign rules
   v
 findings-current, findings.db,       -> owner routing, SLA view, defect filing,
 dashboards                             trends, executive views
```

The historical chain preserves evidence provenance. Its diagram is not permission
to recreate retired file writers or treat unfinished service ports as available.

## Artifact and consumer map

Active core-backed recording and review rows are identified explicitly below;
other legacy producers/consumers remain intended interfaces pending their skill
ports. Read the owning skill's retirement notice; no retired emitter is active.

| Artifact | Schema | Produced by | Consumed by |
|---|---|---|---|
| `<repo>-threat-model.md` | linted by python3 -m traust.cli reporting lint (no JSON schema) | `/threat-model` | `/secure-code-audit` (coverage diff), `/vuln-scan` (focus areas), `/triage` (environment context), `/threat-register` |
| `<repo>-security-audit.json` — the **baseline** | `report.schema.json` | `/secure-code-audit`, `/secure-rpm-audit` | `/triage`, `/track-findings`, `/verify-remediation`, `/patch`, `/vuln-scan` (dedup), `/threat-model` bootstrap, `/create-fuzzing`, `/file-security-defect`, every dashboard via the corpus resolver |
| `<image>-container-audit.json` — a baseline for a registry image | `report.schema.json` | `/secure-container-audit` | `/track-findings`, `/verify-remediation`, dashboards |
| `<repo>-vuln-findings.json` — candidates, not a baseline | `vuln-findings.schema.json` | `/vuln-scan` | `/triage`, `/patch`; `traust reporting record` enters its findings in traust-core as findings of the scan's assessment |
| `<repo>-triage.json` | `triage.schema.json` | `/triage` | `/patch`; explicitly bound source evidence for `traust validation record`; `traust triage record` saves core decisions/review items consumed by `/track-findings` |
| `<repo>-validation.json` | `validation.schema.json` | `/validate-findings` (and extension validators) | `traust validation record` with explicit stored source bindings and run provenance; core canonical decisions/reviews feed `/track-findings`; `/validation-fuzz-dashboard` reads retained reports |
| `<rem_id>-remediation.json` | `remediation.schema.json` | `/remediate-finding` | Human review; `/verify-remediation` re-checks the fork or MR, not this JSON; the core remediation/verification skill port remains unfinished |
| `<repo>-remediation-verification.json` | `verification.schema.json` | `/verify-remediation` | `traust remediation verify-record` records it (`VerificationService.record`): each verdict a decision, `regressions[]` taken in once as findings of the patched commit |
| `<repo>-findings-layer.json` — legacy ledger | `layer.schema.json` | Historical `/track-findings` output | Historical cumulative/projection inputs only; current review reads core findings and attestation, never this file |
| `<repo>-findings-current.{json,md}` — historical derived output | `report.schema.json` | Retired cumulative replay | Retained owner-routing/report/dashboard inputs only; current finding state comes from core queries, not a file refresh |
| `PATCHES/` packet | — | `/patch` | **terminal by design**: a human-review packet; nothing consumes it automatically |
| Private `countersign-queue.md` / human answer / JSON receipt | Core `ReviewItemCase`, `RecordDecision` and review service models | `/track-findings` through `traust findings review-cases --output` / `record` / `apply` | Human reviews escaped cards and edits only the typed JSON answer block; apply records through core history/disposition/attestation, never imports workbench state; token/rationale-free write receipt |

The baseline-only boundary remains a guardrail, not an exception to core
ownership. New findings and decisions go through their domain record doors.
Legacy `findings-current` files are retained artifacts, not files the new
severity writer rebuilds or a second write target.

## Assessment artifacts beside the chain

| Artifact | Schema | Produced by | Consumed by |
|---|---|---|---|
| `<target>-cloud-config-audit.json` (+ its own findings-current) | `cloud-config-audit.schema.json`, `cloud-config-findings-current.schema.json` | `/cloud-config-audit` | `/track-findings`, `/verify-remediation`, SARIF export, dashboards |
| Native impact document (one commit/package/version) | `impact-analysis.schema.json` | `/impact-analysis` via Core exposure/assessment services | Core exposure reads and dependency finding intake for `affected` rows; never `route_impact_findings` or a `findings.db` write |
| `<advisory-id>-impact-analysis.json` | Core `ImpactExport` view; each `.repos[].document` retains a complete native `impact-analysis` document | `traust impact export <advisory-id> --out <path>` after `/impact-analysis` | `/triage`, `/patch`, dependency-exposure review and `traust remediation verify-sweep --impact-filter <path>`; every classification/evidence retained, verification scopes to affected/likely rows |
| `<slug>-pqc-facts.json`, `-pqc-readiness.json`, `-pqc-blockers.json` | `pqc-facts`, `pqc-readiness`, `pqc-blockers` schemas | Core produces and records native facts via `traust pqc prescan`; `/pqc-readiness` authors Layer 2, `traust pqc blockers` derives its remediation projection | `traust pqc prepare` for Layer-2 scoring, `/patch` (first-party blockers), the PQC rollup and dashboards; facts exports retain the native published payload |
| `<service>-isolation-review.{json,md}` | `isolation-review.schema.json` | `/isolation-review` | `/threat-model` tenant-boundary rows (`isolation_review_ref`), portfolio rollups |
| `compliance-assessment.{json,md}` | `compliance-assessment.schema.json` | `/compliance-check` | the compliance dashboard |
| fleet-fix transform records | `fleet-fix.schema.json` | `/fleet-fix` | MR flow via `/remediate-finding`; merge events via `/track-findings` |

Other schema-gated records — doc-variance, attack mappings, benchmark targets,
adapter results, the registries the harness reads — are configuration or
instrumentation rather than scan results; the schema directory is their
inventory.

## What kind of file is it

Where each kind of data is stored, and the variable that places it, is
[storage.md](storage.md). This page settles the prior question — which kind a
file *is* — because that decides what a reader finds when they go looking, and
it is what keeps per-target detail out of the leadership views.

- **Findings-side.** Anything written *about* a specific audited target: audit
  results, validation reports, per-target inventories, privilege profiles.
  These sit in the findings store beside the audit they belong to. Per-target
  results are inventory, not a roll-up, even when a dashboard skill produced
  them.
- **Roll-ups.** An aggregate over many targets: executive summaries, trends,
  per-lane rollups. These go to the metrics tree, and only these do —
  **rollups-only discipline**: a skill writes its detailed output beside the
  findings and only its aggregate view to the dashboard tree.
- **Curated inputs.** Reference data a human maintains — vendor registries,
  operand lists. Not output, and not the skill's: the skill ships the
  *process* that gathers it, one organisation's answers live in the lane's
  `inputs/` subtree, deliberately separate from the lane's per-run output so
  what someone maintains is never mixed with what a run produced.
- **Skill assets.** Templates, rule packs, seed lists — machinery useful to
  anyone. These stay in the skill directory (for example the fuzz-harness
  templates under `create-fuzzing/harnesses/_templates/` or the
  opengrep rule pack, which ships inside traust-engine).

**Deciding.** Ask what produced it. Machinery that would be useful to anyone is
a skill asset. A file written about one audited target is findings-side. An
aggregate over many of those is a roll-up. Reference data someone curates is an
input.

## Projections — one-way views over the artifacts

These forms are not authoritative. Markdown/SARIF helpers remain separately
registered; the old corpus database and cumulative builders were retired.
Do not assume a projection is being regenerated or delete historical artifacts
as part of the severity cutover.

- **Markdown renderings** (`python3 -m traust.cli reporting render`) — the
  `.md` beside every JSON artifact.
- **`findings.db`** — a SQLite projection over every ledger and report, for
  corpus-shaped queries and as a read-only accelerator; never a write target
  ([disposition-ledger.md](disposition-ledger.md) §11b).
- **SARIF 2.1.0** (`python3 -m traust.cli reporting sarif`) — the standard
  interchange format, for whatever dashboard, viewer or aggregator the adopter
  runs. Dispositions surface as suppressions plus a verbatim `properties` copy;
  severities map to `level` and the `security-severity` property. Accepts any
  `report.schema.json` artifact and `*-cloud-config-audit.json`;
  `--results-root`/`--out-dir` sweeps a findings tree, preferring
  findings-current over raw baselines. The reverse direction — SARIF from any
  scanner into `/triage` — is the importer in [sarif.md](sarif.md).

The SARIF emitter and importer, field by field: [sarif.md](sarif.md).

## Validating an artifact

```bash
# Validate against the default schema (security audit); filenames that
# identify triage, vuln-findings, findings-layer, cloud-config-audit
# (+ cloud-config cumulatives), or impact-analysis artifacts are
# auto-detected and routed to their own schemas (detect_schema_path in
# python3 -m traust.cli reporting validate is the authoritative list); validation and
# remediation reports need an explicit --schema
python3 -m traust.cli reporting validate report.json

# Validate against a specific schema
python3 -m traust.cli reporting validate report.json --schema schemas/v1/validation.schema.json
python3 -m traust.cli reporting validate report.json --schema schemas/v1/remediation.schema.json

# Strict mode — adds checks for optional best-practice fields
python3 -m traust.cli reporting validate report.json --strict

# Batch validate a directory
python3 -m traust.cli reporting validate findings/product/

# Render to Markdown
python3 -m traust.cli reporting render report.json

# Export to SARIF 2.1.0 (any SARIF consumer)
python3 -m traust.cli reporting sarif report.json
```

Beyond schema conformance the validator runs type-specific cross-checks:
finding-id uniqueness and severity-count consistency (audit); verdict-count
consistency and chain-reference integrity (validation); check/diffstat
consistency and fork/PR safety (remediation); verdict counts,
commit-attribution consistency, and timeline ordering (verification); event-hash
integrity, append-only ordering, claim-hash and Merkle-root integrity, and the
human-identity rule for false positives (layer).
