# Artifacts — what each stage produces, where it lands, and what consumes it

Every stage of the harness emits one machine-readable artifact, validated
against a JSON Schema before it is written, plus a Markdown rendering for
people. The schemas in the `traust-contracts` package (`schemas/v1/`) are
the authority on what each artifact contains. This page is the map between
them: which skill produces each artifact, which skills and tools consume it,
and where it is written. Field-level structure is in
[report-structure.md](report-structure.md) and the schemas; the ledger's
design is in [disposition-ledger.md](disposition-ledger.md); how a finding
travels from a producer into the ledger is in
[findings-routing.md](findings-routing.md).

## The chain at a glance

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

Every arrow narrows with memory: nothing is deleted, and every stage's output
is auditable back to file:line evidence.

## The core chain

Each row is a scan or assessment result. "Consumed by" lists the downstream
skills and tools that read it directly, checked against each skill's declared
inputs; an artifact with no consumer is marked terminal rather than left
unexplained.

| Artifact | Schema | Produced by | Consumed by |
|---|---|---|---|
| `<repo>-threat-model.md` | linted by python3 -m traust.cli reporting lint (no JSON schema) | `/threat-model` | `/secure-code-audit` (coverage diff), `/vuln-scan` (focus areas), `/triage` (environment context), `/threat-register` |
| `<repo>-security-audit.json` — the **baseline** | `report.schema.json` | `/secure-code-audit`, `/secure-rpm-audit` | `/triage`, `/track-findings`, `/verify-remediation`, `/patch`, `/vuln-scan` (dedup), `/threat-model` bootstrap, `/create-fuzzing`, `/file-security-defect`, every dashboard via the corpus resolver |
| `<image>-container-audit.json` — a baseline for a registry image | `report.schema.json` | `/secure-container-audit` | `/track-findings`, `/verify-remediation`, dashboards |
| `<repo>-vuln-findings.json` — candidates, not a baseline | `vuln-findings.schema.json` | `/vuln-scan` | `/triage`, `/patch`; in diff mode, verified findings also enter the ledger as events |
| `<repo>-triage.json` | `triage.schema.json` | `/triage` | `/patch`; `/track-findings` via `emit_triage_ledger_events` (which also emits the needs-review queue items `/countersign` later reads from the ledger) |
| `<repo>-validation.json` | `validation.schema.json` | `/validate-findings` (and extension validators) | `/track-findings` via `emit_validation_ledger_events` (execution-verified events); `/findings-db` |
| `<rem_id>-remediation.json` | `remediation.schema.json` | `/remediate-finding` | `/verify-remediation` on the fork or MR; merge events reach the ledger through `/track-findings` |
| `<repo>-remediation-verification.json` | `verification.schema.json` | `/verify-remediation` | `/track-findings` via `emit_verification_ledger_events` (resolution events); `regressions[]` routed into the ledger by `route_regressions` |
| `<repo>-findings-layer.json` — **the ledger** | `layer.schema.json` | `/track-findings` (every ledger writer appends here) | `build_cumulative` (derives findings-current), `findings.db` (and through it `/sla-view`), `/findings-trends`, `/countersign`, `/verify-remediation` sweep tiering |
| `<repo>-findings-current.{json,md}` — derived, regenerable | `report.schema.json` | `build_cumulative` (replay of the ledger over the baseline) | owner routing, team reports, `/file-security-defect`, dashboards, SARIF export |
| `PATCHES/` packet | — | `/patch` | **terminal by design**: a human-review packet; nothing consumes it automatically |

Two rules shape this table. Only the three `secure*audit` skills write a
baseline (gate A15); every other producer's findings enter the ledger as
events. And `findings-current` is a cache: it is regenerated from the ledger
on every run and is never edited.

## Assessment artifacts beside the chain

| Artifact | Schema | Produced by | Consumed by |
|---|---|---|---|
| `<target>-cloud-config-audit.json` (+ its own findings-current) | `cloud-config-audit.schema.json`, `cloud-config-findings-current.schema.json` | `/cloud-config-audit` | `/track-findings`, `/verify-remediation`, SARIF export, dashboards |
| `<cve>-impact-analysis.json` | `impact-analysis.schema.json` | `/impact-analysis` | `/triage`, `/verify-remediation --impact-filter`, `/patch`, the `findings.db` `impact` table; `affected` rows become ledger events via `route_impact_findings` |
| `<slug>-pqc-facts.json`, `-pqc-readiness.json`, `-pqc-blockers.json` | `pqc-facts`, `pqc-readiness`, `pqc-blockers` schemas | `/pqc-readiness` | its own Layer-2 scoring, `/patch` (first-party blockers), the PQC rollup and dashboards |
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
  `secure-code-audit/opengrep-rules/` pack).

**Deciding.** Ask what produced it. Machinery that would be useful to anyone is
a skill asset. A file written about one audited target is findings-side. An
aggregate over many of those is a roll-up. Reference data someone curates is an
input.

## Projections — one-way views over the artifacts

Four derived views exist. None is authoritative; each is regenerated from the
artifacts above and can be deleted without losing anything.

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
