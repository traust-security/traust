# Tooling and structure files

The schemas, packaged CLIs and key scripts that make up the harness's deterministic tooling.

The schemas below (from the installed `traust-contracts` package) are the complete set; the scripts listed are the key entry points — packaged CLIs live under `src/traust/`, and skill-specific tooling lives alongside each skill in its own `scripts/` — under a stage directory for workflow skills (`harnessing/3-audit/secure-code-audit/scripts/`), at the `harnessing/` root for the rest.

| Component | Purpose |
|---|---|
| python3 -m traust.cli util safe-exec + the `safe-exec-profiles.yaml` traust-core ships | Enforced sandbox for target-derived commands (argv allowlists, env scrub, shell-free pipelines) — gate rule S10; [docs/safe-exec.md](safe-exec.md) |
| python3 -m traust.cli dashboard refresh | The packaged dashboards rebuild (core views → remaining registered builders → scoreboard); retired corpus projections/builders are not restored — see [continuous-operations.md](continuous-operations.md#standing-jobs--the-complete-inventory) |
| `traust_engine.escaping` | Shared untrusted-text helpers every emitter uses (HTML, inline-script JSON, md cells, CSV, slugs) — library import, not a CLI |
| `schemas/v1/report.schema.json` | JSON Schema (draft 2020-12) for security-audit reports |
| `schemas/v1/triage.schema.json` | JSON Schema for TRIAGE.json validation |
| `schemas/v1/vuln-findings.schema.json` | JSON Schema for vuln-scan candidate reports (`<repo>-vuln-findings.json`) |
| `schemas/v1/adapter-result.schema.json` | JSON Schema for traust-engine scanner adapter `scan()` return values (distinct from skill-level vuln-findings output) |
| `traust-contracts/artifacts_schema/v1/code-facts.schema.json` | Recorded symbols and measured language statistics on a `tool_scan` assessment; read through core's artifact and code-facts services |
| `traust-contracts/artifacts_schema/v1/manifest-coverage.schema.json` | What a commit's manifest SBOM could not resolve, with the SBOM tool's name and version; recorded by core's dependency ingestion before the SBOM, so an unresolved manifest reads as unknown, never as no dependencies |
| `traust-contracts/artifacts_schema/v1/fuzz-campaign.schema.json` | A supplied fuzz-campaign scope reference: a campaign snapshot with declared references, not fuzz execution evidence (`reporting import-fuzz-campaign` is retired in traust; nothing records it) |
| `traust-contracts/artifacts_schema/v1/repo-liveness.schema.json` | Repository liveness facts recorded by traust-core's forge observation, keyed by inventory repository UUID; `traust portfolio liveness` still refuses until plan 15's decision 3 |
| `schemas/v1/validation.schema.json` | JSON Schema for live-validation reports |
| `schemas/v1/remediation.schema.json` | JSON Schema for remediation patches |
| `schemas/v1/verification.schema.json` | JSON Schema for remediation-verification reports |
| `schemas/v1/impact-analysis.schema.json` | JSON Schema for CVE impact-analysis artifacts |
| `schemas/v1/layer.schema.json` | JSON Schema for findings-disposition layers (track-findings ledger) |
| `schemas/v1/refuted-register.schema.json` | JSON Schema for the refuted-finding register: triage or validation refutations kept, integrity-bound, for later execution evidence and countersign |
| `schemas/v1/threat-model.schema.json` | JSON Schema for one subject's threat model contract (`<repo>-threat-model.json`), alongside the authored Markdown (`<repo>-threat-model.md`); the former JSON emitter is retired and the core assessment/artifact skill port is unfinished, with no executable fallback |
| `schemas/v1/run-manifest.schema.json` | JSON Schema for an order's run manifest (`run_order.artifact_id`): config digests in force (the pack version), the budget verdict at admission, the approval, progress and degraded keys (traust-core `OpsService`) |
| `traust-contracts/artifacts_schema/v1/session-task.schema.json` | JSON Schema for a judgement session's runner-staged task: its skill, mode, argv, models, staged inputs and the one output it may produce; paths are task-relative and a manual session has no run order |
| `traust-contracts/artifacts_schema/v1/session-result.schema.json` | JSON Schema for a session's result envelope: executor identity, measured model usage and an optional error; the judged document is the task's declared output, not this envelope |
| `schemas/v1/corpus-registry.schema.json` | JSON Schema for the corpus ownership registry — the subject→owner/business-unit mapping that every denominator divides by |
| `schemas/v1/operator-priv-profile.schema.json` | JSON Schema for per-operator least-privilege profiles (`*-priv-profile.json`), parsed from shipped manifests — declared state, never a live cluster read |
| `traust_core.v1.services.findings.identity.IdentityPolicy` | Core-owned finding fingerprint recipe and version attribution, moved from traust-ledger. Reuse core identity handling; never invent a second recipe or substitute a fingerprint for the finding UUID required by the severity writer. |
| `schemas/v1/isolation-review.schema.json` | JSON Schema for tenant-isolation review reports |
| `schemas/v1/cloud-config-audit.schema.json` | JSON Schema for declared-layer IaC audit reports |
| `schemas/v1/cloud-config-findings-current.schema.json` | JSON Schema for cloud-config cumulative status reports (`*-findings-current.json` from track-findings) |
| `schemas/v1/compliance-assessment.schema.json` | JSON Schema for compliance-check assessment reports |
| `schemas/v1/compliance-mapping.schema.json` | JSON Schema for the control↔check policy mapping |
| `schemas/v1/doc-variance.schema.json` | JSON Schema for documentation-variance registers (`<repo>-doc-variance.json`) — official docs.redhat.com claims contradicted by code evidence, per doc version; source URL schema-restricted to docs.redhat.com (informal inputs never mint variance records) |
| `schemas/v1/compliance-scope.schema.json` | JSON Schema for a compliance boundary declaration (recorded by `python3 -m traust.cli compliance declare`; repo membership resolved from the inventory by `python3 -m traust.cli compliance resolve`) |
| `schemas/v1/pqc-facts.schema.json` | JSON Schema for Core's deterministic Layer 1 crypto census (`*-pqc-facts.json`), produced and recorded by `traust pqc prescan`, exported unchanged — the contract `/patch`'s pqc ingest and the Layer 2 prepass consume; re-check with `traust reporting validate <file> --schema pqc-facts` |
| `schemas/v1/pqc-readiness.schema.json` | JSON Schema for PQC readiness reports |
| `schemas/v1/pqc-blockers.schema.json` | JSON Schema for the findings-shaped projection of readiness remediations (no longer emitted: `traust pqc blockers` derives the items from the recorded report) — mirrors the security-audit findings vocabulary without claiming `report.schema.json` conformance |
| `schemas/v1/pqc-decision-tree.schema.json` | JSON Schema for the PQC provenance decision tree |
| `schemas/v1/pqc-vendor-claims.schema.json` | JSON Schema for the curated, dated vendor PQC claims (scope-ref; recorded by `traust pqc vendor-claims`, a review is a higher `version`; fleet counts are derived by `traust dashboard view pqc-vendors`, never stored) |
| `schemas/v1/fuzz-report.schema.json` | JSON Schema for the document a fuzz assessment holds |
| `schemas/v1/fleet-fix.schema.json` | JSON Schema for fleet-fix transform specs |
| `schemas/v1/sla-policy.schema.json` | JSON Schema for SLA policy files (sla-view) — adopters configuring their own service levels start at [sla-policy.md](sla-policy.md) |
| `schemas/v1/model-registry.schema.json` | JSON Schema for the model registry (config/model-registry.yaml — role routing, tier floors, spend policy) |
| `schemas/v1/benchmark-target.schema.json` | JSON Schema for recall-benchmark target definitions |
| `schemas/v1/below-range-packets.schema.json` | JSON Schema for a commit's below-range evidence packets (traust-core `BelowRangeService.scan`) |
| `schemas/v1/below-range-verdicts.schema.json` | JSON Schema for a below-range review: two blind reviews, a judge on a split, the verdict per packet |
| `schemas/v1/validation-plan.schema.json` | JSON Schema for the validate-findings plan `plan.py` emits |
| `schemas/v1/validation-authorization.schema.json` | JSON Schema for the validate-findings authorization `ValidationService.authorize` records (operator approval of a plan + scope) |
| `schemas/v1/attack-mapping.schema.json` | JSON Schema for the finding-category→ATT&CK mapping table |
| `schemas/v1/adr-registry.schema.json` | JSON Schema for the architecture-decision-record registry |
| `schemas/v1/org-parameters.schema.json` | JSON Schema for org-wide parameter files |
| `schemas/v1/product-definitions-map.schema.json` | JSON Schema for the reviewed package/repo → product map (`traust registry product-map`) |
| `schemas/v1/risk-rating-methodology.schema.json` | JSON Schema for the risk-rating methodology config |
| `schemas/v1/repo-state.schema.json` | JSON Schema for a repository's forge observation: observed default-branch head compared with its latest audit, stored as a repo-state assessment artifact; unavailable/deferred run outcomes are not observation documents |
| python3 -m traust.cli reporting validate | Validates report JSON against schema; supports `--strict` and batch validation |
| python3 -m traust.cli reporting lint | Deterministic threat-model gate — sections/columns/enums, coverage invariant, ID stability, provenance, evidence hygiene |
| python3 -m traust.cli reporting render | Renders validated JSON reports to Markdown |
| python3 -m traust.cli reporting sarif | Exports any report (incl. disposition-aware findings-current and cloud-config audits) to SARIF 2.1.0 for any SARIF consumer — a derived projection, dispositions become suppressions; `--results-root` batch sweep |
| python3 -m traust.cli check citations | Citation verification gate for findings |
| python3 -m traust.cli build symbol-index | Builds symbol index for triage acceleration |
| python3 -m traust.cli admin query-index | Queries the symbol index |
| Retired baseline-claim workflow | Formerly pinned legacy baseline claim hashes; core finding intake/baseline services own the unfinished skill port, with no executable fallback |
| python3 -m traust.cli triage record | Records validated triage decisions through core; human review items feed the countersign queue |
| `traust auth` | Core-owned stored login, local/device-code/token-file authentication, machine service accounts, status, refresh and logout |
| `traust findings` | Core finding reads, forge/Jira import, full review cards/evidence, review requests, direct human judgements, typed Markdown/JSON batch apply and confirm/reject, refuted findings, review surfaces, SARIF and ticket links; both review outcomes require a judged decision and own rationale |
| python3 -m traust.cli check docs-consistency | Doc-drift detection for harness docs |
| `python tools/classify_script_placement.py` | Checkout-only repository-hygiene audit of static CLI importers, registration entries and skill references; emits CSV, never moves files, and is not installed as a runtime command |
| python3 -m traust.cli impact cluster-state-diff | P5 discovery sweep 1 — before/after security-state snapshots (RBAC, SCCs, webhooks, NetworkPolicies, Services/Routes) diffed into validation-discovery candidates for /triage |
| python3 -m traust.cli sweep benchmark | P7 validation-lane benchmark — vulnerable/safe-twin fixtures, confirm-recall + refute-precision + severity-accuracy floors, hybrid release-cut/monthly cadence (check-trigger + drift-watch) |
| python3 -m traust.cli admin attest-target | P2 pre-flight target attestation for validation lanes — fail-closed environment gate (cluster fingerprint, CSV/pod readiness, version-in-range, URL reachability) emitting target-attestation.json |
| `traust validation record` | Typed machine-report recording via core `ValidationService.record`; explicit stored source bindings/provenance, full target-attestation/install observations, core-owned soundness and canonical decisions or review items |
| python3 -m traust.cli registry models | Model-registry loader/resolver — role→model resolution with floor enforcement, routing stamps, spend recording (docs/model-routing.md) |
| python3 -m traust.cli admin checkpoint | Agent checkpoint support |
| python3 -m traust.cli check fix-propagation | Deterministic cross-repo fix-propagation check on traust-core (`ExposureService.consumes_fix`) — has the original commit consumed the fixed version, by its manifest SBOM and the images built from it? Feeds verify-remediation's two-legged rule |
| python3 -m traust.cli impact find / sbom / symbols / analyze / sweep | The impact-analysis and dependency-watch doors on traust-core (`ExposureService`): source advisories, recorded commit SBOMs, fix symbols, per-commit analysis (`--scan` for govulncheck/source tiers) saved as `impact` assessments, dependency finding intake for `affected` commits, and fleet OSV sweep over recorded SBOMs; no fabricated classifier or severity |
| Retired regression router | Formerly converted remediation regressions into event-carried findings; core finding intake owns the replacement, but the skill port is unfinished and there is no executable fallback |
| Retired FP-precedent corpus CLI | Formerly built a tiered refutation-precedent index for triage and the Precision Gate; core finding precedents own the replacement, but the skill port is unfinished and there is no executable fallback |
| python3 -m traust.cli sweep | Class-generalization sweep loop: confirmed finding → candidate rule → corpus-wide sweep → triage-ready candidates |
| python3 -m traust.cli sweep mine | The /mine-ledger miner on traust-core (`DetectionQualityService.mine_rules`) — confirmed-TP corpus, cluster coverage vs the opengrep pack, per-rule campaign precision |
| python3 -m traust.cli sweep regression-drafts / verify-draft | Regression-rule draft staging from confirmed findings recorded fixed on a later commit (`DetectionQualityService.regression_pairs`: pre/post calibration pairs), and the opengrep fires-before / silent-after gate |
| python3 -m traust.cli sweep rule-lane | The weekly rule-mining lane runner — miner → sweep collect/draft → bounded draft staging → `lane-delta.{json,md}` vs the previous mine; exit 1 when the delta needs authoring attention |
| python3 -m traust.cli portfolio liveness | Census-owned repo liveness; refuses until plan 15's decision 3 (the typed repo-liveness status needs a newer traust-core contracts pin) rather than derive a status |
| python3 -m traust.cli check skill-alignment | Pre-commit cross-skill contract gate (A-series rules) |
| python3 -m traust.cli check skill-security | Pre-commit security-posture gate (S-series rules incl. S9 repo-config isolation) |
| python3 -m traust.cli adapters crypto-source / crypto-image / crypto-cluster | Unopinionated crypto data collector on traust-core — source/image/cluster census JSON |
| python3 -m traust.cli util elf | General-purpose ELF binary analyzer (linked libraries, byte scanning) |
