# Standalone usage

Using Traust skills locally, one at a time, outside the automated campaign workflow. For the end-to-end campaign see [campaign-workflow.md](campaign-workflow.md); for the pipeline overview see the [README](../README.md#how-to-use-this-workflow-engine).

"Standalone" mode refers to using any of these skills independently outside of an automated workflow.

## Standalone Skills

These skills work against any codebase or report files you supply _outside of the full workflow_ with minimal coaxing. The expected inputs are always listed in the "Inputs" column, but if you want all of the options, see [docs/skills.md](skills.md).

Skills marked with Environment or Infrastructure requirements need access to services your organisation runs; the workflow engine names the kind of service, your deployment supplies the instance. Typical setup:
* **Employee directory** - the optional `traust.yaml` `identity.directory_command` cross-check; SSO/VPN as your directory requires
* **Jira** - MCP or CLI with access to target projects required
* **Ephemeral OCP Cluster** - any short-lived OCP cluster; if your organization runs an on-demand cluster service, that is the simplest route
* **Playwright** - the playwright MCP server and package installed and configured for web-driving support
* **Google Workspace** - the gws CLI, these skills use the Google Workspace API to modify Google Docs or Drive

Skills with no infrastructure requirement need only the workflow engine and a target codebase.

| Skill | Stage | What It Does | Inputs | Environment & Infrastructure Requirements | Minimum Viable Model |
|-------|-------|--------------|--------|----------------|-----------|
| `threat-model` | ② | Threat model from code, past vulns, or owner interview; review/update/pr modes maintain existing models; emits `<repo>-threat-model.md` gated by `lint_threat_model.py` | Any checkout or PR diff | — | mythos-class |
| `secure-code-audit` | ③ | Multi-framework security audit (OWASP ASVS v5.0, K8s Top 10, CIS, DISA STIG, SLSA, OpenSSF Scorecard) | Any Git repo (cloned automatically) | — | mythos-class |
| `secure-rpm-audit` | ③ | RPM dist-git packaging audit (Fedora Packaging Guidelines RPM01–RPM10, SEI CERT C/C++, ASVS, SLSA) | Any dist-git RPM repo (cloned automatically) | — | mythos-class |
| `secure-container-audit` | ③ (alt) | Container image audit: skopeo config/signature/tag-hygiene inspection, syft SBOM, grype CVE scan, source-drift check | Any registry image ref, payload CSV, or image list | `skopeo`, `syft`, `grype` | opus-class |
| `cloud-config-audit` | ③ (alt) | Declared-layer IaC audit (Terraform, CloudFormation, K8s/Helm, ARM/Bicep, Dockerfiles) via pinned offline Checkov — no cloud API calls by design | Any IaC checkout | `checkov` (pinned, offline) | opus-class |
| `operator-priv-profile` | ③ (adj) | Operator least-privilege assessment in three tiers: static SCC/securityContext/namespace/RBAC profile, kubebuilder-marker surplus diff, gated runtime capture | Any operator repo or bundle manifests | tier 3 only: OCP cluster + explicit authorization | opus-class |
| `pqc-readiness` | — | Post-quantum crypto readiness: Core-native `traust pqc prescan` facts + NIST IR 8547 transition clocks, provenance + VULN/AGIL/PQCA/HNDL scoring; optional unchanged native CBOM (currently a JSON array, not promised CycloneDX) | One selected repo checkout or manifest SBOM | Source: registered checksum-matched scanner, rules and process permission; Rust toolchain (build only) | mythos-class |
| `mine-ledger` | — | Mines ledger-confirmed TPs into the opengrep rule-calibration corpus: coverage gaps, per-rule precision, authoring backlog | Any findings directory with cumulative reports | — | opus-class |
| `security-audit-phased` | ③ (alt) | Multi-phase human-in-the-loop audit: recon → prior-vuln patterns → CWE-taxonomy walk | Any local checkout | — | mythos-class |
| `vuln-scan` | ③ (alt) | Lightweight vulnerability sweep: threat-model-scoped focus areas, parallel review subagents, baseline dedupe | Any local checkout | — | opus-class |
| `triage` | ④ | Adversarial N-vote verification, dedup, precondition-derived re-ranking, and owner routing of raw findings; citation-gated and symbol-index-accelerated | Any scanner output (directory or file) | — | mythos-class |
| `validate-findings` | ⑤ (sub) | Proves/refutes findings against live environment, chains kill-chains | Any audit report | Ephemeral OCP Cluster | mythos-class |
| `validate-browser-finding` | ⑤ (alt) | Browser-based web vulnerability validation (CSRF, XSS, clickjacking) via Playwright | Any audit report | Ephemeral OCP Cluster, Playwright | mythos-class |
| `create-fuzzing` | ⑥ | Offline fuzz harnesses (Go-native default, plus Python/atheris, JS-TS/Jazzer.js, Rust/cargo-fuzz, Java/jazzer templates) for parser/decoder/templater entry points flagged in audit reports; explicitly offline — no cluster, cloud, or network | Any audit report + target checkout | — | opus-class (`fuzz-author` floor) |
| `patch` | ⑦ | Inert candidate-fix diffs per confirmed triage finding (patch subagent + independent reviewer); never applies, never writes outside `./PATCHES/` | A `TRIAGE.json`, audit report, or `*-vuln-findings.json` | — | mythos-class |
| `remediate-finding` | ⑦ | Generate remediation patches on private forks (user supplies their own fork) | Any audit report + a fork with push access | — | mythos-class |
| `verify-remediation` | ⑦ | Verifies a patched repo actually resolves prior audit findings | A previous audit report + patched checkout | — | mythos-class |
| `generate-team-report` | ⑧ | Packages component reports into team-deliverable folders with HTML dashboards | Products registered in traust-core | — | opus-class |
| `track-findings` | ④ | Core-backed finding state, source statement import, verified-human review cards and direct/selected-review judgements; private async Markdown or typed JSON batch answers | Existing core finding/review UUIDs, optional audit labels and forge/Jira source references | Core identity policy and shared `traust auth` login | opus-class |
| `check-harness-docs` | — | Doc-drift guard: checks the harness's own docs (skill/command/script/stage counts + dead links) against the tree | The harness repo itself | — | sonnet-class |
| `check-licensing` | — | Licensing gate: blocks re-imported restrictively-licensed framework text (PEACH/CIS guard, run by the pre-push hook) + license-intake checklist for new external dependencies | The harness repo itself | — | sonnet-class |
| `check-alignment` | — | Cross-skill contract guard: script refs, pre-scan recording conventions, structure-doc links, liveness sourcing, frontmatter + wiring — enforced by the pre-commit hook | The harness repo itself | — | sonnet-class |
| `check-skill-security` | — | Security-posture gate for skills: ten S-rules — allowed-tools confinement, adversarial-content doctrine, git-URL transport gates, shell-exec/token-argv//tmp-path/unpinned-install/egress-grant rules (2026-07 self-audit), repo-config isolation for headless agents (S9, from the b-lite-p5 hostile-`.claude` incident), and safe_exec routing for target builds (S10, sandbox-adoption); enforced by the pre-commit hook and CI | The harness repo itself | — | sonnet-class |
| `crypto-analysis` | — | Probe-driven crypto governance analysis: provider census across 9 ecosystems, governance chain reasoning, builder image crypto swap detection | Any Git repo | — | mythos-class |
| `portfolio-graph` | — | Source-code dependencies on traust-core (the SQLite graph is *retired*): multi-ecosystem module dependency layer (Go plus npm/PyPI/Maven/Cargo/RubyGems/NuGet manifests, language-gated, tree-discovered anywhere in a repo; C/C++ SBOM-only) plus three universal surfaces (Docker base images, GitHub Actions, Helm charts — path-discovered, not language-gated) over the repo-graph spine — CVE blast radius, shared-library fan-in, internal coupling | `repo-graph.json` + `gh` auth | `gh` | opus-class |
| `dependency-watch` | — (daily lane) | Advisory-driven deps lane end to end: feed refresh → new-advisory sweep (never drops CVE-less malicious-package/`MAL-` advisories — the Shai-Hulud class) → `/impact-analysis` reachability → Core direct-entry filing (affected repos' findings are admitted without an authored validity answer the day the advisory lands; the baseline is never written) | optional CVE ID / `--since` | — | opus-class |
| `impact-analysis` | — | Per-repo CVE affectedness across the portfolio graph: blast radius query, L4 package-import refinement, language-specific deep scan (Go's govulncheck + ELF reachability is the strongest tier; other ecosystems get manifest-level analysis); feeds `/triage` Phase 2f, `/verify-remediation --impact-filter`, and the `/dependency-watch` filing leg | A CVE ID + portfolio-graph.db | — | opus-class |
