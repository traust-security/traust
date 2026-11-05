# Requirements

What you need to run the harness, tiered from "any skill at all" up to the
full multi-repository pipeline. This is the requirements overview; the two
companion references are:

- [setup.md](setup.md) — the **installation steps** (`install_traust`, clone,
  `uv sync`, hooks, env vars, toolchain).
- [external-dependencies.md](external-dependencies.md) — the **complete
  dependency inventory**: every tool with the skills that require it, its
  license, and an evidence link.

## Baseline (every usage mode)

| Requirement | Detail |
|---|---|
| OS | macOS or Linux. No Windows support. |
| Python | 3.11+ |
| Git | Any recent version; most audit skills clone their targets |
| An AI coding agent | Claude Code or Crush — the harness is prompt-and-skill tooling driven by an agent, not a standalone scanner. Skills are auto-discovered via the `.claude/skills/` and `.crush/skills/` symlink trees |
| Python dependencies | `uv sync` in the harness repo (installs `traust-core`, and through it `traust-ledger` and `traust-contracts`, from the commit SHAs in `pyproject.toml` via `[tool.uv.sources]`); optional extras via `uv sync --extra signing`. The continuous-ops service `traust-engine` is installed separately (the runtime image includes it): `uv tool install "traust-engine @ git+https://github.com/traust-security/traust-engine@<sha>"` |
| **Operational configuration** | A directory named by `TRAUST_CONFIG_HOME` (default `~/.traust/config`) holding the nine operational config files — corpus registry, product map, budget policy, safe-exec profiles, rule-pack allowlist, hardening weights, dist-git watch list, internal vocabulary, ledger signing public key. `scripts/install_traust` creates it from the templates in `config/`; `install_traust --doctor` verifies it. **Nothing runs without it** — a missing file fails closed. See [config/README.md](../config/README.md) |
| Disk | A few GB free — audit skills clone target repositories into the workspace |

## Model tier

Each skill states a **Minimum Viable Model** in the README's skill tables.
Column semantics: the MVM is the **registry floor of the skill's primary
role** in `config/model-registry.yaml` — the resolution-time-enforced minimum
(python3 -m traust.cli registry models resolve), not a recommendation;
[model-routing.md](model-routing.md) is the contract. The four tier classes:

- **haiku-class** — pure rendering/narration roles (`render-narrate`) with no
  analysis or validity-writing.
- **sonnet-class** — mechanical guardrail skills (doc-drift, licensing,
  alignment checks).
- **opus-class** — inventory, dashboards, packaging, most rollups,
  fuzz-harness authoring (`fuzz-author` floor).
- **mythos-class** — the analysis-heavy core: audits, threat models, triage,
  validation, remediation. Running these on a weaker model measurably degrades
  recall; the error model ([error-model.md](error-model.md)) describes how
  that is measured.

When in doubt, run audits on the strongest model available and dashboards on
whatever is cheap.

Which class each *skill* runs at, why the floors sit where they do, and which
roles may write a validity verdict into the ledger:
[model-classes.md](model-classes.md).

**These are defaults, not requirements.** Every model identifier lives in
`model-registry.yaml`, and the copy in your `$TRAUST_CONFIG_HOME` wins — so a
deployment can repoint any role to its own provider and models, per role,
without touching the harness. See
[Configuring your own models](model-classes.md#configuring-your-own-models).

## CLI tools, by capability

Nothing beyond the baseline is needed until you use a skill that calls for it.
`scripts/install-toolchain.sh <profile>` installs the scanner binaries at the
versions pinned in traust-core's shipped `external-tools.yaml` (the manifest `/drift-watch`
checks installs against); the per-skill mapping and every license are in
[external-dependencies.md](external-dependencies.md). By capability:

| If you want to… | You need |
|---|---|
| Run source-code audits (`secure-code-audit`, `vuln-scan`, `threat-model`, `triage`) | Nothing extra — optional deterministic pre-scanners sharpen results: `opengrep`, `gitleaks`, `govulncheck`, the OSV API dependency pre-scan (osv-scanner only when air-gapped — [setup.md](setup.md#air-gapped-osv-scanning)), and one of `tokei`/`scc`/`cloc` for LoC (toolchain profile `secure-code-audit`) |
| Audit container images (`secure-container-audit`) | `skopeo`, `syft`, `grype`, `cosign`, `podman`. Optional: `yara` for the known-malware-family pre-scan over the exported rootfs (pinned rule pack fetched at run time) — toolchain profile `secure-container-audit` |
| Audit RPM packaging (`secure-rpm-audit`) | GitLab MCP tools, `git`, access to the dist-git lookaside cache; optional `syft`/`grype`/`govulncheck` and the OSV API (osv-scanner when air-gapped) over the prepared source tree, and `yara` — toolchain profile `secure-rpm-audit` |
| Audit IaC (`cloud-config-audit`) | `checkov`, pinned to `CHECKOV_VERSION` in traust-core's `models/cloud_config.py` — `traust cloud-config run` hard-fails on a mismatch and always runs offline. Optional: the `bicep` CLI (pinned `BICEP_VERSION` in traust-engine's `adapters/cloud_config.py`) for the transpile fallback on `.bicep` files checkov's parser rejects — install to `~/.cache/cca-tools/bicep-<version>/bicep` (0700) or set `$CCA_BICEP`; verify the downloaded binary against `BICEP_SHA256` (same file). Without it those files stay loud NOT-ASSESSED gaps |
| Inventory operator-catalog and release-payload targets (`inventory-repositories`) | `oc`, `skopeo`, `podman`, `opm`/`operator-sdk` |
| Validate findings on a live cluster (`validate-findings`, `deploy-operator` (internal extension), `operator-priv-profile` tier 3) | `oc`, `kubectl`, and a **disposable, explicitly authorized** cluster named in the rules-of-engagement file. How the cluster is provisioned is the deployment's concern |
| Validate browser findings (`validate-browser-finding`) | Playwright (`pip install -r requirements.txt` from the repo root, then `playwright install chromium`) |
| Fuzz (`create-fuzzing`) | The target language's toolchain: Go native, `atheris` (Python), `Jazzer.js` (JS/TS), `jazzer` (JVM, pinned), `cargo-fuzz` (Rust) |
| Generate remediations on forks (`remediate-finding`) | A `GITHUB_TOKEN` with fork-push rights — fork setup goes through the GitHub REST API directly (`curl`), no `gh` needed. (`glab` belongs to `fleet-fix` MR automation) |
| PQC readiness (`pqc-readiness`) | `traust pqc prescan` uses Core's registered provider. Source mode needs the pinned executable + matching checksum, readable rules and `process.allowed_binaries` permission; Rust is needed only to build the binary, `git`/`syft` for checkout/SBOM acquisition when needed. SBOM-only mode accepts a manifest without executing the source scanner. Optional x/crypto call-graph evidence needs Go + `callgraph`/`digraph` |
| Sign disposition ledgers | `cosign`, plus the signing private key in your secret store, referenced by `traust.yaml` → `ledger.key_path` — toolchain profile `ledger-signing`; see [signing.md](signing.md) |

## Network & access tiers

| Tier | What it unlocks | Skills affected |
|---|---|---|
| **Offline** | Everything that reads a local checkout: audits, threat models, triage, fuzzing, patch generation | Most of the harness — audit skills default to read-only against the target; the documented exceptions (sanitizer probes via `probe_sanitizers.py --run`, govulncheck, remediation build checks) execute target code only through the `safe_exec` sandbox or a rootless container (gate rule S10) |
| **Public internet** | Vulnerability feeds (OSV, Go vulndb, EPSS, CISA KEV, grype DB, vendor CSAF), forge API lookups, cloning public repositories | dependency pre-scans, CVE enrichment, `dependency-watch`, `impact-analysis`, `portfolio-graph`, the rescan router |
| **Private network** | Your directory service (owner assignment, countersign identity verification), a private forge, an internal product registry, distro packaging hosts | `assign-findings-owners` (internal extension), `reassign-findings-owners`, `countersign`, `secure-rpm-audit`; `sla-view`'s registry join is optional and degrades cleanly when the registry is unreachable |
| **Issue tracker** | Defect filing and backlog sync (Jira, via MCP server or CLI with target-project access) | `file-security-defect` (internal extension) |
| **Disposable cluster** | Live validation — always against disposable, explicitly authorized clusters, never production | `validate-findings`, `deploy-operator` (internal extension), `operator-priv-profile` tier 3 |
| **Collaboration suite** | Findings distribution and ownership-tracker updates (`gws` CLI for Google Workspace) | `reassign-findings-owners` (internal extension) |

## Multi-repository pipeline (additional)

Running the full pipeline across a fleet additionally requires the sibling
**data** repositories cloned beside the harness — an inputs inventory, the
findings store, and the progress-tracker tree ([setup.md](setup.md) has the
layout) — and the git hooks enabled (`git config core.hooksPath .githooks`) so
the doc-consistency, licensing, skill-alignment, and skill security-posture
gates run locally. MCP servers for the flows that use them (GitHub, GitLab,
Jira, Playwright) are inventoried in
[external-dependencies.md](external-dependencies.md).

## Authorization (not optional)

All security testing this harness performs is against explicitly authorized
targets only. Scope validation is fail-closed in the validation skills, live
work targets disposable clusters, and the constraints in
[AGENTS.md](../AGENTS.md) apply to every run. If you are not authorized to
assess a target, no tier above applies — don't point the harness at it.
