# External Dependencies & Licensing

Every external requirement of the harness — Python libraries, CLI tools, MCP
servers, vulnerability-data feeds, and the security frameworks whose content
the skills reference — with its license and an evidence link. Every license
was checked against the upstream LICENSE file or terms page at intake, not
recalled from memory; `/check-licensing` is the intake procedure for adding a
row, and the docs gate fails when a tool the code invokes has no row here.

> **Not legal advice.** This is an engineering-compiled inventory to support a
> licensing review.

**Why the usage model matters.** License obligations attach differently
depending on how a dependency is used:

- **Subprocess CLI** — the harness invokes an unmodified binary and parses its
  output. No linking, no derivation: even GPL tools impose no obligations
  unless the harness *redistributes* them.
- **Imported library** — the Python code `import`s the package; its license
  applies to the combined work more directly (LGPL is the strongest imported).
- **Referenced content** — framework text (benchmarks, standards, taxonomies)
  reproduced or adapted inside skill prompt files is *distributed content*,
  and content licenses (CC variants, CIS/SEI terms) bind regardless of the
  "it's only a prompt" framing. This is where licensing risk concentrates.

## Python libraries (imported)

Declared in `pyproject.toml` (with `requirements.lock` as the hash-pinned
resolution); verified against actual `import`s across `src/`, the sibling
packages, and `harnessing/`.

| Package | Used by | License | Evidence | Notes |
|---|---|---|---|---|
| `traust-core` | typed repository observations and SQL repository/transaction patterns | Apache-2.0 (upstream declaration) | [package license declaration](https://github.com/traust-security/traust-core/blob/main/pyproject.toml) | First-party library; the imported revision declares Apache-2.0 but contains no standalone LICENSE file. |
| `traust-engine` | processing core — validators, scanners, reporting, impact analysis (`traust_engine.*`) | Same license as this harness | sibling repository, installed from its git tag via `[tool.uv.sources]` | Not a third-party licensing surface |
| `traust-contracts` | contract surface — bundled JSON schemas, shared enums, identity vectors | Same license as this harness | sibling repository, installed from its git tag via `[tool.uv.sources]` | Not a third-party licensing surface |
| `traust-ledger` | disposition-ledger kernel — finding identity, Merkle integrity, signing | Same license as this harness | sibling repository, installed from its git tag via `[tool.uv.sources]` | Not a third-party licensing surface |
| `jsonschema` | all validators | MIT | [PyPI](https://pypi.org/pypi/jsonschema/json) | Permissive |
| `pydantic` | immutable typed repository observation records | MIT | [LICENSE](https://github.com/pydantic/pydantic/blob/main/LICENSE) | Imported library; installed by the project dependency resolver. |
| `sqlalchemy` | observation storage through Core's SQL repository pattern | MIT | [LICENSE](https://github.com/sqlalchemy/sqlalchemy/blob/main/LICENSE) | Imported library; SQLite uses the standard-library driver. |
| `referencing` | schema registry for the validators | MIT | [PyPI](https://pypi.org/pypi/referencing/json) | Permissive |
| `pyyaml` | config, scope and targets parsing | MIT | [PyPI](https://pypi.org/pypi/PyYAML/json) | Permissive |
| `playwright` | `validate-browser-finding` | Apache-2.0 | [PyPI](https://pypi.org/pypi/playwright/json) | Downloads browser binaries (Chromium/Firefox/WebKit) carrying their own upstream licenses. |
| `pytest` | test suite only (dev dependency) | MIT | [PyPI](https://pypi.org/pypi/pytest/json) | Not shipped with any artifact. |
| `tree-sitter` (py-tree-sitter) | portfolio-graph Layer 4 symbol extraction — optional dependency group `graph` | MIT | [LICENSE](https://github.com/tree-sitter/py-tree-sitter/blob/master/LICENSE) | Permissive. Core library also MIT ([LICENSE](https://github.com/tree-sitter/tree-sitter/blob/master/LICENSE)). |
| `tree-sitter-go` / `-python` / `-typescript` / `-javascript` grammars | same (one wheel per language) | MIT (each, individually verified) | [go](https://github.com/tree-sitter/tree-sitter-go/blob/master/LICENSE) · [python](https://github.com/tree-sitter/tree-sitter-python/blob/master/LICENSE) · [typescript](https://github.com/tree-sitter/tree-sitter-typescript/blob/master/LICENSE) · [javascript](https://github.com/tree-sitter/tree-sitter-javascript/blob/master/LICENSE) | Permissive. Deliberately the official per-language wheels, NOT grammar aggregation packs whose bundled grammars license individually — adding a language means adding its verified row here. |
| `sigstore` (sigstore-python) | disposition-ledger Merkle-root signing — optional dependency group `signing` | Apache-2.0 | [LICENSE](https://github.com/sigstore/sigstore-python/blob/main/LICENSE) (verbatim Apache-2.0 text; PyPI metadata is empty — the file governs) | Permissive; imported only when signing is used. |
| `fsspec` | `traust_engine.storage` remote tier — **optional extra**, imported lazily; a local path or `file://` never imports it | BSD-3-Clause | [LICENSE](https://github.com/fsspec/filesystem_spec/blob/master/LICENSE) — PyPI metadata carries no license field; the repo is the authority | Permissive |
| `s3fs` / `gcsfs` / `adlfs` | per-backend drivers behind the `s3` / `gcs` extras for `ANALYSIS_RESULTS_URI` / `PORTFOLIO_GRAPH_URI` | BSD-3-Clause (all three) | [s3fs](https://github.com/fsspec/s3fs) · [gcsfs](https://github.com/fsspec/gcsfs/blob/main/LICENSE.txt) · [adlfs](https://github.com/fsspec/adlfs) | Permissive |

## CLI tools (invoked as subprocesses)

None of these are linked or vendored — the harness shells out to whatever is
on `PATH`. Copyleft licenses (GPL) in this table therefore impose **no
obligations** on the harness; they matter only if a distribution *bundles* the
binaries (in which case ship the license text and a source offer for those
tools). Pinned versions for the scanner binaries live in
`config/external-tools.yaml`; `scripts/install-toolchain.sh` installs them.

| Tool | Required by | License | Evidence |
|---|---|---|---|
| `git` | everything | GPL-2.0-only | [COPYING](https://github.com/git/git/blob/master/COPYING) |
| `curl` | toolchain installer (release downloads); `validation-step` safe-exec profile (in-scope lab probes) | curl license (MIT-style) | [COPYING](https://github.com/curl/curl/blob/master/COPYING) |
| `pipx` / `pip` | toolchain installer — isolated installs of Python-packaged CLIs | MIT (pipx) / MIT (pip) | [pipx LICENSE](https://github.com/pypa/pipx/blob/main/LICENSE) · [pip LICENSE](https://github.com/pypa/pip/blob/main/LICENSE.txt) |
| `sha256sum` / `shasum` | toolchain installer — verifies downloaded release archives against the upstream checksum file (GNU coreutils on Linux, Perl `shasum` on macOS) | GPL-3.0-or-later (coreutils) / Perl Artistic+GPL (shasum) | [COPYING](https://git.savannah.gnu.org/cgit/coreutils.git/tree/COPYING) |
| `opengrep` | secure-code-audit, vuln-scan (semantic pre-scan) | LGPL-2.1-only (OCaml libs carry a static-linking exception); single self-contained binary, cosign-signed releases | [LICENSE](https://github.com/opengrep/opengrep/blob/main/LICENSE) — engine only; **rule packs license separately, see the frameworks table** |
| `gitleaks` | secure-code-audit secret pre-scan, delta-watch history scan, router tripwire | MIT | [LICENSE](https://github.com/gitleaks/gitleaks/blob/master/LICENSE) — the **only** secret scanner in scope; detector gaps are closed with harness-owned rules in `harnessing/3-audit/secure-code-audit/gitleaks-rules/`, never by adopting AGPL alternatives |
| `syft` | secure-container-audit; secure-code-audit (optional SBOM step) | Apache-2.0 | [LICENSE](https://github.com/anchore/syft/blob/main/LICENSE) |
| `grype` | secure-container-audit; secure-code-audit (optional SBOM step) | Apache-2.0 (code — DB is data, see feeds table) | [LICENSE](https://github.com/anchore/grype/blob/main/LICENSE) |
| `osv-scanner` | secure-rpm-audit; secure-code-audit / vuln-scan dependency pre-scan; dependency-watch | Apache-2.0 | [LICENSE](https://github.com/google/osv-scanner/blob/main/LICENSE) |
| `govulncheck` | secure-code-audit, secure-rpm-audit, triage, impact-analysis (Go reachability); `go-scan` safe-exec profile | BSD-3-Clause | [LICENSE](https://github.com/golang/vuln/blob/master/LICENSE) |
| `pip-audit` | secure-code-audit optional Python-environment dependency check | Apache-2.0 | [LICENSE](https://github.com/pypa/pip-audit/blob/main/LICENSE) |
| `cosign` | secure-container-audit (signature checks); **ledger Merkle-root signing** (`traust_ledger` keypair backend, offline bundle format — see [signing.md](signing.md)) | Apache-2.0 | [LICENSE](https://github.com/sigstore/cosign/blob/main/LICENSE) |
| `skopeo` | inventory-repositories, secure-container-audit | Apache-2.0 | [LICENSE](https://github.com/containers/skopeo/blob/main/LICENSE) |
| `podman` | inventory-repositories, validate-findings (container adapter), remediate-finding (sandboxed build/test leg, **and** the Phase 4b mutation campaign), property-test (the base-vs-patch differential) | Apache-2.0 | [LICENSE](https://github.com/containers/podman/blob/main/LICENSE) — for the three evidence lanes it is *one of two* acceptable boundaries; a platform-attested sandbox is the other (see the note below), so podman is not a hard requirement on an orchestrated runner |
| `yara` | secure-container-audit (exported rootfs), secure-rpm-audit (prepared source tree) — known-malware-family pre-scan | BSD-3-Clause | [LICENSE](https://github.com/VirusTotal/yara/blob/master/COPYING) — engine only. **Rule packs license separately, see the frameworks table** |
| `checkov` | cloud-config-audit (pinned version, subprocess only — never imported, never vendored; always `--skip-download`, never an API key; `secrets` framework skipped in favour of gitleaks) | Apache-2.0 | [LICENSE](https://github.com/bridgecrewio/checkov/blob/main/LICENSE) — the vendor's SaaS platform is opt-in via API key, which the harness never passes. Checkov's policies are its own Apache-licensed implementations that *map* to CIS and other frameworks — do not add CIS recommendation prose alongside them |
| `bicep` | cloud-config-audit (bicep-transpile fallback, pinned, subprocess only, `bicep build --no-restore`: external registry modules are never fetched) | MIT | [LICENSE](https://github.com/Azure/bicep/blob/main/LICENSE) |
| `pqc-scan` | pqc-readiness — binary built from pinned source by `build_pqc_scan.sh`, invoked by `pqc_facts.py` | MIT | [LICENSE](https://github.com/wakaken/pqc-scan/blob/develop/LICENSE) — rules provenance in the frameworks table |
| `joern` / `joern-parse` / `jimple2cpg` | impact-analysis Java and C/C++ call-site reachability tiers, the taint-flow enumerator, and library-side entry-point expansion (`traust_engine.impact.expand_advisory_entry_points`) — invoked as an external pinned tool, never vendored; emits facts the skill judges, never verdicts. Requires a JDK ≤ 21 (`jimple2cpg`'s bundled bytecode frontend cannot read newer class files), selected per-lane via `JIMPLE_JAVA_HOME` | Apache-2.0 | [LICENSE](https://github.com/joernio/joern/blob/master/LICENSE) |
| `java` (JVM) / `javac` / `jar` (JDK) | runtime for every Joern tier; `java-build` safe-exec profile grants (target build verification) | GPL-2.0 WITH Classpath-exception-2.0 (OpenJDK; Temurin ships the same terms) | [OpenJDK LICENSE](https://github.com/openjdk/jdk/blob/master/LICENSE) — invoked, never redistributed, never linked |
| `go` / `gofmt` (Go toolchain) | create-fuzzing (`go test -fuzz`); pqc-readiness `scan_xcrypto_usage.py --callgraph`; `go-fuzz` safe-exec profile grants; `govulncheck` install | BSD-3-Clause | [LICENSE](https://github.com/golang/go/blob/master/LICENSE) |
| `callgraph` / `digraph` (golang.org/x/tools) | pqc-readiness `scan_xcrypto_usage.py --callgraph` (reachability graph, witness chains) | BSD-3-Clause | [LICENSE](https://github.com/golang/tools/blob/master/LICENSE) — installed with `go install golang.org/x/tools/cmd/<tool>@<pin>` |
| `cargo` / `rustc` (Rust toolchain) | pqc-readiness `build_pqc_scan.sh` (`cargo build --locked`); `rust-fuzz` safe-exec profile grants | MIT OR Apache-2.0 | [LICENSE-MIT](https://github.com/rust-lang/rust/blob/master/LICENSE-MIT) · [LICENSE-APACHE](https://github.com/rust-lang/rust/blob/master/LICENSE-APACHE) |
| `cargo-fuzz` | create-fuzzing Rust targets (runs inside the *target repo's* toolchain; libFuzzer runtime is Apache-2.0 WITH LLVM-exception) | MIT OR Apache-2.0 | [LICENSE-MIT](https://github.com/rust-fuzz/cargo-fuzz/blob/main/LICENSE-MIT) · [LICENSE-APACHE](https://github.com/rust-fuzz/cargo-fuzz/blob/main/LICENSE-APACHE) |
| `jazzer` (JVM, pinned) / `Jazzer.js` | create-fuzzing Java and JS/TS targets (dependencies of generated harnesses in target repos, not of this repo); the Java lane downloads the pinned release with sha256 verification | Apache-2.0 (each) — verified at the pinned tag | [jazzer LICENSE](https://github.com/CodeIntelligenceTesting/jazzer/blob/main/LICENSE) · [jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/LICENSE) |
| `atheris` | create-fuzzing Python targets (imported by generated harnesses in target repos, not by this repo) | Apache-2.0 | [LICENSE](https://github.com/google/atheris/blob/master/LICENSE) |
| `node` / `npm` / `npx` (Node.js) | `node-build` safe-exec profile grants (target build/test steps; Jazzer.js fuzz lane); remediate-finding `run_checks.sh` when the target uses them | MIT (Node.js license, aggregate) / Artistic-2.0 (npm) | [LICENSE](https://github.com/nodejs/node/blob/main/LICENSE) |
| `mvn` / `gradle` | `java-build` safe-exec profile grants (target build verification; the target's own `./gradlew`/`./mvnw` preferred); remediate-finding `run_checks.sh` | Apache-2.0 | [gradle LICENSE](https://github.com/gradle/gradle/blob/master/LICENSE) |
| `kustomize`, `golangci-lint`, `cargo-clippy` | remediate-finding `run_checks.sh` — opportunistic, only if the *target repo* uses them | Apache-2.0 / **GPL-3.0-only** (golangci-lint) / Apache-2.0 (clippy) | [golangci-lint LICENSE](https://github.com/golangci/golangci-lint/blob/main/LICENSE) |
| `tokei` / `scc` / `cloc` | secure-code-audit LoC step (tokei preferred; scc, then cloc as fallbacks) | MIT OR Apache-2.0 / MIT / **GPL-2.0-or-later** (cloc) | [tokei](https://github.com/XAMPPRocky/tokei) · [scc](https://github.com/boyter/scc) · [cloc header](https://github.com/AlDanial/cloc/blob/master/cloc) |
| `universal-ctags` | `build_symbol_index.py` ctags engine (optional; built-in extractors otherwise) | **GPL-2.0-or-later** | [source headers](https://github.com/universal-ctags/ctags/blob/master/main/entry.c) |
| `ast-grep` | fleet-fix structural transforms (`apply_fleet_fix.py`, matcher kind `ast_grep`) | MIT | [LICENSE](https://github.com/ast-grep/ast-grep/blob/main/LICENSE) |
| `gh` | remediate-finding, secure-code-audit (API lookups), the rescan router (`github`-kind hosts) | MIT | [LICENSE](https://github.com/cli/cli/blob/trunk/LICENSE) |
| `glab` | fleet-fix and remediate-finding MR automation (human-gated); the rescan router (`gitlab`-kind hosts) | MIT | [LICENSE](https://gitlab.com/gitlab-org/cli/-/blob/main/LICENSE) |
| `jq` | shell snippets across several skills | MIT (code) + CC-BY-3.0 (docs) | [COPYING](https://github.com/jqlang/jq/blob/master/COPYING) |
| `sqlite3` (CLI + Python stdlib module) | findings.db / portfolio-graph.db projections | Public Domain (SQLite); PSF-2.0 for the stdlib wrapper | [SQLite copyright](https://sqlite.org/copyright.html) |
| `oc` / `kubectl` | inventory-repositories, deploy-operator, validate-findings (cluster adapters); `validation-step` safe-exec profile | Apache-2.0 | [oc](https://github.com/openshift/oc/blob/master/LICENSE) · [kubectl](https://github.com/kubernetes/kubectl/blob/master/LICENSE) |
| `operator-sdk` / `opm` | deploy-operator, inventory-repositories | Apache-2.0 | [operator-sdk](https://github.com/operator-framework/operator-sdk/blob/master/LICENSE) · [operator-registry](https://github.com/operator-framework/operator-registry/blob/master/LICENSE) |
| `aws` (CLI v2) | compliance-check `collect_cloud_inventory.py` (declared cloud inventory export) | Apache-2.0 | [LICENSE](https://github.com/aws/aws-cli/blob/v2/LICENSE.txt) — AWS *service* use is governed separately by AWS service terms |
| `gcloud` (Google Cloud CLI) | pqc-readiness `build_xcrypto_tracker.py --push-sheet` only — mints a short-lived bearer from the operator's own login; never required for the CSV/md outputs | Proprietary (Google Cloud SDK ToS; freely downloadable, not OSS) | [terms](https://cloud.google.com/terms/service-terms) — invoked, never redistributed |
| `gws` (Google Workspace CLI) | reassign-findings-owners (document-share permissions, ownership tracker) | Apache-2.0 | [LICENSE](https://github.com/googleworkspace/cli/blob/main/LICENSE) — README notes it is "not an officially supported Google product" |
| `hypothesis` (+ pinned closure: pytest, pluggy, iniconfig, packaging, pygments, sortedcontainers) | property-test Step 3 (`run_property.sh`) — installed into the throwaway container that runs the differential, never into the harness venv or the target's manifest | **MPL-2.0** (PyPI packaging metadata `license_expression`) | [PyPI](https://pypi.org/project/hypothesis/) · [LICENSE.txt](https://github.com/HypothesisWorks/hypothesis/blob/master/hypothesis-python/LICENSE.txt) — weak copyleft, file-scoped; invoked unmodified as a test dependency, never vendored or redistributed |
| `mewt` | mutation-testing (opt-in; see **Agent skills (runtime plugins)**) — runs a target's own test suite against generated mutants | **AGPL-3.0** | [LICENSE](https://github.com/trailofbits/mewt/blob/main/LICENSE) · [Cargo.toml](https://github.com/trailofbits/mewt/blob/main/Cargo.toml) — subprocess CLI, never linked or redistributed; see the AGPL note below |
| `wasm-tools` / `wasmtime` / `wasmedge` | validate-findings WASM adapter | Apache-2.0 WITH LLVM-exception (OR MIT) / same / Apache-2.0 | [wasm-tools](https://github.com/bytecodealliance/wasm-tools/blob/main/LICENSE-Apache-2.0_WITH_LLVM-exception) · [wasmtime](https://github.com/bytecodealliance/wasmtime/blob/main/LICENSE) · [wasmedge](https://github.com/WasmEdge/WasmEdge/blob/master/LICENSE) |

**Why `hypothesis` sits in this table and not under Python libraries.** It is
never imported by the harness. `run_property.sh` installs the pinned closure
into a disposable container alongside a copy of the target, so it is a
dependency *of the differential run*, not of this package — the same
relationship the CLI tools above have. The whole closure is pinned rather than
resolved: an earlier version used `--no-deps` with a guessed list, missed
`pluggy`, and pytest could not import itself, which the evidence layer read as
a failing property until a precondition check was added.

**AGPL-3.0 and `mewt` (§13).** The usage taxonomy at the top of this document
settles the ordinary case: a subprocess CLI invoking an unmodified binary
creates no linking and no derivation, so even a copyleft tool imposes no
obligation unless a distribution bundles it — and the harness does not bundle
`mewt`. The clause worth recording is **AGPL §13**, which attaches a
source-offer obligation when software is *offered to users over a network*.
`mewt` runs locally and in CI here, so §13 does not attach today; a deployment
that exposed a mutation-testing lane as a hosted service would have to revisit
it before doing so.

**Scope.** `mewt` supports C++, DAML, Go, JavaScript/TypeScript, Rust,
Solidity and Move (README, v4.0.0). It does **not** support Python, which is a
large slice of this portfolio, so mutation results are never portfolio-wide
assurance. This deployment scopes it Go-first via the `mutation-testing`
safe-exec profile; other supported languages are a deliberate later widening,
not an assumed capability.

**Opt-in, not shipped.** The `mewt` roster row lives in the *deployment's*
`$TRAUST_CONFIG_HOME/external-tools.yaml`, not the harness default. That
manifest doubles as the job-image install target, so adding an optional
AGPL engine to the shipped roster would push it into every adopter's image.
Adopters who install the plugin add their own row.

**The execution boundary for evidence lanes, and why podman is optional.**
`run_checks.sh`, `run_mutation.sh` and `run_property.sh` all execute a target
repository's own build/test code — hostile-input execution (rule S10). How
they do it is one deployment setting, `sandbox:` in
`$TRAUST_CONFIG_HOME/execution-boundaries.yaml`:

- **`none`** (default) — direct execution with a scrubbed environment, on a
  disposable copy rather than the worktree the patch diff comes from. What a
  workstation does today, and what an orchestrated runner needs, since a
  locked-down job usually cannot nest a container.
- **`podman`** — nested rootless container, cap-dropped, `no-new-privileges`,
  credential-free, `--network=none`, digest-pinned image.

A configured `podman` mode is **never silently downgraded**: with no working
runtime the lane emits `not_attempted`, because quietly weakening a boundary
someone chose is worse than producing no evidence. Detection is `podman info`,
not `command -v podman` — the client binary exists on a host whose VM is
stopped and in images that ship the CLI with no runtime, and picking podman
there fails every run with exit 125.

The mode that produced a verdict is recorded in each evidence item's
`command` field, so a reader can weigh a nested-podman result differently
from a direct one.

Cluster-provisioning tools (managed-cloud CLIs, installers, deployment
helpers) are **not** harness dependencies. Live validation needs a reachable
cluster named in the rules-of-engagement file; how that cluster is provisioned
is the deployment's concern, and the deployment-specific provisioning skills
carry their own dependency rows in their own repository.

## MCP servers

Consumed as separately-installed servers speaking MCP; the harness contains
none of their code.

| Server | Used by | License | Evidence |
|---|---|---|---|
| github-mcp-server | secure-code-audit, inventory, remediation flows | MIT | [LICENSE](https://github.com/github/github-mcp-server/blob/main/LICENSE) |
| GitLab MCP (zereight/gitlab-mcp) | secure-rpm-audit, ledger/MR flows | MIT | [LICENSE](https://github.com/zereight/gitlab-mcp/blob/main/LICENSE) — community server; a hosted GitLab MCP endpoint is used as a service and its licensing does not attach to clients |
| mcp-atlassian (sooperset) | file-security-defect, Jira flows | MIT | [LICENSE](https://github.com/sooperset/mcp-atlassian/blob/main/LICENSE) — community-maintained, not an Atlassian product |
| playwright-mcp | validate-browser-finding | Apache-2.0 | [LICENSE](https://github.com/microsoft/playwright-mcp/blob/main/LICENSE) |

## Agent skills (runtime plugins)

Claude Code plugins installed per workstation and invoked at runtime. The
harness contains none of their code and adapts none of their prose — the
distinction that keeps a ShareAlike collection usable here (see the content
licenses table below, and rule 6 of the content guard).

| Plugin | Used by | Version at intake | License | Evidence | Risk |
|---|---|---|---|---|---|
| review-walkthrough (marketplace `trailofbits`) | patch, remediate-finding — optional aid for the human-review step; renders a branch diff as a standalone HTML walkthrough | 1.2.2 installed 2026-09-16 (sha a6d1b234198d) | CC-BY-SA-4.0 | [LICENSE](https://github.com/trailofbits/skills/blob/main/LICENSE) · [plugin](https://github.com/trailofbits/skills/tree/main/plugins/review-walkthrough) | **Low while used, not adapted** — invoking it creates no obligation; it reads a git range and writes its own HTML, consuming no harness artifact and writing none |
| mutation-testing (marketplace `trailofbits`) | *no skill consumes it* — operator-facing aid for configuring a campaign and reading survivors interactively. The automated lane depends on the `mewt` binary, not on this plugin | 1.9.1 installed 2026-09-16 (sha a6d1b234198d) | CC-BY-SA-4.0 | [LICENSE](https://github.com/trailofbits/skills/blob/main/LICENSE) · [plugin](https://github.com/trailofbits/skills/tree/main/plugins/mutation-testing) | **Low while used, not adapted** — the skill is a router over `mewt`/`muton`, so the value and the risk both sit in the engine, not the prose |

**Observed drift, 2026-09-16.** Both plugins moved within a day of intake
(1.2.1 -> 1.2.2, 1.9.0 -> 1.9.1). That is the moving-target problem this
section describes, caught by the watcher rather than by chance, and the reason
the versions above are recorded as *installed* with a commit sha rather than
as a pin.

**Freshness.** Plugins have no binary and no `--version`, so
`config/external-tools.yaml` cannot describe them. The roster at
`$TRAUST_CONFIG_HOME/agent-plugins.yaml` drives `check drift`'s
`agent-plugins:*` rows instead: declared-but-absent reports `pending`,
installed-behind-the-marketplace reports `stale`. Neither auto-advances a
version — upstream can change a skill's behaviour *and* its licence terms
between releases, so a `stale` row means re-read this table, not just
`/plugin update`.

**What actually depends on what.** `remediate-finding` Phase 4b
(`run_mutation.sh`) invokes the **`mewt` binary** directly; it does not call
the `mutation-testing` plugin, which ships prose rather than code. So the
automated lane's hard dependency is the `mewt` row under CLI tools, and the
plugin is an operator-facing aid — worth having for interactive campaign
setup and for reading survivors, but nothing breaks without it. Its roster
`consumers` is empty on purpose.

The lane lives in `remediate-finding` because the integration plan's original
target, `patch`'s regression step, is not permitted by the code: `patch`'s static mode cannot execute target code (its own
guidance redirects build/test-verified work here) and its execution-verified
mode delegates wholly to the C/C++ ASAN pipeline ladder. `remediate-finding`
runs a repo's own build/test suite, so it is the only existing home.

The lane emits a typed `evidence[]` item (`kind: mutation`) into the
remediation report rather than prose, and runs inside Phase 4's container
boundary with no native fallback — mewt executes target tests once per mutant,
and Phase 4 already records that PATH shims are not a boundary. Absent mewt or
podman it emits `not_attempted: <reason>`, which is a valid evidence item
rather than a silent skip.

## Vulnerability-data feeds & web APIs

Code and data license differently — all these feeds permit free
*consumption at runtime*; attribution obligations trigger only if the data is
**republished**.

**The machine-readable registry is [`config/feeds.yaml`](../config/feeds.yaml)** —
every source, cached or live, with its endpoint, cadence, licence block, and
consumers. The feed fetcher, the advisory fetcher, and `check_drift.py`
(`feeds:*` freshness + `feed-source:*` liveness) all read it, so adding a
source is a config change and a dead source is a failing row. The table below
is the licensing companion, not a second source of truth. HTTP endpoints are
not covered by the docs gate's subprocess scan — a new feed adds a row here at
intake.

| Feed / API | Used by | Terms | Evidence | Notes |
|---|---|---|---|---|
| Vendor CSAF VEX (Red Hat: `access.redhat.com/security/data/csaf/v2/vex/`) | `fetch_feeds.py --feed vex` (index) + lazy per-CVE load → `/impact-analysis`, `/triage` | CC-BY-4.0 | [Red Hat security data](https://access.redhat.com/security/data) | Per-CVE product impact status (`known_affected`, `fixed`, `known_not_affected` with justification flags). CVE-keyed; the `advisories/` endpoint is advisory-id-keyed (next row). Index synced; documents fetched on demand and cached |
| Vendor CSAF advisories (Red Hat: `access.redhat.com/security/data/csaf/v2/advisories/`) | secure-rpm-audit, container CVE context, `fetch_advisory.py redhat-csaf` | CC-BY-4.0 | [security data page](https://access.redhat.com/security/data) | Attribute the vendor when distributing. Advisory-id-keyed and year-partitioned |
| Vendor CVE data (Red Hat: `access.redhat.com/hydra/rest/securitydata/cve.json`) | `fetch_feeds.py --feed rh-cve` → first-discovery reconciliation | CC-BY-4.0 | [Red Hat security data](https://access.redhat.com/security/data) | Attribute when redistributing. Public endpoint, paginated and incremental from a stored watermark |
| grype vulnerability DB (grype.anchore.io) | secure-container-audit, secure-code-audit SBOM step | **No published license/ToS** — provided "at no cost to users" | [Anchore docs](https://oss.anchore.com/docs/guides/vulnerability/database/) | The one undocumented feed; obtain written terms before redistributing a product that depends on it |
| Go vulnerability DB (vuln.go.dev) | govulncheck runs | CC-BY-4.0 | [copyright](https://vuln.go.dev/copyright) | Attribute if republishing records |
| OSV.dev | osv-scanner, secure-rpm-audit, the CVE-replay monitor, fork-advisory lag, `fetch_advisory.py` | Pass-through: each record keeps its home DB's license (mostly CC-BY-4.0; some CC0/MIT/BSD) | [data docs](https://google.github.io/osv.dev/data/) | Free unauthenticated API; attribute the source DB when reproducing advisory text |
| NVD CVE API | `fetch_advisory.py` → impact-analysis advisory ingestion | Free public API; attribution requested ("This product uses the NVD API but is not endorsed or certified by the NVD"); rate limits apply without an API key | [NVD terms](https://nvd.nist.gov/developers/terms-of-use) | US-Gov data, no content license on records; consumed at runtime, not republished |
| OpenSSF Scorecard API | secure-code-audit, secure-rpm-audit | CDLA-Permissive-2.0 (data); Apache-2.0 (code) | [repo](https://github.com/ossf/scorecard) | Essentially no downstream obligations |
| FIRST EPSS scores | `fetch_feeds.py` cache → CVE-finding enrichment | Free to the public incl. commercial products; "appropriate attribution" requested | [EPSS FAQ](https://www.first.org/epss/faq) | Cite "EPSS at https://www.first.org/epss" wherever scores are rendered |
| CISA KEV catalog | `fetch_feeds.py` cache → CVE-finding enrichment | **CC0-1.0** (no CISA/DHS logo use or endorsement implication) | [license.txt](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | Third-party links inside KEV records carry their own terms |
| GitHub REST API (`/languages`, commits, compare) | secure-code-audit, loc-dashboard, the rescan router | GitHub ToS | [docs](https://docs.github.com/en/rest) | Service terms, not a content license |
| Credential-liveness probe endpoints (GitHub `/user`, GitLab `/api/v4/user`, Slack `auth.test`, OpenShift `users/~`, AWS `sts:GetCallerIdentity`) | validate-findings `credential_liveness.py` | Each service's ToS / API terms | [GitHub](https://docs.github.com/en/rest) · [GitLab](https://docs.gitlab.com/ee/api/) · [Slack](https://api.slack.com/methods/auth.test) | **No harness-owned tokens** — each probe authenticates with the discovered candidate credential itself, one read-only introspection call, explicit-only scope unlock. Keep probing inside the engagement's authorization, which the scope guard enforces |
| Deployment-internal registries and services (product registry, directory service, dist-git lookaside cache) | owner skills, SLA view, defect filing, secure-rpm-audit | Internal to the deployment — no third-party licence surface | — | Network-gated; excluded from `--feed all`; cache-only, never vendored. Configured per deployment |

## Security frameworks & content licenses

The licensing-critical table. Three usage categories, in increasing risk
order: **(a)** citing IDs/names in emitted reports (`CWE-79`, `CIS 1.2.3`,
`PEACH-P`) — uniformly safe, facts and short identifiers are not copyrightable
expression; **(b)** reproducing/adapting framework text inside skill prompt
files — the prompt files are distributed content, so content licenses bind;
**(c)** embedding in a commercial product — same as (b) plus NonCommercial
clauses activate.

Two content clauses bite in category (b) for different reasons, and the
content guard detects both: **NonCommercial** (rule 1) blocks
commercialization, **ShareAlike** (rule 6) blocks relicensing under
Apache-2.0. ShareAlike is survivable when excerpts stay delimited and
attributed — that is why the OWASP rows below are Low — and is a blocker
when a whole BY-SA work is adapted.

| Framework | Used by | License / Terms | Evidence | Risk |
|---|---|---|---|---|
| OWASP ASVS v5.0 | secure-code-audit, secure-rpm-audit, vuln-scan | CC-BY-SA-4.0 | [LICENSE](https://raw.githubusercontent.com/OWASP/ASVS/master/LICENSE.md) | **Low** — attribution + ShareAlike on *adapted excerpts only*; keep them delimited and attributed so SA stays scoped |
| OWASP Kubernetes Top 10 (2025) | secure-code-audit | CC-BY-SA-4.0 | [LICENSE](https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/master/LICENSE) | **Low** — same as ASVS |
| OWASP Risk Rating Methodology | threat-model, threat-register, findings-trends | CC-BY-SA-4.0 | [owasp.org site footer](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) ("all content on the site is Creative Commons Attribution-ShareAlike v4.0") | **Low** — the method is reimplemented in original wording, and its example scales aren't reproduced; cite it, and keep any future excerpt delimited and attributed |
| CIS Kubernetes Benchmark v2.0 | secure-code-audit | CIS non-member ToU: internal, **non-commercial** use only; no derivatives; no incorporation into commercial products | [CIS ToU](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products) | **High** for any commercial embedding of benchmark-derived text (requires a CIS SecureSuite Product Vendor membership). ID-only citations remain safe — and are all the harness emits (enforced, see below) |
| DISA STIG for Kubernetes | secure-code-audit | US Government work — public domain (17 U.S.C. §105) | [§105](https://www.law.cornell.edu/uscode/text/17/105) · [cyber.mil](https://public.cyber.mil/stigs/) | **None** — avoid implying DoD endorsement |
| NIST SP 800-53 rev 5 + SP 800-53B baselines (OSCAL) | compliance-check (canonical spine) | CC0-1.0 / US-Gov public domain | [LICENSE.md](https://github.com/usnistgov/oscal-content/blob/main/LICENSE.md) | **None** — provenance (upstream sha256, retrieval date) recorded next to the vendored derivations |
| FedRAMP rev 5 baselines (OSCAL) | compliance-check (FedRAMP High/Moderate overlays) | US-Gov public domain — the authoritative OSCAL source was decommissioned; community mirrors fail the provenance bar | — | Interim posture: NIST 800-53B Moderate/High selections, labelled as such, until a provenance-grade overlay source is available |
| PCI DSS v4.x | compliance-check (requirement-ID citations only) | **PCI SSC copyright — no open license** | [PCI SSC document library terms](https://www.pcisecuritystandards.org/document_library/) | Bare requirement IDs only, never standard text — enforced by the content guard |
| GDPR (Regulation (EU) 2016/679) | compliance-check (technical-slice catalog) | EUR-Lex reuse: permitted incl. commercial; attribution for editorial content (CC-BY-4.0); metadata CC0 | [EUR-Lex legal notice](https://eur-lex.europa.eu/content/legal-notice/legal-notice.html) | **Low** — law text reproducible; legal compliance judgment stays with counsel |
| SOC 2 / AICPA Trust Services Criteria | compliance-check (criterion-ID citations only) | **AICPA copyright, all rights reserved** | AICPA TSC publications (aicpa-cima.com) | Bare criterion IDs only ("TSC CC6.1"), never criteria text — enforced by the content guard; reference PDFs stay local, never vendored |
| SLSA v1.2 | secure-code-audit, secure-rpm-audit, secure-container-audit | Community Specification License 1.0 | [LICENSE](https://raw.githubusercontent.com/slsa-framework/slsa/main/LICENSE.md) | **Low** — attribution on derivatives; defensive patent-termination clause |
| OpenSSF Scorecard | secure-code-audit, secure-rpm-audit | Apache-2.0 (code) / CDLA-Permissive-2.0 (data) | [repo](https://github.com/ossf/scorecard) | **None** |
| PEACH tenant-isolation framework | secure-code-audit, security-audit-phased (methodology reference) | Upstream content is NonCommercial and self-contradictory (repo `LICENSE.md` CC-BY-NC-**ND**-4.0; README badge and site CC-BY-NC-**SA**-4.0). The harness reproduces none of it: its PEACH sections are original text citing only the methodology, parameter names, and IDs | [LICENSE.md](https://github.com/wiz-sec-public/peach-framework/blob/main/LICENSE.md) · [README](https://github.com/wiz-sec-public/peach-framework/blob/main/README.md) | **Low** while the text stays original — enforced by the content guard |
| Agent-skill collections under CC-BY-SA (e.g. [trailofbits/skills](https://github.com/trailofbits/skills)) | *none adapted* — runtime use only (plugin install / tool invocation); adopted plugins are listed under **Agent skills (runtime plugins)** above | CC-BY-SA-4.0 | [LICENSE](https://github.com/trailofbits/skills/blob/main/LICENSE) | **Low while used, not adapted.** Running a BY-SA skill creates no obligation; copying or adapting its prose into a SKILL.md would, since BY-SA 3(b) demands a CC ShareAlike Adapter's License and Apache-2.0 is not one. Reimplementation from the ideas in original wording is permitted (BY-SA covers expression, not concepts) — cite the upstream as prior art. Provenance markers outside the licensing docs are enforced by the content guard (rule 6) |
| SEI CERT C/C++ Coding Standards | secure-rpm-audit, secure-code-audit (language-conditional lens) | CMU copyright: verbatim whole reproduction + internal derivatives free; other external/commercial use needs written permission | [terms in standard PDF](https://resources.sei.cmu.edu/downloads/secure-coding/assets/sei-cert-c-coding-standard-2016-v01.pdf) | **Medium** — rule IDs + titles + own paraphrase are fine; verbatim rule bodies/examples need permission |
| SEI CERT Oracle Coding Standard for Java | secure-code-audit (language-conditional lens; the Java rule pack cites rule IDs in `metadata.cert` — patterns and text original to the pack) | CMU copyright, same terms | [published standard](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/) | **Medium** — rule IDs + titles + own paraphrase only; never import compliant/noncompliant example code |
| Fedora Packaging Guidelines | secure-rpm-audit | CC-BY-SA-4.0 | [Fedora content license](https://communityblog.fedoraproject.org/fedoras-default-license-for-content-is-now-cc-by-sa-4-0/) | **Low** |
| CWE (MITRE) | all audit skills | CWE ToU: royalty-free incl. commercial; reproduce MITRE copyright notice with copied content | [ToU](https://cwe.mitre.org/about/termsofuse.html) | **None** |
| CAPEC (MITRE) | audit skills (`capec` field) | CAPEC ToU: royalty-free incl. commercial; carry MITRE notice; derivative right not explicit — prefer verbatim-with-notice or ID-only | [ToU](https://capec.mitre.org/about/termsofuse.html) | **None** |
| MITRE ATT&CK (Enterprise) | `harnessing/attack-coverage/` — vendored distilled technique/mitigation table built from one sha256-pinned STIX release; technique IDs cited in validation reports, threat models, and the coverage layer | ATT&CK Terms of Use: royalty-free use, reproduction, and distribution incl. commercial, with attribution and the MITRE copyright statement carried | [ToU](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | **None** — attribution statement embedded in the vendored table and every emitted layer |
| CVSS v3.1/v4.0 (FIRST) | all audit skills | Open standard: free use with attribution to FIRST, scoring per official spec, **vector string published alongside every score** | [spec](https://www.first.org/cvss/v3-1/specification-document) | **None** — the schema's `cvss.vector` requirement satisfies the disclosure condition |
| **Harness-authored opengrep rule pack** (the default) | `run_opengrep.py` default ruleset — `harnessing/3-audit/secure-code-audit/opengrep-rules/`, mined from the deployment's own ledger-confirmed findings | Same license as the harness | in-tree | **None** — own IP; framework citations by ID only, messages in the harness's own words |
| argus-observe-rules (contributor pack) | `run_opengrep.py` **opt-in supplement** — fetched at run time to the user cache, pinned by SHA, never vendored; individual rules enabled per deployment via `$TRAUST_CONFIG_HOME/rule-pack-allowlist.yaml` | MIT | [LICENSE](https://github.com/smith-xyz/argus-observe-rules/blob/main/LICENSE) | **Low** — MIT permits internal use, redistribution and commercial use with attribution; the notice stays with the upstream clone and the pack's licence is recorded in `metadata.tools` per run |
| ReversingLabs YARA rules | `run_yara.py` **default malware-family pack** for secure-container-audit / secure-rpm-audit — fetched at run time to the user cache, pinned by SHA, never vendored | MIT | [LICENSE](https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE) | **Low** — MIT; rolling `develop` branch, so the SHA pin is a deliberate bump watched by the `yara-rules-pin` drift row |
| pqc-scan rules (wakaken/pqc-scan) | pqc-readiness — vendored default rules snapshot (`rules/*.yml`) alongside the pinned binary; supplemented by a harness-owned pack | MIT | [LICENSE](https://github.com/wakaken/pqc-scan/blob/develop/LICENSE) | **Low** — MIT permits vendoring, modification, and redistribution with attribution |

**Rule-pack contract.** `run_opengrep.py` runs the harness-authored pack by
default and accepts supplements only as SHA-pinned, permissively-licensed,
never-vendored inputs whose licence is recorded per run. It refuses
`--config auto` and does not use Semgrep-maintained registry rules, whose
licence restricts use to internal business purposes and forbids distribution;
adopting any new pack goes through `/check-licensing` and adds a row here.

**Content-license rules enforced mechanically** by
`python3 -m traust.cli check content-licenses` (the deterministic core
of `/check-licensing`; run standalone, by the pre-push hook, and by the test
suite):

1. **CIS: identifiers only.** Emitted reports and skill text cite bare CIS
   section IDs; CIS recommendation-text signatures fail the build.
   `validate_report.py --strict` additionally warns when a finding's
   description or remediation matches CIS recommendation-title phrasing.
2. **PEACH: keep it original.** The PEACH sections were rewritten as original
   text; fingerprint phrases from the upstream adaptation fail the build, and
   NonCommercial license markers may appear only in the files that discuss
   licensing (this one and the changelog).
3. **PCI DSS and AICPA TSC: identifiers only.** Standard text and criteria
   text signatures fail the build.
4. **Every `pyproject.toml` dependency has a row here**, and so does every
   CLI tool the code invokes (checked by the docs gate). Adding a dependency
   without its intake row fails the build.

Extend the guard's pattern lists when a new protected content class enters the
harness — never edit them to make a violation pass.

## Citations

Formal citations for the frameworks the harness applies:

- OWASP Foundation. *OWASP Application Security Verification Standard*, v5.0. https://owasp.org/www-project-application-security-verification-standard/ — CC-BY-SA-4.0.
- OWASP Foundation. *OWASP Kubernetes Top 10*, 2025 edition. https://owasp.org/www-project-kubernetes-top-ten/ — CC-BY-SA-4.0.
- OWASP Foundation. *OWASP Risk Rating Methodology*. https://owasp.org/www-community/OWASP_Risk_Rating_Methodology — CC-BY-SA-4.0.
- Center for Internet Security. *CIS Kubernetes Benchmark*, v2.0. https://www.cisecurity.org/benchmark/kubernetes — CIS Terms of Use (non-member).
- Defense Information Systems Agency. *Kubernetes Security Technical Implementation Guide*, V2R6. https://public.cyber.mil/stigs/ — US Government work.
- OpenSSF / The Linux Foundation. *SLSA: Supply-chain Levels for Software Artifacts*, v1.2. https://slsa.dev/ — Community Specification License 1.0.
- OpenSSF. *Scorecard*. https://securityscorecards.dev/ — Apache-2.0 (code), CDLA-Permissive-2.0 (data).
- Wiz, Inc. *PEACH: A Tenant Isolation Framework for Cloud Applications*, v1.1 (2022). https://peach.wiz.io — cited as the source of the methodology only; the harness's PEACH sections are original text and reproduce no Wiz-authored content (upstream content licensing: repo LICENSE.md BY-NC-ND-4.0 vs README/site BY-NC-SA-4.0).
- Software Engineering Institute, Carnegie Mellon University. *SEI CERT C Coding Standard* and *SEI CERT C++ Coding Standard*. https://wiki.sei.cmu.edu/confluence/display/seccode — CMU copyright, permission-based reuse.
- Software Engineering Institute, Carnegie Mellon University. *SEI CERT Oracle Coding Standard for Java*. https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/ — CMU copyright, permission-based reuse; cited by rule ID with original paraphrase only.
- Fedora Project. *Fedora Packaging Guidelines*. https://docs.fedoraproject.org/en-US/packaging-guidelines/ — CC-BY-SA-4.0.
- The MITRE Corporation. *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/ — CWE Terms of Use.
- The MITRE Corporation. *Common Attack Pattern Enumeration and Classification (CAPEC)*. https://capec.mitre.org/ — CAPEC Terms of Use.
- The MITRE Corporation. *MITRE ATT&CK®*. https://attack.mitre.org/ — ATT&CK Terms of Use.
- FIRST.Org, Inc. *Common Vulnerability Scoring System*, v3.1/v4.0. https://www.first.org/cvss/ — open standard, attribution required.
