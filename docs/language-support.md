# Language support — what the harness covers, per capability layer

The harness has two distinct layers of language support, and the distinction
matters more than any single table cell:

1. **The agentic core is language-agnostic.** `/secure-code-audit`,
   `/threat-model`, `/triage`, `/vuln-scan`, `/patch`, and
   `/verify-remediation` read whatever the repository contains and apply the
   same framework mappings and evidence standards. Any language the model can
   read is auditable; Go, Python, Java, JavaScript/TypeScript, C/C++, Rust,
   Ruby, shell, and configuration/IaC languages have all been audited.
2. **Deterministic depth is per-language.** Rule packs, reachability engines,
   fuzzers, and manifest analyzers are built and calibrated per ecosystem.
   This is where languages differ, and where the tables below apply.

Each cell names the tool that provides the capability, so the table can be
checked against the tree: the rule pack the security pack ships
(`packs/security/detection/opengrep-rules/`), the impact tiers in
traust-core (`providers/impact.py`), the fuzz templates under
`harnessing/6-fuzz/create-fuzzing/harnesses/_templates/`, and the tool rows in
[external-dependencies.md](external-dependencies.md).

## Capability matrix

| Capability | Go | Java | C/C++ | Python | JS/TS | Rust | Shell | K8s/YAML/IaC |
|---|---|---|---|---|---|---|---|---|
| Agentic audit / triage / threat model | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Opengrep rule pack (`harness-*`, harness-authored) | ✅ | ✅ | — | ✅ | ✅ (TypeScript) | — | ✅ (bash) | ✅ (YAML) |
| Dependency manifests (`/impact-analysis`, portfolio-graph L1, deps lane, osv) | `go.mod`/`go.sum` | `pom.xml`, Gradle | — (no lockfile ecosystem; header-include grep + SBOM) | requirements, Pipfile, poetry, pyproject | package-lock, yarn | `Cargo.lock`/`Cargo.toml` | — | — |
| CVE reachability tier | govulncheck — **sound in both directions** | symbol-usage scan (manifest + source grep); **no call-graph tier** | Joern c2cpg call-site tier (**promotion-only**) + ELF `DT_NEEDED`/string scans of shipped binaries | symbol-usage scan | symbol-usage scan | symbol-usage scan | — | — |
| Fuzzing (`make fuzz-<id>`) | native `go test -fuzz` (default lane) | jazzer (pinned release) | — | atheris | Jazzer.js | cargo-fuzz (nightly) | — | — |
| Symbol index (triage / diff-scan callers) | built-in + ctags | ctags | ctags | built-in + ctags | built-in + ctags | ctags | built-in (sh) | — |
| Portfolio-graph L4 symbols (tree-sitter) | ✅ | — | — | ✅ | ✅ (ts/tsx/js) | — | — | — |
| Crypto / PQC census (`/pqc-readiness` capability notes) | ✅ Go stdlib | ✅ JDK | ✅ OpenSSL, BoringSSL, AWS-LC, GnuTLS, NSS | ✅ | ✅ Node | ✅ rustls, native-tls | — | RHEL crypto-policies; .NET and Ruby notes also ship |
| Sanitizer micro-probe (deep-FN technique) | — | — | — | ✅ | — | — | — | — |
| Route-guard enumerator | ✅ `net/http`, gorilla-mux, chi/echo/gin-style routers | — | — | ✅ Django / DRF, Flask (incl. Flask-RESTful / flask-restx) | — | — | — | — |
| Config/manifest deep tools | — | — | — | — | — | — | — | Kubernetes-hardening catalog, checkov (Terraform/CloudFormation/ARM+Bicep/Kubernetes/Helm/Dockerfile), config-matrix expander (Helm values, compose, Kubernetes env), YAML rule pack |

Web frameworks the route-guard enumerator does not model (Express,
FastAPI, Spring) are emitted as explicit coverage gaps so the audit's negative
results can say so rather than imply coverage.

**Ruby and C#/.NET** are not matrix columns (no rule pack, reachability engine,
or fuzzer), but their dependency manifests are covered like the columns above:
RubyGems via `Gemfile.lock`/`Gemfile` (+ `*.gemspec`) and NuGet via
`packages.lock.json` (+ `*.csproj`), feeding the same `pkg:<eco>/<name>` node
scheme, ecosystem-tagged `depends_on` edges, and `/impact-analysis --ecosystem`
seeding. Both also have PQC capability notes.

**Three dependency surfaces are path-discovered rather than language-gated** —
found by walking the tree for their manifest filename (`Dockerfile*`,
`.github/workflows/*.y{,a}ml`, `Chart.yaml`) regardless of the repo's
language: Docker base images (`FROM`), GitHub Actions (`uses:`), and Helm chart
dependencies. All three feed the graph and `/impact-analysis --ecosystem`
seeding, but only **GitHub Actions has an OSV CVE lane** (actions advisories
are OSV-native, so `/dependency-watch` covers them like any ecosystem).
**Docker and Helm are graph/blast-radius surfaces only**: no OSV ecosystem
covers a base-image tag or a chart version, so their vulnerability lane is the
container-SBOM/grype path (`/secure-container-audit`), and
`/impact-analysis --ecosystem docker|helm` caps at `likely_affected`.

Packaging/artifact layers are language-independent: containers
(skopeo/syft/grype via `/secure-container-audit`), RPM dist-git
(`/secure-rpm-audit` — spec/scriptlets/patches, SEI CERT lens for the prepared
C tree), SBOM cross-checks, and the YARA malware-family pre-scan over exported
root filesystems and source trees.

## Reading the reachability row honestly

- **Go / govulncheck** is sound in both directions: `symbol_reachable`
  promotes to `affected`, and `not observed` verdicts can demote.
- **Java has no call-graph reachability tier**, and that is structural: Java
  resolves calls through interfaces, so a static call graph cannot connect an
  application's interface call to the library-internal implementation an
  advisory names. A Joern-based tier was built, measured at zero promotions on
  a full advisory sweep, and withdrawn (the structural note in
  [reachability.md](reachability.md) records why). Java advisories cap at
  symbol-usage evidence. (The library-side entry-point expansion was retired:
  nothing read its output.)
- **C/C++ / Joern** is **promotion-only** by design: a found direct call site
  upgrades evidence (`symbol` tier, `affected` with witness); an absent path
  proves nothing (function-pointer dispatch hides edges). File and caller
  function are the authoritative anchors; line numbers are approximate. The
  tier is verified against direct-call ground truth but has not been measured
  on a real advisory corpus, because C/C++ vulnerabilities reach the harness
  through the container-SBOM/grype lane rather than lockfile ecosystems.
- **Everything else** caps at manifest or symbol-usage evidence — the ceiling
  is `likely_affected`, never auto-`affected`. A pin is never reachability.

## Limitations

- **Python, JS/TS, and Rust have no symbol-level reachability engine.** Joern
  frontends for Python and JavaScript exist upstream but are less mature than
  the Java and C frontends and would need a facts-only wrapper validated
  against a ground-truth corpus before default use; given the Java result, the
  first question for any dynamically-dispatched language is whether static
  reachability is achievable at all. `/drift-watch`'s `reachability-coverage`
  rows flag any language dominant across many repos with no engine, so the gap
  is tracked, not just documented.
- **No in-repo C/C++ fuzz lane.** `make fuzz-<id>` covers Go, Java, Python,
  JavaScript/TypeScript, and Rust. C targets need an external fuzzing pipeline.
- **No Rust or C/C++ opengrep tranche.** Agentic review and, for C, the SEI
  CERT lens via `/secure-rpm-audit` carry the load.
- **Taint-flow enumeration is not wired into any skill.** The source-to-sink
  enumerator (`traust.ops.enumerate_taint_flows`, Java servlet and
  C read/recv/getenv families) exists as an opt-in tool pending calibration
  against a precision bar; no audit profile invokes it.
- **Route-guard and sanitizer enumerators are narrow by design.** Route guards
  cover Go HTTP routers, Django/DRF and Flask; the sanitizer probe is Python-only.
  Other frameworks surface as coverage gaps.
- **Symbol index depth varies.** The built-in extractor handles Go, Python,
  TypeScript/JavaScript, and shell definitions; every other language needs
  Universal Ctags on the path, otherwise verifiers fall back to grep.

## Adding a language's deterministic depth

Follow the established patterns: an `ImpactAnalyzer` provider in
traust-core (`providers/impact.py`) for dependency analysis; a
`harnesses/_templates/` entry plus a Makefile lane for fuzzing; an opengrep
tranche mined and calibrated through `/mine-ledger`; a tree-sitter grammar wheel
(verified individually, see the licensing inventory) for graph symbols; and,
for anything Joern-backed, a facts-only wrapper validated against a
ground-truth corpus before default use — with the measured promotion rate, not
"the mechanism works", as the admission criterion.
