# safe_exec — the target-build sandbox

python3 -m traust.cli util safe-exec is the enforced command validator
every harness step uses when it executes something derived from an **audited
checkout** — build systems, test suites, scanners that load target code, and
string-form PoC steps in live validation. Gate rule **S10**
(python3 -m traust.cli check skill-security) makes routing
through it mandatory at commit time: a skill or script that invokes target
build machinery without referencing safe_exec fails the pre-commit and CI
gates.

The design keeps the containment that matters for an auditing harness — argv
allowlisting, env scrubbing, and shell-free execution — and deliberately does
not deny scripting engines or `git clone` outright, because cloning and
building targets is the harness's core function.

## Threat model

A repository under audit is hostile code. Its Makefile, `go.mod` directives,
npm lifecycle scripts, and build tags run with whatever the invoking process
holds — ambient cloud credentials, `GITHUB_TOKEN`, kube contexts. safe_exec
bounds that in three ways:

1. **Argv validation** — the command's head binary must be granted by the
   active profile; shells are never grantable (pipelines execute natively via
   subprocess chaining, so a quoted newline or `;` is data, not a second
   command). Hard-denied binaries, dangerous `git -c` keys, git network
   subcommands, curl exfil flags (`-F`/`-T`/`-d @`/`--config`/`--netrc`/
   `file://`), and kubectl/oc override flags (`--kubeconfig`/`--context`/
   `--token`/`--as`) are rejected regardless of profile.
2. **Env scrubbing** — the child sees a minimal environment plus the profile's
   `keep_env` allowlist. A hostile build cannot read tokens that were never
   in its environment. Assignments to protected vars (`GIT_*`, PATH, LD_*, …)
   in command strings are rejected.
3. **No shell, ever** — commands and pipelines are parsed and executed as
   argv vectors. `safe_exec` may not re-invoke itself, and interpreter heads
   (`python3 -c`, `node -e`) are denied unless the profile grants the
   interpreter explicitly.

## Repo-config isolation for headless agents

The same threat has a second execution surface: the agent runtime itself. A
target repository can ship its own agent configuration — `.claude/`,
`CLAUDE.md`, hooks, settings — and an agent launched with its working
directory inside the clone will load that configuration and run the target's
hooks with the auditor's credentials. So every headless or batch agent launch
runs with:

- its **working directory outside the untrusted checkout** (a scratch
  directory; the clone is passed as a path argument), and
- **target-supplied agent configuration never loaded as configuration** — it
  is data under audit, read by the analysis and never honoured by the runtime.

Gate rule **S9** enforces this at commit time: any file that launches a
headless agent must state the isolation. This is the execution-side half of
the adversarial-content doctrine
([adversarial-content-doctrine.md](adversarial-content-doctrine.md) rule 4);
the doctrine says why, this section says what the launch must look like.

## Profiles

Policy lives in **`$TRAUST_CONFIG_HOME/safe-exec-profiles.yaml`** (an embedded
fallback copy of the `validation-step` profile lives in the module — keep them
in sync; the harness ships the template as
`config/safe-exec-profiles.example.yaml`). Each profile declares `allow`
(binary heads), optional `allowed_path_heads` (e.g. `./gradlew`),
`allow_pipelines`, `keep_env`, and optionally `keep_env_heads` (which segment
heads receive `keep_env`), `curl_allowed_hosts` and `posture`.
Current profiles and their consumers:

| Profile | Used by | Notes |
|---|---|---|
| `validation-step` | validate-findings adapters (string-form PoC steps) | pipelines allowed; `KUBECONFIG` + `VF_OAUTH_TOKEN` kept (the token keeps bearer-auth probes sound) |
| `go-scan` | python3 -m traust.cli adapters govulncheck | govulncheck type-checks and builds the target module — hostile build tags/cgo see only the scrubbed env |
| `go-fuzz`, `java-build`, `python-test`, `node-build`, `rust-fuzz`, `generic-build` | build/test lanes (fuzz-harness and patch-verification steps) | dependency-manager egress from build tools is accepted residual risk: safe_exec constrains argv and environment, not child-process sockets; hermetic prefetch is a deferred hardening |

### Security postures and curl host posture

Safe-exec provides a posture framework modeled on Kubernetes Pod Security Standards:

| Posture | Alias | Egress / Host Semantics | Environment & Redirects |
|---|---|---|---|
| `restricted` | `high` | **Fail closed**: Every curl URL is denied unless its destination is listed in `curl_allowed_hosts` or passed at call time (ROE hosts). | Redirects denied. `keep_env_heads` required on pipelines when env vars are kept. |
| `baseline` | `medium` | **Public allowed, private denied**: Public http/https egress is permitted. Non-global IP ranges (RFC 1918, loopback, link-local/cloud metadata 169.254.169.254) and internal domains (.local, .internal, .cluster.local, localhost) are denied unless explicitly allowlisted. | Redirects denied. `keep_env_heads` enforced when pipelines and env vars are present. |
| `privileged` | `low` | **Fail open**: Unrestricted destinations; empty host list allows any destination. | Redirects allowed when host list is empty. Legacy default. |

Static config cannot name a per-engagement lab cluster. Keep the restricted
profile's static list empty and declare authorization in `targets.yaml`.
`clusters[].api` and explicit `http_targets` provide hosts for command-text probes.
Structured HTTP probes resolve a single endpoint, check resource scope and pass
only that endpoint to safe_exec. Reproduce a host verdict with `--allowed-host`.

### Engagement HTTP authorization

The [targets template](../harnessing/5-validate/validate-findings/targets.example.yaml)
contains optional `http_targets` and per-cluster `http_discovery` fields. These
are explicit-only grants; finding text and inferred scope cannot populate them.

- `http_targets`: exact host, required cluster `context`, optional `namespace`,
  `resource` and `name`, and an independent `credentials` permission.
- `http_discovery.routes`: concrete namespace, optional exact resource `names`,
  approved DNS `domains`, and optional `credentials`. Domain boundaries use a
  DNS-label boundary, not an arbitrary suffix. A discovered hostname is not a grant.
- `http_discovery.nodes`: optional exact `names`, permitted CIDR `networks`, and
  `address_types` (defaults to InternalIP). This narrowly authorizes node reads
  and HTTP probes without adding a wildcard namespace grant.
- `http_discovery.port_forward_credentials`: permits authenticated probes through
  authorized, adapter-owned Pod tunnels. Default false.
- `http_discovery.kube_env`: explicit environment variable names needed by a
  kubeconfig exec-auth plugin when opening a tunnel. No additional variables
  are preserved by default.
- `http_discovery.ca_bundle`: operator-owned CA file for lab TLS. Verification
  stays enabled by default. `insecure_tls: true` is an explicit engagement-only
  exception, never inferred from a finding.
- `http_discovery.session_check_path`: origin-relative identity endpoint that
  returns 2xx only for an authenticated session. Required for authenticated CSRF
  probes; a login page or CSRF cookie alone is not proof of authentication.

Discovery uses the named kubeconfig context and checks any declared API against
that context. Collection reads require `list`, named reads require `get`;
expiry, verb denies and off-limits rules continue to apply. Ambiguous endpoints,
RBAC failures, malformed responses and unauthorized destinations fail closed.
Route/console probes use scoped route discovery; kubelet probes use scoped node
addresses. Service discovery selects a matching Pod and resolves the Service's
target port. The adapter owns the ephemeral local port, readiness deadline and
cleanup. Loopback is not an engagement-wide grant. Service transport defaults to
HTTP unless Service port metadata identifies HTTPS; a reviewed request can select
its scheme explicitly. TLS tunnels retain the service DNS identity and pin the
connection to the owned local port. Proxy environment variables cannot redirect
structured requests.

Generated HTTP plans contain `target.http` rather than shell programs. The request
includes mode, method, relative path, transport, optional port, concrete namespaces
and selection hints. Authentication and CSRF are explicit request options and
require a credential grant; anonymous probes remain anonymous. Token creation
also requires permission for `create serviceaccounts/token`. Console session
cookies stay in memory. HTTP DELETE requires destructive permission; other write
methods are classified as mutating and checked against the corresponding verb.
No shell execution, redirect following or arbitrary cookie-file writes are enabled.
Direct structured cluster-API requests are limited to GET/HEAD health and version
endpoints; Kubernetes resource requests must use resource-aware operations instead.
An authenticated-caller claim is inconclusive until a reviewed authenticated probe
satisfies its identity precondition. Reflected request credentials and CSRF secrets
are redacted before HTTP output reaches evidence artifacts. Sensitive headers
are validated in memory and passed through adapter-owned stdin, not process
arguments. Only the trusted adapter introduces this stdin header source and the
owned-tunnel connection mapping after validation; command text cannot grant them.
Structured steps cannot carry shell rollback commands. Session initialization
must succeed and preserve the server's cookie names; HEAD uses curl's HEAD mode.

The engine allowlist remains hostname-only: it is not port/path isolation or a
DNS-rebinding defense. Optional resource selectors are enforced by the structured
resolver, not by the command-text host allowlist. Use structured requests for
resource-scoped grants and review operator-approved DNS domains/CIDRs accordingly.
Package pins, the deployed skill tree and the selected config home must all carry
this implementation before enabling restricted policy in an estate.

## Modes and the bypass

- **`SAFE_EXEC_MODE=warn|enforce`** — `warn` logs what enforce would have
  blocked and proceeds; used only during a calibration window for a newly
  routed lane, after which the lane flips to enforce.
- **`SAFE_EXEC_DISABLED=<reason>`** — loud operator bypass. Library callers do
  NOT honour it by default (`honor_bypass=False`); when honoured it prints to
  stderr and appends to the bypass log (`~/.local/state/…`, 0700). A bypass
  with no recorded reason is a finding, not a convenience.
- Blocked commands return exit 126 with a `[safe_exec blocked: …]` reason.
  Kubernetes validation policy refusals become `blocked_by_scope`; resolution or
  transport failures are inconclusive. Neither provides evidence to confirm or
  refute a finding.

## CLI

```bash
# validate one argv without running it
python3 -m traust.cli util safe-exec check --profile validation-step -- oc get pods -A
# vet a command string (pipelines parsed, no shell)
python3 -m traust.cli util safe-exec check --profile validation-step --string 'oc get po | grep x'
```

## Tests

`tests/test_safe_exec.py` in traust-engine covers the deny classes, curl and
kube flag hardening, pipeline parsing, env protection, and the recursion cap;
each consumer carries its own regression file. Rule S9 and S10 gate tests live
in the harness's `tests/test_check_skill_security.py`.
