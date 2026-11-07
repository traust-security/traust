# safe_exec — the target-build sandbox

python3 -m traust.cli util safe-exec is the enforced command validator
every harness step uses when it executes something derived from an **audited
checkout** — build systems, test suites, scanners that load target code, and
string-form PoC steps in live validation. Gate rule **S10**
(python3 -m traust.cli check skill-security) makes routing
through it mandatory at commit time: each detected target-build invocation must run through
safe_exec. A prose or comment mention, an import alone, or an unrelated sandboxed build
does not exempt direct builds elsewhere. `safe-exec check` validates argv but does not
execute a build, so it is not routing evidence for a direct invocation.

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

Policy lives in **the `safe-exec-profiles.yaml` traust-core ships** (the project's
policy, not adopter config). Profiles declare binary `allow` and optional
`allowed_path_heads`, `allow_pipelines`, `keep_env`, `keep_env_heads`,
`curl_allowed_hosts` and `posture`. Current profiles and their consumers:

| Profile | Used by | Notes |
|---|---|---|
| `validation-step` | validate-findings adapters (string-form PoC steps) | pipelines allowed; `KUBECONFIG` + `VF_OAUTH_TOKEN` kept (the token keeps bearer-auth probes sound) |
| `go-scan` | python3 -m traust.cli adapters govulncheck | govulncheck type-checks and builds the target module — hostile build tags/cgo see only the scrubbed env |
| `go-fuzz`, `java-build`, `python-test`, `node-build`, `rust-fuzz`, `generic-build` | build/test lanes (fuzz-harness and patch-verification steps) | dependency-manager egress from build tools is accepted residual risk: safe_exec constrains argv and environment, not child-process sockets; hermetic prefetch is a deferred hardening |

### Curl postures and engagement hosts

`restricted` requires an explicit host for every curl URL; `baseline` permits
public destinations but requires explicit authorization for private, loopback,
link-local and internal destinations; `privileged` permits unrestricted egress.
Restricted and baseline profiles do not follow redirects. Host authorization is
hostname-only: it is not port/path isolation or a DNS-rebinding defense.
Profiles may restrict environment variables to selected pipeline heads via
`keep_env_heads`. Command text cannot override proxy, routing or configuration
environment variables.

The CLI's repeatable `--allowed-host` adds a host for one invocation. Validation
adapters bind their hosts per run rather than sharing grants between engagements.
For structured HTTP probes, the adapter checks the selected endpoint against the
engagement and gives safe-exec only that endpoint, not a blanket loopback grant.

### Structured HTTP validation

The [targets template](../harnessing/5-validate/validate-findings/targets.example.yaml)
describes explicit-only `http_targets` and per-cluster `http_discovery` policy.
Neither finding text nor inline or inferred scope grants HTTP destinations.
Exact targets bind a host and context, with optional resource identity and a
separate credentials permission. Route discovery is limited to declared concrete
namespaces, names and DNS domains; node discovery is limited to declared names,
address types and networks. A discovered hostname or address is not a grant by
itself. A named Route with an exact target grant can be resolved without granting
route discovery.
Concrete namespaces from exact targets and `clusters[].namespace_hints` can be
used as discovery candidates when the engagement allows namespace patterns.
Hints are observations, not grants: every candidate still passes the explicit
namespace, off-limits, resource, verb and applicable endpoint or tunnel checks.

The selected named kubeconfig context is resolved and its API compared with the
engagement API. Expiry, off-limits rules and denied verbs continue to apply to
discovery, resource access and the HTTP method. Timezone-aware datetime expiries
are enforced to the instant, including between session requests; date-only
expiries remain valid through that calendar date. Service probes select a
selector-backed Service and matching Pod, resolve its target port and use an
adapter-owned local port-forward with readiness and cleanup. HTTPS retains the
service DNS identity while the connection is routed through the owned tunnel.
The owned tunnel is not an authorization for arbitrary loopback traffic. Structured
requests cannot inherit ambient proxy settings or follow redirects.
Kubeconfig `proxy-url` and insecure API TLS are refused. An engagement may name
additional authentication-plugin variables in `http_discovery.kube_env`; unsafe
proxy, routing, loader and configuration variables cannot be added.
For a non-tunneled endpoint on the pinned Kubernetes API host, only GET/HEAD
requests to `/healthz`, `/livez`, `/readyz` or `/version` at the pinned API
origin are allowed. This restriction also applies to auxiliary identity and
session requests: the CSRF bootstrap request to `/` is forbidden for that API.

TLS verification is enabled by default. An explicit engagement-only
`http_discovery.insecure_tls: true` is honored only in a `lab` environment,
including for authenticated requests and owned tunnels. Disabling verification
can expose credentials to an interceptor; use a trusted `ca_bundle` instead
whenever possible. Finding-controlled probes cannot enable this exception.

Simple literal curl PoCs become structured direct or Route probes only when an
explicit target or Route discovery domain authorizes the host and selected
context. A namespace-less direct target needs an exact host grant and pinned
API, not a wildcard Kubernetes namespace grant. Route replay binds the resolved
Route to the original scheme, host and port. Unsupported curl commands are
recorded as not attempted, not run through a shell or adapted by guessing
their semantics.

HTTP plans contain `target.http` instead of shell programs. GET, HEAD and OPTIONS
are safe; POST, PUT, PATCH and DELETE require destructive opt-in because these
structured probes have no authorized rollback. A tunneled safe request can retry
connection refusal twice; write requests are never retried. Authentication
requires an explicit credential grant, and creating a ServiceAccount token requires
the matching resource and verb authorization. CSRF/session initialization must
actually succeed; authenticated probes require both an operator-configured
`http_discovery.session_check_path` and `session_check_contains` identity marker.
Choose a non-secret marker: the policy is included in the approval snapshot.
The check must return a successful response containing that marker. A cookie,
token, or reachable endpoint alone is not proof of an authenticated session.
Credentials and response-derived secrets are kept out of process arguments
and redacted from evidence. Scope refusals are `blocked_by_scope`; resolution,
transport and unmet preconditions are inconclusive, never evidence of refutation.
Structured HTTP results pass through the existing attestation, soundness and
validation-recording gates; none of those observations are fabricated.

## Modes and the bypass

- **`SAFE_EXEC_MODE=warn|enforce`** — `warn` logs what enforce would have
  blocked and proceeds; used only during a calibration window for a newly
  routed lane, after which the lane flips to enforce.
- **`SAFE_EXEC_DISABLED=<reason>`** — loud operator bypass. Library callers do
  NOT honour it by default (`honor_bypass=False`); when honoured it prints to
  stderr and appends to the bypass log (`~/.local/state/…`, 0700). A bypass
  with no recorded reason is a finding, not a convenience.
- Blocked commands return exit 126 with a `[safe_exec blocked: …]` reason.
  In validate-findings, a blocked step becomes an `inconclusive` verdict —
  never a silent pass, and never grounds for a `refuted` (refutation-soundness
  gate).

## CLI

```bash
# validate one argv without running it
python3 -m traust.cli util safe-exec check --profile validation-step -- oc get pods -A
# vet a command string (pipelines parsed, no shell)
python3 -m traust.cli util safe-exec check --profile validation-step --string 'oc get po | grep x'
```

## Tests

`tests/test_safe_exec.py` in traust-core covers the deny classes, curl and
kube flag hardening, pipeline parsing, environment protection, and recursion;
consumer regression tests cover engagement scope and structured HTTP. Rule S9
and S10 gate tests live in `tests/test_check_skill_security.py`.
