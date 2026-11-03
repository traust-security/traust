# safe_exec — the target-build sandbox

python3 -m traust.cli util safe-exec is the enforced command validator
every harness step uses when it executes something derived from an **audited
checkout** — build systems, test suites, scanners that load target code, and
string-form PoC steps in live validation. Gate rule **S10**
(python3 -m traust.cli check skill-security) makes routing
through it mandatory at commit time: each detected target-build invocation must run
through safe_exec. A prose or comment mention, an import alone, or an unrelated
sandboxed build does not exempt direct builds elsewhere. `safe-exec check` validates
argv but does not execute a build, so it is not routing evidence.

For Python, S10 tracks execution-function aliases and static command values in
statement order, merges possible control-flow bindings conservatively, and
distinguishes actual argv executables from output data. It recognizes command
variables and split operations without trusting a later import, wildcard name,
unrelated safe-exec call or printed example as routing evidence.

S10 is a static admission guard, not a replacement for the execution-time
validator. Target-derived commands must still run under the selected safe-exec
profile; static uncertainty never grants additional runtime privileges.

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
`allow_pipelines`, and `keep_env`. Current profiles and their consumers:

| Profile | Used by | Notes |
|---|---|---|
| `validation-step` | validate-findings adapters (string-form PoC steps) | pipelines allowed; `KUBECONFIG` + `VF_OAUTH_TOKEN` kept (the token keeps bearer-auth probes sound) |
| `go-scan` | python3 -m traust.cli adapters govulncheck | govulncheck type-checks and builds the target module — hostile build tags/cgo see only the scrubbed env |
| `go-fuzz`, `java-build`, `python-test`, `node-build`, `rust-fuzz`, `generic-build` | build/test lanes (fuzz-harness and patch-verification steps) | dependency-manager egress from build tools is accepted residual risk: safe_exec constrains argv and environment, not child-process sockets; hermetic prefetch is a deferred hardening |

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

`tests/test_safe_exec.py` in traust-engine covers the deny classes, curl and
kube flag hardening, pipeline parsing, env protection, and the recursion cap;
each consumer carries its own regression file. Rule S9 and S10 gate tests live
in the harness's `tests/test_check_skill_security.py`.
