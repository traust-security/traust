---
name: check-skill-security
description: Use before committing any new or edited skill or script to the traust repo, or when asked "does this skill degrade our security posture", "run the security-posture check", "is this skill safe to add" — runs python3 -m traust.cli check skill-security, the security-posture guard the pre-commit hook enforces alongside the alignment gate. Verifies privileged skills declare allowed-tools confinement, untrusted-content readers carry the adversarial-content doctrine, no git network command takes an ungated non-literal URL (the confirmed-RCE class from the 2026-07 self-audit), no shell-execution constructs or ps-visible Authorization headers, no fixed /tmp state paths, no unpinned runtime installs, no raw-egress tool grants, headless agents under repo-config isolation, and target-build invocations routed through the safe_exec sandbox.
user-invocable: true
metadata:
  harness.tier: "ci"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash(python3 *-m traust.cli.check_skill_security:*)
---

# check-skill-security — the security-posture gate for skills

Every rule in this checker is a generalized finding from the project's
own 2026-07-24 pre-release security self-audit (internal remediation
plan). The
audit's meta-lesson: unsafe constructs enter one skill at a time while
sibling skills already carry the safe pattern. This gate makes the safe
patterns mechanical for every future skill.

## Run

```bash
python3 -m traust.cli check skill-security            # full listing
python3 -m traust.cli check skill-security --quiet    # violations only
```

Exit 0 = clean. Exit 1 = violations; each names the rule, the file, and
the audit finding class it guards.

## Rules (S-series)

| Rule | Guards against | Audit class |
|---|---|---|
| S1 confinement | privileged skill (push / cluster mutation / target build-test / URL fetch) without an `allowed-tools` allowlist | D1/D2/D3 |
| S2 doctrine | untrusted-content reader without the adversarial-content (CWE-1427) doctrine | D4 |
| S3 git-transport | git network command on a non-literal URL without `GIT_ALLOW_PROTOCOL` + https gate — the confirmed-RCE class | A1/A2/A3 |
| S4 shell-exec | `shell=True`, `os.system`, `bash -lc`, `eval "$…"` | C2 |
| S5 token-argv | Authorization header in curl argv (ps-visible) | E2 |
| S6 tmp-paths | fixed world-writable `/tmp/<name>` state/credential paths | B2/B4/E9 |
| S7 unpinned-install | runtime `pip`/`npm` installs without versions, `go @latest`, `curl\|sh` (in .sh/Makefile) | E1/C3 |
| S8 egress-grants | `allowed-tools` granting raw `curl`/`wget`/`gh api` egress | D7 |
| S9 repo-config isolation | headless-agent launch without the repo-config isolation doctrine (cwd outside the checkout; target `.claude`/`CLAUDE.md`/hooks never loaded) | b-lite-p5 incident 2026-07-26 |
| S10 target-build sandbox | target-build invocation (`make`/`mvn`/`gradle`/`go build`/`npm`/`cargo` in an execution context) without python3 -m traust.cli util safe-exec routing | sandbox-adoption WS1 |

Scope: git-tracked files under `src/traust/` and `harnessing/` only —
untracked work dirs (fuzz clones, venvs, scanner binaries) are target
content, not harness code. Intentional-vulnerability fixtures
(`opengrep-rules/`, `tests/`, `rule-drafts/`) are excluded.

## Exemptions discipline

`EXEMPTIONS` in the script maps `(rule, path)` → reason. Two reason
classes are allowed:

- **`KNOWN — remediation plan Px.y`**: a violation the audit already
  registered, grandfathered until that plan item lands. When the fix
  merges, **remove the entry** — the list must only shrink; a P0 entry
  outliving P0 is itself a finding.
- **`reviewed — <rationale>`**: a deliberate design the team has
  examined (e.g. patch's reviewer-isolation is its doctrine; a checker
  quoting the word "untrusted" in rule prose).

Never add an exemption to make your own new skill pass. If the gate
fires on new code, the code is wrong — the grandfather list exists so
the gate could be introduced at all, not as a pattern to follow.

## When the gate fires on your skill

- **S1**: add `allowed-tools` frontmatter scoped to the scripts and
  read-only tools the skill actually needs (model: `vuln-scan`
  or this skill's own frontmatter).
- **S2**: add the adversarial-content doctrine block (model:
  `secure-code-audit` §Adversarial Repository Content) — or, once the
  shared doctrine include from plan P1.6 exists, reference it.
- **S3**: gate the URL (`^https://` allowlist) *and* set
  `GIT_ALLOW_PROTOCOL=https` in the subprocess env; reject leading-dash
  arguments; commits must match `^[0-9a-f]{7,40}$`.
- **S4**: build argv lists; never hand variable text to a shell.
- **S5**: `curl --config -` with the header on stdin
  (model: `validate-core-ocp/oauth_token.py`).
- **S6**: per-user directory (`~/.cache/<tool>/`, mode 0700) or
  `tempfile.mkstemp`; never a predictable shared name.
- **S7**: pin exact versions; verify checksums for downloaded binaries.
- **S8**: wrap the specific fetch in a scoped script and grant that.
- **S9**: run the headless agent with cwd in a scratch dir and state the
  isolation doctrine in the launching file.
- **S10**: route the build/test invocation through
  python3 -m traust.cli util safe-exec with a profile from
  the `safe-exec-profiles.yaml` traust-core ships (validated argv, git `-c`/network
  hardening, shell-free pipelines, scrubbed env).

## Integrations

Console-only output (no artifact). Enforced by `.githooks/pre-commit`
alongside `check_skill_alignment.py` (A-series); the two are
complementary — alignment guards cross-skill contracts, this guards
security posture. The rule set derives from the internal remediation
plan; update both together when a new finding class is discovered (add
the rule here, register the campaign fix in the tracker).
