#!/usr/bin/env python3
"""Skill security-posture guard — catch a new or edited skill degrading
the harness's security posture, before it is committed.

Born from the 2026-07-24 pre-release self-audit
(progress-tracker/plans/harness-security-remediation-plan.md). The audit
found one repeating meta-pattern: the most privileged skills were the
least confined, and each unsafe construct (git transport injection,
token-in-argv, /tmp credential caches, unpinned installs) entered through
one skill while its siblings already carried the safe pattern. This
checker makes the safe patterns mechanical for every FUTURE skill; the
EXEMPTIONS map grandfathers today's known violators, each entry citing
the remediation-plan item that will remove it — the list must only ever
shrink.

Rules (S-series; A-series lives in check_skill_alignment.py):
  S1 confinement      A SKILL.md whose prose indicates privileged
                      capability (pushing, cluster mutation, running
                      target build/test, fetching URLs) must declare an
                      `allowed-tools` frontmatter allowlist.
                      (Audit findings D1/D2/D3.)
  S2 doctrine         A SKILL.md that reads untrusted target content or
                      report prose must carry the adversarial-content
                      doctrine (CWE-1427 / prompt-injection block).
                      (Audit finding D4.)
  S3 git-transport    A skill/harness script that runs a git network
                      command on a non-literal URL must, in the same
                      file, set GIT_ALLOW_PROTOCOL and show an
                      https-scheme gate. (Audit findings A1/A2/A3 —
                      the confirmed-RCE class.)
  S4 shell-exec       No `shell=True`, `os.system`, `os.popen`, or
                      `bash -lc` on variable text in skill scripts.
                      (Audit finding C2.)
  S5 token-argv       No `curl` with an inline Authorization header —
                      argv is ps-visible; use `--config -` on stdin.
                      (Audit finding E2.)
  S6 tmp-paths        No fixed world-writable `/tmp/<name>` literals for
                      state, credentials, or caches — predictable shared
                      paths are plantable/symlink-squattable.
                      (Audit findings B2/B4/E9.)
  S7 unpinned-install No runtime `pip install pkg` without `==`,
                      `npm install pkg` without `@version`,
                      `go install ...@latest`, or `curl | sh`.
                      (Audit findings E1/C3/E11.)
  S8 egress-grants    allowed-tools may not grant raw network egress
                      (`Bash(curl:*)`, `Bash(wget:*)`, `Bash(gh api:*)`)
                      — an exfiltration channel under injection; wrap
                      the needed fetch in a scoped script.
                      (Audit finding D7.)
  S9 repo-config      A skill/script that launches a headless agent
     isolation        (`claude -p/--print`, `crush run`, `opencode run`)
                      must, in the same file, carry the repo-config
                      isolation doctrine: agent cwd outside the
                      untrusted checkout, and repo-supplied agent config
                      (`.claude/`, `CLAUDE.md`, hooks) never loaded as
                      configuration — it is data under audit. Measured
                      incident 2026-07-26 (b-lite-p5): corpus repos
                      shipping their own `.claude` hooks killed — and
                      could have injected — headless scan workers.

  S10 target-build   A skill/script that executes an audited checkout's
      sandbox        own build machinery (make/mvn/gradle/go build/npm/
                     cargo in an execution context) must route it
                     through traust_engine._util.safe_exec — enforced command
                     validation with profile allowlists, git -c/network
                     hardening, and shell-free pipeline execution.
                     (sandbox-adoption WS1,
                     the sandbox-adoption plan (internal);
                     pattern source: balor-fianna SafeBash.)

Exit 0 = clean (exemptions printed), 1 = violations found.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT, skill_md_paths

REPO = HARNESS_ROOT

# --------------------------------------------------------------------------
# EXEMPTIONS: (rule, path-substring) -> reason. Reasons must cite either a
# remediation-plan item (grandfathered, to be removed when it lands) or a
# reviewed design rationale. This list must only shrink.
# --------------------------------------------------------------------------
EXEMPTIONS: dict[tuple[str, str], str] = {
    # --- S1 confinement: grandfathered pre-audit skills; plan P1.6 / P2 ---
    (
        "S1",
        "harnessing/secure-rpm-audit/SKILL.md",
    ): "grandfathered — same P1.6 batch as secure-code-audit",
    (
        "S1",
        "harnessing/validate-browser-finding/SKILL.md",
    ): "grandfathered — remediation plan P2.14 batch; browser scope.py "
    "fail-closed guard is the operative control",
    # (verify-remediation S1 retired 2026-07-31 P1-W4: allowed-tools
    # added — scoped git + anchored scripts.)
    (
        "S1",
        "harnessing/create-fuzzing/SKILL.md",
    ): "grandfathered — remediation plan P2.11 (C3) container leg",
    (
        "S1",
        "harnessing/compliance-check/SKILL.md",
    ): "grandfathered — P1.6 batch; compliance lane reads declared inventory only",
    # --- S2 doctrine: grandfathered per audit D4; plan P1.6 ---
    # (cloud-config-audit retired 2026-07-31: doctrine section added in
    # the P1 gate rework — exemption no longer needed)
    ("S2", "harnessing/isolation-review/SKILL.md"): "grandfathered — D4 batch, P1.6",
    ("S2", "harnessing/fleet-fix/SKILL.md"): "grandfathered — D4 batch, P2.11",
    ("S2", "harnessing/create-fuzzing/SKILL.md"): "grandfathered — D4 batch, P2.11",
    # --- S2: deterministic aggregators — keyword hits in rationale prose,
    #     no agent reads untrusted content in these flows ---
    (
        "S2",
        "harnessing/check-alignment/SKILL.md",
    ): "reviewed — deterministic checker; 'untrusted' appears in the A11 rule rationale it quotes",
    (
        "S2",
        "harnessing/drift-watch/SKILL.md",
    ): "reviewed — deterministic checker over harness-owned artifacts",
    (
        "S2",
        "harnessing/rbac-tenancy-rollup/SKILL.md",
    ): "reviewed — deterministic rollup; keyword in scope prose",
    # --- S3 git-transport: the P0 fix list; MUST empty when P0 lands ---
    (
        "S3",
        "harnessing/3-audit/pqc-readiness/scripts/bulk_prescan.py",
    ): "reviewed — https-scheme gate at call site (startswith check) prevents non-https;"
    " url originates from the harness corpus registry",
    # --- S4: pod-side shells — the sh -c runs INSIDE the scoped target
    # pod/container via runtime exec, never on the harness host; the
    # outer argv is kubeargv-classified and scope-checked (P0-2) ---
    (
        "S4",
        "harnessing/validate-findings/adapters/container.py",
    ): "reviewed — container-side sh -c via runtime exec; host never "
    "shells out (P0-2 argv analysis + scope gate on the outer argv)",
    (
        "S4",
        "harnessing/validate-findings/adapters/k8s.py",
    ): "reviewed — pod-side sh -c via kubectl/oc exec; host never "
    "shells out (P0-2 kubeargv classification + scope gate)",
    # --- S4 shell-exec ---
    # (base.py entry REMOVED 2026-07-31: P2.13 closed — PoC-string steps
    #  now validate and execute via traust_engine._util.safe_exec, no shell.)
    # --- S5 token-argv ---
    (
        "S5",
        "harnessing/5-validate/validate-findings/novel.py",
    ): "reviewed — Authorization header is in a cmd_template string (recon step"
    " template executed inside the target pod via kubectl exec, not on the harness host)",
    # --- S10 target-build sandbox: grandfathered pending the WS1 skill
    #     integrations (sandbox-adoption-plan §WS1, D-decisions open);
    #     each lands behind safe_exec profiles when its skill integrates ---
    (
        "S10",
        "harnessing/create-fuzzing/SKILL.md",
    ): "grandfathered — go-fuzz profile integration pending (plan WS1)",
    (
        "S10",
        "harnessing/create-fuzzing/Makefile",
    ): "grandfathered — the make-target driver WS1 will wrap",
    (
        "S10",
        "harnessing/create-fuzzing/gen-reports.sh",
    ): "grandfathered — same WS1 batch as the Makefile",
    (
        "S10",
        "harnessing/create-fuzzing/run-sweep.sh",
    ): "grandfathered — same WS1 batch as the Makefile",
    (
        "S10",
        "harnessing/create-fuzzing/scripts/build_fuzz_rollup.py",
    ): "reviewed — rollup reader; build tokens are report/status strings, no execution",
    (
        "S10",
        "harnessing/create-fuzzing/harnesses/_templates/python_fuzz.py",
    ): "reviewed — harness stub dropped INTO the target tree by design; "
    "runs under the target's own build, WS1 wraps the driver",
    (
        "S10",
        "harnessing/pqc-readiness/build_pqc_scan.sh",
    ): "reviewed — builds the PINNED harness-owned pqc-scan tool "
    "(cargo build at a pinned commit), not target code",
    (
        "S10",
        "harnessing/validation-fuzz-dashboard/scripts/build_validation_fuzz_dashboard.py",
    ): "reviewed — dashboard builder; 'go test -fuzz' appears in "
    "rendered method strings, no execution",
    (
        "S10",
        "harnessing/remediate-finding/run_checks.sh",
    ): "reviewed — build/test leg is container-sandboxed (rootless "
    "podman, cap-drop, --network=none test phase, env-stripped "
    "native fallback; P2.11/C1) — stronger containment than "
    "safe_exec argv validation",
    (
        "S10",
        "harnessing/remediate-finding/run_mutation.sh",
    ): "reviewed — same container boundary as run_checks.sh and strictly "
    "tighter: rootless podman, cap-drop, no-new-privileges, "
    "--network=none for the whole campaign (not just the test phase), and a "
    "disposable copy so mutations cannot reach the worktree under review. The "
    "mode is a deployment setting (execution-boundaries.yaml `sandbox:`); a "
    "configured podman mode is never silently downgraded (ToB plan item 3)",
    # --- S6 tmp-paths ---
    (
        "S6",
        "harnessing/rbac-tenancy-rollup/scripts/rbac_bucket_proposal_check.py",
    ): "P3 hardening batch — non-secret scratch file, fixed /tmp name",
    # --- S7 unpinned-install ---
    # --- S8 egress-grants ---
}

# --------------------------------------------------------------------------
# indicators
# --------------------------------------------------------------------------
PRIVILEGE_RX = re.compile(
    r"git push|push(es|ing)? (to|the) (a |the )?(private |fork|mirror)"
    r"|oc (apply|create|delete|adm|exec)|kubectl (apply|create|delete|exec)"
    r"|--destructive|WebFetch|clone[sd]? (it |the |automatically)"
    r"|make test|npm ci|cargo test|go test|run the repo'?s own"
    # container/IaC/sweep tokens (assessment 2026-07-31 root-cause 1:
    # secure-container-audit, crypto-analysis, cloud-config-audit and
    # portfolio-graph were fully unconfined because none of their verbs
    # appeared here)
    r"|podman (pull|create|export|run)|skopeo|docker (pull|create|run)"
    r"|tar -x|checkov|bicep build|govulncheck"
    r"|clone sweep|shallow[- ]clone|gh api",
    re.I,
)
UNTRUSTED_RX = re.compile(
    r"target (repo|checkout|codebase)|untrusted|cloned? (repo|target)"
    r"|finding prose|scanner output"
    r"|hostile|image (label|rootfs|config)|IaC checkout"
    r"|third[- ]party repo",
    re.I,
)
DOCTRINE_RX = re.compile(
    r"CWE-1427|adversarial|prompt.?injection|injected instructions?"
    r"|hostile (repo|content)|do not (follow|obey|execute) instructions",
    re.I,
)
ALLOWED_TOOLS_RX = re.compile(r"^allowed-tools:", re.M)  # legacy sniff — see _frontmatter_allowlist


def _frontmatter_allowlist(text: str):
    """Parse the SKILL.md YAML frontmatter and return its allowed-tools
    list, or None when there is no structurally valid allowlist.

    Fail-closed replacement for the ALLOWED_TOOLS_RX sniff (P1 gate
    rework, assessment root-cause 1): the regex accepted the literal
    string ``allowed-tools:`` anywhere in the body — prose, a fenced
    example, an HTML comment — as proof of confinement. Only a
    non-empty list under the ``allowed-tools`` key of parseable YAML
    frontmatter counts; a missing/malformed frontmatter or a non-list
    value returns None (unconfined).
    """
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end < 0:
        return None
    try:
        import yaml

        fm = yaml.safe_load(text[4:end])
    except Exception:
        return None
    if not isinstance(fm, dict):
        return None
    tools = fm.get("allowed-tools")
    if isinstance(tools, list) and tools and all(isinstance(t, str) for t in tools):
        return tools
    return None


GIT_NET_RX = re.compile(
    r"git[\"',\s]+(?:-C[\"',\s]+\S+[\"',\s]+)?"
    r"[\"']?(clone|ls-remote|fetch|pull|remote[\"',\s]+set-url)"
)
VAR_MARK_RX = re.compile(
    r"[$@{]|%s|\+\s*\w|format\(|f[\"']"
    r"|<[a-z][a-z-]*>"
)  # <github-url>-style placeholders in SKILL prose
HTTPS_GATE_RX = re.compile(
    r"GIT_ALLOW_PROTOCOL|\^https://|startswith\([\"']http"
    r"|https?://\[\^|normalize_repo_url|CLONABLE_RX|^https://github"
    r"|in https://",  # shell `case "$url" in https://…)` gate idiom
    re.M,
)

SHELL_EXEC_RX = re.compile(
    r"shell\s*=\s*True|os\.system\(|os\.popen\("
    r"|[\"'](?:/bin/|/usr/bin/)?(?:ba|z|k|da)?sh[\"'],\s*[\"']-l?c[\"']"
    r"|\beval\s+\"\$"
)
CURL_AUTH_RX = re.compile(r"curl[^\n|;&]*-H[\"'\s]+[\"']?Authorization")
TMP_PATH_RX = re.compile(
    r"[\"'=](/(?:var/)?tmp/[A-Za-z0-9._{}-]+)"
    r"|Path\(\s*[\"']/(?:var/)?tmp/"
    r"|os\.path\.join\(\s*[\"']/(?:var/)?tmp[\"']"
)
UNPINNED_RX = re.compile(
    r"pip3? +(?:-q +)?install +(?!-r|--)(?![^\n]*==)[a-zA-Z]"
    r"|npm +install +(?!--)[^@\s]+\s*$"
    r"|npm +install +(?:--no-save +)?@?[a-zA-Z][^@\n]*$"
    r"|go +install +\S+@latest"
    r"|curl[^\n]*\|\s*(ba)?sh",
    re.M,
)
EGRESS_GRANT_RX = re.compile(r"Bash\((curl|wget|gh api)[:\s]", re.I)

HEADLESS_AGENT_RX = re.compile(
    r"\bclaude\b[^\n]{0,120}(--print\b|\s-p\b|--dangerously-skip-permissions"
    r"|--output-format)"
    r"|\bcrush\s+run\b"
    r"|\bopencode\s+(run\b|--?p\b)"
)
REPO_CONFIG_ISOLATION_RX = re.compile(
    r"repo-config isolation"
    r"|(cwd|working director\w*)[^\n]{0,100}(outside|scratch)"
    r"|never[^\n]{0,80}(load|honor|execute)[^\n]{0,80}"
    r"(\.claude|CLAUDE\.md|repo-supplied)",
    re.I,
)

# S10: target-build tokens that mean "executing the audited checkout's
# own build machinery". pytest is deliberately absent (too ambiguous
# with the harness's own test-suite instructions); the /patch
# integration adds its coverage when it lands (plan WS1).
S10_BUILD_RX = re.compile(
    r"\bmake\s+(?:clone\b|build\b|install\b|fuzz)"
    r"|\bmvn\s+(?:-\S+\s+)*(?:package|install|verify|deploy)\b"
    r"|(?:^|[\s\"'`(])\.?/gradlew\b|\bgradle\s+(?:build|test|assemble)\b"
    r"|\bgo\s+(?:build|test)\s"
    r"|\bnpm\s+(?:ci|run\s+build)\b"
    r"|\bcargo\s+(?:build|test|fuzz)\b"
    # govulncheck loads+builds the target module (hostile build-tags /
    # cgo reachable) — but only invocation shapes count, not mentions
    # of the tool name in prose, version probes, or allowlists
    r"|\bgovulncheck\b[^\n\"']*(?:\./|\.\.\.|-mode\b|-C )",
    re.M,
)
# must reference the script itself (or, for Python callers, the module
# import + .run call) — a bare "safe_exec" substring false-passed on
# run_checks.sh's "safe_executer_test" comment
S10_SAFE_EXEC_RX = re.compile(r"safe_exec\.py|import safe_exec\b|safe_exec\.run\(")
FENCED_BLOCK_RX = re.compile(r"```[a-z]*\n(.*?)```", re.S)

SCRIPT_EXTS = {".py", ".sh", ".bash", ".mk"}
SCRIPT_NAMES = {"Makefile", "GNUmakefile", "justfile"}
# rule-pack fixtures contain intentional vulnerabilities; the checker's
# own source contains the rule regexes it hunts for. The blanket
# "tests/" substring exempted harnessing/<skill>/tests/ scripts from
# every rule (assessment 2026-07-31 rollup-F3) — only the repo-level
# tests tree (rule-regex test data) is excluded now.
FIXTURE_MARKERS = ("opengrep-rules/", "rule-drafts/", "src/traust/cli/check_skill_security.py")
FIXTURE_PREFIXES = ("tests/",)


def _s3_failures(text: str) -> list[str]:
    """S3 over EVERY git-network call site, with continuation-line
    handling and per-site gate proximity. The old shape checked only
    the first match, one physical line, and accepted a gate marker
    anywhere in the file — all three were confirmed evasions
    (assessment 2026-07-31 rollup-F3; live miss in
    build_portfolio_graph.py where the URL f-string sat on the next
    line)."""
    lines = text.splitlines()
    fails = []
    for m in GIT_NET_RX.finditer(text):
        lineno = text.count("\n", 0, m.start())
        # argv/continuation window: the matched line plus the next 3
        window = "\n".join(lines[lineno : lineno + 4])
        if "https://" in window and not VAR_MARK_RX.search(window.split("https://", 1)[0]):
            continue  # literal URL at the site
        if not VAR_MARK_RX.search(window):
            continue  # nothing injectable in reach
        # gate must be NEAR the site (±6 lines), not anywhere in file
        lo, hi = max(0, lineno - 6), lineno + 7
        vicinity = "\n".join(lines[lo:hi])
        if HTTPS_GATE_RX.search(vicinity):
            continue
        fails.append(
            f"git network command on a non-literal URL at line "
            f"{lineno + 1} without GIT_ALLOW_PROTOCOL or an "
            "https-scheme gate near the call site (audit A1/A2/A3 — "
            "RCE class)"
        )
    return fails


def _s4_ast_failures(text: str) -> list[str]:
    """AST leg of S4 for .py files — the shapes the regex cannot see:
    sh/zsh/dash -c argv lists with non-literal payloads, shell=<expr>
    that is not the literal False, and os.exec*/spawn* (assessment
    2026-07-31 rollup-F3)."""
    import ast

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []  # regex leg already ran; never hard-fail the gate
    hits = []
    _SHELLS = {"sh", "bash", "zsh", "ksh", "dash"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = ""
        if isinstance(fn, ast.Attribute):
            name = fn.attr
            if (
                isinstance(fn.value, ast.Name)
                and fn.value.id == "os"
                and (name.startswith(("exec", "spawn")))
            ):
                hits.append(f"os.{name}() at line {node.lineno}")
                continue
        elif isinstance(fn, ast.Name):
            name = fn.id
        for kw in node.keywords:
            if kw.arg == "shell":
                v = kw.value
                if not (isinstance(v, ast.Constant) and v.value is False):
                    hits.append(f"shell=<non-False> at line {node.lineno}")
        if name in ("run", "Popen", "call", "check_output", "check_call") and node.args:
            a0 = node.args[0]
            if isinstance(a0, (ast.List, ast.Tuple)) and len(a0.elts) >= 3:
                e0, e1 = a0.elts[0], a0.elts[1]
                if (
                    isinstance(e0, ast.Constant)
                    and isinstance(e0.value, str)
                    and e0.value.rsplit("/", 1)[-1] in _SHELLS
                    and isinstance(e1, ast.Constant)
                    and str(e1.value) in ("-c", "-lc")
                    and not isinstance(a0.elts[2], ast.Constant)
                ):
                    hits.append(f"[{e0.value!r}, '-c', <non-literal>] at line {node.lineno}")
    return hits


# Workflow skills sit one level deeper than the rest — harnessing/<N>-<stage>/
# <skill>/ vs harnessing/<skill>/ (skill-usability plan 1.2). EXEMPTIONS keys
# use the flat spelling, so match both by dropping the stage segment. Without
# this, `gates:pinned` — this checker's copy on the TARGET branch, run against
# an MR tree — reports every reviewed exemption as a fresh violation the
# moment a skill moves. See the twin of this helper in check_skill_alignment.
_STAGE_SEG_RE = re.compile(r"(harnessing/)[0-9]+-[a-z0-9-]+/")


def _unstaged(rel: str) -> str:
    """The flat spelling of `rel`, with any stage directory removed."""
    return _STAGE_SEG_RE.sub(r"\1", rel)


#: EXEMPTIONS keys matched during a run. Distinct from `used`, which holds one
#: rendered message per matched FILE — so len(used) counts matches, not
#: exemptions, and the "N known exemptions" line was never an exemption count.
#: Anything in EXEMPTIONS and absent from here is stale: the file it covered
#: was moved, renamed or deleted, and the entry now silently protects nothing.
_MATCHED_KEYS: set[tuple[str, str]] = set()


def _exempt(rule: str, rel: str, used: list) -> bool:
    spellings = (rel, _unstaged(rel))
    for (r, p), reason in EXEMPTIONS.items():
        if r == rule and any(p in s for s in spellings):
            used.append(f"({rule} exempt) {rel}: {reason}")
            _MATCHED_KEYS.add((r, p))
            return True
    return False


def unused_exemptions() -> list[tuple[str, str]]:
    """EXEMPTIONS entries that matched nothing in the last run.

    A stale entry is not harmless. It reads as a reviewed decision that still
    applies, and it hides the fact that whatever it excused has gone — the S10
    key for a fuzz harness stayed here for weeks after the file moved to the
    corpus, and nothing reported it, because the only signal was a count of
    matched files that quietly went down.
    """
    return sorted(set(EXEMPTIONS) - _MATCHED_KEYS)


def _tracked_files(repo: Path) -> list[str]:
    """git-tracked files only — untracked work dirs (fuzz clones, venvs,
    scanner bins) are target content, not harness code."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--", "scripts", "harnessing"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        return out.stdout.splitlines()
    except (subprocess.SubprocessError, OSError):
        # fallback: walk, best effort
        return [
            p.relative_to(repo).as_posix()
            for base in ("scripts", "harnessing")
            if (repo / base).is_dir()
            for p in (repo / base).rglob("*")
            if p.is_file()
        ]


def _iter_scripts(repo: Path):
    for rel in sorted(_tracked_files(repo)):
        if any(m in rel for m in FIXTURE_MARKERS):
            continue
        if any(rel.startswith(pre) for pre in FIXTURE_PREFIXES):
            continue
        p = repo / rel
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix in SCRIPT_EXTS or p.name in SCRIPT_NAMES:
            yield p, rel


def _reset_exemption_tracking() -> None:
    _MATCHED_KEYS.clear()


def security_failures(repo: Path = REPO) -> tuple[list[str], list[str]]:
    _reset_exemption_tracking()
    fails: list[str] = []
    used: list[str] = []

    # -- SKILL.md rules (S1, S2, S8) --------------------------------------
    for sk in skill_md_paths(repo):
        rel = sk.relative_to(repo).as_posix()
        text = sk.read_text(encoding="utf-8", errors="replace")
        has_allow = _frontmatter_allowlist(text) is not None

        if PRIVILEGE_RX.search(text) and not has_allow and not _exempt("S1", rel, used):
            fails.append(
                f"S1 {rel}: privileged capability indicated but no "
                "`allowed-tools` allowlist — confine the toolset "
                "(audit D1/D2/D3)"
            )

        if (
            UNTRUSTED_RX.search(text)
            and not DOCTRINE_RX.search(text)
            and not _exempt("S2", rel, used)
        ):
            fails.append(
                f"S2 {rel}: reads untrusted content but carries no "
                "adversarial-content doctrine (CWE-1427 block) "
                "(audit D4)"
            )

        for m in EGRESS_GRANT_RX.finditer(text):
            if not _exempt("S8", rel, used):
                fails.append(
                    f"S8 {rel}: allowed-tools grants raw egress "
                    f"`{m.group(0)}…` — wrap the fetch in a scoped "
                    "script (audit D7)"
                )
            break

        fenced = "\n".join(FENCED_BLOCK_RX.findall(text))
        # S3 over SKILL execution blocks too — prose clone commands with
        # <url>/<branch> placeholders are agent-executed instructions
        # (assessment 2026-07-31 adjudication-H7)
        for s3fail in _s3_failures(fenced):
            if not _exempt("S3", rel, used):
                fails.append(f"S3 {rel} (execution block): {s3fail}")
            break

        if (
            S10_BUILD_RX.search(fenced)
            and not S10_SAFE_EXEC_RX.search(text)
            and not _exempt("S10", rel, used)
        ):
            fails.append(
                f"S10 {rel}: target-build invocation in an execution "
                "block without safe_exec routing — build systems of "
                "audited checkouts are hostile code; run them "
                "through traust_engine._util.safe_exec "
                "(sandbox-adoption WS1)"
            )

        if (
            HEADLESS_AGENT_RX.search(text)
            and not REPO_CONFIG_ISOLATION_RX.search(text)
            and not _exempt("S9", rel, used)
        ):
            fails.append(
                f"S9 {rel}: launches a headless agent without the "
                "repo-config isolation doctrine (agent cwd outside "
                "the checkout; .claude/CLAUDE.md/hooks never loaded "
                "as config) (b-lite-p5 incident 2026-07-26)"
            )

    # -- script rules (S3-S7) ---------------------------------------------
    for p, rel in _iter_scripts(repo):
        text = p.read_text(encoding="utf-8", errors="replace")

        for s3fail in _s3_failures(text):
            if not _exempt("S3", rel, used):
                fails.append(f"S3 {rel}: {s3fail}")
            break  # one report per file; exemption covers the rest

        if SHELL_EXEC_RX.search(text):
            if not _exempt("S4", rel, used):
                fails.append(
                    f"S4 {rel}: shell-execution construct "
                    '(shell=True / os.system / sh|bash -c / eval "$…") '
                    "(audit C2)"
                )
        elif p.suffix == ".py":
            for s4hit in _s4_ast_failures(text):
                if not _exempt("S4", rel, used):
                    fails.append(
                        f"S4 {rel}: shell-execution construct — "
                        f"{s4hit} (AST leg; assessment 2026-07-31 "
                        "rollup-F3)"
                    )
                break

        if (
            S10_BUILD_RX.search(text)
            and not S10_SAFE_EXEC_RX.search(text)
            and not _exempt("S10", rel, used)
        ):
            fails.append(
                f"S10 {rel}: target-build invocation without "
                "safe_exec routing — build systems of audited "
                "checkouts are hostile code; run them through "
                "traust_engine._util.safe_exec (sandbox-adoption WS1)"
            )

        if CURL_AUTH_RX.search(text) and not _exempt("S5", rel, used):
            fails.append(
                f"S5 {rel}: Authorization header in curl argv — "
                "ps-visible; use `curl --config -` on stdin "
                "(audit E2)"
            )

        tm = TMP_PATH_RX.search(text)
        if tm and not _exempt("S6", rel, used):
            fails.append(
                f"S6 {rel}: fixed world-writable path "
                f"`{tm.group(1)}` — use a per-user 0700 dir "
                "(~/.cache or mkstemp) (audit B2/B4/E9)"
            )

        # pip/npm/go pins only meaningful in execution contexts (.sh,
        # Makefile) — in .py they are error-message advice strings
        if (
            (p.suffix == ".sh" or p.name in SCRIPT_NAMES)
            and UNPINNED_RX.search(text)
            and not _exempt("S7", rel, used)
        ):
            fails.append(
                f"S7 {rel}: unpinned runtime install "
                "(pip/npm without version, go @latest, curl|sh) "
                "(audit E1/C3)"
            )

        if (
            HEADLESS_AGENT_RX.search(text)
            and not REPO_CONFIG_ISOLATION_RX.search(text)
            and not _exempt("S9", rel, used)
        ):
            fails.append(
                f"S9 {rel}: launches a headless agent without the "
                "repo-config isolation doctrine (agent cwd outside "
                "the checkout; .claude/CLAUDE.md/hooks never loaded "
                "as config) (b-lite-p5 incident 2026-07-26)"
            )

    return fails, used


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Skill security-posture guard (S-series rules)")
    ap.add_argument("--repo", default=str(REPO))
    ap.add_argument("--quiet", action="store_true", help="suppress exemption listing")
    args = ap.parse_args(argv)

    fails, used = security_failures(Path(args.repo))
    stale = unused_exemptions()
    if stale:
        # Not cosmetic: a stale entry reads as a reviewed decision that still
        # applies, and hides that whatever it excused is gone. Failing is the
        # point — the fix is deleting a line.
        fails += [f"STALE EXEMPTION {r} {p} — matched nothing; prune it" for r, p in stale]
    print(f"Skill security-posture check for {args.repo}")
    if not args.quiet:
        for u in used:
            print(f"    {u}")
    if fails:
        print(f"\n✗ {len(fails)} security-posture violation(s):")
        for f in fails:
            print(f"    - {f}")
        print(
            "\nFix the skill (or add a reviewed EXEMPTIONS entry citing "
            "a remediation-plan item) — see /check-skill-security and "
            "progress-tracker/plans/harness-security-remediation-plan.md"
        )
        return 1
    print(
        f"✓ no security-posture regressions "
        f"({len(EXEMPTIONS)} exemptions, {len(used)} file matches, all cited)"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "skill-security", *sys.argv[1:]]))
