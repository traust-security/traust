#!/usr/bin/env python3
"""
generate_backport_configs.py — Bridge between harness artifacts and Amalgamator.

Reads a remediation JSON (from remediate-finding) and triage JSON (from triage),
scans release branches to find which still need the fix, and generates one
Amalgamator auto_bug_fix YAML config per target branch.

Usage:
    # Scan branches + generate configs:
    python3 generate_backport_configs.py \
        --remediation <path-to-remediation.json> \
        --triage <path-to-triage.json> \
        --repo <path-to-local-clone> \
        --output-dir /tmp/backport-fix/configs

    # Scan only (no config generation):
    python3 generate_backport_configs.py \
        --remediation <path-to-remediation.json> \
        --repo <path-to-local-clone> \
        --scan-only

    # Use explicit branch pattern:
    python3 generate_backport_configs.py \
        --remediation <path-to-remediation.json> \
        --repo <path-to-local-clone> \
        --output-dir /tmp/backport-fix/configs \
        --branch-pattern "release-*"

    # From a patch file (no commit SHA required):
    python3 generate_backport_configs.py \
        --patch-file fix.patch \
        --repo <path-to-local-clone> \
        --source-branch main \
        --branches release-1.5 release-1.4 \
        --build-cmd "make build" --test-cmd "make test" \
        --output-dir /tmp/backport-fix/configs
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

# Sibling module in this same directory; see the note in emit_backport_report.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _harness_paths as _paths  # noqa: E402

log = logging.getLogger(__name__)


def _scanner_invocation() -> tuple[str, dict]:
    """(interpreter, env) that can run `backport_scanner`, best effort.

    The subprocess fallback exists precisely for "the scanner is installed
    somewhere this interpreter cannot see", so it must not spawn
    sys.executable blindly — and an interpreter alone is not enough:
    backport_scanner lives in the amalgamator SOURCE tree, so its root has to
    be on PYTHONPATH as well. Preference: AMALGAMATOR_PYTHON, the amalgamator
    sibling's venv + source root, then the current interpreter as-is.
    """
    base_env = os.environ.copy()
    candidates: list[tuple[str, dict]] = []
    env_py = os.environ.get("AMALGAMATOR_PYTHON", "").strip()
    if env_py:
        candidates.append((env_py, base_env))
    ws = _paths.workspace_root()
    if ws is not None:
        root = ws / "amalgamator"
        env = base_env.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (str(root), env.get("PYTHONPATH", "")) if p
        )
        candidates.append((str(root / ".venv" / "bin" / "python"), env))
    candidates.append((sys.executable, base_env))
    for exe, env in candidates:
        try:
            r = subprocess.run(
                [exe, "-c", "import backport_scanner.run_scanner"],
                capture_output=True, timeout=60, env=env,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return exe, env
    return sys.executable, base_env


# ---------------------------------------------------------------------------
# Harness artifact readers
# ---------------------------------------------------------------------------

def read_remediation(path: Path) -> dict:
    """Read a *-remediation.json and extract fields needed for backporting."""
    with open(path) as f:
        data = json.load(f)

    fork = data.get("fork", {})
    fix_commit = fork.get("fix_commit", "")
    base_ref = fork.get("base_ref", "")
    fix_branch = fork.get("fix_branch", "")
    repo_url = data.get("metadata", {}).get("repository", "")

    build_cmd = ""
    test_cmd = ""
    for check in data.get("checks", []):
        name = check.get("name", "").lower()
        cmd = check.get("command", "")
        if "build" in name or "compile" in name:
            build_cmd = cmd
        elif "test" in name:
            test_cmd = cmd

    findings = data.get("source_findings", [])
    cwes = []
    finding_title = ""
    finding_refs = []
    for f in findings:
        cwes.extend(f.get("cwes", []))
        if not finding_title:
            finding_title = f.get("title", "")
        ref = f.get("finding_ref", "")
        if ref:
            finding_refs.append(ref)

    return {
        "fix_commit": fix_commit,
        "fix_branch": fix_branch,
        "base_ref": base_ref,
        "repo_url": repo_url,
        "build_cmd": build_cmd,
        "test_cmd": test_cmd,
        "cwes": cwes,
        "finding_title": finding_title,
        "finding_refs": finding_refs,
    }


def read_triage(path: Path, finding_refs: list[str] | None = None) -> dict:
    """Read a *-triage.json and extract severity/description context.

    When the remediation names a finding (e.g. "cri-o-triage.json#f001"),
    pick THAT finding: a multi-finding triage file otherwise contributes an
    unrelated vulnerability's title to bug_description.
    """
    with open(path) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    wanted = {r.rsplit("#", 1)[-1] for r in (finding_refs or []) if r}
    chosen = next(
        (f for f in findings if str(f.get("id", "")) in wanted),
        findings[0] if findings else {},
    )
    return {
        "severity": chosen.get("severity", ""),
        "title": chosen.get("title", ""),
        "cve_ids": [],
    }


# ---------------------------------------------------------------------------
# Patch file application
# ---------------------------------------------------------------------------

def apply_patch_as_commit(
    repo_path: Path,
    patch_file: Path,
    source_branch: str,
) -> str:
    """
    Apply a patch on top of origin/<source_branch> in an ISOLATED worktree and
    commit it there.

    The supplied clone is never modified. Applying in the user's checkout and
    running `git add -A` committed whatever untracked files happened to be
    lying around, and those then became part of the backport. A fresh
    worktree contains only the base tree, so `git add -A` there can only add
    what the patch touched.
    """
    import tempfile

    patch_path = patch_file if patch_file.is_absolute() else Path.cwd() / patch_file
    if not patch_path.is_file():
        log.error("Patch file not found: %s", patch_path)
        sys.exit(1)

    base_ref = f"origin/{source_branch}"
    r = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"],
        cwd=repo_path, capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        log.error("Base ref %s does not resolve in %s (fetch it first)",
                  base_ref, repo_path)
        sys.exit(1)

    wt_dir = Path(tempfile.mkdtemp(prefix="backport-fix-patch-"))
    worktree_added = False
    try:
        r = subprocess.run(
            ["git", "worktree", "add", "--detach", str(wt_dir), base_ref],
            cwd=repo_path, capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            log.error("git worktree add failed: %s", r.stderr.strip())
            sys.exit(1)
        worktree_added = True

        r = subprocess.run(
            ["git", "apply", "--stat", str(patch_path)],
            cwd=wt_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            log.error("Patch does not apply cleanly:\n%s", r.stderr.strip())
            sys.exit(1)

        r = subprocess.run(
            ["git", "apply", str(patch_path)],
            cwd=wt_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            log.error("git apply failed:\n%s", r.stderr.strip())
            sys.exit(1)

        # Safe here: the worktree is a pristine checkout of base_ref, so there
        # are no unrelated (untracked) files to sweep in.
        subprocess.run(
            ["git", "add", "-A"],
            cwd=wt_dir, capture_output=True, text=True, timeout=30, check=True,
        )

        commit_msg = f"Apply patch: {patch_file.name}"
        r = subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=wt_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            log.error("git commit failed (patch may be empty):\n%s", r.stderr.strip())
            sys.exit(1)

        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=wt_dir, capture_output=True, text=True, timeout=10,
        )
        fix_commit = r.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{7,40}", fix_commit):
            log.error("Could not read the patch commit SHA: %r", fix_commit)
            sys.exit(1)
    finally:
        if worktree_added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(wt_dir)],
                cwd=repo_path, capture_output=True, text=True, timeout=120,
            )
        shutil.rmtree(wt_dir, ignore_errors=True)

    # Keep the commit reachable: a detached worktree leaves it unreferenced,
    # so a later `git gc` could prune the very commit we are about to
    # cherry-pick. A local branch pins it.
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", patch_file.stem).strip("-") or "patch"
    anchor = f"backport-fix/patch-input-{safe_stem}"
    subprocess.run(
        ["git", "branch", "-f", anchor, fix_commit],
        cwd=repo_path, capture_output=True, text=True, timeout=30,
    )
    log.info("Patch applied as commit %s on branch %s", fix_commit, anchor)
    return fix_commit


# ---------------------------------------------------------------------------
# Branch scanning
# ---------------------------------------------------------------------------

def _bucket_scan_status(status) -> str:
    """
    Only deterministic patch-id matches may auto-exclude a branch;
    heuristic LIKELY_PRESENT/LIKELY_FIXED and errors go to needs-review.
    Accepts enum members, names, wire values, and the scanner JSON's
    display names (ALREADY_FIXED covers exactly EXACT_MATCH+EQUIVALENT).
    """
    s = str(getattr(status, "value", status)).upper()
    if s in ("EXACT_MATCH", "EQUIVALENT", "EQUIVALENT_PATCH", "ALREADY_FIXED"):
        return "already_fixed"
    if s == "NOT_AFFECTED":
        return "not_affected"
    if s == "NEEDS_FIX":
        return "needs_fix"
    return "ambiguous"


def _print_needs_review(ambiguous: list) -> None:
    print()
    print("  NEEDS REVIEW — not auto-backported (fail-closed selection):")
    for b in ambiguous:
        print(f"    ? {b}")
    print("  Resolve each manually, or pass it via explicit --branches to promote.")
    print("  (exit code 3: action incomplete)")


def scan_branches(
    repo_path: Path,
    fix_commit: str,
    branch_pattern: str | None = None,
    branches: list[str] | None = None,
) -> dict:
    """
    Run the Amalgamator branch scanner to find vulnerable branches.

    Returns dict with keys: needs_fix, already_fixed, not_affected, ambiguous.
    Each value is a list of branch names.
    """
    try:
        from backport_scanner.scanner import ScanConfig, run_scan
    except ImportError:
        # Different interpreter than the one the Amalgamator is installed
        # into (e.g. running from the harness venv, scanner in another).
        log.warning(
            "backport_scanner is not importable here — falling back to the "
            "scanner subprocess (run_scanner --config)"
        )
        return scan_branches_subprocess(repo_path, fix_commit, branch_pattern, branches)

    config = ScanConfig(
        repo_path=repo_path,
        fix_commit=fix_commit,
        branches=branches or [],
        branch_pattern=branch_pattern,
    )
    report = run_scan(config)

    # Re-bucket per-branch: the scanner's already_fixed grouping includes
    # the heuristic LIKELY_PRESENT, which must not auto-exclude.
    buckets = {"needs_fix": [], "already_fixed": [], "not_affected": [], "ambiguous": []}
    for r in report.results:
        buckets[_bucket_scan_status(getattr(r, "status", ""))].append(r.branch)
    buckets["total"] = len(report.results)
    return buckets


def scan_branches_subprocess(
    repo_path: Path,
    fix_commit: str,
    branch_pattern: str | None = None,
    branches: list[str] | None = None,
) -> dict:
    """
    Fallback: run the scanner in a subprocess and read its JSON report.

    The scanner prints a human-readable report to stdout and saves JSON only
    to --output, so the report goes to a temp FILE — parsing stdout cannot
    work. Its exit code is also a verdict, not an error signal:
        0 = no branch needs the fix, 1 = needs_fix present, 3 = ambiguous
    Only 2 (per-ref validation errors, or no refs scanned) is a hard failure.

    The JSON report is the authority, not the exit code: an uncaught crash
    also exits 1, so a malformed or error-carrying report must fail closed
    rather than be read as a verdict. The wire contract (0/1/3, refs[] with
    raw_status) is pinned by tests here and should be pinned with the
    scanner project before it changes.
    """
    scan_yaml = {
        "repository": {"local_path": str(repo_path)},
        "fix": {"commit": fix_commit},
        "scan": {},
    }
    if branches:
        scan_yaml["scan"]["branches"] = list(branches)
    if branch_pattern:
        scan_yaml["scan"]["branch_pattern"] = branch_pattern

    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as tmp:
        yaml.dump(scan_yaml, tmp, default_flow_style=False)
        cfg_path = Path(tmp.name)
    report_path = cfg_path.with_suffix(".json")

    try:
        scanner_py, scanner_env = _scanner_invocation()
        try:
            result = subprocess.run(
                [
                    scanner_py, "-m", "backport_scanner.run_scanner",
                    "--config", str(cfg_path),
                    "--output", str(report_path),
                ],
                capture_output=True,
                text=True,
                timeout=1800,
                env=scanner_env,
            )
        except subprocess.TimeoutExpired:
            log.error("Branch scanner timed out after 30 minutes")
            sys.exit(1)

        # 0/1/3 all mean "the scan completed"; 2 means refs failed validation.
        if result.returncode not in (0, 1, 3):
            log.error(
                "Branch scanner failed (exit %d):\n%s",
                result.returncode, result.stderr.strip(),
            )
            sys.exit(1)
        if not report_path.is_file():
            log.error("Branch scanner produced no JSON report at %s", report_path)
            sys.exit(1)

        try:
            report = json.loads(report_path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            log.error("Branch scanner report is unreadable (%s) — failing closed", e)
            sys.exit(1)
        if not isinstance(report, dict):
            log.error("Branch scanner report is not a JSON object — failing closed")
            sys.exit(1)
        errors = (report.get("summary") or {}).get("errors", 0)
        if errors:
            log.error(
                "Branch scanner reported %s ref error(s) — refusing to bucket a "
                "partial scan", errors,
            )
            sys.exit(1)
        refs = report.get("refs", [])
        buckets = {"needs_fix": [], "already_fixed": [], "not_affected": [], "ambiguous": []}
        for r in refs:
            if r.get("ref_type", "branch") != "branch":
                continue
            # raw_status carries the enum value; status carries the display
            # name. _bucket_scan_status understands both, but prefers the
            # value where they differ.
            buckets[_bucket_scan_status(r.get("raw_status") or r.get("status", ""))].append(
                r.get("name", "")
            )
        buckets["total"] = sum(len(v) for v in buckets.values())
        return buckets
    finally:
        cfg_path.unlink(missing_ok=True)
        report_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Seam A — impact-analysis input (dependency CVEs). The artifact carries no
# fix commit: the backportable artifact is the bump commit on the source
# branch, and branch selection is version-based, not patch-id based.
# ---------------------------------------------------------------------------

def _norm_repo_url(u: str) -> str:
    """Normalize a repo identifier (graph id, git URL) for matching."""
    u = u.strip().lower().removeprefix("repo:")
    for pre in ("https://", "http://", "ssh://", "git://"):
        u = u.removeprefix(pre)
    if u.startswith("git@"):
        u = u.removeprefix("git@").replace(":", "/", 1)
    return u.rstrip("/").removesuffix(".git")


def read_impact(path: Path, repo_path: Path, impact_repo: str | None) -> dict:
    """Read a *-impact-analysis.json and select this clone's repos[] entry."""
    with open(path) as f:
        data = json.load(f)
    meta = data.get("metadata", {})
    cve = meta.get("cve", "")
    module = meta.get("module", "")
    fixed_version = meta.get("fixed_version", "")
    if not (cve and module and fixed_version):
        log.error("Impact analysis is missing metadata.cve/module/fixed_version.")
        sys.exit(1)
    ecosystem = str(meta.get("ecosystem", "")).lower()
    if ecosystem and ecosystem not in ("go", "golang"):
        log.error(
            "Impact ecosystem %r is not Go — the version-based branch scan "
            "only understands go.mod/vendor/modules.txt.",
            meta.get("ecosystem"),
        )
        sys.exit(1)
    # Advisories carry bare SemVer ("1.11.3"); Go module files use
    # v-prefixed versions — normalize at ingestion.
    if fixed_version.startswith("V"):
        fixed_version = fixed_version[1:]
    if not fixed_version.startswith("v"):
        fixed_version = "v" + fixed_version

    origin = ""
    try:
        r = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            origin = r.stdout.strip()
    except Exception:
        pass

    want = _norm_repo_url(impact_repo or origin)
    entry = None
    if want:
        for e in data.get("repos", []):
            if _norm_repo_url(e.get("repo", "")) == want:
                entry = e
                break
    if entry is None:
        log.error(
            "No repos[] entry in %s matches this clone (origin=%s). "
            "Pass --impact-repo with the entry's repo id.",
            path, origin or "<unknown>",
        )
        sys.exit(1)

    log.info(
        "Impact entry: %s  classification=%s  version=%s",
        entry.get("repo", ""), entry.get("classification", ""),
        entry.get("version", ""),
    )
    # Classification describes the analyzed commit, not the branches — the
    # per-branch version scan decides; only surface surprising values.
    if entry.get("classification") in ("not_imported", "inconclusive"):
        log.warning(
            "Classification is %r at the analyzed commit — the per-branch "
            "version scan still decides each branch.",
            entry.get("classification"),
        )
    return {
        "cve": cve,
        "module": module,
        "fixed_version": fixed_version,
        "classification": entry.get("classification", ""),
        "repo_id": entry.get("repo", ""),
    }


_GO_IDENT_RE = re.compile(r"^[0-9A-Za-z-]+$")


def parse_go_version(v: str):
    """
    Parse a Go module version (prereleases, pseudo-versions,
    +incompatible) into a semver-ordered comparable key; None if
    unparseable.
    """
    v = v.strip()
    if not v.startswith("v"):
        return None
    v = v[1:].split("+", 1)[0]
    core, _, pre = v.partition("-")
    parts = core.split(".")
    if len(parts) != 3:
        return None
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        return None
    if not pre:
        return (*nums, (1,))
    idents = []
    for ident in pre.split("."):
        if not ident or not _GO_IDENT_RE.match(ident):
            return None
        if ident.isdigit():
            idents.append((0, int(ident), ""))
        else:
            idents.append((1, 0, ident))
    return (*nums, (0, tuple(idents)))


def go_version_lt(a: str, b: str):
    """a < b for Go module versions; None when either is unparseable."""
    ka, kb = parse_go_version(a), parse_go_version(b)
    if ka is None or kb is None:
        return None
    return ka < kb


def _module_version_from_modules_txt(text: str, module: str) -> str | None:
    """Effective version from vendor/modules.txt; a replacement wins."""
    for line in text.splitlines():
        if not line.startswith("# "):
            continue
        toks = line[2:].split()
        if not toks or toks[0] != module:
            continue
        if "=>" in toks:
            # Only a trailing version after "=>" counts: never the
            # replaced-away LHS version, never a vanity path (vitess.io/…).
            after = toks[toks.index("=>") + 1:]
            if len(after) >= 2 and after[-1].startswith("v"):
                return after[-1]
            return "path"
        if len(toks) >= 2 and toks[1].startswith("v"):
            return toks[1]
    return None


def _module_version_from_gomod(text: str, module: str) -> str | None:
    """Version from go.mod require/replace. Returns 'path' when an applicable
    replace directive points at a local path (version indeterminate).

    A version-qualified replace (`replace m v1.0.0 => m v1.9.0`) applies only
    when the required version is v1.0.0 either. Applying it unconditionally
    made a branch look bumped to v1.9.0 while v1.2.0 was what actually built,
    silently excluding a vulnerable branch.
    """
    version = None
    replacements: list[tuple[str | None, str]] = []
    in_require = in_replace = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if line.startswith("replace ("):
            in_replace = True
            continue
        if line == ")":
            in_require = in_replace = False
            continue
        toks = line.split()
        if line.startswith("require ") and len(toks) >= 3 and toks[1] == module:
            version = toks[2]
            continue
        if in_require and len(toks) >= 2 and toks[0] == module:
            version = toks[1]
            continue
        if line.startswith("replace "):
            body = toks[1:]
        elif in_replace:
            body = toks
        else:
            continue
        if "=>" not in body:
            continue
        arrow = body.index("=>")
        left, right = body[:arrow], body[arrow + 1:]
        if not left or left[0] != module:
            continue
        lhs_version = left[1] if len(left) >= 2 and left[1].startswith("v") else None
        target = right[-1] if right and right[-1].startswith("v") else "path"
        replacements.append((lhs_version, target))

    exact = None
    wildcard = None
    for lhs_version, target in replacements:
        if lhs_version is None:
            wildcard = target
        elif version is not None and lhs_version == version:
            exact = target
    # Go gives a version-exact replacement precedence over a wildcard one
    # regardless of directive order; last-match-wins inverted that and could
    # report a vulnerable branch as bumped.
    chosen = exact if exact is not None else wildcard
    return chosen or version


def module_version_at(repo_path: Path, ref: str, module: str):
    """
    Effective version of `module` at `ref`: ('found', v) / ('absent', None)
    / ('ambiguous', None). vendor/modules.txt is consulted first (it holds
    effective versions incl. transitive deps), then go.mod.

    'absent' means: the ref exists, and neither file lists the module.
    A ref that does not resolve, or a file that exists but cannot be read, is
    'ambiguous' — never 'absent', which would silently report a branch as
    not affected.
    """
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        log.error("git rev-parse timed out validating ref %s", ref)
        return ("ambiguous", None)
    if r.returncode != 0:
        log.error("Ref %s does not resolve in %s — cannot classify", ref, repo_path)
        return ("ambiguous", None)

    for fname, parser in (
        ("vendor/modules.txt", _module_version_from_modules_txt),
        ("go.mod", _module_version_from_gomod),
    ):
        # Does the file exist at that ref at all? A missing file is normal
        # (vendoring is optional); an unreadable one is not.
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{ref}:{fname}"],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if exists.returncode != 0:
            continue
        try:
            r = subprocess.run(
                ["git", "show", f"{ref}:{fname}"],
                cwd=repo_path, capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            log.error("git show timed out reading %s at %s", fname, ref)
            return ("ambiguous", None)
        if r.returncode != 0:
            log.error("Cannot read %s at %s: %s", fname, ref, r.stderr.strip())
            return ("ambiguous", None)
        v = parser(r.stdout, module)
        if v == "path":
            return ("ambiguous", None)
        if v:
            return ("found", v)
    return ("absent", None)


def list_release_branches(
    repo_path: Path, branch_pattern: str | None, branches: list[str] | None
) -> list[str]:
    if branches:
        return list(branches)
    pattern = branch_pattern or "release-*"
    try:
        r = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname:short)",
             f"refs/remotes/origin/{pattern}"],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        log.error("git for-each-ref timed out listing branches")
        return []
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("origin/") and "HEAD" not in line:
            out.append(line.removeprefix("origin/"))
    return sorted(out)


def scan_branches_by_version(
    repo_path: Path,
    module: str,
    fixed_version: str,
    branch_pattern: str | None = None,
    branches: list[str] | None = None,
) -> dict:
    """Classify branches by effective module version vs fixed_version
    (patch-ids can't match an independently-bumped branch)."""
    result = {"needs_fix": [], "already_fixed": [], "not_affected": [],
              "ambiguous": [], "total": 0}
    for br in list_release_branches(repo_path, branch_pattern, branches):
        result["total"] += 1
        status, ver = module_version_at(repo_path, f"origin/{br}", module)
        if status == "absent":
            result["not_affected"].append(br)
            continue
        if status != "found":
            result["ambiguous"].append(br)
            continue
        lt = go_version_lt(ver, fixed_version)
        if lt is None:
            result["ambiguous"].append(br)
        elif lt:
            result["needs_fix"].append(br)
        else:
            result["already_fixed"].append(br)
    return result


def find_bump_commit(
    repo_path: Path, source_ref: str, module: str, fixed_version: str,
    max_walk: int = 400,
) -> tuple[str, str | None]:
    """
    Newest commit on source_ref whose effective module version first
    reaches fixed_version. Returns ("found", sha); ("not_fixed", None)
    when source_ref never reaches it; ("not_located", None) when it IS
    fixed but the transition is beyond max_walk (use --fix-commit).
    """
    status, ver = module_version_at(repo_path, source_ref, module)
    if status != "found" or ver is None:
        return ("not_fixed", None)
    lt = go_version_lt(ver, fixed_version)
    if lt is None or lt:
        return ("not_fixed", None)

    try:
        r = subprocess.run(
            ["git", "rev-list", f"--max-count={max_walk}", source_ref,
             "--", "go.mod", "vendor/modules.txt"],
            cwd=repo_path, capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        log.error("git rev-list timed out while locating the bump commit")
        return ("not_located", None)
    for sha in r.stdout.split():  # newest -> oldest
        st_p, v_p = module_version_at(repo_path, f"{sha}~1", module)
        parent_fixed = (
            st_p == "found" and v_p is not None
            and go_version_lt(v_p, fixed_version) is False
        )
        if parent_fixed:
            continue
        st_c, v_c = module_version_at(repo_path, sha, module)
        if (st_c == "found" and v_c is not None
                and go_version_lt(v_c, fixed_version) is False):
            return ("found", sha)
    return ("not_located", None)


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

def get_default_branch(repo_path: Path) -> str:
    """Discover the default branch of the remote."""
    try:
        result = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD", "--short"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip().removeprefix("origin/")
    except Exception:
        pass
    return "main"


# issue_id reaches worktree paths, tracker filenames, and the
# amalgamator/<slug> branch — every embedded token must pass this allowlist.
_ISSUE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_ADVISORY_RE = re.compile(r"(cve-\d{4}-\d{4,}|ghsa(-[a-z0-9]{4}){3})")


def slug_issue_id(
    finding_refs: list[str],
    repo_slug: str,
    safe_branch: str,
    short_sha: str,
) -> str:
    """
    Build a validated issue_id: backport-<repo>-<finding_id>-<branch> for a
    single triage-style ref; multiple findings, CVE-shaped ids (never in
    git-visible identifiers), or invalid tokens fall back to the neutral
    backport-<branch>-<shortsha>. Original refs stay in finding_refs[].
    """
    fallback = f"backport-{safe_branch}-{short_sha}"
    if len(finding_refs) != 1:
        return fallback
    fid = finding_refs[0].rsplit("#", 1)[-1].strip().lower()
    repo = repo_slug.strip().lower()
    if _ADVISORY_RE.search(fid):
        return fallback
    if _ISSUE_TOKEN_RE.match(fid) and _ISSUE_TOKEN_RE.match(repo):
        return f"backport-{repo}-{fid}-{safe_branch}"
    return fallback


_SLUG_BAD_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_slug(branch: str, used: set[str] | None = None) -> str:
    """An allowlisted, collision-safe directory/file slug for a branch name.

    Branch names are attacker-controlled in the sense that any fetched remote
    can introduce one, and git permits quotes and shell metacharacters. The
    slug is used for config filenames and workdir paths, so it must contain
    only [A-Za-z0-9._-]; a collision (release-1.2 vs release-1/2) gets a short
    hash suffix instead of silently overwriting another branch's config.
    """
    slug = _SLUG_BAD_RE.sub("-", branch).strip(".-_") or "branch"
    if used is None:
        return slug
    if slug in used:
        base = slug
        digest = hashlib.sha256(branch.encode()).hexdigest()[:8]
        slug = f"{base}-{digest}"
        n = 1
        while slug in used:          # a crafted name can collide here too
            n += 1
            slug = f"{base}-{digest}-{n}"
    used.add(slug)
    return slug


def make_config_yaml(
    repo_path: Path,
    fix_commit: str,
    target_branch: str,
    source_branch: str,
    bug_description: str,
    build_cmd: str = "",
    test_cmd: str = "",
    finding_refs: list[str] | None = None,
    repo_slug: str = "",
    model: str = "claude-opus-4-6",
    max_retries: int = 3,
    safe_branch: str | None = None,
) -> dict:
    """Produce an Amalgamator auto_bug_fix-compatible YAML dict."""
    short = fix_commit[:10]
    # Caller passes the SAME allocation used for the config filename; deriving
    # it again here let two colliding branches share issue_id/workdir/branch.
    safe_branch = safe_branch or safe_slug(target_branch)
    issue_id = slug_issue_id(finding_refs or [], repo_slug, safe_branch, short)

    cfg = {
        "issue_id": issue_id,
        "bug_description": bug_description,
        "repository": {
            "source_path": str(repo_path),
            "workdir": f"/tmp/bugfix-backport-{safe_branch}-{short}",
        },
        "branches": {
            "source": f"origin/{source_branch}",
            "target": f"origin/{target_branch}",
        },
        "fix": {
            "commit": fix_commit,
        },
        "build": {
            "command": build_cmd,
            "test_command": test_cmd,
        },
        "model": model,
    }
    if max_retries != 3:
        cfg["advanced"] = {"max_build_test_retries": max_retries}
    return cfg


def write_config(data: dict, path: Path) -> None:
    """Write an Amalgamator config YAML to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    log.info("Written config: %s", path)


# ---------------------------------------------------------------------------
# Mode setup — each returns the common context the shared scan/generate
# tail consumes.
# ---------------------------------------------------------------------------

def setup_from_remediation(args) -> dict:
    """Seam B: a *-remediation.json from remediate-finding."""
    rem = read_remediation(args.remediation)

    # Resolve fix_commit: use fork.fix_commit if present, otherwise resolve
    # HEAD of fork.fix_branch. prepare_backport_fork.sh fetches fork-only
    # fixes into refs/remotes/fork/<branch>, so try that remote first — the
    # upstream origin/<branch> is exactly what an embargoed fix is NOT on.
    if not rem["fix_commit"] and rem["fix_branch"]:
        log.info("fix_commit not in remediation JSON, resolving from fix_branch: %s", rem["fix_branch"])
        candidates = [
            f"refs/remotes/fork/{rem['fix_branch']}",
            f"refs/remotes/origin/{rem['fix_branch']}",
            f"origin/{rem['fix_branch']}",
            rem["fix_branch"],
        ]
        for ref in candidates:
            r = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                cwd=args.repo, capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                rem["fix_commit"] = r.stdout.strip()
                log.info("Resolved fix_commit %s from %s", rem["fix_commit"], ref)
                break
        else:
            log.error(
                "Could not resolve fix_branch %s from any of: %s",
                rem["fix_branch"], ", ".join(candidates),
            )
            sys.exit(1)

    if not rem["fix_commit"]:
        log.error("No fix_commit found in remediation JSON and no fix_branch to resolve from.")
        sys.exit(1)

    log.info("Fix commit: %s", rem["fix_commit"])
    log.info("Source branch: %s", rem["base_ref"])
    log.info("Repository: %s", rem["repo_url"])

    triage_info = {}
    if args.triage and args.triage.exists():
        triage_info = read_triage(args.triage, rem["finding_refs"])
        log.info("Finding severity: %s", triage_info.get("severity", "unknown"))

    return {
        "scan_mode": "patch",
        "fix_commit": rem["fix_commit"],
        "source_branch": rem["base_ref"] or get_default_branch(args.repo),
        "build_cmd": args.build_cmd or rem["build_cmd"],
        "test_cmd": args.test_cmd or rem["test_cmd"],
        "finding_refs": rem["finding_refs"],
        "cwes": rem["cwes"],
        "title": triage_info.get("title") or rem["finding_title"] or "Security fix backport",
        "repo_slug": (
            rem["repo_url"].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            if rem["repo_url"] else args.repo.name
        ),
        "module": None,
        "fixed_version": None,
    }


def setup_from_patch(args) -> dict:
    """
    Patch-file input: a .patch file is applied to the source branch to create
    a local fix commit. Optionally enriched by a remediation JSON for context
    (CWEs, finding refs, build/test commands).
    """
    build_cmd = args.build_cmd or ""
    test_cmd = args.test_cmd or ""
    finding_refs = []
    cwes = []
    title = f"Patch: {args.patch_file.name}"
    repo_slug = args.repo.name

    # When combined with --remediation, pull base_ref as default source branch
    # and enrich with CWEs, finding refs, build/test commands.
    rem_base_ref = None
    if args.remediation and args.remediation.exists():
        rem = read_remediation(args.remediation)
        rem_base_ref = rem.get("base_ref")
        build_cmd = build_cmd or rem["build_cmd"]
        test_cmd = test_cmd or rem["test_cmd"]
        finding_refs = rem["finding_refs"]
        cwes = rem["cwes"]
        title = rem["finding_title"] or title
        if rem["repo_url"]:
            repo_slug = rem["repo_url"].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")

    source_branch = args.source_branch or rem_base_ref or "main"
    log.info("Applying patch %s to %s...", args.patch_file, source_branch)
    fix_commit = apply_patch_as_commit(args.repo, args.patch_file, source_branch)

    log.info("Fix commit (from patch): %s", fix_commit)
    log.info("Source branch: %s", source_branch)

    return {
        "scan_mode": "patch",
        "fix_commit": fix_commit,
        "source_branch": source_branch,
        "build_cmd": build_cmd,
        "test_cmd": test_cmd,
        "finding_refs": finding_refs,
        "cwes": cwes,
        "title": title,
        "repo_slug": repo_slug,
        "module": None,
        "fixed_version": None,
    }


def setup_from_impact(args) -> dict:
    """Seam A: a *-impact-analysis.json (dependency CVE, public advisory)."""
    imp = read_impact(args.impact, args.repo, args.impact_repo)
    log.info(
        "CVE %s — module %s, fixed_version %s",
        imp["cve"], imp["module"], imp["fixed_version"],
    )
    source_branch = get_default_branch(args.repo)
    if args.fix_commit:
        fix_commit = args.fix_commit.lower()
        if not re.fullmatch(r"[0-9a-f]{7,40}", fix_commit):
            log.error("--fix-commit must be 7-40 hex chars: %s", args.fix_commit)
            sys.exit(1)
        check = subprocess.run(
            ["git", "cat-file", "-e", f"{fix_commit}^{{commit}}"],
            cwd=args.repo, capture_output=True, timeout=10,
        )
        if check.returncode != 0:
            log.error("--fix-commit %s is not a commit in %s", fix_commit, args.repo)
            sys.exit(1)
        log.info("Using --fix-commit override: %s", fix_commit)
    else:
        status, fix_commit = find_bump_commit(
            args.repo, f"origin/{source_branch}",
            imp["module"], imp["fixed_version"], max_walk=args.max_walk,
        )
        if status == "not_fixed":
            log.error(
                "No commit on origin/%s bumps %s to >= %s — the source branch "
                "is not fixed, so there is nothing to backport. Bump first "
                "(remediate-finding dependency-bump / fleet-fix), then re-run. "
                "(bump-first, fail closed)",
                source_branch, imp["module"], imp["fixed_version"],
            )
            sys.exit(1)
        if status == "not_located":
            log.error(
                "origin/%s IS fixed (%s >= %s) but the bump commit was not "
                "located within the newest %d go.mod-touching commits — pass "
                "--fix-commit <sha> or raise --max-walk. (This is NOT the "
                "bump-first case.)",
                source_branch, imp["module"], imp["fixed_version"], args.max_walk,
            )
            sys.exit(1)
        log.info("Bump commit on origin/%s: %s", source_branch, fix_commit)

    return {
        "scan_mode": "version",
        "fix_commit": fix_commit,
        "source_branch": source_branch,
        "build_cmd": args.build_cmd,
        "test_cmd": args.test_cmd,
        "finding_refs": [imp["cve"]],
        "cwes": [],
        "title": f"bump {imp['module']} to {imp['fixed_version']} for {imp['cve']}",
        "repo_slug": (
            _norm_repo_url(imp["repo_id"]).rsplit("/", 1)[-1] or args.repo.name
        ),
        "module": imp["module"],
        "fixed_version": imp["fixed_version"],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Amalgamator configs from harness remediation artifacts."
    )
    parser.add_argument(
        "--remediation", "-r", type=Path, default=None,
        help="Seam B input: path to *-remediation.json from remediate-finding"
    )
    parser.add_argument(
        "--impact", type=Path, default=None,
        help="Seam A input: path to *-impact-analysis.json (dependency CVE); "
             "branch selection becomes version-based and the fix commit is "
             "located as the bump commit on the source branch (fail-closed "
             "bump-first when absent)"
    )
    parser.add_argument(
        "--impact-repo", type=str, default=None,
        help="repos[] id to select from the impact analysis when the clone's "
             "origin URL does not match (e.g. repo:github.com/org/name)"
    )
    parser.add_argument(
        "--triage", "-t", type=Path, default=None,
        help="Path to *-triage.json from triage (optional, enriches bug "
             "description; --remediation mode only)"
    )
    parser.add_argument(
        "--fix-commit", type=str, default=None,
        help="Seam A only: explicit bump-commit SHA, bypassing history "
             "search (use when the bump is older than --max-walk)"
    )
    parser.add_argument(
        "--max-walk", type=int, default=400,
        help="Seam A only: how many go.mod-touching commits to walk when "
             "locating the bump commit (default: 400)"
    )
    parser.add_argument(
        "--build-cmd", type=str, default="",
        help="Build command for the generated configs (overrides the "
             "remediation checks in Seam B; required knowledge in Seam A "
             "unless left for manual fill-in)"
    )
    parser.add_argument(
        "--test-cmd", type=str, default="",
        help="Test command for the generated configs (see --build-cmd)"
    )
    parser.add_argument(
        "--repo", type=Path, required=True,
        help="Path to local clone of the repository"
    )
    parser.add_argument(
        "--output-dir", "-o", type=Path, default=Path("/tmp/backport-fix/configs"),
        help="Directory to write generated YAML configs"
    )
    parser.add_argument(
        "--branch-pattern", type=str, default=None,
        help="Glob pattern for branch discovery (e.g. 'release-*')"
    )
    parser.add_argument(
        "--branches", nargs="+", default=None,
        help="Explicit list of branches to check"
    )
    parser.add_argument(
        "--scan-only", action="store_true",
        help="Only scan branches, do not generate configs"
    )
    parser.add_argument(
        "--skip-scan", action="store_true",
        help="Skip branch scanning — treat all --branches as NEEDS_FIX and generate configs directly"
    )
    parser.add_argument(
        "--model", type=str, default="claude-opus-4-6",
        help="Model name for Amalgamator config (default: claude-opus-4-6)"
    )
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Max build/test recovery attempts in Phase 4a (default: 3)"
    )
    parser.add_argument(
        "--patch-file", type=Path, default=None,
        help="Path to a .patch file to apply as the fix. The patch is "
             "committed locally on --source-branch, creating a fix_commit "
             "for the backport pipeline. Can be combined with --remediation "
             "for CWE/finding context, or used standalone with --build-cmd "
             "and --branches."
    )
    parser.add_argument(
        "--source-branch", type=str, default=None,
        help="Branch to apply the patch to (default: base_ref from "
             "remediation JSON, or 'main'). Only used with --patch-file."
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.repo.exists():
        log.error("Repository path does not exist: %s", args.repo)
        sys.exit(1)

    has_patch = args.patch_file is not None
    has_rem = args.remediation is not None
    has_impact = args.impact is not None

    if has_patch:
        if has_impact:
            log.error("--patch-file cannot be combined with --impact.")
            sys.exit(1)
        if not args.patch_file.exists():
            log.error("Patch file not found: %s", args.patch_file)
            sys.exit(1)
        if not has_rem and not args.branches:
            log.error(
                "--patch-file without --remediation requires --branches "
                "(target branches cannot be inferred from a patch alone)."
            )
            sys.exit(1)
    elif not (has_rem ^ has_impact):
        log.error(
            "Provide one of: --remediation (Seam B), --impact (Seam A), "
            "or --patch-file (patch input)."
        )
        sys.exit(1)

    if has_impact and args.triage:
        log.error("--triage only applies to --remediation mode.")
        sys.exit(1)
    if has_rem and not has_patch and (args.fix_commit or args.max_walk != 400):
        log.error("--fix-commit/--max-walk only apply to --impact mode.")
        sys.exit(1)
    if has_rem and not args.remediation.exists():
        log.error("Remediation JSON not found: %s", args.remediation)
        sys.exit(1)
    if has_impact and not args.impact.exists():
        log.error("Impact analysis JSON not found: %s", args.impact)
        sys.exit(1)

    # --- Read harness artifacts, resolve the fix commit ---
    if has_patch:
        ctx = setup_from_patch(args)
    elif has_rem:
        ctx = setup_from_remediation(args)
    else:
        ctx = setup_from_impact(args)

    # --- Determine target branches ---
    branch_pattern = args.branch_pattern
    if args.skip_scan and args.branches:
        # Trust the user: skip scanning, treat all explicit branches as NEEDS_FIX
        log.info("--skip-scan: treating %d explicit branch(es) as NEEDS_FIX", len(args.branches))
        scan_result = {
            "needs_fix": list(args.branches),
            "already_fixed": [],
            "not_affected": [],
            "ambiguous": [],
            "total": len(args.branches),
        }
    elif args.skip_scan and not args.branches:
        log.error("--skip-scan requires --branches (need an explicit list to skip scanning)")
        sys.exit(1)
    elif ctx["scan_mode"] == "version":
        # Seam A: dependency CVEs select by effective module version —
        # patch-id scanning can never match an independently-bumped branch.
        log.info("Scanning branches by module version...")
        scan_result = scan_branches_by_version(
            repo_path=args.repo,
            module=ctx["module"],
            fixed_version=ctx["fixed_version"],
            branch_pattern=args.branch_pattern,
            branches=args.branches,
        )
    else:
        # Run the branch scanner. scan_branches() falls back to the scanner
        # subprocess on its own when the module is not importable here; a
        # scanner failure must propagate rather than be retried blindly.
        #
        # A scan with neither an explicit list nor a pattern discovers NO
        # refs (the scanner resolves branches from those two inputs), so the
        # documented "scan the release branches" invocation silently reported
        # "nothing needs fixing". Default the pattern instead.
        if not args.branches and not branch_pattern:
            branch_pattern = "release-*"
            log.info("No --branches/--branch-pattern given — defaulting to %r",
                     branch_pattern)
        log.info("Scanning branches...")
        scan_result = scan_branches(
            repo_path=args.repo,
            fix_commit=ctx["fix_commit"],
            branch_pattern=branch_pattern,
            branches=args.branches,
        )

        # When --branches is explicit and results are ambiguous (e.g. no LLM
        # available for disambiguation), promote ambiguous to needs_fix —
        # the user explicitly asked for these branches.
        if args.branches and scan_result["ambiguous"]:
            promoted = scan_result["ambiguous"]
            log.info(
                "Promoting %d ambiguous branch(es) to NEEDS_FIX (explicit --branches)",
                len(promoted),
            )
            scan_result["needs_fix"].extend(promoted)
            scan_result["ambiguous"] = []

    # An empty scan is never "nothing to do": it usually means the selection
    # inputs matched nothing (wrong pattern, unfetched branches). Fail closed
    # so the caller cannot mistake it for a clean bill of health.
    if scan_result["total"] == 0:
        log.error(
            "Branch scan matched no refs (pattern=%r, explicit=%s). "
            "Pass --branch-pattern or --branches, and ensure the branches "
            "are fetched.",
            branch_pattern if ctx["scan_mode"] != "version" else args.branch_pattern,
            ", ".join(args.branches or []) or "none",
        )
        sys.exit(2)

    # --- Print scan summary ---
    print()
    print("=" * 60)
    print("  BRANCH SCAN RESULTS")
    print("=" * 60)
    print(f"  Repository:  {args.repo}")
    print(f"  Fix commit:  {ctx['fix_commit']}")
    print(f"  Scanned:     {scan_result['total']} branch(es)")
    print()

    if scan_result["needs_fix"]:
        print(f"  NEEDS FIX ({len(scan_result['needs_fix'])}):")
        for b in scan_result["needs_fix"]:
            print(f"    x {b}")
    if scan_result["already_fixed"]:
        print(f"  ALREADY FIXED ({len(scan_result['already_fixed'])}):")
        for b in scan_result["already_fixed"]:
            print(f"    v {b}")
    if scan_result["not_affected"]:
        print(f"  NOT AFFECTED ({len(scan_result['not_affected'])}):")
        for b in scan_result["not_affected"]:
            print(f"    - {b}")
    if scan_result["ambiguous"]:
        print(f"  AMBIGUOUS ({len(scan_result['ambiguous'])}):")
        for b in scan_result["ambiguous"]:
            print(f"    ? {b}")
    print("=" * 60)

    if args.scan_only:
        print("\n  --scan-only: stopping before config generation.")
        if scan_result["ambiguous"]:
            _print_needs_review(scan_result["ambiguous"])
            # An incomplete scan is not a successful scan: automation must be
            # able to tell "nothing to do" from "some refs unresolved".
            sys.exit(3)
        return

    if not scan_result["needs_fix"]:
        print("\n  No branches need the fix. Nothing to generate.")
        if scan_result["ambiguous"]:
            _print_needs_review(scan_result["ambiguous"])
            sys.exit(3)
        return

    # --- Generate configs ---
    bug_desc = ctx["title"]
    cwes_str = ", ".join(ctx["cwes"]) if ctx["cwes"] else ""
    if cwes_str:
        bug_desc = f"Backport: {bug_desc} ({cwes_str})"
    else:
        bug_desc = f"Backport: {bug_desc}"

    used_slugs: set[str] = set()
    for branch in scan_result["needs_fix"]:
        slug = safe_slug(branch, used_slugs)
        cfg = make_config_yaml(
            repo_path=args.repo,
            fix_commit=ctx["fix_commit"],
            target_branch=branch,
            source_branch=ctx["source_branch"],
            bug_description=bug_desc,
            build_cmd=ctx["build_cmd"],
            test_cmd=ctx["test_cmd"],
            finding_refs=ctx["finding_refs"],
            repo_slug=ctx["repo_slug"],
            model=args.model,
            max_retries=args.max_retries,
            safe_branch=slug,
        )
        out_path = args.output_dir / f"{slug}.yaml"
        write_config(cfg, out_path)

    print(f"\n  Generated {len(scan_result['needs_fix'])} config(s) in {args.output_dir}/")
    if ctx["build_cmd"] or ctx["test_cmd"]:
        print(f"  build.command:      {ctx['build_cmd'] or '(empty)'}")
        print(f"  build.test_command: {ctx['test_cmd'] or '(empty)'}")
    else:
        print("  build/test commands are empty — review and fill in manually.")
    print("  Run: bash harnessing/7-remediate/backport-fix/scripts/run_backport.sh --config-dir", args.output_dir)

    # Ambiguous branches were not configured — incomplete, not a success.
    if scan_result["ambiguous"]:
        _print_needs_review(scan_result["ambiguous"])
        sys.exit(3)


if __name__ == "__main__":
    main()
