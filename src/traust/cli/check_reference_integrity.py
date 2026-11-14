#!/usr/bin/env python3
"""Reference-integrity gate (C8.4 placement-rule companion).

Fails when maintained docs/commands/config still cite the retired top-level
scripts/ tree or allowed-tools frontmatter whitelists pre-move script basenames.

Usage:
    python3 -m traust.cli.check_reference_integrity
    python3 -m traust.cli.check_reference_integrity --root .

Exit 0 = clean, 1 = stale references found.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from traust.paths import (
    HARNESS_ROOT,
    skill_md_paths,
    skill_scripts,
)

REPO = HARNESS_ROOT

_EXCLUDE_DOCS = {
    "CHANGELOG.md",
}

_SCRIPTS_SUBPATH_RX = re.compile(
    r"(?<![\w-])scripts/(?:ops/|migrations/|lib/)?[A-Za-z0-9_./-]+\.(?:py|sh)\b"
)
# One OR two segments before scripts/: a non-workflow skill sits at
# harnessing/<skill>/, a workflow skill one level deeper under its stage
# directory, harnessing/<N>-<stage>/<skill>/ (skill-usability plan 1.2).
# Both spellings must match — the single-level form is what the findings
# corpus recorded and is never rewritten.
_HARNESS_SKILL_SCRIPTS_RX = re.compile(
    r"harnessing/(?:[a-z0-9-]+/){1,2}scripts/[A-Za-z0-9_./-]+\.(?:py|sh)\b"
)
# Skill-base placeholders resolve at run time, so the path cannot be checked on
# disk. Spelling is matched loosely on purpose: docs use <skill-base>, and
# pinning one variant silently reclassified correct references as stale.
_SKILL_BASE_SCRIPTS_RX = re.compile(
    r"(?:\.claude/skills/|\.crush/skills/"
    r"|<skill[-_](?:dir|base)>/scripts/"
    r"|\$SKILL_(?:DIR|BASE)/scripts/)",
    re.IGNORECASE,
)
_BARE_ALLOW_RX = re.compile(r"Bash\((python3?) \*([A-Za-z0-9_]+)\.py:")
_SKILLDIR_MISSING_SCRIPTS_RX = re.compile(r"\$SKILL_DIR/([a-z0-9-]+)/([A-Za-z0-9_]+\.py)")
# Corpus / rule-pack examples cite target-repo paths, not harness layout.
_EXAMPLE_MARKERS = ("FIND-", "tp-corpus", "ceph-qe-scripts", "pyscripts/")
_EXCLUDE_PATH_PARTS = ("harnessing/mine-ledger/rule-drafts",)


def _tracked_text_files(repo: Path) -> list[Path]:
    patterns = ("*.md", "*.yaml", "*.yml")
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files", *patterns],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        files = [repo / line for line in out.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = []
        for pat in patterns:
            files.extend(repo.rglob(pat))
    return [p for p in files if p.is_file() and not p.is_symlink()]


def _skill_script_paths(repo: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in skill_scripts(repo):
        skill = p.parent.parent.name
        out[f"{skill}/{p.name}"] = p.relative_to(repo).as_posix()
    return out


def _is_harness_skill_scripts_path(line: str, start: int, end: int) -> bool:
    """True when scripts/... is skill-local, not the retired top-level tree."""
    window_start = max(0, start - 90)
    chunk = line[window_start:end]
    if _HARNESS_SKILL_SCRIPTS_RX.search(chunk):
        return True
    return bool(_SKILL_BASE_SCRIPTS_RX.search(chunk + line[start:end]))


def scripts_path_failures(repo: Path = REPO) -> list[str]:
    failures = []
    for path in _tracked_text_files(repo):
        if path.name in _EXCLUDE_DOCS:
            continue
        rel = path.relative_to(repo)
        if any(part in str(rel) for part in _EXCLUDE_PATH_PARTS):
            continue
        for i, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if "scripts/" not in line:
                continue
            if any(m in line for m in _EXAMPLE_MARKERS):
                continue
            if "progress-tracker/scripts/" in line:
                continue
            if "traust-ledger/scripts/" in line:
                continue
            for m in _SCRIPTS_SUBPATH_RX.finditer(line):
                if _is_harness_skill_scripts_path(line, m.start(), m.end()):
                    continue
                # "Stale" means the reference points at something that is no
                # longer there. A repo-root script that EXISTS is a live
                # reference, not a stale one. Resolve before judging.
                if (repo / m.group(0)).is_file():
                    continue
                failures.append(f"{rel}:{i}: stale scripts/ path -> {m.group(0)}")
    return failures


def allowed_tools_failures(repo: Path = REPO) -> list[str]:
    failures = []
    validate_findings_roots = {
        "run",
        "ingest",
        "plan",
        "execute",
        "report",
        "scope",
        "soundness",
        "credential_liveness",
    }
    for skill_md in skill_md_paths(repo):
        rel = skill_md.relative_to(repo)
        for i, line in enumerate(skill_md.read_text(encoding="utf-8").splitlines(), 1):
            if "Bash(python" not in line:
                continue
            for m in _BARE_ALLOW_RX.finditer(line):
                stem = m.group(2)
                if stem in validate_findings_roots:
                    continue
                if "harnessing/" in line or "-m " in line:
                    continue
                failures.append(
                    f"{rel}:{i}: allowed-tools whitelists moved basename "
                    f"{stem}.py — use python3 -m … or harnessing/…/scripts/"
                )
    return failures


def skill_dir_failures(repo: Path = REPO) -> list[str]:
    skill_scripts = _skill_script_paths(repo)
    failures = []
    for path in _tracked_text_files(repo):
        if path.name in _EXCLUDE_DOCS:
            continue
        rel = path.relative_to(repo)
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _SKILLDIR_MISSING_SCRIPTS_RX.finditer(text):
            key = f"{m.group(1)}/{m.group(2)}"
            if key in skill_scripts:
                failures.append(
                    f"{rel}: $SKILL_DIR/{key} should be $SKILL_DIR/scripts/{m.group(2)}"
                )
    return failures


CHECKS = [
    ("stale scripts/ path references", scripts_path_failures),
    ("allowed-tools pre-move basenames", allowed_tools_failures),
    ("$SKILL_DIR paths missing scripts/", skill_dir_failures),
]


def run(repo: Path = REPO) -> dict[str, list[str]]:
    return {name: fn(repo) for name, fn in CHECKS}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check for stale script-path refs.")
    ap.add_argument("--root", default=str(REPO))
    args = ap.parse_args(argv)
    repo = Path(args.root).resolve()

    results = run(repo)
    total = sum(len(v) for v in results.values())
    print(f"Reference-integrity check for {repo}")
    for name, failures in results.items():
        if failures:
            print(f"\n✗ {name} ({len(failures)}):")
            for f in failures:
                print(f"    - {f}")
    if total == 0:
        print("\n✓ no stale script-path references")
        return 0
    print(f"\n✗ {total} stale reference(s) — update to module paths or harnessing/<skill>/scripts/")
    return 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "reference-integrity", *sys.argv[1:]]))
