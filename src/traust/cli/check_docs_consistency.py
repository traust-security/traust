#!/usr/bin/env python3
"""Doc-consistency checker — catch documentation drift before it ships.

Run this after editing skills, scripts, schemas, or the pipeline docs. It
fails (exit 1) when the maintained docs drift from the actual repository tree.
Nine independent checks (content licensing is enforced separately by
src/traust/cli/check_content_licenses.py — the /check-licensing skill — which the
pre-push hook runs alongside this checker):

1. Count assertions — global "N skills / N commands / N Python scripts /
   N-stage" inventory claims in README/AGENTS/PROCESS/docs must match what the
   tree actually contains. Expected numbers are COMPUTED from the tree, never
   hardcoded, so the checker never itself goes stale: add a skill and the docs
   (not this script) are what must be updated.

2. Dead-path check — every Markdown link with a repo-relative target, and every
   backtick-quoted path under a known in-repo top-level directory, must resolve.
   Catches deleted/renamed references (e.g. a `docs/foo.md` cross-ref that no
   longer exists). Sibling-repo paths, externals, glob/placeholder patterns, and
   historical records (CHANGELOG) are intentionally skipped.

3. Group-README check — the GitLab group profile page (sibling checkout
   ../gitlab-profile/README.md) also states harness facts: the harness version
   ("Harness version: vX.Y.Z", "harness **vX.Y.Z**") and skill/command counts.
   When the sibling is checked out, those claims must match this repo's VERSION
   file and tree counts; when it is not, the check is skipped. Drift here means
   the GROUP README needs an update (and its own commit/push).

4. Version-sync check — pyproject.toml's [project] version must equal the
   VERSION file (it silently drifted 30 releases before this check existed).

5. Symlink integrity — every symlink under .claude/ and .crush/ must resolve.
   Catches half-removed wrapper pairs (a .crush command pointing at a deleted
   .claude wrapper), which the dead-path checks skip by design.

(Plus: enumeration coverage, external-tool dependency rows, and CLI-example
flag drift — see the CHECKS table at the bottom for the full list.)

Usage:
    python3 -m traust.cli.check_docs_consistency          # check this repo
    python3 -m traust.cli.check_docs_consistency --root .  # check an explicit root

Exit code 0 = clean, 1 = drift found (each finding printed).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from traust_contracts.paths import schema_dir

from traust.paths import HARNESS_ROOT, skill_dirs, skill_scripts
from traust.paths import optional_config_path as _cfg_path

REPO = HARNESS_ROOT

# In-repo top-level dirs whose backtick-quoted paths we treat as real references.
IN_REPO_PREFIXES = (
    "harnessing/",
    "docs/",
    "src/",
    ".claude/",
    ".crush/",
    "config/",
    "tests/",
)
# Sibling repos / externals — referenced by path but not verifiable from here.
SIBLING_PREFIXES = (
    "analysis-results/",
    "inputs/",
    "progress-tracker/",
    "repo-verification/",
    "defending-code-reference-harness/",
    "gitlab-profile/",
    "contracts/",
    "traust-ledger/",
    "schema/",
)
GLOB_CHARS = set("*?<>{}|")

# Known-good exceptions. Add here only with justification.
DEAD_PATH_ALLOWLIST: set[str] = {
    # Directory inside an external organisation-registry checkout (team
    # definitions a deployment's inventory extension parses for tracker
    # resolution) — collides with the in-repo config/ prefix but is not a
    # repo path.
    "config/structures/",
}
# Docs that are historical records — they may legitimately cite files that
# existed at the time (e.g. a since-renamed doc) and must not be rewritten.
DEAD_PATH_EXCLUDE_DOCS = {
    "CHANGELOG.md",
    # Dated point-in-time snapshots (banner-enforced by asof_banner_failures)
    # — they cite the tree as it existed on their assessment date and must
    # not be mechanically rewritten to match later reorgs (e.g. the
    # schemas now ship in the installed traust-contracts package).
}

WORD2NUM = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
    "twenty-one": 21,
    "twenty-two": 22,
    "twenty-three": 23,
    "twenty-four": 24,
    "twenty-five": 25,
    "twenty-six": 26,
    "twenty-seven": 27,
    "twenty-eight": 28,
    "twenty-nine": 29,
    "thirty": 30,
    "thirty-one": 31,
    "thirty-two": 32,
    "thirty-three": 33,
    "thirty-four": 34,
    "thirty-five": 35,
}

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
BACKTICK = re.compile(r"`([^`]+)`")


def _to_int(token: str):
    token = token.strip().lower()
    if token.isdigit():
        return int(token)
    return WORD2NUM.get(token)


# The canonical pipeline stage count is a DECLARED constant, not derived:
# deriving it from PROCESS.md's own headings made the gate circular — the
# doc could drop half the pipeline and the "N-stage" claims still matched
# (docs-verification 2026-07-31, core-8). Changing the pipeline shape now
# requires touching this constant AND the docs in one reviewed commit.
# Canon: README.md pipeline diagram ①–⑨ == PROCESS.md ## Stage 1..9.
CANONICAL_STAGE_COUNT = 9


def _process_stage_heading_failures(repo: Path) -> list[str]:
    """PROCESS.md's ## Stage N headings must match the declared canon."""
    text = (repo / "PROCESS.md").read_text(encoding="utf-8")
    found = len(re.findall(r"(?m)^## Stage \d+", text))
    if found != CANONICAL_STAGE_COUNT:
        return [
            f"PROCESS.md: {found} '## Stage N' headings but the canonical "
            f"pipeline is {CANONICAL_STAGE_COUNT} stages "
            "(CANONICAL_STAGE_COUNT in this script — change the pipeline "
            "shape by updating the constant and the docs together)"
        ]
    return []


def expected_counts(repo: Path = REPO) -> dict:
    n_skill_scripts = len(skill_scripts(repo))
    packaged = len(list((repo / "src/traust").rglob("*.py")))
    return {
        "skills": len(skill_dirs(repo)),
        "commands": len(list((repo / ".claude/commands").glob("*.md"))),
        "scripts": n_skill_scripts + packaged,
        "stages": CANONICAL_STAGE_COUNT,
    }


# (source-of-truth key, regex capturing the count token). Patterns are
# deliberately specific to *global inventory* phrasings so subset counts like
# "the 3 validation skills" are never matched.
_COUNT_CHECKS = [
    ("skills", re.compile(r"all (\w+) skills")),
    ("skills", re.compile(r"(\w+) active skills")),
    ("skills", re.compile(r"reference for all (\w+) skills")),
    ("skills", re.compile(r"all (\w+) skills symlinked")),
    ("skills", re.compile(r"(\w+) skills total")),
    ("commands", re.compile(r"(\w+) slash command")),
    ("scripts", re.compile(r"(\w+) Python scripts")),
    ("stages", re.compile(r"(\w+)-stage")),
]


def _count_docs(repo: Path) -> list[Path]:
    return [repo / f for f in ("README.md", "AGENTS.md", "PROCESS.md")] + sorted(
        (repo / "docs").glob("*.md")
    )


def count_failures(repo: Path = REPO) -> list[str]:
    expected = expected_counts(repo)
    failures = _process_stage_heading_failures(repo)
    for doc in _count_docs(repo):
        if not doc.exists():
            continue
        text = doc.read_text(encoding="utf-8")
        rel = doc.relative_to(repo)
        for key, pat in _COUNT_CHECKS:
            for m in pat.finditer(text):
                n = _to_int(m.group(1))
                if n is None:
                    continue  # not a numeric count claim
                if n != expected[key]:
                    failures.append(
                        f"{rel}: claims {n} {key} ('{m.group(0)}') but tree has {expected[key]}"
                    )
    return failures


def _tracked_markdown(repo: Path) -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "*.md"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        files = [repo / line for line in out.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = [p for p in repo.rglob("*.md") if ".git" not in p.parts]
    # Skip symlinks (e.g. .crush/ mirrors — same content, may dangle) and any
    # non-regular / unreadable file.
    return [p for p in files if p.is_file() and not p.is_symlink()]


def _status(target: str, md: Path, repo: Path) -> str:
    """Classify target as 'exists', 'missing' (in-repo but absent), or
    'external' (resolves outside the repo — not verifiable here)."""
    saw_in_repo = False
    for base in (repo, md.parent):
        cand = base / target
        try:
            cand.resolve().relative_to(repo)
        except ValueError:
            continue  # this candidate escapes the repo
        saw_in_repo = True
        if cand.exists():
            return "exists"
    return "missing" if saw_in_repo else "external"


def dead_link_failures(repo: Path = REPO) -> list[str]:
    failures = []
    for md in _tracked_markdown(repo):
        if md.name in DEAD_PATH_EXCLUDE_DOCS:
            continue
        text = md.read_text(encoding="utf-8")
        rel = md.relative_to(repo)
        for target in LINK.findall(text):
            t = target.split("#", 1)[0].strip()
            if not t or t in DEAD_PATH_ALLOWLIST:
                continue
            if t.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            if t.startswith(SIBLING_PREFIXES) or t.startswith("/"):
                continue
            if any(c in t for c in GLOB_CHARS):
                continue
            if "/" not in t and "." not in t:
                continue  # placeholder like [text](url), not a path
            if _status(t, md, repo) == "missing":
                failures.append(f"{rel}: dead link -> {t}")
    return failures


def dead_backtick_failures(repo: Path = REPO) -> list[str]:
    failures = []
    for md in _tracked_markdown(repo):
        if md.name in DEAD_PATH_EXCLUDE_DOCS:
            continue
        text = md.read_text(encoding="utf-8")
        rel = md.relative_to(repo)
        for token in BACKTICK.findall(text):
            t = token.strip()
            if (
                " " in t
                or "/" not in t
                or t in DEAD_PATH_ALLOWLIST
                or "**" in t
                or any(c in t for c in GLOB_CHARS)
            ):
                continue
            if not t.startswith(IN_REPO_PREFIXES):
                continue  # only vet paths under known in-repo dirs
            if _status(t.rstrip("/"), md, repo) == "missing":
                failures.append(f"{rel}: dead backtick path -> {token}")
    return failures


def _group_readme(repo: Path) -> Path:
    return repo.parent / "gitlab-profile" / "README.md"


# Group-README claims. Version lines must mention 'harness' so framework
# versions (ASVS v5.0, SLSA v1.2, ...) are never matched; count patterns run
# on text with markdown bold stripped so "**34** slash-command" matches.
_GROUP_VERSION = re.compile(r"v(\d+\.\d+\.\d+)")
_GROUP_COUNT_CHECKS = [
    ("skills", re.compile(r"(\w+) skills")),
    ("skills", re.compile(r"Skills \((\w+)\), by function")),
    ("commands", re.compile(r"(\w+) (?:slash[- ]commands?|commands)")),
]


def group_readme_failures(repo: Path = REPO) -> list[str]:
    """Vet harness facts stated on the group profile page, when checked out."""
    readme = _group_readme(repo)
    if not readme.is_file():
        return []  # sibling not checked out (CI, standalone) — skip
    raw = readme.read_text(encoding="utf-8")
    rel = "../gitlab-profile/README.md"
    failures = []

    version = (repo / "VERSION").read_text(encoding="utf-8").strip()
    for line in raw.splitlines():
        if "harness" not in line.lower():
            continue
        for m in _GROUP_VERSION.finditer(line):
            if m.group(1) != version:
                failures.append(f"{rel}: claims harness v{m.group(1)} but VERSION is {version}")

    expected = expected_counts(repo)
    text = raw.replace("**", "")
    for key, pat in _GROUP_COUNT_CHECKS:
        for m in pat.finditer(text):
            n = _to_int(m.group(1))
            if n is None:
                continue
            if n != expected[key]:
                failures.append(
                    f"{rel}: claims {n} {key} ('{m.group(0)}') "
                    f"but the harness tree has {expected[key]}"
                )
    return failures


_PYPROJECT_VERSION = re.compile(r'(?m)^version\s*=\s*"([^"]+)"')


def version_sync_failures(repo: Path = REPO) -> list[str]:
    """pyproject.toml [project] version and version.args must equal VERSION.

    version.args feeds the Konflux build-args-file param so the container
    image is labeled (and release-tagged via {{ oci_version }}) with the
    harness version; if it drifts from VERSION, published images carry the
    wrong version tag.
    """
    failures = []
    version = (repo / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        m = _PYPROJECT_VERSION.search(pyproject.read_text(encoding="utf-8"))
        if m is None:
            # fail-closed: the guard was silently dead for months because
            # pyproject carried no version field at all (docs-verification
            # 2026-07-31 §core-6) — absence must fail, not pass
            failures.append(
                "pyproject.toml: no [project] version field — the "
                f"version-sync guard cannot verify it equals {version}"
            )
        elif m.group(1) != version:
            failures.append(f'pyproject.toml: version = "{m.group(1)}" but VERSION is {version}')
    version_args = repo / "version.args"
    if version_args.is_file():
        args_value = version_args.read_text(encoding="utf-8").strip()
        if args_value != f"VERSION={version}":
            failures.append(f"version.args: {args_value!r} but expected 'VERSION={version}'")
    return failures


def symlink_failures(repo: Path = REPO) -> list[str]:
    """Every symlink under the agent-discovery layers must resolve."""
    failures = []
    for layer in (".claude", ".crush"):
        base = repo / layer
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_symlink() and not p.exists():
                failures.append(f"{p.relative_to(repo)}: dangling symlink -> {Path.readlink(p)}")
    return failures


# --- external CLI tools must have a docs/external-dependencies.md row ------
# /check-licensing gates PYTHON deps (pyproject -> doc rows); this is the
# matching gate for CLI TOOLS the harness shells out to. Detection covers
# the literal-invocation styles in live use:
#   subprocess.run(["tool", ...]) / shutil.which("tool")
#   add_argument("--tool", default="tool")   (self-named override flag)
#   ... / "bin" / "tool"                     (vendored-binary path)
#   command -v tool                          (shell scripts)
_TOOL_INVOKE_RXS = [
    re.compile(r'shutil\.which\(\s*["\']([A-Za-z0-9_.-]+)["\']'),
    re.compile(
        r"subprocess\.(?:run|Popen|check_output|check_call|call)"
        r'\(\s*\[\s*["\']([A-Za-z0-9_.-]+)["\']'
    ),
    re.compile(
        r'add_argument\(\s*["\']--([a-z0-9-]+)["\'][^)]*'
        r'default=["\']\1["\']'
    ),
    re.compile(r'["\']bin["\']\s*/\s*["\']([A-Za-z0-9_.-]+)["\']'),
]
_TOOL_SH_RX = re.compile(r"command -v\s+([A-Za-z0-9_.-]+)")
# base-system / interpreter binaries that need no dependency row
_TOOL_IGNORE = {"python", "python3", "sh", "bash", "env", "open", "xdg-open"}
# rule-pack fixtures contain example invocations that are scan TARGETS,
# not harness dependencies; tests exercise fakes
_TOOL_SKIP_PARTS = {"opengrep-rules", "tests", ".venv", "__pycache__", "clones"}


def external_tool_failures(repo: Path = REPO) -> list[str]:
    doc = repo / "docs" / "external-dependencies.md"
    if not doc.is_file():
        return []
    doc_text = doc.read_text(encoding="utf-8", errors="replace").lower()
    failures = []
    seen: dict[str, str] = {}
    for pat in ("scripts/**/*.py", "harnessing/**/*.py", "scripts/**/*.sh", "harnessing/**/*.sh"):
        for p in repo.glob(pat):
            if _TOOL_SKIP_PARTS.intersection(p.parts):
                continue
            if not p.is_file():
                # glob can match directories with tool-like names
                # (e.g. a vendored "helm.sh/" dir inside a fuzz clone)
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            rxs = list(_TOOL_INVOKE_RXS)
            if p.suffix == ".sh":
                rxs.append(_TOOL_SH_RX)
            for rx in rxs:
                for m in rx.finditer(text):
                    name = m.group(1)
                    if name.lower() in _TOOL_IGNORE or name.endswith(".py"):
                        continue
                    seen.setdefault(name, str(p.relative_to(repo)))
    # safe-exec profile allowlists are grant surface too: a binary the
    # sandbox may execute is a dependency whether or not any Python file
    # names it literally (docs-verification 2026-07-31, peripheral-2 —
    # the gate was blind to YAML allowlists). POSIX text/coreutils
    # utilities are ignored like the base-system set above.
    _coreutils = {
        "jq",
        "grep",
        "base64",
        "head",
        "tail",
        "tr",
        "wc",
        "cat",
        "sleep",
        "echo",
        "printf",
        "ls",
        "mktemp",
        "make",
        "git",
        "curl",
    }
    # The deployment's profiles when this checkout has one; else the shipped
    # template, so the roster check still runs in open-source CI.
    profiles = repo / "config" / "safe-exec-profiles.yaml"
    if repo == REPO and not profiles.is_file():
        resolved = _cfg_path("safe-exec-profiles.yaml")
        if resolved is not None:
            profiles = resolved
    if not profiles.is_file():
        profiles = repo / "config" / "safe-exec-profiles.example.yaml"
    if profiles.is_file():
        try:
            import yaml as _yaml

            pdoc = _yaml.safe_load(profiles.read_text(encoding="utf-8"))
            for pname, prof in (pdoc.get("profiles") or {}).items():
                for binname in prof.get("allow") or []:
                    b = str(binname)
                    if b.lower() in _TOOL_IGNORE or b.lower() in _coreutils:
                        continue
                    seen.setdefault(b, f"{profiles.name} ({pname} allow)")
        except Exception:
            pass  # unparseable profiles are safe_exec's own problem

    for name in sorted(seen):
        if name.lower() not in doc_text:
            failures.append(
                f"external tool '{name}' (invoked by {seen[name]}) has no "
                f"row in docs/external-dependencies.md — run the "
                f"/check-licensing intake and add one"
            )
    return failures


def coverage_failures(repo: Path = REPO) -> list[str]:
    """Enumeration coverage: docs that present themselves as skill/schema
    inventories must actually mention every item. Count checks alone let a
    table silently omit entries while the stated total stays correct."""
    failures = []
    skills = [d.name for d in skill_dirs(repo)]
    schemas = sorted(p.name for p in schema_dir().glob("*.json"))
    docs_md = sorted(p.name for p in (repo / "docs").glob("*.md"))
    # The README's skill and schema inventories were split into docs/ on
    # 2026-09-09; a mention in the README or in the relevant inventory page
    # suffices (placement is editorial).
    skill_pages = ("README.md", "docs/standalone-usage.md", "docs/campaign-workflow.md")
    schema_pages = ("README.md", "docs/tooling-and-structure-files.md")
    for doc_rel, items, label, required in (
        (skill_pages, skills, "skill", None),
        # docs/skills.md is the reference: each skill needs its own section
        ("docs/skills.md", skills, "skill", "## {item}"),
        (schema_pages, schemas, "schema", None),
        # every guide under docs/ must be reachable from the README —
        # an unlinked doc is invisible to harness users
        ("README.md", docs_md, "doc", None),
    ):
        pages = (doc_rel,) if isinstance(doc_rel, str) else doc_rel
        present = [repo / p for p in pages if (repo / p).is_file()]
        if not present:
            continue
        text = "\n".join(p.read_text(encoding="utf-8") for p in present)
        doc_rel = " / ".join(p.relative_to(repo).as_posix() for p in present)
        for item in items:
            needle = required.format(item=item) if required else item
            if needle not in text:
                what = "has no section" if required else "is not mentioned"
                failures.append(f"{doc_rel}: {label} '{item}' {what}")
    return failures


# --- CLI-example flag drift -------------------------------------------------
# The worst rot class the 2026-07-25 docs-verification sweep found: command
# examples whose flags no longer exist (`validate_report.py --validate` had
# been dead for ~150 releases across three docs, and every reader's first
# command failed). For every maintained-doc line that invokes an in-repo
# Python script, each `--flag` token following the script path must appear
# literally in that script's source (argparse add_argument strings). Values
# are not checked; `--help` is argparse-implicit.
_SCRIPT_INVOKE_RX = re.compile(
    r"((?:scripts|harnessing/[A-Za-z0-9_-]+)/[A-Za-z0-9_./-]+\.py)([^\n|;]*)"
)
_FLAG_RX = re.compile(r"(--[A-Za-z0-9][A-Za-z0-9-]*)")
_CLI_IMPLICIT = {"--help"}
# script rel-path -> flags that are legitimate but not literal in its source
# (e.g. built dynamically). Add only with justification.
_CLI_FLAG_ALLOWLIST: dict[str, set[str]] = {}


def cli_example_failures(repo: Path = REPO) -> list[str]:
    failures = []
    src_cache: dict[str, str | None] = {}
    for doc in _count_docs(repo):
        if not doc.exists() or doc.name in DEAD_PATH_EXCLUDE_DOCS:
            continue
        # join shell line-continuations so multi-line examples scan whole
        text = doc.read_text(encoding="utf-8").replace("\\\n", " ")
        rel = doc.relative_to(repo)
        for m in _SCRIPT_INVOKE_RX.finditer(text):
            script_rel, tail = m.group(1), m.group(2)
            if script_rel not in src_cache:
                p = repo / script_rel
                src_cache[script_rel] = (
                    p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
                )
            src = src_cache[script_rel]
            if src is None:
                continue  # nonexistent script — the dead-path check owns it
            allowed = _CLI_FLAG_ALLOWLIST.get(script_rel, set())
            for flag in _FLAG_RX.findall(tail):
                if flag in _CLI_IMPLICIT or flag in allowed:
                    continue
                if f'"{flag}"' not in src and f"'{flag}'" not in src:
                    failures.append(
                        f"{rel}: example invokes {script_rel} with {flag}, "
                        f"which does not exist in that script"
                    )
    return failures


# --- partial enum quotes ----------------------------------------------------
# The docs-sweep rot class where a doc enumerates a schema enum but lags it
# (validation_status missing `hardening`, source_type missing
# `triage_report`). When a maintained-doc line names an enum-bearing field
# AND backtick-quotes 3+ of its values but not all of them, that is an
# enumeration attempt that silently under-reports. Enum lists belong in
# docs/report-structure.md / the schemas — link, don't restate.
_ENUM_MIN_QUOTED = 3


def _schema_enums(repo: Path) -> dict[str, set[str]]:
    """field name -> enum values, for fields whose enum is IDENTICAL every
    time the name appears across installed package schemas/*.json. Names that mean different
    enums in different schemas (e.g. `verdict` in triage vs validation vs
    fips contexts) are ambiguous and dropped — a doc enumerating one family
    would otherwise be flagged for 'missing' another family's values.
    Only identifier-like enums of 4+ values are considered."""
    import json as _json

    seen: dict[str, list[frozenset]] = {}

    def walk(node, prop: str | None):
        if isinstance(node, dict):
            e = node.get("enum")
            if (
                prop
                and isinstance(e, list)
                and len(e) >= 4
                and all(isinstance(v, str) and re.fullmatch(r"[a-z0-9_-]+", v) for v in e)
            ):
                seen.setdefault(prop, []).append(frozenset(e))
            for k, v in node.items():
                walk(
                    v,
                    k
                    if k
                    not in (
                        "items",
                        "properties",
                        "$defs",
                        "definitions",
                        "anyOf",
                        "oneOf",
                        "allOf",
                    )
                    else prop,
                )
        elif isinstance(node, list):
            for v in node:
                walk(v, prop)

    for sp in sorted(schema_dir().glob("*.json")):
        try:
            walk(_json.loads(sp.read_text(encoding="utf-8")), None)
        except (OSError, ValueError):
            continue
    return {field: set(sets[0]) for field, sets in seen.items() if len(set(sets)) == 1}


def partial_enum_failures(repo: Path = REPO) -> list[str]:
    enums = _schema_enums(repo)
    failures = []
    for doc in _count_docs(repo):
        if not doc.exists() or doc.name in DEAD_PATH_EXCLUDE_DOCS:
            continue
        rel = doc.relative_to(repo)
        for line in doc.read_text(encoding="utf-8").splitlines():
            quoted = set(BACKTICK.findall(line))
            if not quoted:
                continue
            for field, values in enums.items():
                if field not in line:
                    continue
                hit = quoted & values
                missing = values - quoted
                if len(hit) >= _ENUM_MIN_QUOTED and missing:
                    failures.append(
                        f"{rel}: line enumerating `{field}` quotes "
                        f"{len(hit)}/{len(values)} enum values — missing "
                        f"{sorted(missing)}. List all values or link the "
                        f"docs/report-structure.md instead of restating."
                    )
    return failures


# --- as-of banners on assessment/draft docs ---------------------------------
# Point-in-time judgments presented as live rot silently (the 2026-07-25
# sweep found four such docs up to ~143 releases stale). Any docs/*.md whose
# name marks it as an assessment or draft must carry a dated as-of banner.
_ASOF_DOC_RX = re.compile(r"(assessment|draft|comparison)", re.IGNORECASE)
_ASOF_LINE_RX = re.compile(r"(?i)(as of|snapshot|assessed at|statuses as of).{0,120}20\d{2}-\d{2}")


def asof_banner_failures(repo: Path = REPO) -> list[str]:
    failures = []
    for doc in sorted((repo / "docs").glob("*.md")):
        if not _ASOF_DOC_RX.search(doc.name):
            continue
        text = doc.read_text(encoding="utf-8")
        if not _ASOF_LINE_RX.search(text):
            failures.append(
                f"docs/{doc.name}: assessment/draft doc has no dated "
                f"as-of banner ('as of'/'snapshot'/'assessed at' + a "
                f"YYYY-MM date) — point-in-time judgments must be dated "
                f"so they read as snapshots, not live status."
            )
    return failures


def conflict_marker_failures(repo: Path) -> list[str]:
    """Unresolved git conflict markers in tracked text files.

    Added 2026-08-13 after a bad push: a rebase-resolution script failed
    silently, `git rebase --continue` committed the conflicted file, and
    CHANGELOG.md reached main with six markers in it. Every other gate
    passed, because none of them looked.

    Triggers ONLY on `<<<<<<< ` and `>>>>>>> ` at line start. `=======` is
    deliberately NOT a trigger: it is a legitimate Markdown setext H1
    underline, so flagging it would false-positive on ordinary docs. The
    two directional markers have no legitimate use at line start, and a
    conflict always carries at least one of them.

    A file may opt out with the marker `docs-check: allow-conflict-markers`
    (for docs that legitimately demonstrate conflict resolution).
    """
    failures: list[str] = []
    try:
        tracked = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, OSError):
        return []  # fail open: never block on tooling
    if tracked.returncode != 0:
        return []
    skip_ext = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".pdf",
        ".ico",
        ".zip",
        ".gz",
        ".db",
        ".bin",
        ".woff",
        ".woff2",
        ".jar",
    }
    for rel in tracked.stdout.split("\0"):
        if not rel:
            continue
        p = repo / rel
        if p.suffix.lower() in skip_ext or not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: not our call
        if "docs-check: allow-conflict-markers" in text:
            continue
        hits = [
            str(n)
            for n, line in enumerate(text.splitlines(), 1)
            if line.startswith("<<<<<<< ") or line.startswith(">>>>>>> ")
        ]
        if hits:
            failures.append(
                f"{rel}: unresolved git conflict marker(s) at line(s) "
                f"{', '.join(hits[:6])}"
                + (" …" if len(hits) > 6 else "")
                + " — a conflicted file was committed; resolve and amend"
            )
    return failures


# --- phantom skills ---------------------------------------------------------
# coverage_failures() checks one direction: every skill in the tree is
# mentioned in the docs. This is the other, and it is the one that bit us --
# two skills moved to the internal extension repo on 2026-09-01 and their
# README rows stayed, advertising capabilities this repo does not carry.
_EXTERNAL_MARKERS = ("internal extension repo", "external repo", "not in this repo")


def phantom_skill_failures(repo: Path = REPO) -> list[str]:
    """A doc table row naming a skill absent from the tree, without saying so."""
    have = {d.name for d in skill_dirs(repo)}
    failures = []
    for rel in (
        "README.md",
        "PROCESS.md",
        "docs/skills.md",
        "docs/standalone-usage.md",
        "docs/campaign-workflow.md",
    ):
        doc = repo / rel
        if not doc.is_file():
            continue
        header = ""
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if not stripped.startswith("|"):
                header = ""  # table ended
                continue
            if not header:  # first row of a table is its header
                header = stripped.lower()
                continue
            # Only skill inventories. Repository maps and model-tier tables
            # also have backticked first cells and are not claims about skills.
            if "skill" not in header:
                continue
            m = re.match(r"\|\s*`([a-z0-9][a-z0-9-]+)`\s*\|", stripped)
            if not m or m.group(1) in have:
                continue
            if any(mark in line for mark in _EXTERNAL_MARKERS):
                continue
            failures.append(
                f"{rel}:{lineno}: table row names skill '{m.group(1)}', which is not "
                f"in this repo -- remove the row or mark it '(internal extension repo)'"
            )
    return failures


# --- config/ hygiene ---------------------------------------------------------
# The open-source harness ships exactly three estate-neutral config files plus a
# *.example.* template per deployment file (config/README.md). Anything else in
# config/ is deployment data that leaked back in — the failure shape this
# repo had before 2026-09-03, when corpus-config, product map, budget policy,
# signing key and safe-exec profiles all sat here.
CONFIG_SHIPPED = {"README.md", "external-tools.yaml", "feeds.yaml", "model-registry.yaml"}
CONFIG_EXAMPLE_RX = re.compile(r"^[a-z0-9-]+\.example\.[a-z]+$")


def _estate_patterns() -> list[tuple[str, re.Pattern]] | None:
    """Block/review rules from scan_internal_refs — universal + the deployment
    vocabulary in $TRAUST_CONFIG_HOME. None when no vocabulary is configured
    (a CI checkout without a config home), in which case the estate-marker leg
    of the config check is skipped rather than run against a shipped list: a
    gate that carries the internal names it looks for has published them
    (2026-09-07 review §1)."""
    try:
        from traust.cli.scan_internal_refs import all_rules

        rules = all_rules()
    except Exception:
        return None
    return [
        (rid, re.compile(pat, re.IGNORECASE))
        for rid, tier, pat, _why in rules
        if tier in ("block", "review")
    ]


def config_hygiene_failures(repo: Path = REPO) -> list[str]:
    failures: list[str] = []
    cfg = repo / "config"
    if not cfg.is_dir():
        return failures
    patterns = _estate_patterns()
    for f in sorted(cfg.iterdir()):
        if f.name.startswith("."):
            failures.append(
                f"config/{f.name}: hidden file in shipped config/ "
                "(operational config belongs in $TRAUST_CONFIG_HOME)"
            )
            continue
        if f.name not in CONFIG_SHIPPED and not CONFIG_EXAMPLE_RX.match(f.name):
            failures.append(
                f"config/{f.name}: not a shipped file or a *.example.* "
                "template -- operational config belongs in $TRAUST_CONFIG_HOME"
            )
            continue
        if f.name == "internal-vocabulary.example.yaml":
            # The template IS a vocabulary: its placeholder patterns match
            # their own literal text. When an adopter's config home was
            # installed from the templates (export dry-run 2026-09-08), the
            # active vocabulary is this file and the leg flagged it against
            # itself. The scrub scanner skips vocabulary files the same way.
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rid, rx in patterns or []:
            m = rx.search(text)
            if m:
                failures.append(
                    f"config/{f.name}: matches estate rule {rid!r} ({m.group(0)[:40]!r})"
                )
    return failures


def skills_reference_failures(repo: Path = REPO) -> list[str]:
    """docs/skills.md is GENERATED from the skill tree; a hand edit or a
    stale copy fails here with the regeneration command."""
    if repo != REPO:
        return []  # fixture repos have no generated reference
    from traust.cli.build_skills_reference import OUT, render

    try:
        expected = render(repo)
    except Exception as e:  # pragma: no cover - generator failure is itself the finding
        return [f"docs/skills.md: generator failed: {e}"]
    current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
    if current != expected:
        return [
            "docs/skills.md is stale or hand-edited — regenerate with "
            "python3 -m traust.cli.build_skills_reference"
        ]
    return []


# --- CLI invocation syntax --------------------------------------------------
# The CLI is grouped (`traust <group> <op>`). Each module still answers to the
# pre-grouping `python3 -m traust.cli.<module>` via its `__main__` delegate, so
# a stale doc example keeps working and drifts silently. Docs standardise on the
# grouped form; this catches the dot-separated one.
#
# `traust.cli.<module>` WITHOUT the `python3 -m` prefix is a module path, not an
# invocation (e.g. traust.cli.budget_shadow, which has no CLI at all), so only
# the runnable spelling is flagged.
_DOT_INVOKE_RX = re.compile(r"python3 -m traust\.cli\.([a-z_][a-z0-9_]*)")


def _grouped_form(repo: Path, module: str) -> str | None:
    """The `<group> <op>` a module's __main__ delegate forwards to, if any."""
    src = repo / "src" / "traust" / "cli" / f"{module}.py"
    if not src.exists():
        return None
    m = re.search(
        r'main\(\s*\[\s*"([a-z][a-z-]*)"\s*,\s*"([a-z][a-z-]*)"',
        src.read_text(encoding="utf-8"),
    )
    return f"{m.group(1)} {m.group(2)}" if m else None


# docs/cli-reference.md documents the deprecated spellings on purpose, so it is
# the one file where they are not drift. Same shape as the partial-enum check
# exempting the schema doc that owns the enum.
_CLI_SYNTAX_EXEMPT = {"docs/cli-reference.md"}


def _cli_scanned_docs(repo: Path) -> list[Path]:
    """Files whose CLI invocations are held to the grouped syntax."""
    docs = list(_count_docs(repo))
    docs += sorted(p for p in (repo / "config").iterdir() if p.is_file())
    docs += sorted((repo / "harnessing").glob("*/SKILL.md"))
    docs += sorted((repo / "harnessing").glob("*/*/SKILL.md"))
    docs += sorted((repo / ".claude" / "commands").glob("*.md"))
    return [d for d in docs if d.exists() and not d.is_symlink()]


def cli_syntax_failures(repo: Path = REPO) -> list[str]:
    failures = []
    for doc in _cli_scanned_docs(repo):
        rel = doc.relative_to(repo)
        if rel.as_posix() in _CLI_SYNTAX_EXEMPT:
            continue
        try:
            text = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _DOT_INVOKE_RX.finditer(text):
            module = m.group(1)
            grouped = _grouped_form(repo, module)
            fix = (
                f"python3 -m traust.cli {grouped}"
                if grouped
                else f"`traust.cli.{module}` (no CLI — reference it as a module path)"
            )
            failures.append(
                f"{rel}: `python3 -m traust.cli.{module}` uses the pre-grouping "
                f"invocation — use {fix}"
            )
    return failures


def cli_reference_failures(repo: Path = REPO) -> list[str]:
    """docs/cli-reference.md's group/op table vs the live GROUPS registry."""
    doc = repo / "docs" / "cli-reference.md"
    if not doc.exists():
        return [f"docs/cli-reference.md is missing — it is the canonical CLI listing"]
    try:
        from traust.cli.groups import GROUPS
    except ImportError as exc:  # pragma: no cover
        return [f"docs/cli-reference.md: cannot import GROUPS ({exc})"]

    text = doc.read_text(encoding="utf-8")
    failures = []
    documented = {
        m.group(1): {o.strip(" `") for o in m.group(2).split(",")}
        for m in re.finditer(r"^\| `([a-z]+)` \| [^|]* \| (.+?) \|$", text, re.MULTILINE)
    }
    for group, ops in GROUPS.items():
        if group == "tools":  # deprecated; listed prose-side, not in the table
            continue
        if group not in documented:
            failures.append(f"docs/cli-reference.md: group `{group}` is not listed")
            continue
        missing = set(ops) - documented[group]
        extra = documented[group] - set(ops)
        if missing:
            failures.append(
                f"docs/cli-reference.md: group `{group}` missing op(s) "
                f"{', '.join(sorted(missing))}"
            )
        if extra:
            failures.append(
                f"docs/cli-reference.md: group `{group}` lists op(s) not in the "
                f"registry: {', '.join(sorted(extra))}"
            )
    for group in documented:
        if group not in GROUPS:
            failures.append(f"docs/cli-reference.md: `{group}` is not a real group")
    return failures


# A grouped invocation naming an operation the group does not have. This is the
# other half of the syntax problem: an earlier migration rewrote module paths
# used as nouns in prose into invocations, producing text like
# "python3 -m traust.cli corpus resolves triage companions" (`resolves` is not an
# op) and "sweep rule-expressibility routing" (not an op). Those read as commands
# and are unrunnable, and the dot-separated check cannot see them.
#
# Only flagged when the GROUP is real and the next token is not one of its ops,
# so ordinary prose after a complete command is not misread.
_GROUPED_INVOKE_RX = re.compile(r"python3 -m traust\.cli ([a-z][a-z0-9-]*) ([a-z][a-z0-9-]*)")


def cli_op_failures(repo: Path = REPO) -> list[str]:
    try:
        from traust.cli.groups import GROUPS
    except ImportError as exc:  # pragma: no cover
        return [f"cannot import GROUPS ({exc})"]

    failures = []
    for doc in _cli_scanned_docs(repo):
        rel = doc.relative_to(repo)
        if rel.as_posix() in _CLI_SYNTAX_EXEMPT:
            continue
        try:
            text = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _GROUPED_INVOKE_RX.finditer(text):
            group, op = m.group(1), m.group(2)
            if group not in GROUPS or op in GROUPS[group]:
                continue
            failures.append(
                f"{rel}: `python3 -m traust.cli {group} {op}` — `{op}` is not an "
                f"operation of group `{group}` (has: "
                f"{', '.join(sorted(GROUPS[group]))}). If the sentence means the "
                f"module rather than a command, name the module instead."
            )
    return failures



# --- model-class index vs its sources -------------------------------------
#
# docs/model-classes.md indexes which tier class each skill runs at. Nothing in
# the tree links a skill to a class mechanically (skill frontmatter carries
# `harness.tier`, a different axis), so the index is derived from the two usage
# tables. This check is what keeps the two in agreement.
_MODEL_CLASS_DOC = "docs/model-classes.md"
_MODEL_CLASS_SOURCES = ("docs/campaign-workflow.md", "docs/standalone-usage.md")


def _class_rows(repo: Path, rel: str) -> dict[str, str]:
    """skill -> tier class, from table rows shaped `| `skill` | ... | X-class |`."""
    out: dict[str, str] = {}
    path = repo / rel
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        m = re.match(r"`([a-z0-9-]+)`", cells[0])
        cls = next((c for c in cells if c.endswith("-class")), None)
        if m and cls:
            out[m.group(1)] = cls
    return out


def _class_index(repo: Path) -> dict[str, str]:
    """skill -> class, from model-classes.md's `### `<class>`` sections."""
    doc = repo / _MODEL_CLASS_DOC
    if not doc.is_file():
        return {}
    text = doc.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    # Stop at the NEXT heading of any kind, not the next class heading: the
    # page ends with prose sections ("Not classed…", "Making this mechanical")
    # whose backticked role names would otherwise be absorbed into the last
    # class listed.
    bounds = [m.start() for m in re.finditer(r"^#{2,3} ", text, re.M)]
    heads = list(re.finditer(r"^### `([a-z]+-class)`", text, re.M))
    for m in heads:
        end = next((b for b in bounds if b > m.start()), len(text))
        for name in re.findall(r"`([a-z0-9-]+)`", text[m.end() : end]):
            if not name.endswith("-class"):
                out[name] = m.group(1)
    return out


def model_class_failures(repo: Path = REPO) -> list[str]:
    if not (repo / _MODEL_CLASS_DOC).is_file():
        return []
    source: dict[str, str] = {}
    for rel in _MODEL_CLASS_SOURCES:
        source.update(_class_rows(repo, rel))
    index = _class_index(repo)
    real = {d.name for d in skill_dirs()}
    where = " / ".join(_MODEL_CLASS_SOURCES)
    out = []
    for name, cls in sorted(index.items()):
        if name not in real:
            out.append(f"{_MODEL_CLASS_DOC}: indexes '{name}', not a skill in the tree")
        elif name in source and source[name] != cls:
            out.append(
                f"{_MODEL_CLASS_DOC}: '{name}' indexed {cls} but {where} says {source[name]}"
            )
        elif name not in source:
            out.append(
                f"{_MODEL_CLASS_DOC}: '{name}' indexed {cls} with no class in {where} "
                "— classify it there first"
            )
    for name, cls in sorted(source.items()):
        if name in real and name not in index:
            out.append(
                f"{_MODEL_CLASS_DOC}: '{name}' is {cls} in the usage tables but not indexed"
            )
    return out



# --- graph consumer lists vs what actually opens each graph ----------------
#
# docs/graphs.md names every skill/script that reads each graph. That list was
# built by searching for the artifact filename, so it goes stale the moment a
# new consumer appears — which is exactly the drift that made "how are the
# graphs used" unanswerable before the doc existed.
_GRAPHS_DOC = "docs/graphs.md"
_GRAPH_ARTIFACTS = ("portfolio-graph.db", "repo-graph.json")
# This module names both artifacts as check data, and check_drift is
# documented under its skill name rather than its module name.
_GRAPH_CONSUMER_SKIP = {"check_docs_consistency"}
_GRAPH_CONSUMER_ALIASES = {"check_drift": "drift-watch"}


def _graph_consumers(repo: Path, artifact: str) -> set[str]:
    """Skill dirs and src/ modules that reference `artifact`."""
    found: set[str] = set()
    for base, label in ((repo / "harnessing", "skill"), (repo / "src" / "traust", "src")):
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in (".md", ".py") or not path.is_file():
                continue
            try:
                if artifact not in path.read_text(encoding="utf-8", errors="ignore"):
                    continue
            except OSError:
                continue
            if label == "skill":
                # the owning skill directory is the one holding SKILL.md
                for parent in path.parents:
                    if (parent / "SKILL.md").is_file():
                        found.add(parent.name)
                        break
            else:
                found.add(path.stem)
    return found


def graph_consumer_failures(repo: Path = REPO) -> list[str]:
    doc = repo / _GRAPHS_DOC
    if not doc.is_file():
        return []
    text = doc.read_text(encoding="utf-8")
    out = []
    for artifact in _GRAPH_ARTIFACTS:
        actual = _graph_consumers(repo, artifact)
        # the graph skills themselves are the producers, not consumers to list
        actual -= {"portfolio-graph", "repo-graph"} | _GRAPH_CONSUMER_SKIP
        missing = sorted(
            n for n in actual if n not in text and _GRAPH_CONSUMER_ALIASES.get(n, n) not in text
        )
        if missing:
            out.append(
                f"{_GRAPHS_DOC}: {artifact} is read by {', '.join(missing)} "
                "but they are not named in the doc"
            )
    return out



# --- docs/ is adopter-facing: no estate markers ---------------------------
#
# Everything under docs/ ships to adopters, so it must read as product
# documentation rather than as one deployment's notes. config_hygiene_failures
# already applies the deployment vocabulary to config/; this applies the same
# block/review rules to docs/, which was previously unchecked. Estate-specific
# FIGURES (graph sizes, corpus counts) cannot be pattern-matched and remain a
# review concern — state them as "deployment-specific" instead.
def docs_estate_marker_failures(repo: Path = REPO) -> list[str]:
    docs = repo / "docs"
    if not docs.is_dir():
        return []
    patterns = _estate_patterns()
    if patterns is None:
        return []
    failures = []
    for f in sorted(docs.rglob("*.md")):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rid, rx in patterns:
            if rx.search(text):
                rel = f.relative_to(repo)
                failures.append(
                    f"{rel}: deployment vocabulary rule {rid} matched — docs/ is "
                    "adopter-facing and must stay estate-neutral"
                )
    return failures


CHECKS = [
    ("unresolved conflict markers", conflict_marker_failures),
    ("generated skills reference (docs/skills.md matches the tree)", skills_reference_failures),
    (
        "config/ hygiene (shipped files + templates only, no estate markers)",
        config_hygiene_failures,
    ),
    ("count drift", count_failures),
    ("enumeration coverage (skills/schemas in README + docs/skills.md)", coverage_failures),
    ("dead markdown links", dead_link_failures),
    ("dead backtick paths", dead_backtick_failures),
    ("group README drift (../gitlab-profile)", group_readme_failures),
    ("version sync (pyproject.toml, version.args vs VERSION)", version_sync_failures),
    ("dangling symlinks (.claude/, .crush/)", symlink_failures),
    ("undocumented external tools (docs/external-dependencies.md)", external_tool_failures),
    ("CLI-example flag drift (doc examples vs script argparse)", cli_example_failures),
    ("partial enum quotes (doc enumerations vs schema enums)", partial_enum_failures),
    ("as-of banners on assessment/draft docs", asof_banner_failures),
    ("phantom skills (doc rows naming skills not in the tree)", phantom_skill_failures),
    ("CLI invocation syntax (grouped `<group> <op>`, not dot-separated)", cli_syntax_failures),
    ("CLI reference drift (docs/cli-reference.md vs GROUPS registry)", cli_reference_failures),
    ("CLI operation names (grouped invocations name a real op)", cli_op_failures),
    ("model-class index (docs/model-classes.md vs the usage tables)", model_class_failures),
    ("graph consumer lists (docs/graphs.md vs what opens each graph)", graph_consumer_failures),
    ("docs/ estate neutrality (adopter-facing, no deployment vocabulary)", docs_estate_marker_failures),
]


def run(repo: Path = REPO) -> dict[str, list[str]]:
    return {name: fn(repo) for name, fn in CHECKS}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check harness docs for drift.")
    ap.add_argument("--root", default=str(REPO), help="Repo root to check (default: this harness).")
    args = ap.parse_args(argv)
    repo = Path(args.root).resolve()

    results = run(repo)
    total = sum(len(v) for v in results.values())
    counts = expected_counts(repo)
    print(f"Doc-consistency check for {repo}")
    print(
        f"  tree: {counts['skills']} skills, {counts['commands']} commands, "
        f"{counts['scripts']} scripts, {counts['stages']} stages"
    )
    print(
        "  group README: "
        + ("checked" if _group_readme(repo).is_file() else "not checked out — skipped")
    )
    for name, failures in results.items():
        if failures:
            print(f"\n✗ {name} ({len(failures)}):")
            for f in failures:
                print(f"    - {f}")
    if total == 0:
        print("\n✓ docs are consistent with the tree")
        return 0
    print(
        f"\n✗ {total} drift issue(s) found — update the docs (not the counts "
        f"in this script) to match the tree."
    )
    return 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "docs-consistency", *sys.argv[1:]]))
