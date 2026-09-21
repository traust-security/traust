#!/usr/bin/env python3
"""Content-license guard — deterministic enforcement of the two licensing
rules established by the 2026-07-16 license sweep (see
docs/external-dependencies.md, "Security frameworks & content licenses").

1. PEACH keep-it-original (v0.54.2). The PEACH tenant-isolation sections
   were rewritten as original text because the upstream Wiz content is
   CC-NonCommercial (and self-contradictory: repo LICENSE.md BY-NC-ND vs
   README badge BY-NC-SA). Pasting upstream PEACH prose or tables back into
   a skill re-creates the commercialization blocker. Guarded two ways:
   (a) NonCommercial license markers ("BY-NC", "NonCommercial") may appear
       only in the files that *discuss* licensing (ALLOWLIST) — anywhere
       else they signal that licensed content was re-imported;
   (b) fingerprint phrases from the removed Wiz-derived adaptation
       (distinctive strings from its tables, recoverable from git history
       before v0.54.2) must not reappear anywhere.

2. CIS ID-only citations. CIS non-member Terms of Use prohibit derivative
   works and commercial embedding, so the harness cites bare section IDs
   ("CIS 5.1.3") and never reproduces benchmark recommendation text. CIS
   recommendation titles have a machine-detectable shape — "Ensure that
   the --<flag> argument is set to ..." and "(Automated)"/"(Manual)"
   scoring suffixes — whose appearance in prompts or docs means benchmark
   text was copied in. (Verified 2026-07-16: zero hits in the harness tree
   and across the whole findings corpus, so any future hit is new.)

3. Dependency intake. Every package in pyproject.toml (core dependencies
   and optional groups alike) must have a row in
   docs/external-dependencies.md — a new imported library without a
   verified license row is exactly how the sigstore gap (v0.73.1,
   retroactive intake) happened. The /check-licensing skill's Job 2 is
   the intake procedure; this check makes running it mechanical.

4. PCI DSS ID-only citations (compliance-check Phase 0, 2026-07-19).
   PCI DSS carries PCI SSC copyright with no open license, so the CIS
   rule applies verbatim: cite bare requirement IDs ("PCI DSS 8.3.6"),
   never standard text. The v4.x requirement structure has distinctive
   section headings whose appearance means standard text was pasted in.

5. AICPA TSC (SOC 2) ID-only citations (compliance-check Phase 0
   addendum, 2026-07-19). The Trust Services Criteria are AICPA
   copyright, all rights reserved: cite bare criterion IDs
   ("TSC CC6.1"), never criteria text. Detectable markers: embedded
   COSO principle statements and points-of-focus boilerplate.

6. ShareAlike provenance markers (2026-09-15). BY-SA section 3(b)
   requires any Adapted Material that is *Shared* to carry a CC license
   with the same License Elements — which Apache-2.0 is not. The harness
   therefore treats wholesale adaptation of a BY-SA work differently from
   the delimited, attributed framework excerpts it already relies on:
   docs/external-dependencies.md rates OWASP ASVS and the Kubernetes
   Top 10 (both CC-BY-SA-4.0) **Low** precisely because their excerpts stay
   delimited and attributed, keeping SA scoped. That posture is recorded
   there, not decided here.

   What this rule enforces is narrower and mechanical: a BY-SA *provenance
   marker* ("CC BY-SA", "Attribution-ShareAlike", "ShareAlike", the licence
   URL) appearing outside the files that discuss licensing means BY-SA
   material arrived with its license notice attached — i.e. someone pasted
   a licensed work in rather than excerpting under the recorded posture.
   The marker is the signal; the judgment lives in the doc.

   The case that prompted it: agent-skill collections published under BY-SA
   (trailofbits/skills). *Using* such a skill at runtime — installing it as
   a plugin, invoking its tools — creates no obligation at all. Copying or
   adapting its SKILL.md prose into this tree does, because that text is
   then distributed under our license. Clean-room reimplementation from the
   *ideas* stays permitted: BY-SA covers expression, not concepts. Cite the
   upstream as prior art and keep the wording original.

The fingerprint phrases recorded here are short strings (not copyrightable
expression) kept solely to detect re-importation. Extend the lists when a
new protected content class enters the harness.

Usage:
    python3 -m traust.cli.check_content_licenses           # check this repo
    python3 -m traust.cli.check_content_licenses --root .  # explicit root

Exit code 0 = clean, 1 = violation found (each finding printed). This is
the deterministic core of the /check-licensing skill; the pre-push hook
(.githooks/pre-push) runs it on every push, independently of the
doc-consistency checker, and the test suite runs it against the live tree.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT

REPO = HARNESS_ROOT

# Files that legitimately discuss the restricted licenses by name.
ALLOWLIST = {
    "docs/external-dependencies.md",
    "CHANGELOG.md",
    "src/traust/cli/check_content_licenses.py",  # this file carries the patterns
    # The skill whose whole subject is these rules: its violation-class table
    # has to name "NonCommercial" and "ShareAlike" to explain them. It escaped
    # the allowlist until 2026-09-15 only because its wording ("CC-NC-licensed")
    # happened to dodge both patterns.
    "harnessing/check-licensing/SKILL.md",
}

# Trees/files scanned. tests/ is excluded (fixtures need the patterns);
# .claude/ and .crush/ are symlink farms into harnessing/ — non-symlink
# command wrappers under .claude/commands are scanned explicitly.
SCAN_GLOBS = (
    "harnessing/**/*.md",
    "harnessing/**/*.py",
    "harnessing/**/*.sh",
    "harnessing/**/*.yaml",
    "docs/**/*.md",
    "scripts/*.py",
    ".claude/commands/*.md",
    "*.md",
)

# --- Rule 1a: NonCommercial license markers -------------------------------
NC_MARKER_RE = re.compile(r"BY-NC|Non-?Commercial", re.IGNORECASE)

# --- Rule 6: ShareAlike license markers -----------------------------------
# Apache-2.0 cannot serve as the Adapter's License for BY-SA material
# (BY-SA 3(b)), so BY-SA prose must not be copied or adapted into this tree.
# "CC BY-SA", "BY-SA 4.0", "Attribution-ShareAlike", bare "ShareAlike", and
# the licence URL are all matched. `BY-NC-SA` is left to rule 1a, which
# reports it as NonCommercial — the stronger blocker of the two.
SA_MARKER_RE = re.compile(
    r"Attribution-ShareAlike"
    r"|CC[ -]BY[ -]SA"
    r"|\bBY-SA\b"
    r"|\bShareAlike\b"
    r"|creativecommons\.org/licenses/by-sa",
    re.IGNORECASE,
)

# --- Rule 1b: fingerprints of the removed Wiz-derived PEACH adaptation ----
# Distinctive substrings from the pre-v0.54.2 tables (git history:
# harnessing/3-audit/secure-code-audit/SKILL.md before commit d7daa22). Any one of
# them reappearing means the old adaptation (or its upstream source) was
# pasted back in.
PEACH_FINGERPRINTS = (
    "Arbitrary code execution environment",
    "Arbitrary file scanner / image parser",
    "Queue message upload",
    "Data entry form / simple REST field",
    "otherwise-harmless bug in a customer-facing interface",
    "Tenants on separate physical machines",
    "separation is by per-tenant encryption/authorization keys only",
    "unrelated certs/keys reachable from the tenant",
    "Interface complexity reference",
    "strongest → weakest as a *sole* boundary",
)

# --- Rule 2: CIS benchmark recommendation-text signatures ------------------
CIS_TEXT_RES = (
    re.compile(
        r"[Ee]nsure that the [^\n]{0,80}?(argument|parameter|plugin)"
        r" is set"
    ),
    re.compile(r"CIS[^\n]{0,120}\((?:Automated|Manual)\)"),
)

# --- Rule 4: PCI DSS requirement-text signatures ----------------------------
# PCI DSS is PCI SSC copyright (no open license); the harness cites bare
# requirement IDs ("PCI DSS 8.3.6") and never reproduces standard text
# (compliance-check Phase 0, 2026-07-19 — the CIS precedent applied).
# The v4.x standard's requirement structure has machine-detectable
# section headings that only appear when actual standard text is pasted:
PCI_TEXT_RES = (
    re.compile(r"Customized Approach Objective"),
    re.compile(r"Defined Approach (?:Requirements?|Testing Procedures)"),
)

# --- Rule 5: AICPA Trust Services Criteria (SOC 2) text signatures ----------
# The TSC document is AICPA copyright, all rights reserved (verified on
# the 2022 SSAE 21 illustrative report, compliance Phase 0 addendum
# 2026-07-19): cite bare criterion IDs ("TSC CC6.1") only. TSC criteria
# text has two machine-detectable structural markers — the embedded COSO
# principle statements and the points-of-focus boilerplate:
TSC_TEXT_RES = (
    re.compile(r"COSO Principle \d+:"),
    re.compile(
        r"[Pp]oints of focus (?:that highlight|specifically "
        r"related to all engagements)"
    ),
)


# Git-ignored working data the globs must never descend into:
# fuzz-harness clones (third-party trees + per-clone .fuzzvenv whose
# vendored pip SPDX tables legitimately contain NC license strings).
_SKIP_PARTS = {"clones", ".fuzzvenv"}


def _scan_files(repo: Path):
    seen: set[Path] = set()
    for glob in SCAN_GLOBS:
        for path in sorted(repo.glob(glob)):
            if path.is_symlink() or not path.is_file():
                continue
            if _SKIP_PARTS.intersection(path.parts):
                continue
            real = path.resolve()
            if real in seen:
                continue
            seen.add(real)
            yield path


def pyproject_dependencies(repo: Path) -> list[str]:
    """Package names from [project.dependencies] and every
    [project.optional-dependencies] group — multi-line and inline list
    forms alike (the sigstore group was inline; a line-based parser
    missed it). tomllib (3.11+) with a specifier-strip; regex fallback
    keeps 3.10 working."""
    path = repo / "pyproject.toml"
    if not path.is_file():
        return []
    specs: list[str] = []
    try:
        import tomllib

        data = tomllib.loads(path.read_text())
        project = data.get("project", {})
        specs.extend(project.get("dependencies", []))
        for group in (project.get("optional-dependencies") or {}).values():
            specs.extend(group)
    except Exception:
        specs = re.findall(r'"([A-Za-z0-9._-]+[^"]*)"', path.read_text())
    names = set()
    for s in specs:
        m = re.match(r"\s*([A-Za-z0-9._-]+)", s)
        if m:
            names.add(m.group(1))
    return sorted(names)


def dependency_intake_failures(repo: Path) -> list[str]:
    doc_path = repo / "docs" / "external-dependencies.md"
    if not doc_path.is_file():
        return []
    doc = doc_path.read_text().lower()
    failures = []
    for dep in pyproject_dependencies(repo):
        if dep.lower() not in doc:
            failures.append(
                f"pyproject.toml: dependency '{dep}' has no row in "
                f"docs/external-dependencies.md — run the "
                f"/check-licensing intake (verify upstream license with "
                f"evidence, classify usage model, add the row)"
            )
    return failures


def content_license_failures(repo: Path = REPO) -> list[str]:
    failures: list[str] = []
    for path in _scan_files(repo):
        rel = path.relative_to(repo).as_posix()
        if rel in ALLOWLIST:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            m = NC_MARKER_RE.search(line)
            if m:
                failures.append(
                    f"{rel}:{n}: NonCommercial license marker "
                    f"'{m.group(0)}' — CC-NC-licensed content re-imported? "
                    f"(PEACH rule 1a; see docs/external-dependencies.md)"
                )
            elif (m := SA_MARKER_RE.search(line)) is not None:
                failures.append(
                    f"{rel}:{n}: ShareAlike license marker '{m.group(0)}' — "
                    f"BY-SA content adapted into this Apache-2.0 tree? BY-SA "
                    f"3(b) requires a CC ShareAlike Adapter's License, which "
                    f"Apache-2.0 is not. Use the upstream at runtime, or "
                    f"reimplement from the ideas in original wording "
                    f"(rule 6; see docs/external-dependencies.md)"
                )
            for phrase in PEACH_FINGERPRINTS:
                if phrase in line:
                    failures.append(
                        f"{rel}:{n}: fingerprint of the removed Wiz-derived "
                        f"PEACH adaptation ('{phrase}') — the PEACH sections "
                        f"must stay original text (rule 1b)"
                    )
            for rx in CIS_TEXT_RES:
                m = rx.search(line)
                if m:
                    failures.append(
                        f"{rel}:{n}: CIS benchmark recommendation-text "
                        f"signature ('{m.group(0)[:60]}') — cite bare CIS "
                        f"section IDs only, never benchmark text (rule 2)"
                    )
            for rx in PCI_TEXT_RES:
                m = rx.search(line)
                if m:
                    failures.append(
                        f"{rel}:{n}: PCI DSS requirement-text signature "
                        f"('{m.group(0)[:60]}') — PCI SSC copyright: cite "
                        f"bare requirement IDs only, never standard text "
                        f"(rule 4)"
                    )
            for rx in TSC_TEXT_RES:
                m = rx.search(line)
                if m:
                    failures.append(
                        f"{rel}:{n}: AICPA TSC criteria-text signature "
                        f"('{m.group(0)[:60]}') — AICPA copyright: cite "
                        f"bare TSC criterion IDs only (rule 5)"
                    )
    failures.extend(dependency_intake_failures(repo))
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Guard against re-importing NC- or SA-licensed framework text."
    )
    ap.add_argument("--root", default=str(REPO), help="Repo root to check (default: this harness).")
    args = ap.parse_args(argv)
    repo = Path(args.root).resolve()

    failures = content_license_failures(repo)
    print(f"Content-license guard for {repo}")
    if not failures:
        print(
            "✓ no NC- or SA-licensed content markers, PEACH-adaptation "
            "fingerprints, CIS benchmark text, PCI DSS standard text, "
            "or AICPA TSC criteria text found"
        )
        return 0
    print(f"\n✗ {len(failures)} violation(s):")
    for f in failures:
        print(f"    - {f}")
    print(
        "\nSee docs/external-dependencies.md (Security frameworks & content licenses) "
        "for why these rules exist and how to remediate."
    )
    return 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "content-licenses", *sys.argv[1:]]))
