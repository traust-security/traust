#!/usr/bin/env python3
"""Skill enumeration — one helper, two layouts.

`skill_dirs()` exists so the stage-directory move
(progress-tracker/plans/skill-usability-reorganization-plan.md 1.2) costs
one function instead of ten call sites. These tests hold both halves of
that claim: the live flat tree enumerates exactly as the old
`harnessing/*/SKILL.md` glob did, and a nested fixture enumerates too —
so the move is a no-op for every gate, provable before it happens.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from traust.cli import check_docs_consistency as D
from traust.cli import check_skill_alignment as A
from traust.paths import (
    HARNESS_ROOT,
    skill_dirs,
    skill_md_paths,
    skill_scripts,
)

FRONTMATTER = '---\nname: {name}\nmetadata:\n  harness.tier: "primary"\n---\nbody\n'


def _skill(root: Path, rel: str, name: str | None = None) -> Path:
    """Write a skill at `rel` under `root`, returning its directory."""
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(FRONTMATTER.format(name=name or d.name), encoding="utf-8")
    return d


class TestLiveTree(unittest.TestCase):
    def test_covers_both_levels_of_the_live_tree(self):
        """Every SKILL.md in the tree is found, at whichever depth it sits.

        This replaced an equality against the flat `harnessing/*/SKILL.md`
        glob. That assertion was only true while every skill was flat, so it
        had to become a superset check the moment the first stage directory
        landed — the glob is now the subset that has not moved yet.
        """
        flat = {p.parent.name for p in HARNESS_ROOT.glob("harnessing/*/SKILL.md")}
        nested = {p.parent.name for p in HARNESS_ROOT.glob("harnessing/*/*/SKILL.md")}
        found = {d.name for d in skill_dirs()}
        self.assertEqual(found, flat | nested)
        self.assertTrue(flat <= found, "a flat skill went missing")

    def test_names_are_unique(self):
        names = [d.name for d in skill_dirs()]
        self.assertEqual(
            len(names),
            len(set(names)),
            "two skills share a name — the sort is not a "
            "total order and rule A6 should have caught it",
        )

    def test_sorted_by_name(self):
        names = [d.name for d in skill_dirs()]
        self.assertEqual(names, sorted(names))

    def test_every_dir_carries_a_skill_md(self):
        for d in skill_dirs():
            self.assertTrue((d / "SKILL.md").is_file(), d)

    def test_md_paths_and_scripts_agree_with_dirs(self):
        self.assertEqual(skill_md_paths(), [d / "SKILL.md" for d in skill_dirs()])
        for s in skill_scripts():
            self.assertEqual(s.parent.name, "scripts")
            self.assertIn(s.parent.parent, skill_dirs())


class TestNestedLayout(unittest.TestCase):
    """The Milestone-1.2 layout, exercised before the move lands."""

    def _repo(self, tmp: Path) -> Path:
        _skill(tmp, "harnessing/census")  # stays at root
        _skill(tmp, "harnessing/4-triage/triage")  # nested
        _skill(tmp, "harnessing/3-audit/vuln-scan")  # nested
        return tmp

    def test_finds_both_levels(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d))
            self.assertEqual([p.name for p in skill_dirs(repo)], ["census", "triage", "vuln-scan"])

    def test_a_stage_directory_is_not_itself_a_skill(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d))
            self.assertNotIn("4-triage", [p.name for p in skill_dirs(repo)])

    def test_does_not_descend_into_a_skill(self):
        """A SKILL.md inside a skill — a cloned target, a template — is
        not a skill of its own; that is what bounds the walk at two
        levels instead of using rglob."""
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d))
            _skill(repo, "harnessing/census/vendored/impostor")
            self.assertNotIn("impostor", [p.name for p in skill_dirs(repo)])

    def test_scripts_resolve_at_either_depth(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d))
            for rel in ("harnessing/census", "harnessing/4-triage/triage"):
                (repo / rel / "scripts").mkdir()
                (repo / rel / "scripts" / "build.py").write_text("# x\n")
            self.assertEqual(
                [p.relative_to(repo).as_posix() for p in skill_scripts(repo)],
                [
                    "harnessing/census/scripts/build.py",
                    "harnessing/4-triage/triage/scripts/build.py",
                ],
            )

    def test_missing_harnessing_dir_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(skill_dirs(Path(d)), [])


class TestGatesAreLayoutAgnostic(unittest.TestCase):
    """The point of 1.1: the gates see a nested skill, and report its
    real path rather than a reconstructed `harnessing/<name>/`."""

    def test_alignment_reads_a_nested_skill_at_its_real_path(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _skill(repo, "harnessing/4-triage/triage", name="wrong-name")
            (repo / "docs").mkdir()
            (repo / "scripts").mkdir()
            a6 = [f for f in A.alignment_failures(repo) if f.startswith("A6")]
            self.assertEqual(len(a6), 1, a6)
            self.assertIn("harnessing/4-triage/triage/SKILL.md", a6[0])

    def test_skill_count_sees_nested_skills(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _skill(repo, "harnessing/census")
            _skill(repo, "harnessing/4-triage/triage")
            (repo / ".claude" / "commands").mkdir(parents=True)
            (repo / "src" / "traust").mkdir(parents=True)
            self.assertEqual(D.expected_counts(repo)["skills"], 2)


if __name__ == "__main__":
    unittest.main()


def test_harness_root_is_the_checkout_unless_harness_root_names_the_payload(
    tmp_path: Path,
) -> None:
    def root(env: dict[str, str]) -> str:
        code = "from traust.paths import HARNESS_ROOT; print(HARNESS_ROOT)"
        done = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    env = {k: v for k, v in os.environ.items() if k != "HARNESS_ROOT"}
    assert root(env) == str(HARNESS_ROOT)
    assert root({**env, "HARNESS_ROOT": str(tmp_path)}) == str(tmp_path)
