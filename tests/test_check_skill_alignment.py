#!/usr/bin/env python3
"""Skill-alignment guard tests — live tree + fixture misalignments."""

import os
import tempfile
import unittest
from pathlib import Path

import pytest

from traust.cli import check_skill_alignment as A


def mini_repo(tmp: Path, skill_md: str, name: str = "demo-skill", wire: bool = True) -> Path:
    d = tmp / "harnessing" / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(skill_md)
    (tmp / "docs").mkdir(exist_ok=True)
    (tmp / "scripts").mkdir(exist_ok=True)
    (tmp / "scripts" / "run_opengrep.py").write_text("# stub\n")
    if wire:
        for p in (
            tmp / ".claude" / "skills",
            tmp / ".crush" / "skills",
            tmp / ".claude" / "commands",
            tmp / ".crush" / "commands",
        ):
            p.mkdir(parents=True, exist_ok=True)
        (tmp / ".claude" / "skills" / name).symlink_to(d)
        (tmp / ".crush" / "skills" / name).symlink_to(d)
        (tmp / ".claude" / "commands" / f"{name}.md").write_text("wrap\n")
        (tmp / ".crush" / "commands" / f"{name}.md").write_text("wrap\n")
    return tmp


ALIGNED = """---
name: demo-skill
metadata:
  harness.tier: "primary"
---
Run `python scripts/run_opengrep.py <dir>` and record
`metadata.additional.deterministic_steps`; judge each fact via
scanner_correlation entries. Sets `metadata.audit_profile: "code"` per
docs/report-structure.md. Reads repo_status from repo-liveness.json.
"""


class TestLiveTree(unittest.TestCase):
    def test_current_tree_aligned(self):
        used: list = []
        failures = A.alignment_failures(A.REPO, used)
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_exemptions_all_used(self):
        used: list = []
        A.alignment_failures(A.REPO, used)
        self.assertEqual(len(used), len(A.EXEMPTIONS), "stale EXEMPTIONS entry — prune it")

    def test_pre_commit_hook_wired(self):
        hook = (A.REPO / ".githooks" / "pre-commit").read_text()
        self.assertIn("check_skill_alignment.py", hook)


class TestRules(unittest.TestCase):
    def _failures(self, skill_md, name="demo-skill", wire=True):
        with tempfile.TemporaryDirectory() as d:
            repo = mini_repo(Path(d), skill_md, name, wire)
            # rules referencing docs need the file to exist for A4 pass-case
            (repo / "docs" / "report-structure.md").write_text("x\n")
            return A.alignment_failures(repo)

    def test_aligned_skill_passes(self):
        self.assertEqual(self._failures(ALIGNED), [])

    def test_a1_dead_script_reference(self):
        fails = self._failures("---\nname: demo-skill\n---\nRun `scripts/does_not_exist.py`.\n")
        self.assertTrue(any(f.startswith("A1") for f in fails), fails)

    def test_a2_opengrep_without_conventions(self):
        fails = self._failures(
            "---\nname: demo-skill\n---\n"
            "Run `python scripts/run_opengrep.py x` and put results in "
            "`metadata.tools`.\n"
        )
        self.assertTrue(any(f.startswith("A2") for f in fails), fails)

    def test_a2_mention_without_report_is_ignored(self):
        fails = self._failures(
            "---\nname: demo-skill\n---\nSee `run_opengrep.py` for the swappable-input pattern.\n"
        )
        self.assertFalse(any(f.startswith("A2") for f in fails), fails)

    def test_a4_profile_without_structure_link(self):
        fails = self._failures(
            '---\nname: demo-skill\n---\nSet `metadata.audit_profile: "code"`.\n'
        )
        self.assertTrue(any(f.startswith("A4") for f in fails), fails)

    def test_a5_liveness_without_artifact(self):
        fails = self._failures("---\nname: demo-skill\n---\nStamp repo_status from GitHub.\n")
        self.assertTrue(any(f.startswith("A5") for f in fails), fails)

    def test_a6_name_mismatch(self):
        fails = self._failures("---\nname: other-name\n---\nbody\n")
        self.assertTrue(any(f.startswith("A6") for f in fails), fails)

    def test_a7_missing_wiring(self):
        fails = self._failures("---\nname: demo-skill\n---\nbody\n", wire=False)
        self.assertEqual(sum(1 for f in fails if f.startswith("A7")), 4, fails)

    def test_a8_checkov_without_contract(self):
        fails = self._failures(
            "---\nname: demo-skill\n---\nRun run_checkov.py against the checkout.\n"
        )
        self.assertTrue(any(f.startswith("A8") for f in fails), fails)

    def test_a8_checkov_with_contract(self):
        fails = self._failures(
            "---\nname: demo-skill\n---\n"
            "Run run_checkov.py, record metadata.deterministic_steps; "
            "declared configuration only.\n"
        )
        self.assertFalse(any(f.startswith("A8") for f in fails), fails)

    def test_a11_broad_interpreter_allowance_fails(self):
        for entry in (
            "Bash(python3:*)",
            "Bash(python:*)",
            "Bash(bash:*)",
            "Bash(sh:*)",
            "Bash(node:*)",
            "Bash(*)",
        ):
            fails = self._failures(
                "---\nname: demo-skill\nallowed-tools:\n  - Read\n  - " + entry + "\n---\nbody\n"
            )
            self.assertTrue(
                any(f.startswith("A11") for f in fails), f"{entry} not flagged: {fails}"
            )

    def test_a11_scoped_scripts_and_comments_pass(self):
        # scoped per-script grants pass; a frontmatter comment that merely
        # names the broad pattern (the warning at the point of temptation)
        # must not trip the rule
        fails = self._failures(
            "---\nname: demo-skill\nallowed-tools:\n"
            "  # never widen to Bash(python3:*) - A11 blocks it\n"
            "  - Bash(python3 *validate_report.py:*)\n"
            "  - Bash(jq:*)\n---\nbody\n"
        )
        self.assertFalse(any(f.startswith("A11") for f in fails), fails)

    def test_a11_body_prose_ignored(self):
        fails = self._failures(
            "---\nname: demo-skill\n---\n"
            "Never grant Bash(python3:*) in allowed-tools.\n"
            "- Bash(python3:*) is the anti-pattern this doc warns about\n"
        )
        self.assertFalse(any(f.startswith("A11") for f in fails), fails)


class TestStructuralGrants(unittest.TestCase):
    """P1 gate rework (2026-07-31): A11 structural leg + A14."""

    _failures = TestRules._failures

    def test_a11_flow_style_and_quoted_entries(self):
        # the old line-anchored regex saw neither of these
        for fm in (
            '---\nname: demo-skill\nallowed-tools: [Read, "Bash(python3:*)"]\n---\nbody\n',
            '---\nname: demo-skill\nallowed-tools:\n  - "Bash(bash:*)"\n---\nbody\n',
        ):
            fails = self._failures(fm)
            self.assertTrue(any(f.startswith("A11") for f in fails), fails)

    def test_a11_versioned_and_path_prefixed_interpreters(self):
        for entry in ("Bash(python3.11:*)", "Bash(/usr/bin/python3:*)", "Bash(pip3.12:*)"):
            fails = self._failures(
                "---\nname: demo-skill\nallowed-tools:\n  - " + entry + "\n---\nbody\n"
            )
            self.assertTrue(
                any(f.startswith("A11") for f in fails), f"{entry} not flagged: {fails}"
            )

    def test_a11_new_broad_heads(self):
        for entry in ("Bash(git:*)", "Bash(find:*)", "Bash(open:*)", "Bash(env:*)", "Bash(make:*)"):
            fails = self._failures(
                "---\nname: demo-skill\nallowed-tools:\n  - " + entry + "\n---\nbody\n"
            )
            self.assertTrue(
                any(f.startswith("A11") for f in fails), f"{entry} not flagged: {fails}"
            )

    def test_a11_unparseable_frontmatter_fails_closed(self):
        fails = self._failures(
            "---\nname: demo-skill\ndescription: bad: colon: soup\n"
            "allowed-tools:\n  - Read\n---\nbody\n"
        )
        self.assertTrue(any(f.startswith("A11") for f in fails), fails)

    def test_a14_leading_wildcard_interpreter_grant(self):
        fails = self._failures(
            "---\nname: demo-skill\nallowed-tools:\n"
            "  - Bash(python3 *validate_report.py:*)\n---\nbody\n"
        )
        self.assertTrue(any(f.startswith("A14") for f in fails), fails)

    def test_a14_anchored_grant_passes(self):
        fails = self._failures(
            "---\nname: demo-skill\nallowed-tools:\n"
            "  - Bash(python3 *traust/scripts/validate_report.py:*)\n"
            "---\nbody\n"
        )
        self.assertFalse(any(f.startswith("A14") for f in fails), fails)

    def test_a11_subcommand_scoped_git_passes(self):
        fails = self._failures(
            "---\nname: demo-skill\nallowed-tools:\n"
            "  - Bash(git log:*)\n  - Bash(git diff:*)\n---\nbody\n"
        )
        self.assertFalse(any(f.startswith("A11") for f in fails), fails)


class TestU3Tier(unittest.TestCase):
    """U3 — every skill declares metadata.harness.tier. A new skill is
    the case this exists for: the label was applied to all 58 at once,
    and without a gate the 59th arrives untiered."""

    def _u3(self, skill_md, name="demo-skill"):
        with tempfile.TemporaryDirectory() as d:
            repo = mini_repo(Path(d), skill_md, name)
            return [f for f in A.alignment_failures(repo) if f.startswith("U3")]

    def test_new_skill_without_tier_fails(self):
        fails = self._u3("---\nname: demo-skill\n---\nbody\n")
        self.assertEqual(len(fails), 1, fails)
        self.assertIn("metadata.harness.tier", fails[0])

    def test_every_enum_value_passes(self):
        for tier in A.TIERS:
            self.assertEqual(
                self._u3(
                    f'---\nname: demo-skill\nmetadata:\n  harness.tier: "{tier}"\n---\nbody\n'
                ),
                [],
                tier,
            )

    def test_unquoted_scalar_passes(self):
        # YAML gives a str either way; requiring the quotes would be
        # stricter than the spec, which only asks for string values.
        self.assertEqual(
            self._u3("---\nname: demo-skill\nmetadata:\n  harness.tier: secondary\n---\nbody\n"), []
        )

    def test_value_outside_enum_fails(self):
        # Asserts the durable contract rather than the phrasing: the
        # message echoes the offending value and names every legal tier,
        # so an author can fix it without opening the checker.
        # "n-a" was the plan's original name for the gates tier before
        # review settled on "ci"; it is pinned as off-enum so the older
        # spelling cannot creep back in as an accepted alias.
        for bad in ('"Primary"', '"core"', '"n/a"', '"n-a"', "3"):
            fails = self._u3(
                f"---\nname: demo-skill\nmetadata:\n  harness.tier: {bad}\n---\nbody\n"
            )
            self.assertEqual(len(fails), 1, (bad, fails))
            self.assertIn(bad.strip('"'), fails[0])
            for tier in A.TIERS:
                self.assertIn(tier, fails[0])

    def test_missing_value_is_reported_as_missing_not_none(self):
        # The missing and off-enum cases share one message now, so the
        # absent case must not surface as the bare repr `None`.
        fails = self._u3("---\nname: demo-skill\n---\nbody\n")
        self.assertEqual(len(fails), 1, fails)
        self.assertIn("missing", fails[0])
        self.assertNotIn("None", fails[0])

    def test_nested_form_is_not_the_contract(self):
        # `harness: {tier: ...}` looks equivalent but is not what the
        # spec's string-keyed metadata map allows, so it must not pass.
        fails = self._u3(
            "---\nname: demo-skill\nmetadata:\n  harness:\n    tier: primary\n---\nbody\n"
        )
        self.assertEqual(len(fails), 1, fails)

    def test_other_metadata_keys_are_left_alone(self):
        self.assertEqual(
            self._u3(
                "---\nname: demo-skill\nmetadata:\n"
                '  author: someone\n  version: "6.0"\n'
                '  harness.tier: "tertiary"\n---\nbody\n'
            ),
            [],
        )

    def test_metadata_not_a_mapping_fails(self):
        fails = self._u3("---\nname: demo-skill\nmetadata: primary\n---\nbody\n")
        self.assertEqual(len(fails), 1, fails)

    def test_unparseable_frontmatter_fails_closed(self):
        fails = self._u3("---\nname: demo-skill\ndescription: bad: colon: soup\n---\nbody\n")
        self.assertEqual(len(fails), 1, fails)
        self.assertIn("must fail, not pass", fails[0])

    def test_takes_no_exemptions(self):
        # The rule is documented as exemption-free; an EXEMPTIONS entry
        # for it would be dead config that reads as an escape hatch.
        self.assertEqual([k for k in A.EXEMPTIONS if k[0] == "U3"], [])


class TestArtifactGraphDirection(unittest.TestCase):
    """A9/A10 rework (2026-07-31): structured Emits/Consumes lines are
    authoritative; A10 needs a real heading; declared artifacts bypass
    the hyphen filter."""

    def test_consumes_declaration_never_counts_as_production(self):
        produced, mentioned = A._skill_artifacts(
            "## Integrations\n\n**Consumes:** `foo-report.json` from /other-skill.\n"
        )
        self.assertNotIn("foo-report.json", produced)
        self.assertIn("foo-report.json", mentioned)

    def test_emits_declaration_counts_as_production(self):
        produced, _ = A._skill_artifacts(
            "## Integrations\n\n**Emits:** `foo-report.json` consumed by /other.\n"
        )
        self.assertIn("foo-report.json", produced)

    def test_declarations_suppress_verb_heuristic(self):
        # an arrow/verb line elsewhere must not credit production once
        # the skill declares its emissions
        produced, _ = A._skill_artifacts(
            "The mapping writes `bar-things.json` rows.\n\n"
            "## Integrations\n\n"
            "**Emits:** `foo-report.json`.\n"
        )
        self.assertNotIn("bar-things.json", produced)

    def test_declared_hyphen_free_artifact_survives_filter(self):
        # hyphen-free names are normally dropped as state/scratch files;
        # an explicit declaration keeps them in the graph (bare META
        # names like PATCHES.json stay excluded via ARTIFACT_SKIP_RE —
        # /patch declares its packet terminal instead)
        produced, _ = A._skill_artifacts(
            "## Integrations\n\n**Emits:** `fleetrows.json` per repo.\n"
        )
        self.assertIn("fleetrows.json", produced)


@pytest.mark.requires_git
class TestA13SkillsDocSync(unittest.TestCase):
    def _repo_with_staged_skill(self, tmp, stage_skills_doc=False):
        import subprocess

        repo = Path(tmp)
        subprocess.run(["git", "-C", tmp, "init", "-q"], check=True)
        subprocess.run(["git", "-C", tmp, "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", tmp, "config", "user.name", "t"], check=True)
        d = repo / "harnessing" / "demo"
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text("---\nname: demo\n---\nv1\n")
        (repo / "docs").mkdir()
        (repo / "docs" / "skills.md").write_text("## demo\n")
        subprocess.run(["git", "-C", tmp, "add", "-A"], check=True)
        subprocess.run(["git", "-C", tmp, "commit", "-qm", "base"], check=True)
        (d / "SKILL.md").write_text("---\nname: demo\n---\nv2\n")
        subprocess.run(["git", "-C", tmp, "add", "harnessing/demo/SKILL.md"], check=True)
        if stage_skills_doc:
            (repo / "docs" / "skills.md").write_text("## demo\nv2\n")
            subprocess.run(["git", "-C", tmp, "add", "docs/skills.md"], check=True)
        return repo

    def test_staged_skill_without_doc_fails_under_hook_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo_with_staged_skill(tmp)
            env_backup = dict(os.environ)
            try:
                os.environ["HARNESS_PRE_COMMIT"] = "1"
                os.environ.pop("SKILLS_DOC_WAIVER", None)
                fails = A.a13_skills_doc_sync_failures(repo)
                self.assertTrue(any(f.startswith("A13") for f in fails))
                # waiver silences it
                os.environ["SKILLS_DOC_WAIVER"] = "typo only"
                self.assertEqual(A.a13_skills_doc_sync_failures(repo), [])
            finally:
                os.environ.clear()
                os.environ.update(env_backup)

    def test_inert_outside_hook_and_passes_with_doc(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo_with_staged_skill(tmp, stage_skills_doc=True)
            env_backup = dict(os.environ)
            try:
                os.environ.pop("HARNESS_PRE_COMMIT", None)
                self.assertEqual(A.a13_skills_doc_sync_failures(repo), [])
                os.environ["HARNESS_PRE_COMMIT"] = "1"
                os.environ.pop("SKILLS_DOC_WAIVER", None)
                self.assertEqual(A.a13_skills_doc_sync_failures(repo), [])
            finally:
                os.environ.clear()
                os.environ.update(env_backup)


if __name__ == "__main__":
    unittest.main()


class TestStageDepthExemptionMatching(unittest.TestCase):
    """The twin of the security checker's test: a flat EXEMPTIONS key must
    cover the same skill nested under a stage directory, so `gates:pinned`
    (the target branch's checker against an MR tree) does not turn every
    reviewed exemption into a violation when a skill moves."""

    def test_flat_key_matches_nested_path(self):
        # A14 harnessing/threat-model/SKILL.md is a real reviewed key;
        # the skill nests under 2-threat-model after the stage restructure.
        used: list = []
        self.assertTrue(A._exempt("A14", "harnessing/2-threat-model/threat-model/SKILL.md", used))
        self.assertTrue(used, "the hit must be recorded for the used-check")

    def test_flat_key_still_matches_flat_path(self):
        self.assertTrue(A._exempt("A14", "harnessing/threat-model/SKILL.md", []))

    def test_unrelated_path_is_not_exempted(self):
        self.assertFalse(A._exempt("A14", "harnessing/5-validate/not-a-real-skill/SKILL.md", []))

    def test_unstaged_strips_only_the_stage_segment(self):
        self.assertEqual(
            A._unstaged("harnessing/4-triage/triage/SKILL.md"), "harnessing/triage/SKILL.md"
        )
        self.assertEqual(A._unstaged("harnessing/triage/SKILL.md"), "harnessing/triage/SKILL.md")
        self.assertEqual(A._unstaged("docs/skills.md"), "docs/skills.md")

    def test_stage_segment_pattern_needs_the_numeric_prefix(self):
        # `harnessing/<skill>/scripts/` must not be mistaken for a stage:
        # only a leading `<N>-` directory is one.
        self.assertEqual(
            A._unstaged("harnessing/census/scripts/x.py"), "harnessing/census/scripts/x.py"
        )


class TestA17LocationsNote(unittest.TestCase):
    NOTE = (
        "> **Paths.** `analysis-results/…` in this skill are the default layout; "
        "they resolve through `locations:` in `traust.yaml` in `$TRAUST_CONFIG_HOME`.\n"
    )

    def _a17(self, body):
        with tempfile.TemporaryDirectory() as d:
            repo = mini_repo(Path(d), "---\nname: demo-skill\n---\n# Demo\n\n" + body)
            return [f for f in A.a17_locations_note_failures(repo) if f.startswith("A17")]

    def test_tree_without_note_fails(self):
        fails = self._a17("Reads `analysis-results/findings/`.\n")
        self.assertEqual(len(fails), 1, fails)
        self.assertIn("analysis-results/", fails[0])

    def test_tracker_tree_without_note_fails(self):
        self.assertTrue(self._a17("Writes to progress-tracker/metrics/.\n"))

    def test_tree_with_note_passes(self):
        self.assertEqual(self._a17(self.NOTE + "\nReads `analysis-results/findings/`.\n"), [])

    def test_no_tree_no_requirement(self):
        self.assertEqual(self._a17("Reads the target checkout only.\n"), [])

    def test_live_tree_carries_the_note(self):
        self.assertEqual(
            [f for f in A.a17_locations_note_failures(A.REPO) if f.startswith("A17")], []
        )


class TestA7Tracked(unittest.TestCase):
    """A wiring link that exists on disk but is untracked is a failure: the
    export dry-run (2026-09-08) shipped a tree missing two .crush links because
    .crush/.gitignore is `*` and nobody `git add -f`ed them."""

    def test_untracked_wiring_is_flagged(self):
        import subprocess
        import tempfile
        from pathlib import Path

        from traust.cli import check_skill_alignment as C

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            subprocess.run(["git", "init", "-q", repo], check=True)
            (repo / ".crush").mkdir()
            (repo / ".crush" / ".gitignore").write_text("*\n")
            self.assertIsNotNone(C._tracked_paths(repo))
            self.assertNotIn(".crush/skills/x", C._tracked_paths(repo))
            # force-added link is tracked
            (repo / ".crush" / "skills").mkdir()
            (repo / ".crush" / "skills" / "x").write_text("stub")
            subprocess.run(["git", "-C", repo, "add", "-f", ".crush/skills/x"], check=True)
            self.assertIn(".crush/skills/x", C._tracked_paths(repo))

    def test_non_git_tree_skips_the_check(self):
        import tempfile
        from pathlib import Path

        from traust.cli import check_skill_alignment as C

        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(C._tracked_paths(Path(td)))
