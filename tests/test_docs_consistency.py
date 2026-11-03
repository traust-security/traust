#!/usr/bin/env python3
"""Documentation-consistency guardrails.

Thin test wrapper around `traust.cli.check_docs_consistency` (the single source
of truth for the checks). Fails when the maintained docs drift from the tree:
count claims (skills/commands/scripts/stages) or dead repo-relative paths.
Run the script directly for a human-readable report:

    python traust.cli.check_docs_consistency
"""

import tempfile
import unittest
from pathlib import Path

import pytest

from traust.cli import check_docs_consistency as C
from traust.cli.__main__ import main as cli_main


class TestDocConsistency(unittest.TestCase):
    def test_counts_match_tree(self):
        failures = C.count_failures()
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_no_dead_markdown_links(self):
        failures = C.dead_link_failures()
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_no_dead_backtick_paths(self):
        failures = C.dead_backtick_failures()
        self.assertEqual(failures, [], "\n" + "\n".join(failures))


class TestCliExampleFlags(unittest.TestCase):
    def test_live_tree_clean(self):
        self.assertEqual(C.cli_example_failures(), [])

    def test_bad_flag_flagged_good_flag_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "scripts").mkdir()
            (repo / "scripts" / "mytool.py").write_text(
                "import argparse\n"
                "ap = argparse.ArgumentParser()\n"
                'ap.add_argument("--strict", action="store_true")\n'
            )
            (repo / "docs").mkdir()
            (repo / "PROCESS.md").write_text("x\n")
            (repo / "AGENTS.md").write_text("x\n")
            (repo / "README.md").write_text(
                "Run `python scripts/mytool.py report.json --strict`.\n"
                "Legacy: `python scripts/mytool.py --validate report.json`\n"
                "Multi-line:\n"
                "```bash\n"
                "python scripts/mytool.py \\\n"
                "  --no-such-flag value\n"
                "```\n"
                "Implicit: `python scripts/mytool.py --help`\n"
            )
            failures = C.cli_example_failures(repo)
            flagged = sorted(f.split("with ")[1].split(",")[0] for f in failures)
            self.assertEqual(flagged, ["--no-such-flag", "--validate"])

    def test_nonexistent_script_left_to_dead_path_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docs").mkdir()
            (repo / "PROCESS.md").write_text("x\n")
            (repo / "AGENTS.md").write_text("x\n")
            (repo / "README.md").write_text("`python scripts/gone.py --whatever`\n")
            self.assertEqual(C.cli_example_failures(repo), [])


class TestPartialEnumAndAsofChecks(unittest.TestCase):
    def test_live_tree_clean(self):
        self.assertEqual(C.partial_enum_failures(), [])
        self.assertEqual(C.asof_banner_failures(), [])

    def test_partial_enum_flagged_full_and_ambiguous_pass(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            schema_d = repo / "schemas"
            schema_d.mkdir()
            (schema_d / "a.json").write_text(
                '{"properties": {"status_kind": {"enum": '
                '["alpha", "beta", "gamma", "delta"]}, '
                '"verdictish": {"enum": ["one", "two", "three", "four"]}}}'
            )
            (schema_d / "b.json").write_text(
                '{"properties": {"verdictish": {"enum": ["five", "six", "seven", "eight"]}}}'
            )
            (repo / "docs").mkdir()
            (repo / "PROCESS.md").write_text("x\n")
            (repo / "AGENTS.md").write_text("x\n")
            (repo / "README.md").write_text(
                "status_kind is one of `alpha`, `beta`, `gamma`.\n"
                "status_kind full: `alpha`, `beta`, `gamma`, `delta`.\n"
                "verdictish may be `one`, `two`, `three` here.\n"
            )
            with mock.patch.object(C, "schema_dir", return_value=schema_d):
                fails = C.partial_enum_failures(repo)
            self.assertEqual(len(fails), 1)  # partial flagged once
            self.assertIn("status_kind", fails[0])
            self.assertIn("delta", fails[0])  # names the missing value
            # ambiguous field (two different enums) never flagged
            self.assertFalse(any("verdictish" in f for f in fails))

    def test_asof_banner_required_on_assessment_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docs").mkdir()
            (repo / "docs" / "foo-assessment.md").write_text("# Foo\nno date\n")
            (repo / "docs" / "bar-draft.md").write_text("# Bar\nSnapshot as of 2026-07-25.\n")
            (repo / "docs" / "normal-guide.md").write_text("# G\n")
            fails = C.asof_banner_failures(repo)
            self.assertEqual(len(fails), 1)
            self.assertIn("foo-assessment.md", fails[0])


class TestVersionSyncAndSymlinks(unittest.TestCase):
    def test_live_tree_clean(self):
        self.assertEqual(C.version_sync_failures(), [])
        self.assertEqual(C.symlink_failures(), [])

    def test_pyproject_drift_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "VERSION").write_text("2.0.0\n")
            (repo / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n')
            failures = C.version_sync_failures(repo)
            self.assertTrue(any("1.0.0" in f and "2.0.0" in f for f in failures))

    def test_version_args_drift_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "VERSION").write_text("2.0.0\n")
            (repo / "version.args").write_text("VERSION=1.9.0\n")
            failures = C.version_sync_failures(repo)
            self.assertTrue(any("version.args" in f and "2.0.0" in f for f in failures))

    def test_version_args_in_sync_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "VERSION").write_text("2.0.0\n")
            (repo / "version.args").write_text("VERSION=2.0.0\n")
            self.assertEqual(C.version_sync_failures(repo), [])

    def test_dangling_symlink_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".claude" / "commands").mkdir(parents=True)
            (repo / ".claude" / "commands" / "x.md").symlink_to("../nonexistent.md")
            failures = C.symlink_failures(repo)
            self.assertTrue(any("dangling symlink" in f for f in failures))

    def test_undocumented_external_tool_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docs").mkdir()
            (repo / "docs" / "external-dependencies.md").write_text(
                "| `documented-tool` | x | MIT | link |\n"
            )
            (repo / "scripts").mkdir()
            (repo / "scripts" / "a.py").write_text(
                "import subprocess, shutil\n"
                'subprocess.run(["documented-tool", "-v"])\n'
                'shutil.which("mystery-scanner")\n'
                'ap.add_argument("--othertool", default="othertool")\n'
                'p = HERE / "bin" / "vendored-bin"\n'
                'subprocess.run(["python3", "x.py"])\n'
            )
            (repo / "harnessing" / "s").mkdir(parents=True)
            (repo / "harnessing" / "s" / "b.sh").write_text("command -v shell-tool || exit 1\n")
            failures = C.external_tool_failures(repo)
            flagged = {f.split("'")[1] for f in failures}
            self.assertEqual(
                flagged, {"mystery-scanner", "othertool", "vendored-bin", "shell-tool"}
            )

    def test_external_tools_skip_fixture_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "docs").mkdir()
            (repo / "docs" / "external-dependencies.md").write_text("|\n")
            d = repo / "harnessing" / "x" / "opengrep-rules"
            d.mkdir(parents=True)
            (d / "fixture.py").write_text('subprocess.run(["nslookup", host])\n')
            self.assertEqual(C.external_tool_failures(repo), [])


class TestConflictMarkers(unittest.TestCase):
    """Added after a bad push: a rebase-resolution script failed silently,
    `git rebase --continue` committed the conflicted file, and CHANGELOG.md
    reached main with six markers. Every other gate passed because none of
    them looked."""

    def _repo(self, files):
        import subprocess

        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for rel, body in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        return root

    def test_markers_are_caught(self):
        repo = self._repo(
            {
                "CHANGELOG.md": "# Changelog\n\n<<<<<<< HEAD\ntheirs\n"
                "=======\nmine\n>>>>>>> abc123 (c)\n"
            }
        )
        out = C.conflict_marker_failures(repo)
        self.assertEqual(len(out), 1)
        self.assertIn("CHANGELOG.md", out[0])
        self.assertIn("conflict marker", out[0])

    def test_setext_heading_is_not_a_false_positive(self):
        """`=======` is a legitimate Markdown H1 underline — which is why
        only the directional markers trigger."""
        repo = self._repo({"doc.md": "My Title\n=======\n\nbody\n"})
        self.assertEqual(C.conflict_marker_failures(repo), [])

    def test_clean_tree_passes(self):
        repo = self._repo({"a.py": "x = 1\n", "b.md": "# T\n\ntext\n"})
        self.assertEqual(C.conflict_marker_failures(repo), [])

    def test_opt_out_marker_is_honoured(self):
        repo = self._repo(
            {
                "howto.md": "docs-check: allow-conflict-markers\n\n"
                "<<<<<<< HEAD\nexample\n>>>>>>> other\n"
            }
        )
        self.assertEqual(C.conflict_marker_failures(repo), [])

    def test_untracked_files_are_ignored(self):
        repo = self._repo({"a.py": "x = 1\n"})
        (repo / "scratch.md").write_text("<<<<<<< HEAD\n", encoding="utf-8")
        self.assertEqual(C.conflict_marker_failures(repo), [])

    def test_non_git_dir_fails_open(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        (Path(td.name) / "x.md").write_text("<<<<<<< HEAD\n", encoding="utf-8")
        self.assertEqual(C.conflict_marker_failures(Path(td.name)), [])

    def test_check_is_registered_first(self):
        """It should run early — a conflicted file makes other checks
        report confusing downstream noise."""
        self.assertEqual(C.CHECKS[0][0], "unresolved conflict markers")


if __name__ == "__main__":
    unittest.main()


class TestPhantomSkills(unittest.TestCase):
    """A doc row may not advertise a skill this repo does not carry.

    Two skills moved to the internal extension repo on 2026-09-01 and their
    README rows stayed behind. Nothing caught it: coverage_failures() only
    checks that every skill in the tree is mentioned, never the reverse.
    """

    def test_live_tree_has_no_phantom_rows(self):
        self.assertEqual(C.phantom_skill_failures(), [])

    def test_detects_a_row_naming_a_missing_skill(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "harnessing").mkdir()
            (repo / "README.md").write_text(
                "| Skill | Stage |\n|---|---|\n| `no-such-skill` | (1) |\n", encoding="utf-8"
            )
            out = C.phantom_skill_failures(repo)
            self.assertTrue(any("no-such-skill" in f for f in out), out)

    def test_external_marker_silences_it(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "harnessing").mkdir()
            (repo / "README.md").write_text(
                "| Skill | Stage |\n|---|---|\n"
                "| `no-such-skill` | (1) (internal extension repo) |\n",
                encoding="utf-8",
            )
            self.assertEqual(C.phantom_skill_failures(repo), [])

    def test_ignores_non_skill_tables(self):
        """Repository maps and tier tables also have backticked first cells."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "harnessing").mkdir()
            (repo / "README.md").write_text(
                "| Repository | Role |\n|---|---|\n| `analysis-results` | outputs |\n",
                encoding="utf-8",
            )
            self.assertEqual(C.phantom_skill_failures(repo), [])


class TestDocsIndexCoverage(unittest.TestCase):
    """Every docs/ page must be reachable from the README: listed there, or
    in the docs/README.md index that the README links."""

    def _repo(self, td, readme, index=None, pages=("guide.md",)):
        repo = Path(td)
        (repo / "harnessing").mkdir()
        (repo / "docs").mkdir()
        for page in pages:
            (repo / "docs" / page).write_text("# page\n", encoding="utf-8")
        (repo / "README.md").write_text(readme, encoding="utf-8")
        if index is not None:
            (repo / "docs" / "README.md").write_text(index, encoding="utf-8")
        return repo

    @staticmethod
    def _doc_failures(repo):
        return [f for f in C.coverage_failures(repo) if "doc '" in f or "docs index" in f]

    def test_page_listed_only_in_linked_index_passes(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(td, "See [docs](docs/README.md).\n", index="- [guide](guide.md)\n")
            self.assertEqual(self._doc_failures(repo), [])

    def test_index_not_linked_from_readme_fails(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(td, "No docs link here.\n", index="- [guide](guide.md)\n")
            out = self._doc_failures(repo)
            self.assertTrue(any("docs index" in f for f in out), out)

    def test_page_in_neither_fails(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(
                td,
                "See [docs](docs/README.md).\n",
                index="- [other](other.md)\n",
                pages=("guide.md", "other.md"),
            )
            out = self._doc_failures(repo)
            self.assertTrue(any("doc 'guide.md' is not mentioned" in f for f in out), out)

    def test_readme_listing_still_suffices_without_index(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(td, "- [guide](docs/guide.md)\n")
            self.assertEqual(self._doc_failures(repo), [])


class TestSingleRulePack(unittest.TestCase):
    """Rule packs live only in the security pack; no other copy or stale pointer here."""

    def test_live_tree_has_no_rule_pack_copy(self):
        self.assertEqual(C.rule_pack_copy_failures(), [])

    def test_a_rule_pack_directory_fails(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "harnessing" / "3-audit" / "secure-code-audit" / "opengrep-rules").mkdir(
                parents=True
            )
            out = C.rule_pack_copy_failures(repo)
            self.assertTrue(any("rule-pack copy" in f for f in out), out)

    def test_a_pointer_to_the_old_copy_fails(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "guide.md").write_text(
                "See harnessing/3-audit/secure-code-audit/gitleaks-rules/x.toml\n", encoding="utf-8"
            )
            out = C.rule_pack_copy_failures(repo)
            self.assertTrue(any("removed rule-pack copy" in f for f in out), out)

    def test_changelog_history_is_exempt(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "CHANGELOG.md").write_text(
                "moved harnessing/3-audit/secure-code-audit/opengrep-rules\n", encoding="utf-8"
            )
            self.assertEqual(C.rule_pack_copy_failures(repo), [])


class TestModelClassRoot(unittest.TestCase):
    def test_model_class_failures_uses_selected_repo_skill_tree(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            skill = repo / "harnessing" / "3-audit" / "campaign-fixture-skill"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: campaign-fixture-skill\ndescription: Fixture skill.\n---\n",
                encoding="utf-8",
            )
            docs = repo / "docs"
            docs.mkdir()
            usage = docs / "campaign-workflow.md"
            index = docs / "model-classes.md"
            usage.write_text("| `campaign-fixture-skill` | sonnet-class |\n", encoding="utf-8")
            index.write_text("### `sonnet-class`\n\n`campaign-fixture-skill`\n", encoding="utf-8")

            self.assertEqual(C.model_class_failures(repo), [])

            usage.write_text("| `triage` | sonnet-class |\n", encoding="utf-8")
            index.write_text("### `sonnet-class`\n\n`triage`\n", encoding="utf-8")
            self.assertTrue(any("triage" in failure for failure in C.model_class_failures(repo)))


@pytest.fixture
def estate_repo(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "docs").mkdir()
    text = (
        "endpoint: http://10.23.45.67\n"
        "service: estate-fixture.invalid\n"
        "public: public-fixture.invalid\n"
    )
    (tmp_path / "config" / "model-registry.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "docs" / "guide.md").write_text(text, encoding="utf-8")
    return tmp_path


def test_configured_vocabulary_keeps_universal_and_deployment_rules(estate_repo, monkeypatch):
    vocabulary = estate_repo / "vocabulary.yaml"
    vocabulary.write_text(
        "rules:\n"
        "  - {id: estate-fixture, tier: review, pattern: 'estate-fixture\\.invalid'}\n"
        "  - {id: public-fixture, tier: note, pattern: 'public-fixture\\.invalid'}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HARNESS_INTERNAL_VOCABULARY", str(vocabulary))
    for check in (C.config_hygiene_failures, C.docs_estate_marker_failures):
        failures = check(estate_repo)
        assert len(failures) == 2
        assert any("rfc1918" in failure for failure in failures)
        assert any("estate-fixture" in failure for failure in failures)


@pytest.mark.parametrize(
    "content",
    [
        b"rules: [",
        b"",
        b"false",
        b"[]",
        b"rules: []",
        b"rules:\n  - {id: fixture, tier: block, pattern: '['}\n",
        b"rules:\n  - {id: fixture, tier: nope, pattern: fixture}\n",
        b"rules:\n  - {id: [], tier: block, pattern: fixture}\n",
        b"rules:\n  - {id: fixture, tier: block, pattern: 42}\n",
        b"rules:\n  - {id: fixture, tier: block, pattern: fixture, why: [invalid]}\n",
        b"\xff",
    ],
)
def test_malformed_configured_vocabulary_fails_and_retains_universal_rules(
    estate_repo, monkeypatch, content
):
    vocabulary = estate_repo / "vocabulary.yaml"
    vocabulary.write_bytes(content)
    monkeypatch.setenv("HARNESS_INTERNAL_VOCABULARY", str(vocabulary))
    for check in (C.config_hygiene_failures, C.docs_estate_marker_failures):
        failures = check(estate_repo)
        assert len(failures) == 2
        assert any(str(vocabulary) in failure for failure in failures)
        assert any("rfc1918" in failure for failure in failures)


def test_vocabulary_directory_is_invalid_configured_data(estate_repo, monkeypatch):
    vocabulary = estate_repo / "vocabulary.yaml"
    vocabulary.mkdir()
    monkeypatch.setenv("HARNESS_INTERNAL_VOCABULARY", str(vocabulary))
    for check in (C.config_hygiene_failures, C.docs_estate_marker_failures):
        failures = check(estate_repo)
        assert len(failures) == 2
        assert any(str(vocabulary) in failure for failure in failures)
        assert any("rfc1918" in failure for failure in failures)


@pytest.mark.parametrize("missing_path", [False, True])
def test_absent_vocabulary_is_the_unconfigured_case(estate_repo, monkeypatch, missing_path):
    if missing_path:
        monkeypatch.setenv("HARNESS_INTERNAL_VOCABULARY", str(estate_repo / "absent.yaml"))
    else:
        monkeypatch.delenv("HARNESS_INTERNAL_VOCABULARY", raising=False)
    assert C.config_hygiene_failures(estate_repo) == []
    assert C.docs_estate_marker_failures(estate_repo) == []
    (estate_repo / "config" / "deployment.yaml").write_text("private: true\n", encoding="utf-8")
    failures = C.config_hygiene_failures(estate_repo)
    assert len(failures) == 1
    assert "config/deployment.yaml" in failures[0]


def test_grouped_docs_gate_refuses_malformed_vocabulary_without_other_issues(
    estate_repo, monkeypatch
):
    from traust.cli.groups import GROUPS

    (estate_repo / "config" / "model-registry.yaml").write_text("models: {}\n", encoding="utf-8")
    (estate_repo / "docs" / "guide.md").write_text("# Portable guide\n", encoding="utf-8")
    (estate_repo / "PROCESS.md").write_text(
        "\n".join(f"## Stage {stage}" for stage in range(1, C.CANONICAL_STAGE_COUNT + 1)),
        encoding="utf-8",
    )
    (estate_repo / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    (estate_repo / "docs" / "cli-reference.md").write_text(
        "# CLI Command Reference\n\n"
        "| Group | Description | Operations |\n"
        "|---|---|---|\n"
        + "\n".join(
            f"| `{group}` | CLI group | {', '.join(f'`{op}`' for op in sorted(ops))} |"
            for group, ops in GROUPS.items()
        )
        + "\n",
        encoding="utf-8",
    )
    vocabulary = estate_repo / "vocabulary.yaml"
    monkeypatch.setenv("HARNESS_INTERNAL_VOCABULARY", str(vocabulary))
    argv = ["check", "docs-consistency", "--root", str(estate_repo)]
    assert cli_main(argv) == 0
    vocabulary.write_text("rules: [", encoding="utf-8")
    assert cli_main(argv) == 1
    vocabulary.write_text(
        "rules:\n  - {id: estate-fixture, tier: block, pattern: 'estate-fixture\\.invalid'}\n",
        encoding="utf-8",
    )
    assert cli_main(argv) == 0
