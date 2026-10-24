#!/usr/bin/env python3
"""`check drift`'s agent-plugins rows.

config/external-tools.yaml describes a binary — a `version_cmd` to run and a
GitHub release to compare against. A Claude Code plugin has neither, so
adopting one would leave a dependency nothing watches; these rows close that.

Network is never touched here: `_marketplace_version` is stubbed, and its own
contract (clone, read .claude-plugin/marketplace.json, find the entry) is
exercised against a local git repo instead.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from traust.cli import check_drift as D

ROSTER = (
    "plugins:\n"
    "  - name: review-walkthrough\n"
    "    marketplace: trailofbits\n"
    "    repo: https://github.com/trailofbits/skills\n"
)


class AgentPluginRows(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.roster = self.tmp / "agent-plugins.yaml"
        self.roster.write_text(ROSTER)
        self.state = self.tmp / "installed_plugins.json"
        self._saved = (D.AGENT_PLUGINS_MANIFEST, D._PLUGIN_STATE, D._marketplace_version)
        D.AGENT_PLUGINS_MANIFEST = self.roster
        D._PLUGIN_STATE = self.state
        D._marketplace_version = lambda url, name: ("1.2.1", None)

    def tearDown(self):
        D.AGENT_PLUGINS_MANIFEST, D._PLUGIN_STATE, D._marketplace_version = self._saved
        self._tmp.cleanup()

    def _installed(self, version, sha="abc123def456789", when="2026-09-15T00:00:00Z"):
        self.state.write_text(
            json.dumps(
                {
                    "version": 2,
                    "plugins": {
                        "review-walkthrough@trailofbits": [
                            {"version": version, "gitCommitSha": sha, "lastUpdated": when}
                        ]
                    },
                }
            )
        )

    def _row(self):
        rows = D.check_agent_plugins(self.tmp)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_no_roster_is_silent(self):
        """An adopter using no plugins gets no rows, not an error."""
        D.AGENT_PLUGINS_MANIFEST = None
        self.assertEqual(D.check_agent_plugins(self.tmp), [])

    def test_empty_roster_is_silent(self):
        self.roster.write_text("plugins: []\n")
        self.assertEqual(D.check_agent_plugins(self.tmp), [])

    def test_declared_but_not_installed_is_pending(self):
        self.state.write_text(json.dumps({"version": 2, "plugins": {}}))
        row = self._row()
        self.assertEqual(row["status"], "pending")
        self.assertIn("/plugin install", row["refresh"])

    def test_matching_version_is_fresh(self):
        self._installed("1.2.1")
        row = self._row()
        self.assertEqual(row["status"], "fresh")
        self.assertIn("abc123def456", row["detail"])

    def test_behind_upstream_is_stale(self):
        self._installed("0.0.1")
        row = self._row()
        self.assertEqual(row["status"], "stale")
        self.assertIn("0.0.1", row["detail"])
        self.assertIn("1.2.1", row["detail"])
        # the row must send the reader back to the licence record: upstream can
        # change a skill's terms between versions, not just its behaviour
        self.assertIn("external-dependencies.md", row["refresh"])

    def test_newest_install_record_wins(self):
        """Multiple scopes can install the same plugin; take the latest."""
        self.state.write_text(
            json.dumps(
                {
                    "version": 2,
                    "plugins": {
                        "review-walkthrough@trailofbits": [
                            {"version": "0.0.1", "lastUpdated": "2026-01-01T00:00:00Z"},
                            {"version": "1.2.1", "lastUpdated": "2026-09-15T00:00:00Z"},
                        ]
                    },
                }
            )
        )
        self.assertEqual(self._row()["status"], "fresh")

    def test_non_https_repo_is_refused(self):
        self.roster.write_text(
            "plugins:\n  - name: x\n    marketplace: y\n    repo: git://evil/repo\n"
        )
        row = self._row()
        self.assertEqual(row["status"], "unavailable")
        self.assertIn("non-https", row["detail"])

    def test_unreadable_state_is_unavailable_not_fresh(self):
        """A headless runner has no plugin state; never report that as fresh."""
        D._PLUGIN_STATE = self.tmp / "absent.json"
        row = self._row()
        self.assertEqual(row["status"], "unavailable")

    def test_upstream_error_is_unavailable(self):
        D._marketplace_version = lambda url, name: (None, "cannot reach upstream")
        self._installed("1.2.1")
        self.assertEqual(self._row()["status"], "unavailable")

    def test_registered_in_CHECKS(self):
        self.assertIn(D.check_agent_plugins, D.CHECKS)


class MarketplaceLookup(unittest.TestCase):
    """The manifest half of the upstream lookup, with no git and no network."""

    def test_finds_the_named_plugin(self):
        doc = {"plugins": [{"name": "other", "version": "1"}, {"name": "demo", "version": "9.9.9"}]}
        self.assertEqual(D._plugin_version_from_manifest(doc, "demo", "u"), ("9.9.9", None))

    def test_absent_plugin_reports_why(self):
        version, err = D._plugin_version_from_manifest({"plugins": []}, "demo", "u")
        self.assertIsNone(version)
        self.assertIn("not listed", err)

    def test_manifest_without_plugins_key(self):
        version, err = D._plugin_version_from_manifest({}, "demo", "u")
        self.assertIsNone(version)
        self.assertIn("not listed", err)

    def test_non_https_transport_is_refused_by_the_fetcher(self):
        """Defence in depth: the caller gates on https, and so does the clone.

        `_marketplace_version` pins GIT_ALLOW_PROTOCOL=https, so a local path
        or file:// URL cannot be cloned even if it reached this far.
        """
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "mk"
            (repo / ".claude-plugin").mkdir(parents=True)
            (repo / ".claude-plugin" / "marketplace.json").write_text(
                json.dumps({"plugins": [{"name": "demo", "version": "9.9.9"}]})
            )
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "user.name=t",
                    "commit",
                    "-qm",
                    "x",
                ],
                check=True,
            )
            version, err = D._marketplace_version(str(repo), "demo")
            self.assertIsNone(version)
            self.assertIn("cannot clone", err)


if __name__ == "__main__":
    unittest.main()
