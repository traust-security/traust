"""Tests for traust.ops.build_crown_jewel_tiers (deep-fn plan Phase C).

Synthetic fixtures: a tiny portfolio-graph.db, findings.db, threat-register
JSON, and priv-profile files under a fake results root. Covers score
composition, missing-source degradation (no threat register → run proceeds
with a stated gap), tier sizing, and the DRAFT marker.
"""

from __future__ import annotations

import json
import math
import sqlite3
import unittest
from pathlib import Path

from traust.ops import build_crown_jewel_tiers as cjt


def make_graph_db(path: Path, repos, declares, depends):
    """repos: [(id, name)], declares: [(repo_id, module_id)],
    depends: [(repo_id, module_id)]."""
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                            label TEXT, attrs TEXT);
        CREATE TABLE edges (src TEXT NOT NULL, dst TEXT NOT NULL,
                            rel TEXT NOT NULL, attrs TEXT,
                            UNIQUE(src, dst, rel));
        """
    )
    mods = {m for _, m in declares} | {m for _, m in depends}
    for rid, name in repos:
        attrs = json.dumps({"name": name, "org": "acme", "url": f"https://github.com/acme/{name}"})
        con.execute("INSERT INTO nodes VALUES (?, 'repo', ?, ?)", (rid, f"acme/{name}", attrs))
    for m in mods:
        con.execute("INSERT INTO nodes VALUES (?, 'module', ?, '{}')", (m, m))
    for src, dst in declares:
        con.execute("INSERT INTO edges VALUES (?, ?, 'declares', '{}')", (src, dst))
    for src, dst in depends:
        con.execute("INSERT INTO edges VALUES (?, ?, 'depends_on', '{}')", (src, dst))
    con.commit()
    con.close()


def make_findings_db(path: Path, rows):
    """rows: [(repo_key, base_slug, ownership, severity, resolution,
    validity, is_branch_audit)]."""
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE repos (repo_key TEXT PRIMARY KEY, tree TEXT NOT NULL,
          ownership TEXT NOT NULL, business_unit TEXT NOT NULL,
          label TEXT NOT NULL, product TEXT, repo_dir TEXT NOT NULL,
          base_slug TEXT NOT NULL, ref TEXT, repo_url TEXT,
          is_branch_audit INTEGER NOT NULL, is_md_only INTEGER NOT NULL,
          preferred TEXT NOT NULL, report_kind TEXT NOT NULL,
          report_path TEXT, audit_date TEXT);
        CREATE TABLE findings (repo_key TEXT NOT NULL, finding_id TEXT NOT NULL,
          title TEXT, severity TEXT, primary_cwe TEXT, cwes TEXT,
          cvss_score REAL, cvss_vector TEXT, fingerprint TEXT, validity TEXT,
          resolution TEXT, assurance TEXT, validation_status TEXT,
          last_updated TEXT, paths TEXT, control_refs TEXT,
          PRIMARY KEY (repo_key, finding_id));
        """
    )
    seen = set()
    for i, (repo_key, slug, own, sev, res, val, branch) in enumerate(rows):
        if repo_key not in seen:
            seen.add(repo_key)
            con.execute(
                "INSERT INTO repos VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    repo_key,
                    "findings",
                    own,
                    "hp",
                    "eng",
                    None,
                    slug,
                    slug,
                    None,
                    None,
                    branch,
                    0,
                    "json",
                    "code-audit",
                    None,
                    None,
                ),
            )
        con.execute(
            "INSERT INTO findings (repo_key, finding_id, severity, validity,"
            " resolution) VALUES (?,?,?,?,?)",
            (repo_key, f"F-{i}", sev, val, res),
        )
    con.commit()
    con.close()


def make_register(path: Path, entries):
    """entries: [(repo_dir, impact, status)]."""
    threats = [
        {
            "key": f"p/{repo}:T{i}",
            "product": "p",
            "model": f"findings/p/{repo}/{repo}-threat-model.md",
            "id": f"T{i}",
            "impact": impact,
            "status": status,
        }
        for i, (repo, impact, status) in enumerate(entries, 1)
    ]
    path.write_text(json.dumps({"meta": {}, "threats": threats}))


def make_priv_profile(root: Path, slug: str, **kw):
    d = root / "findings" / slug
    d.mkdir(parents=True, exist_ok=True)
    profile = {
        "repo": slug,
        "workloads": [],
        "rbac_flags": kw.get("rbac_flags", {}),
        "scc_requests": kw.get("scc_requests", []),
        "sccs_shipped": kw.get("sccs_shipped", []),
        "summary": {
            "privileged_or_host_workloads": kw.get("priv_workloads", 0),
            "cluster_scoped_rules": kw.get("cluster_rules", 0),
        },
    }
    (d / f"{slug}-priv-profile.json").write_text(json.dumps(profile))


class Fixture(unittest.TestCase):
    """Base: builds a 3-repo world.

    alpha: fan-in 2 (beta+gamma depend on its module), critical open
           threat, cluster-privileged profile (tier 3), 1 open crit +
           1 open high.
    beta:  fan-in 0, high open threat (plus one MITIGATED existential
           that must not count), elevated profile (tier 2), 1 open high,
           1 resolved crit (must not count), 1 branch-audit crit (must
           not count).
    gamma: fan-in 0, no threats, no profile, no findings → score 0,
           excluded from tiers.
    """

    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp(prefix="cjt-test-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "analysis-results"
        (self.root / "graph").mkdir(parents=True)
        self.out = self.tmp / "out"
        make_graph_db(
            self.root / "graph" / "portfolio-graph.db",
            repos=[
                ("repo:g/acme/alpha", "alpha"),
                ("repo:g/acme/beta", "beta"),
                ("repo:g/acme/gamma", "gamma"),
            ],
            declares=[("repo:g/acme/alpha", "module:acme/alpha-lib")],
            depends=[
                ("repo:g/acme/beta", "module:acme/alpha-lib"),
                ("repo:g/acme/gamma", "module:acme/alpha-lib"),
                ("repo:g/acme/alpha", "module:acme/alpha-lib"),
            ],  # self: no
        )
        make_findings_db(
            self.root / "graph" / "findings.db",
            rows=[
                ("findings/alpha/x", "alpha", "owned", "critical", "open", "confirmed", 0),
                ("findings/alpha/x", "alpha", "owned", "high", "open", "confirmed", 0),
                ("findings/beta/x", "beta", "owned", "high", "open", "confirmed", 0),
                ("findings/beta/x", "beta", "owned", "critical", "resolved", "confirmed", 0),
                ("findings/beta/br", "beta", "owned", "critical", "open", "confirmed", 1),
            ],
        )
        self.register = self.tmp / "threat-register.json"
        make_register(
            self.register,
            [
                ("alpha", "critical", "unmitigated"),
                ("beta", "high", "partially_mitigated"),
                ("beta", "existential", "mitigated"),  # closed: must not count
            ],
        )
        make_priv_profile(self.root, "alpha", priv_workloads=1)
        make_priv_profile(self.root, "beta", rbac_flags={"secrets_access": ["k"]})

    def run_script(self, *extra):
        rc = cjt.main(
            [
                "--results-root",
                str(self.root),
                "--out-dir",
                str(self.out),
                "--threat-register",
                str(self.register),
                *extra,
            ]
        )
        self.assertEqual(rc, 0)
        return json.loads((self.out / "crown-jewel-tiers.json").read_text())

    @staticmethod
    def row(payload, slug):
        for tier in payload["tiers"].values():
            for r in tier:
                if r["slug"] == slug:
                    return r
        return None


class TestScoreComposition(Fixture):
    def test_components_and_score(self):
        payload = self.run_script()
        alpha = self.row(payload, "alpha")
        self.assertIsNotNone(alpha)
        c = alpha["components"]
        # fan-in: 2 dependents (self-dep excluded), corpus max 2 → 1.0
        self.assertEqual(c["fanin"]["raw"], 2)
        self.assertAlmostEqual(c["fanin"]["normalized"], 1.0, places=4)
        # threat: 1 open critical → 4/5
        self.assertEqual(c["threat"]["open_threats"], 1)
        self.assertEqual(c["threat"]["max_open_impact"], "critical")
        self.assertAlmostEqual(c["threat"]["normalized"], 0.8, places=4)
        # priv: privileged workload → tier 3 → 1.0
        self.assertEqual(c["priv"]["tier"], 3)
        # findings: 1 crit + 1 high open at HEAD → load 3, corpus max 3 → 1.0
        self.assertEqual(c["findings"]["open_critical"], 1)
        self.assertEqual(c["findings"]["open_high"], 1)
        self.assertAlmostEqual(c["findings"]["normalized"], 1.0, places=4)
        expected = 100 * (0.35 * 1.0 + 0.25 * 0.8 + 0.20 * 1.0 + 0.20 * 1.0)
        self.assertAlmostEqual(alpha["score"], round(expected, 2), places=2)

    def test_closed_and_branch_rows_excluded(self):
        payload = self.run_script()
        beta = self.row(payload, "beta")
        c = beta["components"]
        # mitigated existential must not count → max open impact = high
        self.assertEqual(c["threat"]["max_open_impact"], "high")
        # resolved crit + branch-audit crit must not count
        self.assertEqual(c["findings"]["open_critical"], 0)
        self.assertEqual(c["findings"]["open_high"], 1)
        # beta load = 1; alpha corpus max = 3 → log2(2)/log2(4) = 0.5
        self.assertAlmostEqual(c["findings"]["normalized"], math.log2(2) / math.log2(4), places=4)
        self.assertEqual(c["priv"]["tier"], 2)
        # zero-score gamma excluded from all tiers
        self.assertIsNone(self.row(payload, "gamma"))
        self.assertEqual(payload["meta"]["scored_repos"], 2)


class TestMissingSourceDegradation(Fixture):
    def test_no_threat_register_proceeds_with_gap(self):
        rc = cjt.main(
            [
                "--results-root",
                str(self.root),
                "--out-dir",
                str(self.out),
                "--threat-register",
                str(self.tmp / "nope.json"),
            ]
        )
        self.assertEqual(rc, 0)  # never crash
        payload = json.loads((self.out / "crown-jewel-tiers.json").read_text())
        self.assertTrue(any("threat register not found" in g for g in payload["meta"]["gaps"]))
        self.assertNotIn("threat", payload["meta"]["weights_effective"])
        # remaining weights renormalized: .35+.20+.20 = .75
        self.assertAlmostEqual(sum(payload["meta"]["weights_effective"].values()), 1.0, places=3)
        alpha = self.row(payload, "alpha")
        self.assertNotIn("threat", alpha["components"])
        # gap also stated in the markdown
        md = (self.out / "crown-jewel-tiers.md").read_text()
        self.assertIn("Gaps (formula degraded)", md)

    def test_no_findings_db_proceeds_with_gap(self):
        (self.root / "graph" / "findings.db").unlink()
        payload = self.run_script()
        self.assertTrue(any("findings.db not found" in g for g in payload["meta"]["gaps"]))
        self.assertNotIn("findings", payload["meta"]["weights_effective"])

    def test_missing_graph_db_is_fatal(self):
        (self.root / "graph" / "portfolio-graph.db").unlink()
        rc = cjt.main(
            [
                "--results-root",
                str(self.root),
                "--out-dir",
                str(self.out),
                "--threat-register",
                str(self.register),
            ]
        )
        self.assertEqual(rc, 1)  # no universe → no ranking


class TestTierSizing(Fixture):
    def test_tier1_size_flag(self):
        payload = self.run_script("--tier1-size", "1")
        self.assertEqual(len(payload["tiers"]["tier1"]), 1)
        self.assertEqual(payload["tiers"]["tier1"][0]["slug"], "alpha")
        self.assertEqual(len(payload["tiers"]["tier2"]), 1)  # beta
        self.assertEqual(payload["tiers"]["tier2"][0]["slug"], "beta")
        self.assertEqual(payload["tiers"]["watch"], [])

    def test_default_tier1_is_20(self):
        payload = self.run_script()
        self.assertEqual(payload["meta"]["tier_sizing"]["tier1"], 20)
        # only 2 scored repos → both land in tier1
        self.assertEqual(len(payload["tiers"]["tier1"]), 2)


class TestDraftMarker(Fixture):
    def test_marker_in_json_and_md(self):
        payload = self.run_script()
        self.assertEqual(payload["meta"]["status"], cjt.DRAFT_MARKER)
        self.assertIn("unsigned", cjt.DRAFT_MARKER)
        md = (self.out / "crown-jewel-tiers.md").read_text()
        self.assertGreaterEqual(md.count(cjt.DRAFT_MARKER), 2)  # top and bottom


if __name__ == "__main__":
    unittest.main()
