#!/usr/bin/env python3
"""Tests for the PQC wiring across skills:
decision-tree artifact, probe catalogue, chain vocabulary, validator."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_schema(name):
    from traust.paths import schema_path as _sp

    return json.loads(_sp(name).read_text(encoding="utf-8"))


class TestDecisionTree(unittest.TestCase):
    def _load(self, rel):
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def _write_validator(self):
        import jsonschema
        from referencing import Registry, Resource

        tree = _load_schema("pqc-decision-tree")
        report = _load_schema("report")
        resources = [(schema["$id"], Resource.from_contents(schema)) for schema in (tree, report)]
        return jsonschema.Draft202012Validator(
            {"$ref": tree["$id"] + "#/definitions/canonical_write"},
            registry=Registry().with_resources(resources),
        )

    def test_tree_validates_against_schema(self):
        tree = self._load(
            "harnessing/3-audit/pqc-readiness/notes/reference/pqc-readiness-decision-tree.json"
        )
        self._write_validator().validate(tree)

    def test_external_blocking_is_not_a_new_effort_size(self):
        import jsonschema

        tree = self._load(
            "harnessing/3-audit/pqc-readiness/notes/reference/pqc-readiness-decision-tree.json"
        )
        tree["remediation_effort"]["rules"][0]["effort"] = "blocked-external"
        with self.assertRaises(jsonschema.ValidationError):
            self._write_validator().validate(tree)

    def test_crosswalk_covers_every_provenance_class(self):
        tree = self._load(
            "harnessing/3-audit/pqc-readiness/notes/reference/pqc-readiness-decision-tree.json"
        )
        xwalk = tree["tls_control_crosswalk"]
        covered = set()
        for k, v in xwalk.items():
            if not k.startswith("_"):
                covered.update(v)
        # every provenance class except not-assessable maps to a TLS control
        self.assertEqual(
            covered,
            {
                "inherited-platform",
                "inherited-constrained",
                "delegated-dependency",
                "native-first-party",
                "vendored",
                "externalized",
            },
        )

    def test_classification_map_values_match_report_schema(self):
        tree = self._load(
            "harnessing/3-audit/pqc-readiness/notes/reference/pqc-readiness-decision-tree.json"
        )
        report = _load_schema("report")
        allowed = set(report["$defs"]["finding"]["properties"]["pqc_classification"]["enum"])
        vals = {v for k, v in tree["pqc_classification_map"].items() if not k.startswith("_")}
        self.assertTrue(vals <= allowed, vals - allowed)


class TestProbeCatalogue(unittest.TestCase):
    def test_pqc_probes_present_and_safe(self):
        import novel

        pqc = {k: v for k, v in novel.PROBE_CATALOGUE.items() if any(p.get("pqc") for p in v)}
        self.assertEqual(
            {k[1] for k in pqc},
            {"pqc-tls-negotiation", "pqc-cert-algorithm", "pqc-crypto-policy", "pqc-backend-tls"},
        )
        for entries in pqc.values():
            for p in entries:
                self.assertEqual(p["classification"], "safe")
                self.assertEqual(p["mitre"], [])

    def test_all_catalogue_mitre_refs_valid_against_pinned_table(self):
        import attack_refs
        import novel

        ids = sorted(
            {
                t
                for entries in novel.PROBE_CATALOGUE.values()
                for p in entries
                for t in p.get("mitre", [])
            }
        )
        self.assertEqual(attack_refs.validate_ids(ids), [])

    def test_pqc_recon_steps_emitted(self):
        import novel

        class _CS:
            namespaces = ["*"]

        class _Scope:
            clusters = {"__current__": _CS()}
            containers = ["myapp"]
            container_runtimes = ["podman"]
            wasm_artifacts = []

        steps = novel.recon_steps(_Scope())
        pqc = [s for s in steps if s.target.get("pqc")]
        self.assertGreaterEqual(len(pqc), 4)
        self.assertTrue(all(s.classification == "safe" for s in pqc))


class TestPqcCaps(unittest.TestCase):
    def test_caps_mapping(self):
        import chain

        self.assertIn(
            "tls-hybrid-ke",
            chain.pqc_caps_from_probe(
                "TLS 1.3 group negotiation", "Negotiated TLS1.3 group: X25519MLKEM768"
            ),
        )
        self.assertIn(
            "tls-classical-ke-only",
            chain.pqc_caps_from_probe(
                "TLS 1.3 group negotiation", "Negotiated TLS1.3 group: X25519"
            ),
        )
        self.assertIn(
            "backend-tls-classical",
            chain.pqc_caps_from_probe(
                "Downstream backend hop TLS posture", "Negotiated TLS1.3 group: secp256r1"
            ),
        )
        self.assertIn(
            "crypto-policy-legacy", chain.pqc_caps_from_probe("crypto-policy", "LEGACY\n0")
        )
        self.assertEqual(chain.pqc_caps_from_probe("x", ""), set())

    def test_pqc_caps_never_in_attack_maps(self):
        import chain

        self.assertFalse(set(chain.PQC_CAPS) & set(chain.MITRE_MAP))
        self.assertFalse(set(chain.PQC_CAPS) & set(chain.CAP_IMPLIES))
