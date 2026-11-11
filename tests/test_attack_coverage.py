#!/usr/bin/env python3
"""Tests for the vendored ATT&CK tables, read through traust-core's catalog."""

import unittest

import attack_refs


class TestAttackTables(unittest.TestCase):
    def test_pinned_tables_load_through_core(self):
        # core's loader gates the mapping schema, version agreement and referential integrity
        catalog = attack_refs.catalog()
        self.assertGreater(len(catalog.techniques), 500)
        self.assertIn("MITRE", catalog.attribution)
        self.assertEqual(catalog.techniques["T1611"].name, "Escape to Host")

    def test_validate_ids_rejects_bad_refs(self):
        self.assertEqual(attack_refs.validate_ids(["T1611"]), [])
        errs = attack_refs.validate_ids(["T9999", "not-an-id", "T1562"])
        self.assertEqual(len(errs), 3)
        self.assertIn("revoked", " ".join(errs))

    def test_capability_map_covers_chain_capabilities(self):
        cm = attack_refs.capability_map()
        for cap in (
            "pod-exec",
            "host-exec",
            "secret-read",
            "sa-token",
            "rbac-escalation",
            "cluster-admin",
            "etcd-access",
        ):
            self.assertIn(cap, cm)
            self.assertTrue(cm[cap])

    def test_category_map_covers_report_vocabulary(self):
        vocab = {
            "injection",
            "authentication",
            "authorization",
            "secrets-management",
            "supply-chain",
            "insecure-workload-config",
            "network-exposure",
            "cryptography",
            "input-validation",
            "path-traversal",
            "cross-site-scripting",
            "ssrf",
            "resource-management",
            "logging-monitoring",
            "data-exposure",
            "tenant-isolation",
        }
        self.assertEqual(set(attack_refs.category_map()), vocab)


if __name__ == "__main__":
    unittest.main()
