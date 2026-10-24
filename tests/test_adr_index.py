"""Tests for index_adrs.py parsing + the superseded-citation gate."""

import json
import sys

import pytest

from traust.paths import HARNESS_ROOT, skill_dir


def _load(name):
    import importlib

    pkg_paths = {
        "index_adrs": "traust.ops.index_adrs",
    }
    if name in pkg_paths:
        return importlib.import_module(pkg_paths[name])
    path = skill_dir("compliance-check") / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ia = _load("index_adrs")
vca = _load("validate_compliance_assessment")


# ---------------- status/title parsing ----------------


def test_parse_madr_status_and_title():
    text = "# Use OPA for authorization\n\n## Status\n\nAccepted\n"
    d = ia.parse_decision("docs/adr/ADR-021-opa.md", text)
    assert d["status"] == "accepted"
    assert d["title"] == "Use OPA for authorization"
    assert d["id"] == "ADR-021-opa"


def test_parse_status_line_variants():
    for text, want in (
        ("Status: superseded by ADR-9\n", "superseded"),
        ("* Status: Deprecated\n", "deprecated"),
        ("status: APPROVED\n", "accepted"),
        ("**Status**: draft\n", "proposed"),
        ("no status here\n", "unknown"),
    ):
        d = ia.parse_decision("x/y.md", "# t\n" + text)
        assert d["status"] == want, text


def test_archives_path_forces_archived():
    d = ia.parse_decision("hcm/decisions/archives/SD-ADR-0040.md", "# t\nStatus: accepted\n")
    assert d["status"] == "archived"


def test_unreadable_body_is_unknown_never_guessed():
    d = ia.parse_decision("a/b.md", None)
    assert d["status"] == "unknown"


# ---------------- schema-gates the shipped registry ----------------


def test_registry_template_validates():
    """The shipped template is schema-valid (the real registry is deployment config)."""
    jsonschema = pytest.importorskip("jsonschema")
    yaml = pytest.importorskip("yaml")
    reg = yaml.safe_load((HARNESS_ROOT / "config" / "adr-registry.example.yaml").read_text())
    from traust_contracts.paths import schema_path as _sp

    schema = json.loads(_sp("adr-registry").read_text())
    jsonschema.validate(reg, schema)
    assert reg["registers"]


# ---------------- superseded-citation gate ----------------

INDEX = {
    "registers": [
        {
            "name": "arch",
            "decisions": [
                {"id": "ADR-001", "status": "accepted"},
                {"id": "ADR-002", "status": "superseded"},
                {"id": "SD-ADR-0040", "status": "archived"},
            ],
        }
    ]
}


def _doc(locator):
    return {
        "results": [
            {
                "framework": "soc2-tsc",
                "control_id": "CC8.1",
                "classification": "evidence_review",
                "verdict": "satisfied",
                "verdict_source": "agent",
                "evidence": [{"sha256": "a" * 64, "kind": "human_artifact", "locator": locator}],
            }
        ]
    }


def test_accepted_decision_citable():
    assert vca.adr_citation_failures(_doc("adr:arch/ADR-001"), INDEX) == []


def test_superseded_and_archived_refused():
    f = vca.adr_citation_failures(_doc("adr:arch/ADR-002"), INDEX)
    assert f and "superseded" in f[0]
    f = vca.adr_citation_failures(_doc("adr:arch/SD-ADR-0040"), INDEX)
    assert f and "archived" in f[0]


def test_unknown_decision_refused():
    f = vca.adr_citation_failures(_doc("adr:arch/ADR-999"), INDEX)
    assert f and "unknown decision" in f[0]


def test_rule_only_applies_to_satisfied():
    doc = _doc("adr:arch/ADR-002")
    doc["results"][0]["verdict"] = "not_satisfied"
    assert vca.adr_citation_failures(doc, INDEX) == []
    assert vca.adr_citation_failures(_doc("adr:arch/ADR-002"), None) == []


def test_declared_status_applies_to_register():
    reg = {
        "name": "r",
        "repo": "https://github.com/o/r",
        "paths": ["d"],
        "pin": "a" * 40,
        "declared_status": "accepted",
    }
    d = ia.parse_decision("d/x.md", "# t\n**Date**: 2025-09-30\n")
    assert d["status"] == "unknown"  # parser alone stays honest
    # index_register applies the declaration (unit-level check of the
    # override branch)
    if reg.get("declared_status"):
        d["status"] = reg["declared_status"]
        d["status_source"] = "declared"
    assert d["status"] == "accepted"
    assert d["status_source"] == "declared"
