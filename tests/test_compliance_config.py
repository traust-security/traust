"""The compliance policy data and config templates are schema-valid (moved from
test_compliance_phase1.py and test_adr_index.py when their scripts went to traust-core)."""

import json

import pytest

from tests.compliance_paths import compliance_registry, org_parameters, org_parameters_template
from traust.paths import HARNESS_ROOT

jsonschema = pytest.importorskip("jsonschema")
yaml = pytest.importorskip("yaml")


def _schema(name):
    from traust.paths import schema_path as _sp

    return json.loads(_sp(name.removesuffix(".schema.json")).read_text())


def test_seed_registry_validates():
    reg = yaml.safe_load(compliance_registry().read_text())
    jsonschema.validate(reg, _schema("compliance-mapping.schema.json"))
    check_ids = {c["id"] for c in reg["checks"]}
    for ctl in reg["controls"]:
        for cid in ctl.get("checks") or []:
            assert cid in check_ids, f"{ctl['control_id']} references unknown check {cid}"


@pytest.mark.parametrize("which", ["suite", "template"])
def test_seed_org_parameters_validate_and_cover_registry_refs(which):
    path = org_parameters() if which == "suite" else org_parameters_template()
    params = yaml.safe_load(path.read_text())
    jsonschema.validate(params, _schema("org-parameters.schema.json"))
    reg = yaml.safe_load(compliance_registry().read_text())
    declared = set(params["parameters"])
    for chk in reg["checks"]:
        exp = (chk.get("assertion") or {}).get("expected")
        if isinstance(exp, str) and exp.startswith("param:"):
            assert exp[6:] in declared, f"{chk['id']} needs {exp}"


def test_registry_template_validates():
    """The shipped template is schema-valid (the real registry is deployment config)."""
    reg = yaml.safe_load(
        (HARNESS_ROOT / "docs" / "examples" / "adr-registry.example.yaml").read_text()
    )
    jsonschema.validate(reg, _schema("adr-registry"))
    assert reg["registers"]
