"""Fixture calibration gate for every registry check (Phase 2a).

Admission rule (FP hard requirement 4): a deterministic check exists
only with known-bad + known-good fixtures it passes — not_satisfied on
bad/, satisfied on good/. This test IS that gate for the whole registry:
a check added without fixtures, or with fixtures it fails, breaks CI.
"""

import importlib.util
import json
import sys

import pytest

from traust.paths import skill_dir

yaml = pytest.importorskip("yaml")

from tests.compliance_paths import compliance_fixtures_dir, compliance_registry, org_parameters

_SPEC = importlib.util.spec_from_file_location(
    "compliance_assert", skill_dir("compliance-check") / "scripts" / "compliance_assert.py"
)
ca = importlib.util.module_from_spec(_SPEC)
sys.modules["compliance_assert"] = ca
_SPEC.loader.exec_module(ca)


def _registry():
    return yaml.safe_load(compliance_registry().read_text())


def _org_params():
    return yaml.safe_load(org_parameters().read_text())


def _checks():
    return _registry()["checks"]


@pytest.mark.parametrize(
    "check", _checks(), ids=lambda c: c["id"] if isinstance(c, dict) else str(c)
)
def test_check_calibrates_on_its_fixtures(check):
    fdir = compliance_fixtures_dir() / check.get("fixtures", f"fixtures/{check['id']}/")
    bad = fdir / "bad" / "snapshot.json"
    good = fdir / "good" / "snapshot.json"
    assert bad.is_file() and good.is_file(), (
        f"{check['id']}: fixtures missing at {fdir} — a check without "
        "known-bad/known-good fixtures is inadmissible"
    )
    params = _org_params()
    res_bad = ca.evaluate_check(check, json.loads(bad.read_text()), params)
    res_good = ca.evaluate_check(check, json.loads(good.read_text()), params)
    assert res_bad["verdict"] == "not_satisfied", f"{check['id']}: silent on known-bad ({res_bad})"
    assert res_good["verdict"] == "satisfied", f"{check['id']}: fired on known-good ({res_good})"
    assert res_bad["evidence"], f"{check['id']}: no evidence on bad"


def test_every_deterministic_control_references_existing_checks():
    reg = _registry()
    check_ids = {c["id"] for c in reg["checks"]}
    for ctl in reg["controls"]:
        if ctl["classification"] == "deterministic":
            assert ctl.get("checks"), (
                f"{ctl['framework']}:{ctl['control_id']} deterministic without checks"
            )
            for cid in ctl["checks"]:
                assert cid in check_ids, f"{ctl['control_id']} references unknown {cid}"
