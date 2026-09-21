"""scanner_differential.py — stage 8's one executable claim.

Fixtures are real `adapters opengrep` output (2026-09-16) over a two-revision
Python fixture: `subprocess.run("echo " + user_input, shell=True)` before,
`subprocess.run(["echo", user_input])` after. The rule
`traust-python-injection-subprocess-shell` fires on the first and not the
second.

Captured output carries the capture machine's absolute paths, and this repo is
public. `rules[].config_paths` and `target` in both fixtures were rewritten to
neutral `/tmp/scanner-diff/...` paths; nothing here reads either field, so the
rewrite costs the tests nothing. If you re-capture, rewrite them again.

The third verdict is the one worth protecting: if the rule never fired on the
unpatched revision there is nothing to observe, and crediting the patch for a
clean scan would manufacture evidence out of a rule-pack change.
"""

import importlib.util
import json
import sys
from pathlib import Path

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "scanner_differential",
    skill_dir("verify-remediation") / "scripts" / "scanner_differential.py",
)
sd = importlib.util.module_from_spec(_SPEC)
sys.modules["scanner_differential"] = sd
_SPEC.loader.exec_module(sd)

FIX = Path(__file__).parent / "fixtures" / "scanner-diff"
BASE = FIX / "opengrep-base.json"
PATCHED = FIX / "opengrep-patched.json"
RULE = "traust-python-injection-subprocess-shell"


def _item(base, patched, rule_id=RULE, file=None):
    return sd.build_item(
        tool="opengrep", rule_id=rule_id, file=file,
        base_facts=sd.load_facts(base) if base else None,
        patched_facts=sd.load_facts(patched) if patched else None,
        base_ref="fa4b872", base_report=str(base), patched_report=str(patched),
    )


def test_real_fixture_has_the_expected_shape():
    """Guards the fixtures themselves: a silent rule-pack change must not
    quietly turn these tests into tautologies."""
    base = sd.load_facts(BASE)
    assert base and base[0]["rule_id"] == RULE
    assert sd.load_facts(PATCHED) == []


def test_fact_cleared_proves():
    item = _item(BASE, PATCHED)
    assert item["outcome"] == "proves"
    assert "does not establish the fix is correct" in item["patched_observation"]


def test_fact_still_firing_fails_to_prove():
    item = _item(BASE, BASE)
    assert item["outcome"] == "fails_to_prove"
    assert "has not cleared its own backing evidence" in item["patched_observation"]


def test_no_backing_fact_on_base_is_not_attempted():
    """Never credit a patch for a rule that never fired."""
    item = _item(PATCHED, PATCHED)
    assert item["outcome"].startswith("not_attempted:")
    assert "does not fire on the unpatched revision" in item["outcome"]
    assert "base_observation" not in item


def test_unreadable_scan_is_not_attempted():
    assert _item(None, PATCHED)["outcome"].startswith("not_attempted:")
    assert _item(BASE, None)["outcome"].startswith("not_attempted:")


def test_selector_ignores_line_numbers():
    """A patch moves lines; matching on them would call everything cleared."""
    base = sd.load_facts(BASE)
    moved = [dict(base[0], start_line=base[0]["start_line"] + 40)]
    item = sd.build_item(
        tool="opengrep", rule_id=RULE, file=None, base_facts=base,
        patched_facts=moved, base_ref="r", base_report="b", patched_report="p",
    )
    assert item["outcome"] == "fails_to_prove"


def test_file_selector_alone_works():
    item = _item(BASE, PATCHED, rule_id=None, file="app.py")
    assert item["outcome"] == "proves"


def test_a_proof_claim_carries_both_observations():
    item = _item(BASE, PATCHED)
    assert item["base_observation"] and item["patched_observation"]


def test_unrelated_rule_selector_finds_no_baseline():
    item = _item(BASE, PATCHED, rule_id="some-other-rule")
    assert item["outcome"].startswith("not_attempted:")
