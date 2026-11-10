"""The skill's Bash grants must name exact script paths.

Two holes this pins shut:

* `Bash(python3 *…/script.py:*)` also matched `python3 -c '<code>' …/script.py`
  because the `*` absorbed the interpreter options.
* `Bash(bash *ensure_fork.sh:*)` matched any same-named script, including one
  planted in a target checkout. Agents only call `prepare_backport_fork.sh`,
  which invokes ensure_fork itself, so that grant must not exist.
"""
from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
SKILL = REPO / "harnessing" / "7-remediate" / "backport-fix" / "SKILL.md"
SCRIPTS_PREFIX = "harnessing/7-remediate/backport-fix/scripts/"


def _grants() -> list[str]:
    text = SKILL.read_text()
    frontmatter = text.split("---", 2)[1]
    doc = yaml.safe_load(frontmatter)
    return [g for g in (doc.get("allowed-tools") or []) if g.startswith("Bash(")]


def test_no_wildcard_between_interpreter_and_script():
    for grant in _grants():
        assert not re.match(r"Bash\((bash|python3) \*", grant), grant


def test_no_filename_wildcard_script_grant():
    for grant in _grants():
        assert not re.search(r"\*[^)]*\.(sh|py)", grant), grant


def test_ensure_fork_is_not_granted():
    # It runs inside prepare_backport_fork.sh; granting it by name would match
    # a planted same-named script anywhere.
    assert not any("ensure_fork" in g for g in _grants())


def test_script_grants_are_exact_paths():
    for grant in _grants():
        inner = grant[len("Bash("):-1]
        if not inner.startswith(("bash ", "python3 ")):
            continue
        if inner.startswith("python3 -m traust.cli reporting validate"):
            continue
        assert inner.startswith("bash " + SCRIPTS_PREFIX) or inner.startswith(
            "python3 " + SCRIPTS_PREFIX
        ), grant


def test_rg_is_not_granted():
    # `rg --pre <cmd>` executes arbitrary programs; Grep is already granted.
    assert not any(g.startswith("Bash(rg") for g in _grants())


def test_no_command_executing_rg_options_in_any_grant():
    for grant in _grants():
        assert "--pre" not in grant and "--search-zip" not in grant, grant
