"""`traust remediation property-evidence`: the CLI layer only. Arguments become one call to
core's verdict rules; the item is printed as JSON. The rules themselves are traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from typing import Any

import pytest

from traust.cli import remediation


def run(*argv: str) -> tuple[int, Any]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = remediation.property_evidence_(list(argv))
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else None


@pytest.mark.parametrize(
    ("base_rc", "patched_rc", "outcome"),
    [(1, 0, "proves"), (1, 1, "fails_to_prove"), (0, 0, "fails_to_prove"), (2, 0, "not_attempted")],
)
def test_two_exit_codes_become_one_item(base_rc: int, patched_rc: int, outcome: str) -> None:
    rc, item = run(
        *("--test-path", "tests/test_clean_property.py", "--base-ref", "fa4b872"),
        *("--base-rc", str(base_rc), "--patched-rc", str(patched_rc)),
        *("--tool-version", "hypothesis 6.168.0", "--boundary", "podman"),
        *("--base-log", "/out/property-base.log", "--patched-log", "/out/property-patched.log"),
    )
    assert rc == 0
    assert item["kind"] == "property" and item["outcome"].startswith(outcome)


def test_exit_codes_are_required() -> None:
    with pytest.raises(SystemExit):
        run("--test-path", "t.py", "--base-ref", "r", "--base-rc", "1")
