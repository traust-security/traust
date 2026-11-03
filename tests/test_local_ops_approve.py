"""`ops-approve`'s selector door: a crafted order selector must be refused
before any order is touched, and the make recipe must not interpolate the
selector into the command text (regression for the crafted-selector finding)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "local_ops.sh"


@pytest.mark.parametrize(
    "selector",
    [
        "'; touch /tmp/qodo-pwned; #",
        'x"; bash scripts/local_ops.sh approve; #',
        "$(touch /tmp/qodo-pwned)",
        "ORD-1; touch /tmp/qodo-pwned",
        "ORD *",
        "ORD;1",
    ],
)
def test_shell_breaking_selectors_are_refused_before_any_order_is_touched(
    selector: str,
) -> None:
    """Validation runs before the database is opened: no rig needed, and a
    refused selector must leave nothing behind."""
    r = subprocess.run(
        ["bash", str(SCRIPT), "approve", selector],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=dict(os.environ),
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "order selector must be an id prefix" in r.stderr
    assert not Path("/tmp/qodo-pwned").exists()


def test_the_make_recipe_passes_the_selector_through_the_environment() -> None:
    """The recipe must reference the shell variable, never the value: make
    expands $(ORDER) into the command text before the shell parses it, so an
    interpolated selector would be shell syntax, not an argument."""
    r = subprocess.run(
        ["make", "-n", "ops-approve", "ORDER='; touch /tmp/qodo-pwned #'"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=dict(os.environ),
    )
    assert r.returncode == 0, r.stderr
    assert '"$ORDER"' in r.stdout
    assert "touch /tmp/qodo-pwned" not in r.stdout
