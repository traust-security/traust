from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml
from traust_core.v1.context import TRAUST_CONFIG_HOME_DEFAULT, Config, resolve_config_home

# Capture the operator config home before the suite replaces TRAUST_CONFIG_HOME.
_OPERATOR_CONFIG_HOME = resolve_config_home()
if _OPERATOR_CONFIG_HOME is not None:
    os.environ["TRAUST_OPERATOR_CONFIG_HOME"] = str(_OPERATOR_CONFIG_HOME)

# The suite must never run against an operator's full config home (corpus-config,
# feeds, etc.). Build a private home from fixtures and isolated temp data trees.
# progress_tracker is borrowed from the operator traust.yaml's locations when set — same
# path production uses, so compliance tests exercise the real loader contract.
# HARNESS_TEST_FIXTURE_CONFIG=1 so live smokes skip when no sibling checkout.
_TEST_HOME = Path(tempfile.mkdtemp(prefix="traust-app-test-cfg-"))
shutil.copytree(Path(__file__).parent / "fixtures" / "config", _TEST_HOME, dirs_exist_ok=True)
_ISO = Path(tempfile.mkdtemp(prefix="traust-app-test-data-"))
(_ISO / "ws").mkdir(parents=True, exist_ok=True)
(_ISO / "progress-tracker").mkdir(parents=True, exist_ok=True)


def _progress_tracker_from_operator_config() -> Path | None:
    if _OPERATOR_CONFIG_HOME is None:
        return None
    locs = Config.from_home(_OPERATOR_CONFIG_HOME).locations
    if not locs.progress_tracker:
        return None
    return Path(locs.progress_tracker)


def _resolve_progress_tracker() -> Path:
    configured = _progress_tracker_from_operator_config()
    if configured is not None:
        return configured
    return (_ISO / "progress-tracker").resolve()


(_TEST_HOME / "traust.yaml").write_text(
    yaml.safe_dump(
        {
            "locations": {
                "workspace": str(_ISO / "ws"),
                "analysis_results": str(_ISO / "analysis-results"),
                "progress_tracker": str(_resolve_progress_tracker()),
            }
        }
    ),
    encoding="utf-8",
)
os.environ["TRAUST_CONFIG_HOME"] = str(_TEST_HOME)
os.environ["HARNESS_INTERNAL_VOCABULARY"] = str(
    Path(__file__).parent / "fixtures" / "public-export" / "internal-vocabulary.yaml"
)
os.environ["HARNESS_TEST_FIXTURE_CONFIG"] = "1"

# Isolated HOME: core's default store (~/.traust) and anything else keyed on
# HOME never touches the developer's home directory.
_HOME = _TEST_HOME / "home"
_HOME.mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = str(_HOME)
_XDG_CONFIG = _HOME / ".config"
_XDG_CONFIG.mkdir()
os.environ["XDG_CONFIG_HOME"] = str(_XDG_CONFIG)

assert _TEST_HOME.resolve() != TRAUST_CONFIG_HOME_DEFAULT.resolve(), (
    "test suite must not inherit ~/.traust/config"
)

from traust.paths import skill_dir

# Tier 0: traust-core (contracts and ledger through it).

# Resolved by skill NAME, not by a hardcoded depth: a workflow skill sits at
# harnessing/<N>-<stage>/<skill>/ and the rest at harnessing/<skill>/, and
# skill_dir() spans both. Still an explicit list rather than every skill --
# these go on sys.path and skills share module basenames (plan.py,
# coverage.py), so widening it would change which module an import resolves
# to. Entries are (skill,) or (skill, "scripts").
_SKILL_SCRIPT_ENTRIES = [
    ("track-findings",),
    ("track-findings", "scripts"),
    ("verify-remediation", "scripts"),
    ("secure-code-audit", "scripts"),
    ("refresh-dashboards", "scripts"),
    ("census", "scripts"),
    ("compliance-check", "scripts"),
    ("mine-ledger", "scripts"),
    ("impact-analysis", "scripts"),
    ("triage", "scripts"),
    ("portfolio-graph", "scripts"),
    ("dependency-watch",),
    ("dependency-watch", "scripts"),
    ("pqc-readiness",),
    ("pqc-readiness", "scripts"),
    ("attack-coverage", "scripts"),
    ("fleet-fix", "scripts"),
    ("findings-trends", "scripts"),
    ("executive-summary-findings", "scripts"),
    ("validate-browser-finding", "scripts"),
    ("threat-register",),
    ("threat-register", "scripts"),
    ("vuln-scan", "scripts"),
    ("validate-findings",),
]

SKILL_SCRIPT_DIRS = [skill_dir(skill).joinpath(*rest) for skill, *rest in _SKILL_SCRIPT_ENTRIES]

for path in SKILL_SCRIPT_DIRS:
    entry = str(path)
    if entry not in sys.path:
        sys.path.insert(0, entry)


def _can_git_init():
    """Probe whether git init works in a temp directory."""
    probe = None
    try:
        probe = tempfile.mkdtemp(prefix="_git_probe_")
        subprocess.run(
            ["git", "init", "-q", probe],
            capture_output=True,
            timeout=10,
            check=True,
        )
        return True
    except Exception:
        return False
    finally:
        if probe:
            shutil.rmtree(probe, ignore_errors=True)


CAN_GIT_INIT = _can_git_init()


@pytest.fixture(autouse=True)
def _skip_if_no_git(request):
    if request.node.get_closest_marker("requires_git") and not CAN_GIT_INIT:
        pytest.skip("git init blocked in this environment")
