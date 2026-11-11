"""Harness repo layout — skill enumeration and schema paths.

Config-owned runtime locations (workspace, analysis-results, inputs) resolve
through :mod:`traust.context` after ``load()`` at entry
points. This module holds harness-checkout layout only (harnessing/, schemas).
"""

from __future__ import annotations

import os
from pathlib import Path

from traust_core.v1.context import config_path, optional_config_path, schema_dir, schema_path
from traust_core.v1.errors import DeploymentConfigMissing

_PKG_ROOT = Path(__file__).resolve().parent
# A wheel install (the runtime image) has no checkout around the package: the image copies the
# harness payload elsewhere and names it in HARNESS_ROOT.
HARNESS_ROOT = Path(os.environ.get("HARNESS_ROOT") or _PKG_ROOT.parents[1])
SRC_DIR = HARNESS_ROOT / "src"
CLI_DIR = _PKG_ROOT / "cli"
HARNESSING_DIR = HARNESS_ROOT / "harnessing"
SECURITY_PACK_DIR = HARNESS_ROOT / "packs" / "security"
#: The pack's opengrep rules and gitleaks config: the defaults when traust.yaml names none.
OPENGREP_RULES_DIR = SECURITY_PACK_DIR / "detection" / "opengrep-rules"
GITLEAKS_CONFIG = SECURITY_PACK_DIR / "detection" / "gitleaks-rules" / "gitleaks-default.toml"
#: The repo's ``config/`` holds SOURCE only — shipped defaults + ``*.example.*``
#: templates + README, never read at runtime. All runtime config (including where
#: the harness reads/writes data) resolves from the one config home via
#: :func:`traust.context.load`.

__all__ = [
    "DeploymentConfigMissing",
    "config_path",
    "optional_config_path",
    "schema_path",
]

#: The file that makes a directory a skill (Agent Skills spec).
SKILL_MD = "SKILL.md"


def skill_dirs(repo: Path | None = None) -> list[Path]:
    """Every skill directory under ``harnessing/``, sorted by skill name.

    A skill is any directory holding a ``SKILL.md``. Today all 58 sit one
    level below ``harnessing/``; the skill-usability reorganization
    (progress-tracker/plans/skill-usability-reorganization-plan.md 1.2)
    nests the 34 workflow skills one level deeper under a stage directory
    — ``harnessing/4-triage/triage/`` — while the other 24 stay at the
    root. So this walks two levels and takes whichever one carries the
    ``SKILL.md``, and the move costs this function nothing.

    Enumerate through here instead of globbing ``harnessing/*/SKILL.md``:
    ten call sites baked that depth in, which is the whole reason the move
    looked expensive. The walk stops at a skill boundary, so a ``SKILL.md``
    *inside* a skill — a cloned target repo, a template — is never counted
    as a skill of its own.

    ``repo`` is a harness checkout root, so a gate can pass its own and
    resolve against a test fixture tree; it defaults to this checkout.
    Order is by ``name``, not by path: names are unique (rule A6), so it is
    a total order, and gate output does not reshuffle when the stage
    directories land.
    """
    root = (repo / "harnessing") if repo is not None else HARNESSING_DIR
    if not root.is_dir():
        return []
    found: list[Path] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if (child / SKILL_MD).is_file():
            found.append(child)
            continue
        found.extend(
            nested
            for nested in sorted(child.iterdir())
            if nested.is_dir() and (nested / SKILL_MD).is_file()
        )
    return sorted(found, key=lambda p: p.name)


def skill_dir(name: str, repo: Path | None = None) -> Path:
    """The directory of the skill called ``name``, whichever depth it sits at.

    Look a skill up through here rather than building ``harnessing/<name>``
    from parts. A composed path cannot be caught by a string sweep and, once
    a skill nests under its stage directory, silently resolves to somewhere
    that does not exist — a runtime ``FileNotFoundError`` in a script rather
    than a lint failure. This raises :class:`KeyError` at the lookup instead,
    naming the skill that is missing.
    """
    for d in skill_dirs(repo):
        if d.name == name:
            return d
    raise KeyError(f"no skill named {name!r} under harnessing/")


def skill_md_paths(repo: Path | None = None) -> list[Path]:
    """Every ``SKILL.md``, in :func:`skill_dirs` order."""
    return [d / SKILL_MD for d in skill_dirs(repo)]


def skill_scripts(repo: Path | None = None, pattern: str = "*.py") -> list[Path]:
    """Skill-local ``scripts/`` files, by skill name then filename."""
    return [script for d in skill_dirs(repo) for script in sorted((d / "scripts").glob(pattern))]


def schemas_dir() -> Path:
    return schema_dir()


SCHEMA_DIR = schemas_dir()
