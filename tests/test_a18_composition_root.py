"""A18 — engine and config-home resolution happen only in the composition root.

`src/traust/context.py` calls `HarnessEngine.load()` once and turns
`DeploymentConfigMissing` into a one-line `SystemExit(2)`. 93 modules call
`load_engine()` and 96 call `add_config_home_arg()`, so every lane inherits the same
config precedence (CLI flag > AUDIT_RESULTS_ROOT > `locations.yaml`) and the same
fail-loud exit, pinned by `tests/test_context.py`. A second caller re-resolves config
on its own terms and the guarantee stops being one.

The invariant was declared in the module docstring from the start and held across all
93 sites by discipline alone — no gate checked it. This rule lands with **zero**
violations, so, exactly as with A16, these tests are the only thing between it and
quiet uselessness: a rule that cannot fail proves nothing.

The false positive that would have sunk it, tested below: 8 modules import
`HarnessEngine` purely to annotate a parameter. Banning the import flags all 8 and the
rule gets waived in a week, so A18 matches the CALL and leaves annotations alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from traust.cli.check_skill_alignment import a18_composition_root_failures

REPO = Path(__file__).resolve().parent.parent


def _run(tmp_repo: Path) -> list[str]:
    return a18_composition_root_failures(tmp_repo)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src" / "traust" / "cli").mkdir(parents=True)
    return tmp_path


def _write(repo: Path, name: str, body: str) -> None:
    (repo / "src" / "traust" / "cli" / name).write_text(body, "utf-8")


def test_the_real_tree_is_clean():
    """The ratchet must start green, or it will be waived on day one."""
    assert a18_composition_root_failures(REPO) == []


def test_catches_a_second_engine_resolution(repo):
    """The 94th call site — the whole reason this rule exists."""
    _write(
        repo,
        "bad1.py",
        ("from traust_engine import HarnessEngine\ndef bad():\n    return HarnessEngine.load()\n"),
    )
    out = _run(repo)
    assert len(out) == 1
    assert "outside the composition root" in out[0]


def test_catches_direct_construction_skipping_load(repo):
    """`HarnessEngine(...)` never reaches the DeploymentConfigMissing handler."""
    _write(
        repo,
        "bad2.py",
        ("from traust_engine import HarnessEngine\ndef bad(ctx):\n    return HarnessEngine(ctx)\n"),
    )
    assert len(_run(repo)) == 1


def test_catches_direct_config_home_resolution(repo):
    _write(
        repo,
        "bad3.py",
        (
            "from traust_contracts.config import deployment_config_dir\n"
            "def bad():\n"
            "    return deployment_config_dir() / 'corpus-config.yaml'\n"
        ),
    )
    out = _run(repo)
    assert len(out) == 1
    assert "resolves the config home directly" in out[0]


def test_allows_the_composition_root_itself(repo):
    """context.py is the one place both calls belong."""
    (repo / "src" / "traust" / "context.py").write_text(
        "from traust_contracts.config import deployment_config_dir\n"
        "from traust_engine import HarnessEngine\n"
        "def load_engine(config_home=None):\n"
        "    return HarnessEngine.load(config_home=config_home)\n"
        "def home():\n"
        "    return deployment_config_dir()\n",
        "utf-8",
    )
    assert _run(repo) == []


def test_allows_config_home_in_paths_the_sanctioned_resolver(repo):
    """`traust.paths` owns config-path resolution (config/README.md)."""
    (repo / "src" / "traust" / "paths.py").write_text(
        "from traust_contracts.config import deployment_config_dir\n"
        "def config_path(name):\n"
        "    return deployment_config_dir() / name\n",
        "utf-8",
    )
    assert _run(repo) == []


def test_ignores_an_annotation_only_import(repo):
    """The false positive that would get the rule waived — 8 real modules do this."""
    _write(
        repo,
        "ok1.py",
        (
            "from traust_engine import HarnessEngine\n"
            "from traust.context import load_engine\n"
            "def ok(engine: HarnessEngine) -> None:\n"
            "    pass\n"
            "def also_ok() -> HarnessEngine:\n"
            "    engine: HarnessEngine = load_engine()\n"
            "    return engine\n"
        ),
    )
    assert _run(repo) == []


def test_ignores_an_isinstance_check(repo):
    _write(
        repo,
        "ok2.py",
        (
            "from traust_engine import HarnessEngine\n"
            "def ok(x):\n"
            "    return isinstance(x, HarnessEngine)\n"
        ),
    )
    assert _run(repo) == []


def test_ignores_a_reexport_without_a_call(repo):
    """paths.py's real shape: an import and an `__all__` entry, neither a call."""
    _write(
        repo,
        "ok3.py",
        (
            "from traust_contracts.config import (\n"
            "    deployment_config_dir,\n"
            ")\n"
            '__all__ = ["deployment_config_dir"]\n'
        ),
    )
    assert _run(repo) == []


def test_ignores_commented_out_code(repo):
    _write(
        repo,
        "ok4.py",
        ("def ok():\n    # return HarnessEngine.load()\n    pass\n"),
    )
    assert _run(repo) == []


def test_ignores_tests(repo):
    d = repo / "src" / "traust" / "cli" / "tests"
    d.mkdir()
    (d / "test_thing.py").write_text(
        "from traust_engine import HarnessEngine\ndef t():\n    return HarnessEngine.load()\n",
        "utf-8",
    )
    assert _run(repo) == []


def test_covers_the_harnessing_tree_too(repo):
    """Skill-co-located scripts are the likelier place for a stray resolution."""
    d = repo / "harnessing" / "3-audit" / "vuln-scan" / "scripts"
    d.mkdir(parents=True)
    (d / "stray.py").write_text(
        "from traust_engine import HarnessEngine\ndef bad():\n    return HarnessEngine.load()\n",
        "utf-8",
    )
    assert len(_run(repo)) == 1
