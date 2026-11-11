"""P1 regression tests — public-release-blocker fixes from
progress-tracker/plans/harness-security-remediation-plan.md."""

import importlib
import importlib.util
import sys
from pathlib import Path

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_symbol_index_skips_file_symlinks(tmp_path):
    """B5: symlinked files must not be read out of the checkout."""
    bsi = _load("build_symbol_index_p1", "src/traust/cli/build_symbol_index.py")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("def real_fn():\n    pass\n")
    secret = tmp_path / "outside.py"
    secret.write_text("def leaked_secret_fn():\n    pass\n")
    (repo / "evil.py").symlink_to(secret)
    names = [n for n, *_ in bsi.extract_builtin(repo)]
    assert "real_fn" in names
    assert "leaked_secret_fn" not in names


def test_symbol_index_cache_is_per_user(tmp_path, monkeypatch):
    """B4: no shared predictable /tmp cache."""
    bsi = _load("build_symbol_index_p1", "src/traust/cli/build_symbol_index.py")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    out = bsi.default_index_path(tmp_path, "abc1234")
    assert str(out).startswith(str(tmp_path / "xdg"))
    assert (tmp_path / "xdg" / "symbol-index").stat().st_mode & 0o777 == 0o700


def test_no_raw_egress_grants_in_portable_skills():
    """D7: raw curl / gh api grants removed."""
    for skill in ("impact-analysis", "threat-model"):
        text = (skill_dir(skill) / "SKILL.md").read_text()
        assert "Bash(curl:*)" not in text, skill
        assert "Bash(gh api:*)" not in text, skill


def test_flagship_has_allowlist_and_core_skills_have_doctrine():
    """D3 + D4."""
    sca = (skill_dir("secure-code-audit") / "SKILL.md").read_text()
    assert "allowed-tools:" in sca.split("---")[1]
    for skill in ("vuln-scan", "verify-remediation", "threat-model", "security-audit-phased"):
        text = (skill_dir(skill) / "SKILL.md").read_text()
        assert "adversarial-content-doctrine.md" in text, skill


def test_lockfile_exists_and_is_hashed():
    """E1: docs point at a hash-locked install."""
    lock = (_ROOT / "requirements.lock").read_text()
    assert lock.count("--hash=sha256:") > 100
    for doc in ("docs/setup.md", "docs/getting-started.md"):
        assert "--require-hashes -r requirements.lock" in (_ROOT / doc).read_text(), doc


def test_containerfile_base_cannot_float():
    """E5: no FROM in the Containerfile may resolve to a movable ref.

    A base pulled by tag can silently change under an already-published
    artifact. Two ways to satisfy that: pin the base by digest, or have no
    base at all (``FROM scratch`` — what this data-only image does). Either
    is fine; a bare or tagged image reference is not.
    """
    cf = (_ROOT / "Containerfile").read_text()
    stages, bases = set(), []
    for line in cf.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].upper() != "FROM":
            continue
        bases.append(parts[1])
        if len(parts) >= 4 and parts[2].upper() == "AS":
            stages.add(parts[3])

    assert bases, "Containerfile declares no FROM"
    for base in bases:
        if base in stages:
            continue  # reference to an earlier stage in this file, not a pull
        assert "@sha256:" in base or base == "scratch", (
            f"unpinned base image {base!r} — pin it by digest or use scratch"
        )


def test_precommit_hook_never_writes_home():
    """E8: the hook may hint, never link."""
    hook = (_ROOT / ".githooks/pre-commit").read_text()
    assert "ln -s" not in hook
    assert "link_skills.sh" in hook
