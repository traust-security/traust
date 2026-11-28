"""The backport-fix image installs traust from the same pins as traust's uv.lock."""

from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTAINER = ROOT / "harnessing" / "7-remediate" / "backport-fix" / "container"
LOCK = tomllib.loads((ROOT / "uv.lock").read_text())
PACKAGES = {p["name"]: p for p in LOCK["package"]}


def _requirements(name: str) -> dict[str, tuple[str, list[str]]]:
    out: dict[str, tuple[str, list[str]]] = {}
    text = (CONTAINER / name).read_text()
    for block in re.split(r"\n(?=\S)", text):
        m = re.match(r"([A-Za-z0-9_.-]+)==([^\s;\\]+)", block)
        if m:
            out[m.group(1).lower()] = (m.group(2), re.findall(r"--hash=sha256:[0-9a-f]{64}", block))
    return out


def test_the_traust_security_commits_are_the_uv_lock_revisions():
    containerfile = (CONTAINER / "Containerfile").read_text()
    for arg, package in (
        ("TRAUST_CORE_REF", "traust-core"),
        ("TRAUST_CONTRACTS_REF", "traust-contracts"),
        ("TRAUST_LEDGER_REF", "traust-ledger"),
    ):
        pinned = re.search(rf"^ARG {arg}=([0-9a-f]{{40}})$", containerfile, re.M)
        assert pinned, arg
        assert PACKAGES[package]["source"]["git"].endswith("#" + pinned.group(1)), package
    assert re.search(r"^ARG TRAUST_REF=[0-9a-f]{40}$", containerfile, re.M)


def test_every_registry_package_is_hash_pinned_at_its_uv_lock_version():
    reqs = _requirements("requirements-traust.txt")
    assert reqs
    for name, (version, hashes) in reqs.items():
        assert hashes, name
        assert PACKAGES[name]["version"] == version, name
    assert not {"traust", "traust-core", "traust-contracts", "traust-ledger"} & set(reqs)


def test_the_build_backends_are_hash_pinned():
    for name in ("requirements-build.txt", "requirements-editable.txt"):
        reqs = _requirements(name)
        assert reqs and all(hashes for _, hashes in reqs.values()), name


def test_the_amalgamator_layer_is_the_complete_hash_pinned_set():
    # Qodo #464: only the five top-level packages were pinned, without hashes
    reqs = _requirements("requirements-amalgamator.txt")
    assert all(hashes for _, hashes in reqs.values())
    top = {
        "pyyaml": "6.0.3",
        "colorama": "0.4.6",
        "claude-agent-sdk": "0.2.161",
        "litellm": "1.103.9",
        "anthropic": "1.13.0",
        "google-auth": None,
    }
    for name, version in top.items():
        assert name in reqs, name
        assert version is None or reqs[name][0] == version, name
    containerfile = (CONTAINER / "Containerfile").read_text()
    install = re.search(
        r"pip install --no-cache-dir --require-hashes --no-deps \\\s*"
        r"-r /tmp/requirements-amalgamator\.txt",
        containerfile,
    )
    assert install, "the Amalgamator layer must install the locked set with hashes, no deps"
    assert "claude-agent-sdk==" not in containerfile  # no unhashed top-level installs left
