"""Pinned Opengrep installation: official asset selection and fail-closed integrity."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "install-toolchain.sh"
# Official v1.25.0 release-asset digest metadata:
# https://api.github.com/repos/opengrep/opengrep/releases/tags/v1.25.0
ASSETS = [
    (
        "Linux",
        "x86_64",
        "opengrep_manylinux_x86",
        "9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33",
    ),
    (
        "Linux",
        "aarch64",
        "opengrep_manylinux_aarch64",
        "fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6",
    ),
    (
        "Darwin",
        "arm64",
        "opengrep_osx_arm64",
        "3543fcabae9db2ae5bc974a3b75426353f0a3e369181b2157ef27f46867996c8",
    ),
    (
        "Darwin",
        "x86_64",
        "opengrep_osx_x86",
        "fa2487b75527be1cc9ae4f9b0cb09a340454e7973c76785568285cbbcd977cb4",
    ),
]
PAYLOAD = b"#!/bin/sh\nprintf 'opengrep fixture\\n'\n"


def _executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def _installer(tmp_path: Path, platform=ASSETS[0], *, pin="1.25.0", corrupt=False):
    system, arch, _asset, official_digest = platform
    script = tmp_path / "scripts" / SCRIPT.name
    script.parent.mkdir()
    # Substitute only the fixture's expected digest in a disposable installer
    # copy. Its real SHA-256 computation still verifies the downloaded bytes.
    source = SCRIPT.read_text()
    assert source.count(official_digest) == 1
    script.write_text(source.replace(official_digest, hashlib.sha256(PAYLOAD).hexdigest()))
    pins = tmp_path / "external-tools.yaml"
    pins.write_text(
        f'tools:\n  - name: opengrep\n    expected: "{pin}"\n'
        '  - name: gitleaks\n    expected: "8.30.1"\n'
    )
    _executable(
        tmp_path / ".venv" / "bin" / "python",
        '#!/bin/sh\nprintf "%s\\n" "$INSTALLER_TEST_PINS"\n',
    )
    tools = tmp_path / "tools"
    _executable(
        tools / "uname",
        '#!/bin/sh\ncase "$1" in -s) echo "$INSTALLER_TEST_OS";; '
        '-m) echo "$INSTALLER_TEST_ARCH";; esac\n',
    )
    _executable(
        tools / "curl",
        '#!/bin/sh\nset -eu\ndest=""\nurl=""\nwhile [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) dest="$2"; shift;; https://*) url="$1";; esac\n'
        '  shift\ndone\nprintf "%s\\n" "$url" >> "$INSTALLER_TEST_DOWNLOADS"\n'
        'cp "$INSTALLER_TEST_ASSET" "$dest"\n',
    )
    asset = tmp_path / "download"
    asset.write_bytes(b"corrupt download" if corrupt else PAYLOAD)
    env = {
        **os.environ,
        "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "HARNESS_BIN_DIR": str(tmp_path / "installed"),
        "INSTALLER_TEST_PINS": str(pins),
        "INSTALLER_TEST_OS": system,
        "INSTALLER_TEST_ARCH": arch,
        "INSTALLER_TEST_ASSET": str(asset),
        "INSTALLER_TEST_DOWNLOADS": str(tmp_path / "downloads"),
    }
    return script, env


def _run(script: Path, env: dict[str, str], *args: str):
    return subprocess.run(
        ["bash", str(script), *args], capture_output=True, text=True, env=env, check=False
    )


@pytest.mark.parametrize("platform", ASSETS, ids=[row[2] for row in ASSETS])
def test_installs_only_the_verified_pinned_platform_asset(tmp_path: Path, platform) -> None:
    script, env = _installer(tmp_path, platform)
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode == 0, result.stdout + result.stderr
    installed = tmp_path / "installed" / "opengrep"
    assert installed.read_bytes() == PAYLOAD
    assert installed.stat().st_mode & 0o111 == 0o111
    assert (tmp_path / "downloads").read_text().splitlines() == [
        f"https://github.com/opengrep/opengrep/releases/download/v1.25.0/{platform[2]}"
    ]


def test_checksum_mismatch_never_replaces_an_existing_binary(tmp_path: Path) -> None:
    script, env = _installer(tmp_path, corrupt=True)
    installed = tmp_path / "installed" / "opengrep"
    _executable(installed, "#!/bin/sh\nexit 99\n")
    original = installed.read_bytes()
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert installed.read_bytes() == original


def test_only_an_already_verified_binary_can_skip_download(tmp_path: Path) -> None:
    script, env = _installer(tmp_path)
    installed = tmp_path / "installed" / "opengrep"
    installed.parent.mkdir()
    _executable(installed, PAYLOAD.decode())
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "already installed and checksum verified" in result.stdout
    assert not (tmp_path / "downloads").exists()


def test_unrecorded_version_cannot_download_without_a_reviewed_digest(tmp_path: Path) -> None:
    script, env = _installer(tmp_path, pin="99.0.0")
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode != 0
    assert "no verified opengrep asset for v99.0.0" in result.stderr
    assert not (tmp_path / "downloads").exists()


@pytest.mark.parametrize(
    "args",
    [("--tool",), ("--tool", "unknown"), ("--tool", "opengrep", "vuln-scan")],
)
def test_invalid_or_ambiguous_tool_selection_never_downloads(tmp_path: Path, args) -> None:
    script, env = _installer(tmp_path)
    result = _run(script, env, *args)
    assert result.returncode != 0
    assert not (tmp_path / "downloads").exists()


def test_single_tool_dry_run_never_downloads(tmp_path: Path) -> None:
    script, env = _installer(tmp_path)
    result = _run(script, env, "--tool", "opengrep", "--dry-run")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "would install opengrep v1.25.0" in result.stdout
    assert not (tmp_path / "downloads").exists()


def test_existing_profile_selection_keeps_its_tool_set(tmp_path: Path) -> None:
    script, env = _installer(tmp_path)
    result = _run(script, env, "vuln-scan", "--dry-run")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Tools: opengrep gitleaks" in result.stdout
    assert not (tmp_path / "downloads").exists()
