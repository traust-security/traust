"""Exercise local and image Opengrep installation with real SHA-256 checks."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "install-toolchain.sh"
RELEASE_METADATA = REPO / "scripts" / "opengrep-release.sh"
CONTAINERFILE = REPO / "Containerfile.tools"
ASSETS = [
    ("Linux", "x86_64", "opengrep_manylinux_x86"),
    ("Linux", "aarch64", "opengrep_manylinux_aarch64"),
    ("Darwin", "arm64", "opengrep_osx_arm64"),
    ("Darwin", "x86_64", "opengrep_osx_x86"),
]
# A tampered copy still reports the pinned version. Version checks cannot prove integrity.
PAYLOAD = b"#!/bin/sh\nprintf 'invoked\\n' >> \"$INSTALLER_TEST_EXECUTED\"\nprintf '1.25.0\\n'\n"


def _executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def _installer(
    tmp_path: Path,
    platform=ASSETS[0],
    *,
    pin="1.25.0",
    corrupt=False,
    review_fixture=True,
):
    system, arch, _asset = platform
    script = tmp_path / "scripts" / SCRIPT.name
    script.parent.mkdir()
    shutil.copyfile(SCRIPT, script)
    metadata = RELEASE_METADATA.read_text()
    if review_fixture:
        # Only the disposable metadata approves our fixture; production digests
        # and both actual installation programs remain unchanged.
        selected = subprocess.run(
            [
                "sh",
                "-c",
                '. "$1"; opengrep_release 1.25.0 "$2" "$3"',
                "metadata",
                str(RELEASE_METADATA),
                "darwin" if system == "Darwin" else "linux",
                "arm64" if arch in ("arm64", "aarch64") else "amd64",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        _name, official_digest = selected.stdout.split()
        metadata = metadata.replace(official_digest, hashlib.sha256(PAYLOAD).hexdigest())
    (script.parent / RELEASE_METADATA.name).write_text(metadata)
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
    for command in ("chmod", "install"):
        executable = shutil.which(command)
        assert executable is not None
        _executable(
            tools / command,
            '#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$INSTALLER_TEST_PERMISSIONS"\n'
            f'exec {shlex.quote(executable)} "$@"\n',
        )
    if shutil.which("sha256sum") is None:
        # macOS supplies shasum, with the same check/status interface. Hashing
        # remains real, rather than a fake digest success response.
        _executable(tools / "sha256sum", '#!/bin/sh\nexec shasum -a 256 "$@"\n')
    asset = tmp_path / "download"
    asset.write_bytes(PAYLOAD + b"# tampered\n" if corrupt else PAYLOAD)
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
        "INSTALLER_TEST_EXECUTED": str(tmp_path / "executed"),
        "INSTALLER_TEST_PERMISSIONS": str(tmp_path / "permissions"),
        "TMPDIR": str(tmp_path / "temporary"),
    }
    Path(env["TMPDIR"]).mkdir()
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
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "permissions").exists()
    assert not list(Path(env["TMPDIR"]).iterdir())


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


def test_official_metadata_rejects_a_version_reporting_test_binary(tmp_path: Path) -> None:
    script, env = _installer(tmp_path, review_fixture=False)
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert not (tmp_path / "installed" / "opengrep").exists()
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "permissions").exists()


@pytest.mark.parametrize(("system", "arch"), [("FreeBSD", "x86_64"), ("Linux", "s390x")])
def test_unsupported_platform_cannot_download(tmp_path: Path, system: str, arch: str) -> None:
    script, env = _installer(tmp_path)
    env.update(INSTALLER_TEST_OS=system, INSTALLER_TEST_ARCH=arch)
    result = _run(script, env, "--tool", "opengrep")
    assert result.returncode != 0
    assert "Unsupported" in result.stdout
    assert not (tmp_path / "downloads").exists()


def _image_installer(
    tmp_path: Path,
    platform=ASSETS[0],
    *,
    pin="1.25.0",
    target_arch=None,
    corrupt=False,
    review_fixture=True,
):
    """Stage the builder's real COPY and execute its real Opengrep RUN without OCI."""
    _script, env = _installer(tmp_path, platform, corrupt=corrupt, review_fixture=review_fixture)
    root = tmp_path / "image"
    (root / "out" / "bin").mkdir(parents=True)
    stage = ""
    commands = []
    copied_paths = []
    for line in CONTAINERFILE.read_text().replace("\\\n", "").splitlines():
        instruction, _, body = line.strip().partition(" ")
        if instruction == "FROM":
            stage = body.rsplit(" AS ", 1)[-1]
        elif stage == "tools-builder" and instruction == "COPY":
            source, destination = shlex.split(body)
            target = root / destination.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tmp_path / source, target)
            copied_paths.append((destination, str(target)))
        elif (
            stage == "tools-builder"
            and instruction == "RUN"
            and "github.com/opengrep/opengrep/releases/download/" in body
        ):
            commands.append(body)
    assert len(commands) == 1, "execute exactly the image's Opengrep installation step"
    command = commands[0]
    for destination, target in copied_paths:
        command = command.replace(destination, shlex.quote(target))
    command = command.replace("/out/bin", shlex.quote(str(root / "out" / "bin")))
    script = tmp_path / "image-install.sh"
    script.write_text(command + "\n")
    env.update(
        OPENGREP_VERSION=pin,
        TARGETARCH=target_arch or ("arm64" if platform[1] == "aarch64" else "amd64"),
    )
    return script, env


@pytest.mark.parametrize("platform", ASSETS[:2], ids=[row[2] for row in ASSETS[:2]])
def test_image_installs_and_executes_only_verified_platform_asset(tmp_path: Path, platform) -> None:
    script, env = _image_installer(tmp_path, platform)
    result = _run(script, env)
    assert result.returncode == 0, result.stdout + result.stderr
    installed = tmp_path / "image" / "out" / "bin" / "opengrep"
    assert installed.read_bytes() == PAYLOAD
    assert installed.stat().st_mode & 0o777 == 0o755
    assert (tmp_path / "executed").read_text().splitlines() == ["invoked"]
    assert (tmp_path / "permissions").exists()
    assert (tmp_path / "downloads").read_text().splitlines() == [
        f"https://github.com/opengrep/opengrep/releases/download/v1.25.0/{platform[2]}"
    ]
    assert not list(Path(env["TMPDIR"]).iterdir())


@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "previous-binary"])
def test_image_tampering_fails_before_chmod_execution_or_replacement(
    tmp_path: Path, existing: bool
) -> None:
    script, env = _image_installer(tmp_path, corrupt=True)
    installed = tmp_path / "image" / "out" / "bin" / "opengrep"
    original = b"#!/bin/sh\nexit 99\n"
    if existing:
        _executable(installed, original.decode())
    result = _run(script, env)
    assert result.returncode != 0
    if existing:
        assert installed.read_bytes() == original
    else:
        assert not installed.exists()
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "permissions").exists()
    assert not list(Path(env["TMPDIR"]).iterdir())


@pytest.mark.parametrize(("pin", "target_arch"), [("99.0.0", "amd64"), ("1.25.0", "s390x")])
def test_image_unreviewed_release_cannot_download(
    tmp_path: Path, pin: str, target_arch: str
) -> None:
    script, env = _image_installer(tmp_path, pin=pin, target_arch=target_arch)
    result = _run(script, env)
    assert result.returncode != 0
    assert "no verified opengrep asset" in result.stderr
    assert not (tmp_path / "downloads").exists()
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "permissions").exists()


def test_image_consumes_official_metadata_not_just_a_version_check(tmp_path: Path) -> None:
    script, env = _image_installer(tmp_path, review_fixture=False)
    result = _run(script, env)
    assert result.returncode != 0
    assert not (tmp_path / "image" / "out" / "bin" / "opengrep").exists()
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "permissions").exists()
