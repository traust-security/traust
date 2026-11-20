"""Execute the quality gate; optionally exercise the pinned OCI artifact helper.

OCI integration requires TRAUST_TEST_ARTIFACT_STORE (a writable test repository).
TRAUST_TEST_CONTAINER_RUNTIME defaults to podman; setting it explicitly also enables
container-only CA startup tests. Optional registry settings are
TRAUST_TEST_ARTIFACT_AUTHFILE and TRAUST_TEST_ARTIFACT_ORAS_OPTIONS; use a disposable
registry, since the tests push artifacts. No cluster or Git source access is used.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PIPELINES = ("traust-pull-request.yaml", "traust-push.yaml")
RULES = "packs/security/detection/opengrep-rules"
UV_COMMANDS = [
    ["sync", "--frozen"],
    ["run", "python", "-m", "traust.cli", "admin", "toolchain", "setup", "--tool", "opengrep"],
    ["run", "python", "-m", "traust.cli", "sweep", "check-rules", RULES],
]
SOURCE_URLS = (
    "https://github.com/example/public.git",
    "https://github.com/example/private.git",
    "git@github.com:example/private.git",
)


def _tasks(pipeline: str) -> dict[str, Any]:
    document = yaml.safe_load((REPO / ".tekton" / pipeline).read_text())
    return {task["name"]: task for task in document["spec"]["pipelineSpec"]["tasks"]}


def _source(path: Path, url: str = SOURCE_URLS[0]) -> None:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {url}\n')
    (path / "source-identity").write_text("exact resolved clone content\n")
    rules = path / RULES
    rules.mkdir(parents=True)
    (rules / "rule.yaml").write_text("artifact rule bytes\n")


def _quality_env(tmp_path: Path) -> dict[str, str]:
    """Replace only external setup/quality commands, not the gate script itself."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "stage = 'sync' if args[0] == 'sync' else ('install' if 'setup' in args else 'quality')\n"
        "record = {'args': args, 'cwd': str(Path.cwd()),\n"
        "          'identity': Path('source-identity').read_text(),\n"
        "          'rule': Path('packs/security/detection/opengrep-rules/rule.yaml').read_text(),\n"
        "          'origin': Path('.git/config').read_text()}\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as stream:\n"
        "    stream.write(json.dumps(record) + '\\n')\n"
        "if stage == os.environ.get('FAIL_STAGE'):\n"
        "    sys.exit({'sync': 31, 'install': 32, 'quality': 33}[stage])\n"
    )
    uv.chmod(0o755)
    git = bin_dir / "git"
    git.write_text("#!/bin/sh\necho 'unexpected source Git access' >&2\nexit 97\n")
    git.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    return {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "COMMAND_LOG": str(tmp_path / "commands.jsonl"),
        # A caller requesting optional image checks be skipped must not skip this gate.
        "SKIP_CHECKS": "true",
        "FAIL_STAGE": "",
    }


def _run_quality(
    task: dict[str, Any], workdir: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    step = next(step for step in task["taskSpec"]["steps"] if step["name"] == "check-rules")
    source = workdir / Path(step["workingDir"]).relative_to("/var/workdir")
    return subprocess.run(
        ["bash", "-c", step["script"]],
        cwd=source,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


@pytest.mark.parametrize("pipeline", PIPELINES)
@pytest.mark.parametrize(
    ("failure", "code", "completed"),
    [("", 0, 3), ("sync", 31, 1), ("install", 32, 2), ("quality", 33, 3)],
)
def test_quality_executes_from_source_and_propagates_failures(
    tmp_path: Path, pipeline: str, failure: str, code: int, completed: int
) -> None:
    workdir = tmp_path / "workdir"
    _source(workdir / "source", SOURCE_URLS[2])
    env = _quality_env(tmp_path)
    env["FAIL_STAGE"] = failure
    result = _run_quality(_tasks(pipeline)["opengrep-quality"], workdir, env)
    assert result.returncode == code, result.stdout + result.stderr
    records = [json.loads(line) for line in Path(env["COMMAND_LOG"]).read_text().splitlines()]
    assert [record["args"] for record in records] == UV_COMMANDS[:completed]
    assert all(record["cwd"] == str((workdir / "source").resolve()) for record in records)
    assert all(record["identity"] == "exact resolved clone content\n" for record in records)
    assert all(record["rule"] == "artifact rule bytes\n" for record in records)
    assert all(SOURCE_URLS[2] in record["origin"] for record in records)


def _artifact_command(
    workdir: Path,
    image: str,
    *args: str,
    retry_max_tries: int | None = None,
    restore_step: dict[str, Any] | None = None,
    trusted_ca: Path | None = None,
    entrypoint: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Use the pinned upstream container, registry client and archive code."""
    runtime = shlex.split(os.environ.get("TRAUST_TEST_CONTAINER_RUNTIME", "podman"))
    command = [
        *runtime,
        "run",
        "--rm",
        "--network=host",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--env",
        "HOME=/tmp",
        "--volume",
        f"{workdir}:/var/workdir:Z",
    ]
    if retry_max_tries is not None:
        command += ["--env", f"RETRY_MAX_TRIES={retry_max_tries}"]
    authfile = os.environ.get("TRAUST_TEST_ARTIFACT_AUTHFILE")
    if authfile:
        command += [
            "--volume",
            f"{Path(authfile).resolve()}:/artifact-auth.json:ro,Z",
            "--env",
            "AUTHFILE=/artifact-auth.json",
        ]
    oras_options = os.environ.get("TRAUST_TEST_ARTIFACT_ORAS_OPTIONS")
    if oras_options:
        command += ["--env", f"ORAS_OPTIONS={oras_options}"]
    if restore_step is not None:
        for variable in restore_step.get("env", []):
            command += ["--env", f"{variable['name']}={variable['value']}"]
        for mount in restore_step.get("volumeMounts", []):
            if mount["name"] != "trusted-ca":
                continue
            assert trusted_ca is not None
            source = trusted_ca / mount["subPath"] if "subPath" in mount else trusted_ca
            mode = "ro,Z" if mount.get("readOnly") else "Z"
            command += ["--volume", f"{source}:{mount['mountPath']}:{mode}"]
    if entrypoint is not None:
        command += ["--entrypoint", entrypoint]
    return subprocess.run(
        [*command, image, *args], text=True, capture_output=True, check=False, timeout=300
    )


@pytest.mark.skipif(
    not (
        os.environ.get("TRAUST_TEST_CONTAINER_RUNTIME")
        or os.environ.get("TRAUST_TEST_ARTIFACT_STORE")
    ),
    reason="requires an explicitly enabled container runtime",
)
@pytest.mark.parametrize("pipeline", PIPELINES)
@pytest.mark.parametrize(
    "projection", ("absent-configmap", "absent-key", "empty-bundle", "populated-bundle")
)
def test_real_optional_ca_helper_startup(tmp_path: Path, pipeline: str, projection: str) -> None:
    """Run the pinned helper against directory projections, not YAML assertions.

    An absent optional ConfigMap and an absent selected key both project an empty
    directory. This models their container view; kubelet projection itself still
    requires cluster verification.
    """
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    trusted_ca = tmp_path / "trusted-ca"
    trusted_ca.mkdir()
    bundle = trusted_ca / "ca-bundle.crt"
    if projection == "populated-bundle":
        certificate = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
        bundle.write_text(ssl.DER_cert_to_PEM_cert(certificate))
    elif projection == "empty-bundle":
        bundle.touch()
    restore = _tasks(pipeline)["opengrep-quality"]["taskSpec"]["steps"][0]
    # The same probe without the optional mount records the image's default trust.
    probe = r"""
set -euo pipefail
source /usr/local/bin/oras_opts.sh
printf 'SSL_CERT_FILE=%s\n' "${SSL_CERT_FILE:-}"
printf 'ORAS_OPTION=%s\n' "${oras_opts[@]}"
for bundle in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
    if test -s "$bundle"; then
        printf 'SYSTEM_TRUST=%s\n' "$(sha256sum "$bundle")"
    fi
done
if test -n "${SSL_CERT_FILE:-}"; then
    printf 'CUSTOM_TRUST=%s\n' "$(sha256sum "$SSL_CERT_FILE" | cut -d ' ' -f 1)"
fi
"""
    baseline = _artifact_command(workdir, restore["image"], "-c", probe, entrypoint="/bin/bash")
    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    started = _artifact_command(
        workdir,
        restore["image"],
        "-c",
        probe,
        restore_step=restore,
        trusted_ca=trusted_ca,
        entrypoint="/bin/bash",
    )
    assert started.returncode == 0, started.stdout + started.stderr
    defaults = baseline.stdout.splitlines()
    configured = started.stdout.splitlines()
    system_trust = [line for line in defaults if line.startswith("SYSTEM_TRUST=")]
    assert system_trust, baseline.stdout
    assert [line for line in configured if line.startswith("SYSTEM_TRUST=")] == system_trust
    assert [line for line in configured if line.startswith("ORAS_OPTION=")] == [
        line for line in defaults if line.startswith("ORAS_OPTION=")
    ]
    if projection == "populated-bundle":
        assert "SSL_CERT_FILE=/var/run/trusted-ca/ca-bundle.crt" in configured
        assert f"CUSTOM_TRUST={hashlib.sha256(bundle.read_bytes()).hexdigest()}" in configured
    else:
        assert "SSL_CERT_FILE=" in configured
        assert not any(line.startswith("CUSTOM_TRUST=") for line in configured)


@pytest.mark.skipif(
    not os.environ.get("TRAUST_TEST_ARTIFACT_STORE"),
    reason="requires a container runtime and writable disposable OCI artifact repository",
)
@pytest.mark.parametrize("pipeline", PIPELINES)
@pytest.mark.parametrize("url", SOURCE_URLS)
def test_real_source_artifact_round_trip_and_failed_quality(
    tmp_path: Path, pipeline: str, url: str
) -> None:
    workdir = tmp_path / "workdir"
    original = workdir / "clone-output"
    _source(original, url)
    task = _tasks(pipeline)["opengrep-quality"]
    restore = task["taskSpec"]["steps"][0]
    created = _artifact_command(
        workdir,
        restore["image"],
        "create",
        "--store",
        os.environ["TRAUST_TEST_ARTIFACT_STORE"],
        "/var/workdir/SOURCE_ARTIFACT=/var/workdir/clone-output",
    )
    assert created.returncode == 0, created.stdout + created.stderr
    artifact = (workdir / "SOURCE_ARTIFACT").read_text()
    assert artifact.startswith("oci:") and "@sha256:" in artifact
    # The original checkout is gone: only the digest-pinned clone artifact can work.
    shutil.rmtree(original)
    args = [arg.replace("$(params.SOURCE_ARTIFACT)", artifact) for arg in restore["args"]]
    trusted_ca = tmp_path / "trusted-ca"
    trusted_ca.mkdir()
    restored = _artifact_command(
        workdir, restore["image"], *args, restore_step=restore, trusted_ca=trusted_ca
    )
    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert (workdir / "source" / "source-identity").read_text() == "exact resolved clone content\n"
    assert url in (workdir / "source" / ".git" / "config").read_text()
    env = _quality_env(tmp_path)
    env["FAIL_STAGE"] = "quality"
    result = _run_quality(task, workdir, env)
    assert result.returncode == 33, result.stdout + result.stderr
    records = [json.loads(line) for line in Path(env["COMMAND_LOG"]).read_text().splitlines()]
    assert [record["args"] for record in records] == UV_COMMANDS
    assert all(record["rule"] == "artifact rule bytes\n" for record in records)
    assert all(url in record["origin"] for record in records)


@pytest.mark.skipif(
    not os.environ.get("TRAUST_TEST_ARTIFACT_STORE"),
    reason="requires a container runtime and writable disposable OCI artifact repository",
)
@pytest.mark.parametrize("pipeline", PIPELINES)
def test_real_missing_artifact_fails_before_quality(tmp_path: Path, pipeline: str) -> None:
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    task = _tasks(pipeline)["opengrep-quality"]
    restore = task["taskSpec"]["steps"][0]
    missing = f"oci:{os.environ['TRAUST_TEST_ARTIFACT_STORE']}@sha256:{'0' * 64}"
    args = [arg.replace("$(params.SOURCE_ARTIFACT)", missing) for arg in restore["args"]]
    trusted_ca = tmp_path / "trusted-ca"
    trusted_ca.mkdir()
    result = _artifact_command(
        workdir,
        restore["image"],
        *args,
        retry_max_tries=1,
        restore_step=restore,
        trusted_ca=trusted_ca,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (workdir / "source" / "source-identity").exists()
