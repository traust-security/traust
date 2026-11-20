"""Execute the quality gate; optionally round-trip real pinned OCI source artifacts.

OCI integration requires TRAUST_TEST_ARTIFACT_STORE (a writable test repository).
TRAUST_TEST_CONTAINER_RUNTIME defaults to podman. Optional registry settings are
TRAUST_TEST_ARTIFACT_AUTHFILE and TRAUST_TEST_ARTIFACT_ORAS_OPTIONS; use a disposable
registry, since the tests push artifacts. No cluster or Git source access is used.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
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
    workdir: Path, image: str, *args: str, retry_max_tries: int | None = None
) -> subprocess.CompletedProcess[str]:
    """Use the actual upstream image entrypoint, registry client and archive code."""
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
    return subprocess.run(
        [*command, image, *args], text=True, capture_output=True, check=False, timeout=300
    )


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
    restored = _artifact_command(workdir, restore["image"], *args)
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
    result = _artifact_command(workdir, restore["image"], *args, retry_max_tries=1)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (workdir / "source" / "source-identity").exists()
