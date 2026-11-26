"""Strict smoke only: build the named SDK/Core proofs against fresh candidate sources."""

import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from scripts.check_ops_pins import (
    checkout_head,
    committed,
    fetch_commit,
    locked_commit,
    locked_pair,
    sdk_pair,
    sdk_revision,
)

RECORDS = "tests/v1/rest/assessments/test_records.py"
ROLLBACK = "test_recording_runner_fails_the_order_after_intake_rollback"
RECLAIM = "test_sdk_claim_reclaim_recording"
SDK_RECORDINGS = ("TestE2ERecordingPreservesReportFields", "TestE2ESCIQueuedScanFeedsTriage")


def require_go_pass(output: str, name: str) -> None:
    # go test -run exits zero for a missing or skipped test. Count only the
    # testing package's *named* result, not a package-level PASS or a RUN line.
    passed = re.findall(rf"^--- PASS: {re.escape(name)} \(", output, re.MULTILINE)
    skipped = re.search(rf"^\s*--- SKIP: {re.escape(name)}[ /]", output, re.MULTILINE)
    if len(passed) != 1 or skipped:
        raise ValueError(f"need one non-skipped PASS for {name}; got {len(passed)}")
    print(f"SDK proof: {name} passed")


def require_pytest_pass(xml: Path, name: str) -> None:
    cases = ET.parse(xml).findall(".//testcase")
    if [case.get("name") for case in cases] != [name] or any(
        child.tag in {"skipped", "error", "failure"} for case in cases for child in case
    ):
        raise ValueError(f"need one non-skipped pytest pass: {name}")
    print(f"Core proof: {name} passed")


def output(command: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    print(result.stdout, flush=True)
    result.check_returncode()
    return result.stdout


def require_smoke_container(ops_dir: str, port: str) -> None:
    """The proofs write to the database, so it must be the one cmd_smoke just created: its
    container is named after the smoke's random directory, must exist and run, and must be
    what publishes Postgres on 127.0.0.1:<port>. An operator database on that port, reached by
    a direct invocation with the same variables, has no such container and is refused."""
    container = f"traust-{ops_dir.removeprefix('.')}"
    if os.environ.get("OPS_CONTAINER") != container:
        raise ValueError(f"recording proof requires the smoke's own container ({container})")
    runtime = shutil.which("podman") or shutil.which("docker")
    if runtime is None:
        raise ValueError("recording proof needs podman or docker to confirm the smoke container")
    state = subprocess.run(
        [runtime, "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
    )
    if state.returncode or state.stdout.strip() != "true":
        raise ValueError(f"recording proof: smoke container {container} is not running")
    published = subprocess.run(
        [runtime, "port", container, "5432/tcp"], capture_output=True, text=True
    )
    if published.returncode or f"127.0.0.1:{port}" not in published.stdout.split():
        raise ValueError(f"recording proof: {container} does not publish 127.0.0.1:{port}")


def main() -> None:
    # cmd_smoke supplies the loopback URL of its just-created container. Never
    # default to ~/.traust, or let a standalone invocation use an operator DB.
    db = os.environ.get("TRAUST_TEST_DATABASE_URL", "")
    parsed = urlsplit(db)
    ops_dir, port = os.environ.get("OPS_DIR", ""), os.environ.get("OPS_PORT", "")
    if not (
        os.environ.get("OPS_ACCEPTANCE") == "1"
        and re.fullmatch(r"\.local-ops-smoke\.[A-Za-z0-9]{8}", ops_dir)
        and parsed.scheme == "postgresql+psycopg"
        and parsed.hostname == "127.0.0.1"
        and str(parsed.port) == port
        and not (parsed.query or parsed.fragment)
    ):
        raise ValueError("recording proof requires the disposable acceptance Postgres")
    require_smoke_container(ops_dir, port)
    cli = Path.cwd()
    core_ref, contracts_ref = locked_pair(committed(cli, checkout_head(cli, "CLI"), "uv.lock"))
    sdk_ref = sdk_revision(Path(os.environ["OPS_SDK_CHECKOUT"]))
    with TemporaryDirectory() as scratch:
        root = Path(scratch)
        core, sdk = root / "core", root / "sdk"
        fetch_commit(core, "traust-core", core_ref)
        fetch_commit(sdk, "traust-sdk", sdk_ref)
        go = sdk / "go"
        if sdk_pair((go / "Makefile").read_text()) != (core_ref, contracts_ref):
            raise ValueError("SDK recording inputs differ from rig lock")
        if locked_commit((core / "uv.lock").read_text(), "traust-contracts") != contracts_ref:
            raise ValueError("Core tests and rig locked different contracts commits")
        home = root / "home"
        home.mkdir()
        # Do not inherit pytest selection, Go workspaces, deployment configuration,
        # Git credentials or forge/model tokens. Both harnesses mint local tokens.
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_TERMINAL_PROMPT": "0",
            "UV_LOCKED": "1",  # includes nested uv run in the SDK e2e harness
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly -v",
        }
        subprocess.run(
            ["uv", "sync", "--locked", "--extra", "postgres"], cwd=core, env=env, check=True
        )
        for name, go_test in (
            (ROLLBACK, "TestCoreIntakeRollback"),
            (RECLAIM, "TestCoreClaimReclaim"),
        ):
            for backend in ("sqlite", "postgres"):
                case = f"{name}[{backend}]"
                report = root / f"{case}.xml"
                log = output(
                    [
                        str(core / ".venv/bin/python"),
                        "-m",
                        "pytest",
                        "-q",
                        "-s",
                        "--runxfail",
                        f"--junitxml={report}",
                        f"{RECORDS}::{case}",
                    ],
                    core,
                    {**env, "TRAUST_TEST_DATABASE_URL": db, "TRAUST_TEST_SDK_GO": str(go)},
                )
                require_pytest_pass(report, case)
                require_go_pass(log, go_test)
        # The SDK owns server/forge setup. Use the *same fresh Core commit*,
        # not its normal shared CORE_SOURCE cache. No caller-supplied targets.
        log = output(["make", "e2e", f"CORE_SOURCE={core}"], go, env)
        for test in SDK_RECORDINGS:
            require_go_pass(log, test)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        sys.exit(f"FAIL: incomplete SDK/Core recording proof: {exc}")
