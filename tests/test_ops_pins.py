import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_ops_pins import UPSTREAM, locked_pair, sdk_pair
from scripts.check_ops_recording import ROLLBACK, require_go_pass, require_pytest_pass

CORE = "a" * 40
CONTRACTS = "b" * 40
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_ops_pins.py"


def inputs() -> str:
    return "\n".join(
        f'[[package]]\nname = "traust-{name}"\n'
        f'source = {{ git = "{UPSTREAM}traust-{name}.git?rev={sha}#{sha}" }}'
        for name, sha in (("core", CORE), ("contracts", CONTRACTS))
    )


def test_installed_resolution_and_sdk_generator_inputs_can_agree() -> None:
    assert locked_pair(inputs()) == sdk_pair(f"CONTRACTS_REF := {CONTRACTS}\nCORE_REF := {CORE}\n")


@pytest.mark.parametrize("revision", ["development", CORE[:8], CONTRACTS])
def test_a_branch_abbreviation_or_different_resolution_is_not_a_pin(revision: str) -> None:
    with pytest.raises(ValueError):
        locked_pair(inputs().replace(f"rev={CORE}", f"rev={revision}"))


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        [
            "git",
            "-C",
            repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=pin@example.test",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgSign=false",
            *args,
        ],
        text=True,
    ).strip()


def checkpoint(repo: Path) -> str:
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "candidate")
    return git(repo, "rev-parse", "HEAD")


def metadata(root: Path, name: str) -> Path:
    return root / "site" / (name.replace("-", "_") + "-1.dist-info")


def direct_url(sha: str, requested: str | None = None, *, name: str = "traust-core") -> str:
    return json.dumps(
        {
            "url": f"{UPSTREAM}{name}.git",
            "vcs_info": {"vcs": "git", "commit_id": sha, "requested_revision": requested or sha},
        }
    )


@pytest.fixture
def rig(tmp_path: Path) -> Path:
    """Real candidate commits plus an isolated interpreter metadata search path."""
    for repo in ("cli", "engine", "sdk"):
        (tmp_path / repo).mkdir()
        git(tmp_path / repo, "init", "-q")
    cli = tmp_path / "cli"
    fixtures = cli / "scripts/ops_smoke"
    fixtures.mkdir(parents=True)
    (fixtures / "forge.py").write_text("# synthetic forge fixture\n")
    (fixtures / "authored.json").write_text("{}\n")
    shutil.copyfile(SCRIPT, cli / "scripts/check_ops_pins.py")
    for repo, name in (("cli", "traust"), ("engine", "traust-engine")):
        (tmp_path / repo / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\n[tool.uv.sources]\n'
            f'traust-core = {{git="{UPSTREAM}traust-core.git", rev="{CORE}"}}\n'
        )
        (tmp_path / repo / "uv.lock").write_text(inputs())
        checkpoint(tmp_path / repo)
    go = tmp_path / "sdk/go"
    (go / "v1/types").mkdir(parents=True)
    (go / "Makefile").write_text(f"CORE_REF := {CORE}\nCONTRACTS_REF := {CONTRACTS}\n")
    (go / "v1/types/version.go").write_text(f'package types\nconst ContractsRef = "{CONTRACTS}"\n')
    checkpoint(tmp_path / "sdk")
    engine_head = git(tmp_path / "engine", "rev-parse", "HEAD")
    # A separate bare upstream for each participant. Only the fixture transport
    # is substituted; the checker really fetches into an empty object store.
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    for project in ("engine", "sdk"):
        git(
            tmp_path,
            "clone",
            "-q",
            "--bare",
            "--no-local",
            project,
            f"upstream/traust-{project}.git",
        )
    real_git = shutil.which("git")
    assert real_git
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    git_shim = bin_dir / "git"
    rewrite = f"url.{upstream.as_uri()}/.insteadOf={UPSTREAM}"
    git_shim.write_text(
        "#!/bin/sh\nexport GIT_ALLOW_PROTOCOL=file\n"
        f'exec {shlex.quote(real_git)} -c {shlex.quote(rewrite)} "$@"\n'
    )
    git_shim.chmod(0o755)
    for name, command, target, sha in (
        ("traust", "traust", "traust.cli.__main__", ""),
        ("traust-core", "traust-server", "traust_core.v1.rest.server", CORE),
        ("traust-contracts", "", "", CONTRACTS),
        ("traust-engine", "traust-engine", "traust_engine.ops.cli", engine_head),
    ):
        info = metadata(tmp_path, name)
        info.mkdir(parents=True)
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: 1\n")
        source_root = cli / "src" if name == "traust" else tmp_path / "site"
        package = source_root / name.replace("-", "_")
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").touch()
        if command:
            (info / "entry_points.txt").write_text(
                f"[console_scripts]\n{command} = {target}:main\n"
            )
            module = source_root / Path(*target.split(".")).with_suffix(".py")
            module.parent.mkdir(parents=True, exist_ok=True)
            module.write_text("def main(): return 0\n")
        if sha:
            (info / "direct_url.json").write_text(direct_url(sha, name=name))
        else:
            (info / "direct_url.json").write_text(
                json.dumps({"url": cli.as_uri(), "dir_info": {"editable": True}})
            )
    checkpoint(cli)
    return tmp_path


def check(root: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    # -S excludes the workstation's real installations, even when an input is missing.
    return subprocess.run(
        [sys.executable, "-S", "scripts/check_ops_pins.py", *args],
        cwd=root / "cli",
        env={
            "HOME": str(root),
            "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
            "GIT_CONFIG_NOSYSTEM": "1",
            "PYTHONPATH": os.pathsep.join(map(str, (root / "cli/src", root / "site"))),
            "PYTHONDONTWRITEBYTECODE": "1",
            "OPS_ENGINE_CHECKOUT": str(root / "engine"),
            "OPS_SDK_CHECKOUT": str(root / "sdk"),
            "OPS_ENGINE_SRC": "",
            **env,
        },
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.requires_git
def test_exact_agreement_and_engine_identity(rig: Path) -> None:
    result = check(rig)
    assert result.returncode == 0, result.stderr
    assert "same-interpreter traust-server: traust-core" in result.stdout
    assert f"SDK generated types: contracts={CONTRACTS}" in result.stdout
    assert "installed pins agree" in result.stdout
    for participant in ("engine", "sdk"):
        assert f"independent fetch: {UPSTREAM}traust-{participant}.git@" in result.stdout

    (metadata(rig, "traust-engine") / "direct_url.json").write_text(
        direct_url("d" * 40, name="traust-engine")
    )
    stale = check(rig)
    assert stale.returncode == 1
    assert "pin disagreement: engine" in stale.stderr


@pytest.mark.requires_git
def test_matching_manifests_do_not_prove_runtime(rig: Path) -> None:
    for name in ("traust-core", "traust-contracts"):
        (metadata(rig, name) / "direct_url.json").write_text(direct_url("d" * 40, name=name))
    preflight = check(rig, "--preflight")
    assert preflight.returncode == 0, preflight.stderr
    assert "installed runtime not yet checked" in preflight.stdout
    for mode, status in (((), 1), (("--probe",), 0)):
        result = check(rig, *mode)
        assert result.returncode == status, result.stderr
        for key in ("core", "contracts"):
            line = next(
                line for line in result.stderr.splitlines() if f"pin disagreement: {key}:" in line
            )
            assert "runner/engine lock" in line and "server runtime" in line
        assert ("DIAGNOSTIC ONLY" in result.stdout) == bool(mode)


@pytest.mark.requires_git
def test_local_engine_probe_reports_declared_and_locked_skew(rig: Path) -> None:
    project = rig / "engine/pyproject.toml"
    project.write_text(project.read_text().replace(CORE, "c" * 40))
    checkpoint(rig / "engine")
    local = json.dumps({"url": (rig / "engine").as_uri(), "dir_info": {}})
    (metadata(rig, "traust-engine") / "direct_url.json").write_text(local)
    strict = check(rig)
    assert strict.returncode == 1
    assert "unpinned local path installation" in strict.stderr
    assert "pin disagreement: core:" in strict.stderr

    probe = check(rig, "--probe", OPS_ENGINE_CHECKOUT="", OPS_ENGINE_SRC=str(rig / "engine"))
    assert probe.returncode == 0, probe.stderr
    assert "runner/engine declared" in probe.stderr
    assert "runner/engine lock" in probe.stderr
    assert "unpinned local path installation" in probe.stderr
    assert "DIAGNOSTIC ONLY: DISAGREEMENT" in probe.stdout


@pytest.mark.requires_git
def test_missing_candidate_and_runtime_evidence_is_not_a_pass(rig: Path) -> None:
    (metadata(rig, "traust-core") / "entry_points.txt").unlink()
    (metadata(rig, "traust-contracts") / "direct_url.json").unlink()
    result = check(rig, OPS_SDK_CHECKOUT="", OPS_ENGINE_CHECKOUT="")
    assert result.returncode == 1
    for reason in (
        "SDK Git checkout",
        "engine Git checkout",
        "traust-server entry point",
        "missing direct_url.json",
    ):
        assert reason in result.stderr


@pytest.mark.requires_git
@pytest.mark.parametrize("bad", ["{", "[]", direct_url(CORE[:12]), direct_url(CORE, "main")])
def test_invalid_installed_provenance_is_not_a_pin(rig: Path, bad: str) -> None:
    (metadata(rig, "traust-core") / "direct_url.json").write_text(bad)
    result = check(rig)
    assert result.returncode == 1
    assert "installed traust-core:" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.requires_git
def test_sdk_candidate_inputs_and_embedded_stamp_are_both_checked(rig: Path) -> None:
    stamp = rig / "sdk/go/v1/types/version.go"
    stamp.write_text(stamp.read_text().replace(CONTRACTS, "c" * 40))
    dirty = check(rig)
    assert dirty.returncode == 1
    assert "differs from candidate commit" in dirty.stderr
    checkpoint(rig / "sdk")
    stale = check(rig)
    assert stale.returncode == 1
    assert "pin disagreement: contracts:" in stale.stderr and "SDK generated types" in stale.stderr


def test_sdk_must_not_override_a_pinned_ref_with_a_branch() -> None:
    with pytest.raises(ValueError, match="one literal CORE_REF"):
        sdk_pair(f"CORE_REF := {CORE}\nCONTRACTS_REF := {CONTRACTS}\nCORE_REF = main\n")


@pytest.mark.requires_git
@pytest.mark.parametrize(
    "repo,path,stage",
    [
        ("cli", "uv.lock", False),
        ("cli", "scripts/check_ops_pins.py", False),
        ("cli", "scripts/ops_smoke/forge.py", True),
        ("cli", "scripts/ops_smoke/authored.json", False),
        ("cli", "scripts/ops_smoke/untracked.py", False),
        ("sdk", "go/v1/ops/record.go", False),
        ("engine", "runner.py", True),
    ],
)
def test_dirty_executed_inputs_fail_preflight(rig: Path, repo: str, path: str, stage: bool) -> None:
    source = rig / repo / path
    source.parent.mkdir(parents=True, exist_ok=True)
    with source.open("a") as out:
        out.write("\n# dirty\n")
    if stage:
        git(rig / repo, "add", path)
    result = check(rig, "--preflight")
    assert result.returncode == 1
    assert "differs from candidate commit" in result.stderr and path in result.stderr
    assert "independent fetch:" not in result.stdout


@pytest.mark.requires_git
def test_ignored_fixture_is_not_committed_input(rig: Path) -> None:
    cli = rig / "cli"
    path = "scripts/ops_smoke/ignored.json"
    (cli / ".git/info/exclude").write_text(path + "\n")
    (cli / path).write_text("{}\n")
    result = check(rig, "--preflight")
    assert result.returncode == 1
    assert "uncommitted CLI input" in result.stderr and path in result.stderr


@pytest.mark.requires_git
@pytest.mark.parametrize("repo", ["engine", "sdk"])
def test_clean_local_only_commit_cannot_certify_remote_source(rig: Path, repo: str) -> None:
    (rig / repo / "not-published").touch()
    checkpoint(rig / repo)
    result = check(rig, "--preflight")
    assert result.returncode == 1
    assert f"fetchable traust-{repo}" in result.stderr
    assert check(rig, "--probe").returncode == 0


@pytest.mark.requires_git
def test_git_file_sha_is_not_upstream_engine_provenance(rig: Path) -> None:
    head = git(rig / "engine", "rev-parse", "HEAD")
    url = (rig / "engine").as_uri()
    requested = check(rig, "--preflight", OPS_ENGINE_SRC=f"git+{url}@{head}")
    assert requested.returncode == 1
    assert "engine source must be the independent HTTPS repository" in requested.stderr
    info = metadata(rig, "traust-engine") / "direct_url.json"
    direct = json.loads(info.read_text())
    info.write_text(json.dumps({**direct, "url": url}))
    installed = check(rig)
    assert installed.returncode == 1
    assert "not installed from its independent HTTPS repository" in installed.stderr


@pytest.mark.requires_git
def test_cli_from_another_checkout_is_not_the_tested_cli(rig: Path) -> None:
    info = metadata(rig, "traust") / "direct_url.json"
    info.write_text(json.dumps({"url": rig.as_uri(), "dir_info": {"editable": True}}))
    result = check(rig)
    assert result.returncode == 1
    assert "installed editable from this exact checkout" in result.stderr


@pytest.mark.requires_git
def test_shadowed_core_fails_even_with_exact_distribution_metadata(rig: Path) -> None:
    shadow = rig / "draft/src"
    shutil.copytree(rig / "site/traust_core", shadow / "traust_core")
    result = check(
        rig,
        PYTHONPATH=os.pathsep.join(map(str, (shadow, rig / "cli/src", rig / "site"))),
    )
    assert result.returncode == 1
    assert "traust_core import resolves to" in result.stderr
    assert str(shadow) in result.stderr and str(rig / "site/traust_core") in result.stderr


@pytest.mark.requires_git
def test_server_module_must_resolve_under_the_core_distribution(rig: Path) -> None:
    rest = rig / "site/traust_core/v1/rest"
    shadow = rig / "draft/rest"
    shadow.mkdir(parents=True)
    (shadow / "server.py").write_text("# substituted entry module\n")
    (rest / "__init__.py").write_text(f"__path__.insert(0, {str(shadow)!r})\n")
    result = check(rig)
    assert result.returncode == 1
    assert "traust_core.v1.rest.server import resolves to" in result.stderr
    assert str(shadow / "server.py") in result.stderr


def test_recording_proof_rejects_skip_no_match_and_wrong_backend(tmp_path: Path) -> None:
    name = "TestCoreIntakeRollback"
    passed = f"--- PASS: {name} (0.03s)\n"
    require_go_pass(passed, name)
    for output in (
        "ok (no tests to run)",
        passed * 2,
        f"--- SKIP: {name} (0.00s)\n",
        passed + f"    --- SKIP: {name}/nested (0.00s)\n",
    ):
        with pytest.raises(ValueError, match="non-skipped PASS"):
            require_go_pass(output, name)
    xml = tmp_path / "report.xml"
    case = f"{ROLLBACK}[postgres]"
    good = f'<testcase name="{case}"/>'
    xml.write_text(f"<testsuite>{good}</testsuite>")
    require_pytest_pass(xml, case)
    for invalid in (
        "",
        good * 2,
        good.replace("postgres", "sqlite"),
        good.replace("/>", "><skipped/></testcase>"),
    ):
        xml.write_text(f"<testsuite>{invalid}</testsuite>")
        with pytest.raises(ValueError, match="non-skipped pytest pass"):
            require_pytest_pass(xml, case)


def _runtime(tmp_path: Path, running: str, published: str) -> Path:
    """A stand-in podman answering `inspect` and `port` for the smoke container."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "podman"
    fake.write_text(
        f'#!/bin/sh\ncase "$1" in inspect) echo {running} ;; port) echo {published} ;; esac\n'
    )
    fake.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize(
    ("container", "running", "published", "refused"),
    [
        ("traust-local-ops-smoke.Ab12Cd34", "true", "127.0.0.1:55999", None),
        ("traust-ops-local", "true", "127.0.0.1:55999", "smoke's own container"),
        ("traust-local-ops-smoke.Ab12Cd34", "false", "127.0.0.1:55999", "not running"),
        ("traust-local-ops-smoke.Ab12Cd34", "true", "127.0.0.1:5432", "does not publish"),
    ],
    ids=["the smoke's container", "another container", "stopped", "another port"],
)
def test_recording_proof_writes_only_to_the_smokes_own_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container: str,
    running: str,
    published: str,
    refused: str | None,
) -> None:
    """A direct invocation against an existing local database on the same port has no
    container named after the smoke's directory publishing it: refused before any write."""
    from scripts.check_ops_recording import require_smoke_container

    monkeypatch.setenv("PATH", str(_runtime(tmp_path, running, published)))
    monkeypatch.setenv("OPS_CONTAINER", container)
    if refused is None:
        require_smoke_container(".local-ops-smoke.Ab12Cd34", "55999")
    else:
        with pytest.raises(ValueError, match=refused):
            require_smoke_container(".local-ops-smoke.Ab12Cd34", "55999")
