"""`traust adapters`, `traust util elf|safe-exec` and `traust admin toolchain` on traust-core's
tool doors: exit codes, the safe-exec bypass and the doctor."""

from __future__ import annotations

import json
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from traust.cli import toolchain
from traust.cli.groups import adapters, util


@pytest.fixture
def bindir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "bin"
    path.mkdir()
    monkeypatch.setenv("PATH", f"{path}{os.pathsep}{os.environ['PATH']}")
    return path


def fake(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!{sys.executable}\nimport json, sys\nargs = sys.argv[1:]\n{body}\n")
    path.chmod(0o755)


def opengrep_args(target: Path, **kw) -> SimpleNamespace:
    base = {
        "config_home": None,
        "target": str(target),
        "rules": [],
        "out": str(target.parent / "og.json"),
        "timeout": 60,
        "rule_allow": None,
        "rule_pack": None,
        "opengrep": "opengrep",
    }
    return SimpleNamespace(**{**base, **kw})


@pytest.mark.parametrize(
    ("kw", "code", "message"),
    [
        ({"rules": ["auto"]}, 2, "refusing '--rules auto'"),
        ({"rule_allow": "@/nonexistent"}, 2, "--rule-allow: no such file"),
        ({"rule_pack": Path("/nonexistent-pack")}, 1, "rule pack is not a directory"),
    ],
)
def test_opengrep_refusals_keep_their_exit_codes(
    tmp_path: Path, bindir: Path, capsys, kw: dict, code: int, message: str
) -> None:
    fake(bindir, "opengrep", "print('{}')")
    target = tmp_path / "repo"
    target.mkdir()
    assert adapters.call_opengrep(opengrep_args(target, **kw)) == code
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("failure", "category"),
    [
        ("invalid-output", "invalid_output"),
        ("timeout", "scan_timeout"),
        ("abnormal-exit", "opengrep_failed"),
    ],
)
def test_opengrep_process_failures_are_observable_without_writing_a_report(
    tmp_path: Path, bindir: Path, capsys: pytest.CaptureFixture[str], failure: str, category: str
) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    rule = tmp_path / "transport.yaml"
    rule.write_text(
        "rules:\n  - id: transport-check\n    languages: [python]\n"
        "    severity: ERROR\n    message: Unsafe call\n    pattern: dangerous($X)\n"
    )
    rule.with_suffix(".py").write_text(
        "# ruleid: transport-check\ndangerous(value)\n# ok: transport-check\nsafe(value)\n"
    )
    native_receipts = """#!/bin/sh
case "$1" in
  --version) printf '1.25.0\\n'; exit 0 ;;
  validate) exit 0 ;;
  test)
    for root do :; done
    config=$(find "$root" -type f -name '*.yaml' -print -quit)
    fixture="${config%.yaml}.py"
    printf '{"results":{"%s":{"checks":{"transport-check":{"passed":true,"errors":[],"matches":{"%s":{"expected_lines":[2],"reported_lines":[2]}}}}}},"fixtest_results":{},"config_missing_tests":[],"config_missing_fixtests":[],"config_with_errors":[]}\\n' "$config" "$fixture"
    exit 0 ;;
esac
printf 'PRIVATE_ENGINE_DETAIL' >&2
"""
    behavior = {
        "invalid-output": "printf 'PRIVATE_ENGINE_DETAIL not JSON\\n'",
        "timeout": "exec sleep 10",
        "abnormal-exit": "exit 2",
    }[failure]
    scanner = bindir / "opengrep"
    scanner.write_text(native_receipts + behavior + "\n")
    scanner.chmod(0o755)
    assert adapters.call_opengrep(opengrep_args(target, rules=[str(rule)], timeout=2)) == 1
    diagnostic = capsys.readouterr().err
    assert diagnostic.startswith(category + ": ")
    assert diagnostic.partition(": ")[2].strip()
    assert "PRIVATE_ENGINE_DETAIL" not in diagnostic
    assert not (tmp_path / "og.json").exists()


def yara_args(target: Path, **kw) -> SimpleNamespace:
    base = {
        "config_home": None,
        "target": str(target),
        "rules": [],
        "out": target.parent / "y.json",
        "timeout": 60,
        "yara": "yara",
        "max_file_mb": 1,
    }
    return SimpleNamespace(**{**base, **kw})


def test_yara_refuses_a_movable_rules_ref_with_exit_2_and_needs_its_binary(
    tmp_path: Path, bindir: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("PATH", str(bindir))
    assert adapters.call_yara(yara_args(tmp_path)) == 1
    assert "yara not found on PATH (yara)" in capsys.readouterr().err
    fake(bindir, "yara", "print('4.5.8')")
    assert adapters.call_yara(yara_args(tmp_path, rules=["https://example.test/r@main"])) == 2
    assert "40-hex" in capsys.readouterr().err


def test_gitleaks_without_its_binary_is_exit_1(tmp_path: Path, capsys) -> None:
    rules = tmp_path / "g.toml"
    rules.write_text("title = 't'\n")
    args = SimpleNamespace(
        config_home=None,
        repo=tmp_path,
        out=tmp_path / "g.json",
        mode="dir",
        config=rules,
        timeout=60,
        gitleaks="no-such-gitleaks",
    )
    assert adapters.call_gitleaks(args) == 1
    assert "gitleaks not found on PATH (no-such-gitleaks)" in capsys.readouterr().err


def test_joern_writes_its_facts_and_soundness(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    out = tmp_path / "deep" / "joern.json"
    args = SimpleNamespace(
        config_home=None,
        repo=tmp_path,
        out=out,
        language="java",
        symbols=[],
        packages="",
        module="",
        timeout=60,
        max_sites=10,
    )
    assert adapters.call_joern(args) == 0
    doc = json.loads(out.read_text())
    assert doc["status"] == "skipped: joern not on PATH" and "soundness" in doc
    assert f"joern-reachability: skipped: joern not on PATH → {out}" in capsys.readouterr().out


def test_checkov_reports_the_khs_facts(tmp_path: Path, capsys) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
        "  - name: c\n    image: i\n    securityContext:\n      privileged: true\n"
    )
    args = SimpleNamespace(target=str(tmp_path), out=None, summary=True)
    assert adapters.call_checkov(args) == 0
    assert "KHS-W01: 1" in capsys.readouterr().out


def elf(tmp_path: Path) -> Path:
    path = tmp_path / "bin.elf"
    header = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    path.write_bytes(header + b"SSL_CTX_new\x00")
    return path


def test_util_elf(tmp_path: Path, capsys) -> None:
    args = SimpleNamespace(binary=elf(tmp_path), symbol=["SSL_CTX_new"], max_scan_mb=1)
    assert util.call_elf(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["metadata"] == {"arch": "x86_64", "elf_class": 64, "endian": "little"}
    assert out["string_matches"][0]["matched"] == "SSL_CTX_new"
    text = tmp_path / "t"
    text.write_text("x")
    assert util.call_elf(SimpleNamespace(binary=text, symbol=[], max_scan_mb=1)) == 1
    assert util.call_elf(SimpleNamespace(binary=tmp_path / "none", symbol=[], max_scan_mb=1)) == 2


def safe_exec_args(mode: str, profile: str = "go-scan", cmd=(), string=None, config_home=None):
    return SimpleNamespace(
        config_home=config_home,
        safe_exec_mode=mode,
        profile=profile,
        string=string,
        cmd=list(cmd),
        timeout=30,
        cwd=None,
    )


def test_safe_exec_checks_and_runs_under_the_profile(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SAFE_EXEC_DISABLED", raising=False)
    monkeypatch.delenv("SAFE_EXEC_MODE", raising=False)
    assert util.call_safe_exec(safe_exec_args("check", "validation-step", ["echo", "hi"])) == 0
    assert capsys.readouterr().out == "OK\n"
    assert util.call_safe_exec(safe_exec_args("check", cmd=["echo", "hi"])) == 1
    assert capsys.readouterr().out.startswith("BLOCK: ")
    assert util.call_safe_exec(safe_exec_args("run", "validation-step", string="echo hi")) == 0
    assert capsys.readouterr().out == "hi\n"
    assert util.call_safe_exec(safe_exec_args("run", cmd=["echo", "hi"])) == 126
    assert capsys.readouterr().err.startswith("[safe_exec blocked: ")


def test_safe_exec_warn_mode_runs_what_it_would_block(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SAFE_EXEC_DISABLED", raising=False)
    monkeypatch.setenv("SAFE_EXEC_MODE", "warn")
    assert util.call_safe_exec(safe_exec_args("check", cmd=["echo", "hi"])) == 0
    assert capsys.readouterr().out.startswith("WARN (would block): ")
    assert util.call_safe_exec(safe_exec_args("run", cmd=["echo", "hi"])) == 0
    out = capsys.readouterr()
    assert out.out == "hi\n" and "WARN (would block, running anyway" in out.err


def test_the_bypass_runs_unvetted_but_shouts_and_logs_to_a_private_file(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    log = tmp_path / "state" / "traust-engine" / "safe-exec-bypass.log"
    monkeypatch.setattr(util, "BYPASS_LOG", log)
    monkeypatch.delenv("SAFE_EXEC_MODE", raising=False)
    monkeypatch.setenv("SAFE_EXEC_DISABLED", "calibrating")
    assert util.call_safe_exec(safe_exec_args("run", cmd=["echo", "hi"])) == 0
    out = capsys.readouterr()
    line = "SAFE_EXEC BYPASS profile=go-scan reason='calibrating' cmd=['echo', 'hi']"
    assert out.out == "hi\n" and f"*** {line}" in out.err
    assert log.read_text().rstrip().endswith(line)
    assert stat.S_IMODE(log.parent.stat().st_mode) == 0o700


def test_safe_exec_lists_profiles_and_names_a_missing_one(capsys) -> None:
    assert util.call_safe_exec(safe_exec_args("list-profiles")) == 0
    assert any(line.startswith("go-scan ") for line in capsys.readouterr().out.splitlines())
    assert util.call_safe_exec(safe_exec_args("check", "nope", ["echo"])) == 2
    assert "unknown safe_exec profile 'nope'" in capsys.readouterr().err


def test_safe_exec_in_an_empty_home_lists_core_shipped_profiles(tmp_path: Path, capsys) -> None:
    assert util.call_safe_exec(safe_exec_args("list-profiles", config_home=tmp_path)) == 0
    assert any(line.startswith("go-scan ") for line in capsys.readouterr().out.splitlines())


def test_the_doctor_checks_each_profile_tool_on_the_core_toolchain(
    bindir: Path, monkeypatch, capsys
) -> None:
    fake(bindir, "opengrep", "print('opengrep 1.25.0')")
    fake(bindir, "gitleaks", "print('8.0.0')")
    monkeypatch.setenv("PATH", str(bindir))
    assert toolchain.main(["doctor", "--profile", "vuln-scan"]) == 1
    out = capsys.readouterr().out
    assert "[+] opengrep             OK       opengrep 1.25.0" in out
    assert "[!] gitleaks             VERSION  installed 8.0.0, need >= 8.30.1" in out
    assert "issue(s) found" in out
    assert toolchain.main(["doctor", "--profile", "nope"]) == 1
    assert "Available profiles:" in capsys.readouterr().err


@pytest.fixture
def invalid_config_home(tmp_path: Path) -> Path:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text("database: [\n")
    return home


def _run_toolchain_cli(*args: str) -> subprocess.CompletedProcess[str]:
    repo = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "HARNESS_ROOT": str(repo),
        "PYTHONPATH": os.pathsep.join(
            filter(None, (str(repo / "src"), os.environ.get("PYTHONPATH")))
        ),
    }
    return subprocess.run(
        [sys.executable, "-m", "traust.cli", "admin", "toolchain", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("config_source", ["environment", "argument"])
def test_grouped_setup_one_tool_reaches_the_pinned_installer_without_deployment_config(
    tmp_path: Path, bindir: Path, monkeypatch, invalid_config_home: Path, config_source: str
) -> None:
    downloads = tmp_path / "downloads"
    fake(
        bindir,
        "curl",
        f"open({str(downloads)!r}, 'a').write('download attempted\\n')\nsys.exit(97)",
    )
    (bindir / "python3").symlink_to(sys.executable)
    installed = tmp_path / "installed"
    monkeypatch.setenv("HARNESS_BIN_DIR", str(installed))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    args = []
    if config_source == "environment":
        monkeypatch.setenv("TRAUST_CONFIG_HOME", str(invalid_config_home))
    else:
        args = ["--config-home", str(invalid_config_home)]

    result = _run_toolchain_cli(*args, "setup", "--tool", "opengrep", "--dry-run")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Tool: opengrep" in result.stdout
    assert "dry-run: would install opengrep v1.25.0" in result.stdout
    assert not downloads.exists()
    assert not installed.exists()


@pytest.mark.parametrize(
    "args",
    [
        ["setup", "--profile", "vuln-scan", "--dry-run"],
        ["doctor", "--profile", "vuln-scan"],
        ["fetch-dbs", "--profile", "vuln-scan"],
    ],
)
def test_grouped_profile_operations_still_validate_deployment_config(
    invalid_config_home: Path, args: list[str]
) -> None:
    result = _run_toolchain_cli("--config-home", str(invalid_config_home), *args)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "traust.yaml not resolvable:" in result.stderr
    assert "Harness toolchain installer" not in result.stdout


@pytest.mark.parametrize("dry_run", [False, True])
def test_setup_one_tool_delegates_only_that_tool_to_the_installer(
    tmp_path: Path, monkeypatch, invalid_config_home: Path, dry_run: bool
) -> None:
    installer = tmp_path / "install-toolchain.sh"
    recorded_args = tmp_path / "installer-args"
    installer.write_text('printf "%s\\n" "$@" > "$INSTALLER_TEST_ARGS"\nexit 17\n')
    monkeypatch.setenv("INSTALLER_TEST_ARGS", str(recorded_args))
    monkeypatch.setattr(toolchain, "INSTALL_SCRIPT", installer)
    args = ["--config-home", str(invalid_config_home), "setup", "--tool", "opengrep"]
    if dry_run:
        args.append("--dry-run")
    assert toolchain.main(args) == 17
    expected = ["--tool", "opengrep"]
    if dry_run:
        expected.append("--dry-run")
    assert recorded_args.read_text().splitlines() == expected


@pytest.mark.parametrize(
    "args",
    [
        ["setup"],
        ["setup", "--tool", "unknown"],
        ["setup", "--tool", "opengrep", "--profile", "vuln-scan"],
    ],
)
def test_setup_rejects_missing_unknown_or_ambiguous_selection(monkeypatch, args) -> None:
    def unexpected_load(*_args):
        pytest.fail("invalid selection must fail before loading deployment context")

    monkeypatch.setattr(toolchain, "load", unexpected_load)
    with pytest.raises(SystemExit) as error:
        toolchain.main(args)
    assert error.value.code == 2


def test_setup_one_tool_fails_when_the_verified_installer_is_missing(
    tmp_path: Path, monkeypatch, capsys, invalid_config_home: Path
) -> None:
    monkeypatch.setattr(toolchain, "INSTALL_SCRIPT", tmp_path / "missing")
    assert (
        toolchain.main(["--config-home", str(invalid_config_home), "setup", "--tool", "opengrep"])
        == 1
    )
    assert "installer is missing" in capsys.readouterr().err
