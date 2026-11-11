"""`traust adapters`, `traust util elf|safe-exec` and `traust admin toolchain` on traust-core's
tool doors: exit codes, the safe-exec bypass and the doctor."""

from __future__ import annotations

import json
import os
import stat
import struct
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


def test_opengrep_without_json_or_in_time_is_exit_1(tmp_path: Path, bindir: Path, capsys) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    fake(bindir, "opengrep", "print('not json')")
    assert adapters.call_opengrep(opengrep_args(target, rules=[str(target)])) == 1
    assert "opengrep produced no JSON" in capsys.readouterr().err
    fake(bindir, "opengrep", "import time; time.sleep(5)")
    assert adapters.call_opengrep(opengrep_args(target, rules=[str(target)], timeout=1)) == 1
    assert "opengrep timed out after 1s" in capsys.readouterr().err


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
