"""``traust util redact`` scrubs through core's redaction door (``services.redaction``)."""

from __future__ import annotations

import io
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from traust.cli.__main__ import main

TOKEN = "ghp_" + "a" * 36
FIXTURE = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURE, config)
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def redact(home: Path, monkeypatch, *argv: str, stdin: str = "") -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return main(["util", "redact", "--config-home", str(home), *argv])


def test_stdin_is_scrubbed(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, stdin=f"token={TOKEN}\n") == 0
    out, err = capsys.readouterr()
    assert out == "token=ghp_a...REDACTED\n"
    assert "1 hit(s) on stdin" in err


def test_clean_stdin_passes_through(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, stdin="nothing here\n") == 0
    assert capsys.readouterr() == ("nothing here\n", "")


def test_scan_only_lists_each_secret_once(home, monkeypatch, capsys):
    """Behaviour change: the engine's scan listed this token as github-token and bearer-token."""
    assert redact(home, monkeypatch, "--scan-only", stdin=f"Authorization: Bearer {TOKEN}") == 1
    assert json.loads(capsys.readouterr().out) == [
        {"category": "github-token", "match_prefix": "ghp_a"}
    ]


def test_scan_only_clean_exits_0(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, "--scan-only", stdin="clean") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_files_are_redacted_in_place(home, monkeypatch, tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "a.txt").write_text(f"key {TOKEN}\n")
    (tree / "b.txt").write_text("clean\n")
    assert redact(home, monkeypatch, str(tree)) == 0
    assert (tree / "sub" / "a.txt").read_text() == "key ghp_a...REDACTED\n"
    assert (tree / "b.txt").read_text() == "clean\n"


def test_scan_only_leaves_files_alone_and_fails(home, monkeypatch, tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(f"key {TOKEN}\n")
    assert redact(home, monkeypatch, "--scan-only", str(f)) == 1
    assert f.read_text() == f"key {TOKEN}\n"


@pytest.mark.parametrize("scan_only", [False, True])
def test_non_utf8_bundle_fails_closed_and_continues(home, monkeypatch, tmp_path, capsys, scan_only):
    tree = tmp_path / "bundle"
    tree.mkdir()
    first = tree / "a-report.txt"
    binary = tree / "b-evidence.bin"
    last = tree / "z-report.txt"
    text = f"key {TOKEN}\n"
    evidence = b"\xff" + TOKEN.encode("utf-8")
    first.write_text(text, encoding="utf-8")
    binary.write_bytes(evidence)
    last.write_text(text, encoding="utf-8")
    original_write = Path.write_text

    def guard_write(path, *args, **kwargs):
        if scan_only and path.is_relative_to(tree):
            pytest.fail("scan-only attempted to write a deliverable")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", guard_write)
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(tree)) == 2
    expected = text if scan_only else "key ghp_a...REDACTED\n"
    assert first.read_text(encoding="utf-8") == expected
    assert last.read_text(encoding="utf-8") == expected
    assert binary.read_bytes() == evidence
    out, err = capsys.readouterr()
    assert "b-evidence.bin" in err
    assert TOKEN not in out + err


@pytest.mark.parametrize("scan_only", [False, True])
def test_read_failure_is_safe_and_not_successful(home, monkeypatch, tmp_path, capsys, scan_only):
    tree = tmp_path / "bundle"
    tree.mkdir()
    unreadable = tree / f"a-evidence-{TOKEN}\n.txt"
    readable = tree / "z-report.txt"
    text = f"key {TOKEN}\n"
    unreadable.write_text(text, encoding="utf-8")
    readable.write_text(text, encoding="utf-8")
    original_read = Path.read_text

    def denied_read(path, *args, **kwargs):
        if path == unreadable:
            raise PermissionError(f"private exception content: {TOKEN}")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied_read)
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(tree)) == 2
    expected = text if scan_only else "key ghp_a...REDACTED\n"
    assert original_read(unreadable, encoding="utf-8") == text
    assert readable.read_text(encoding="utf-8") == expected
    out, err = capsys.readouterr()
    assert "a-evidence-ghp_a...REDACTED\\n.txt" in err
    assert "private exception content" not in out + err
    assert TOKEN not in out + err


def test_write_failure_fails_closed_and_continues(home, monkeypatch, tmp_path, capsys):
    tree = tmp_path / "bundle"
    tree.mkdir()
    unwritable = tree / "a-report.txt"
    writable = tree / "z-report.txt"
    text = f"key {TOKEN}\n"
    unwritable.write_text(text, encoding="utf-8")
    writable.write_text(text, encoding="utf-8")
    original_write = Path.write_text

    def denied_write(path, *args, **kwargs):
        if path == unwritable:
            raise PermissionError(f"private exception content: {TOKEN}")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", denied_write)
    assert redact(home, monkeypatch, str(tree)) == 2
    assert unwritable.read_text(encoding="utf-8") == text
    assert writable.read_text(encoding="utf-8") == "key ghp_a...REDACTED\n"
    out, err = capsys.readouterr()
    assert "a-report.txt" in err
    assert "private exception content" not in out + err
    assert TOKEN not in out + err


@pytest.mark.parametrize("scan_only", [False, True])
@pytest.mark.parametrize("operation", ["lstat", "iterdir"])
def test_traversal_failure_fails_closed_and_continues(
    home, monkeypatch, tmp_path, capsys, scan_only, operation
):
    tree = tmp_path / "bundle"
    blocked = tree / "a-uninspected"
    blocked.mkdir(parents=True)
    hidden = blocked / "evidence.txt"
    readable = tree / "z-report.txt"
    text = f"key {TOKEN}\n"
    hidden.write_text(text, encoding="utf-8")
    readable.write_text(text, encoding="utf-8")
    original = getattr(Path, operation)

    def denied(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError(f"private exception content: {TOKEN}")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, operation, denied)
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(tree)) == 2
    assert hidden.read_text(encoding="utf-8") == text
    expected = text if scan_only else "key ghp_a...REDACTED\n"
    assert readable.read_text(encoding="utf-8") == expected
    out, err = capsys.readouterr()
    assert "a-uninspected" in err
    assert "private exception content" not in out + err
    assert TOKEN not in out + err


@pytest.mark.parametrize("scan_only", [False, True])
def test_missing_path_is_an_operational_failure(home, monkeypatch, tmp_path, capsys, scan_only):
    missing = tmp_path / "missing.txt"
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(missing)) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "missing.txt" in err
    assert not missing.exists()


@pytest.mark.parametrize("as_root", [False, True])
@pytest.mark.parametrize("target_kind", ["file", "directory", "missing"])
@pytest.mark.parametrize("scan_only", [False, True])
def test_symlinks_fail_without_following_outside_bundle(
    home, monkeypatch, tmp_path, capsys, as_root, target_kind, scan_only
):
    tree = tmp_path / "bundle"
    tree.mkdir()
    target = tmp_path / "outside"
    evidence = target
    if target_kind == "directory":
        target.mkdir()
        evidence = target / "evidence.txt"
    if target_kind != "missing":
        evidence.write_text(f"key {TOKEN}\n", encoding="utf-8")
    link = tree / "uninspected-link"
    link.symlink_to(target, target_is_directory=target_kind == "directory")
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(link if as_root else tree)) == 2
    if target_kind != "missing":
        assert evidence.read_text(encoding="utf-8") == f"key {TOKEN}\n"
    else:
        assert not target.exists()
    assert link.is_symlink()
    out, err = capsys.readouterr()
    assert out == ""
    assert "uninspected-link" in err
    assert TOKEN not in err


def test_internal_symlink_is_not_silently_certified(home, monkeypatch, tmp_path):
    tree = tmp_path / "bundle"
    tree.mkdir()
    report = tree / "report.txt"
    report.write_text(f"key {TOKEN}\n", encoding="utf-8")
    (tree / "link").symlink_to(report)
    assert redact(home, monkeypatch, str(tree)) == 2
    assert report.read_text(encoding="utf-8") == "key ghp_a...REDACTED\n"


@pytest.mark.parametrize("scan_only", [False, True])
def test_special_file_is_not_inspected(home, monkeypatch, tmp_path, capsys, scan_only):
    pipe = tmp_path / "evidence.pipe"
    os.mkfifo(pipe)
    flags = ["--scan-only"] if scan_only else []
    assert redact(home, monkeypatch, *flags, str(pipe)) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "evidence.pipe" in err


def test_scan_only_clean_bundle_succeeds_without_writes(home, monkeypatch, tmp_path):
    tree = tmp_path / "bundle"
    tree.mkdir()
    report = tree / "report.txt"
    report.write_text("clean\n", encoding="utf-8")
    original_write = Path.write_text

    def guard_write(path, *args, **kwargs):
        if path.is_relative_to(tree):
            pytest.fail("scan-only attempted to write a deliverable")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", guard_write)
    assert redact(home, monkeypatch, "--scan-only", str(tree)) == 0
    assert report.read_text(encoding="utf-8") == "clean\n"
