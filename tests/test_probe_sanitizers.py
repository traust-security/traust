#!/usr/bin/env python3
"""Tests for harnessing/3-audit/secure-code-audit/scripts/probe_sanitizers.py — the Phase-B3 (D4 narrow slice)
sanitizer micro-probe lane tool (probing; discovery is traust-core's, behind
`traust adapters sanitizers`). The bypassable-sanitizer fixture mirrors
bt-awx-001 residual #3 (a sanitize_jinja that strips ASCII jinja markers
but not variants); the soundness fixtures pin the Phase-1 rule that an
error transcript is never evidence of safety."""

import json
import subprocess
import sys

import probe_sanitizers as ps
import pytest

from traust.paths import skill_dir

_SECURE_CODE_AUDIT_SCRIPTS = skill_dir("secure-code-audit") / "scripts"

SCRIPT = _SECURE_CODE_AUDIT_SCRIPTS / "probe_sanitizers.py"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "util.py").write_text(
        "def sanitize_jinja(value):\n"
        "    # strips ASCII jinja markers only — fullwidth survives\n"
        "    return value.replace('{{', '').replace('{%', '')\n"
        "\n"
        "def sanitize_label(value):\n"
        "    # strict whitelist: every corpus survival token carries a\n"
        "    # non-alphanumeric character, so nothing survives this\n"
        "    return ''.join(c for c in value\n"
        "                   if c.isascii() and (c.isalnum() or c == ' '))\n"
        "\n"
        "def validate_name(value):\n"
        "    raise RuntimeError('needs app context')\n"
        "\n"
        "def unrelated_helper(a, b):\n"
        "    return a + b\n"
    )
    return tmp_path


def _cand(function: str, line: int, path: str = "util.py") -> dict:
    return {"function": function, "path": path, "line": line, "arg": "value", "is_method": False}


CANDIDATES = [_cand("sanitize_jinja", 1), _cand("sanitize_label", 5), _cand("validate_name", 11)]


def _only(name: str) -> list[dict]:
    return [c for c in CANDIDATES if c["function"] == name]


# --------------------------------------------------------------------------
# probing (--run) — the acceptance shape: residual #3 detected
# --------------------------------------------------------------------------


def test_bypassable_sanitizer_survives_unicode_variant(repo):
    cands = _only("sanitize_jinja")
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "survived"
    by_payload = {t["payload"]: t["outcome"] for t in result["transcript"]}
    # ASCII jinja markers are stripped, but the fullwidth variant and the
    # dunder body both survive — exactly the bypass shape narrative
    # review missed on awx
    assert by_payload["{{7*7}}"] == "neutralized"
    assert by_payload["｛｛7*7｝｝"] == "survived"
    assert by_payload["{{''.__class__.__mro__}}"] == "survived"


def test_effective_sanitizer_neutralizes(repo):
    cands = _only("sanitize_label")
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "neutralized"
    assert result["survived"] == 0


def test_erroring_function_is_inconclusive_never_safe(repo):
    cands = _only("validate_name")
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "inconclusive"
    assert all(t["outcome"] == "error" for t in result["transcript"])
    assert "RuntimeError" in result["transcript"][0]["exception"]


def test_unimportable_module_is_skipped_with_reason(tmp_path):
    (tmp_path / "needs_dep.py").write_text(
        "import definitely_not_installed_dep\ndef sanitize_x(v):\n    return v\n"
    )
    cands = [_cand("sanitize_x", 2, "needs_dep.py")]
    [result] = ps.probe(tmp_path, cands, timeout=30)
    assert result["outcome"] == "skipped"
    assert "definitely_not_installed_dep" in result["reason"]


def test_transcript_records_payload_and_output(repo):
    cands = _only("sanitize_jinja")
    [result] = ps.probe(repo, cands, timeout=30)
    entry = result["transcript"][0]
    assert {"class", "payload", "outcome"} <= set(entry)
    assert any("output_excerpt" in t for t in result["transcript"])


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------


def _write_candidates(tmp_path, candidates=CANDIDATES):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps({"candidates": candidates}))
    return path


def test_bound_methods_are_skipped_not_run(repo):
    method = {**_cand("sanitize_jinja", 1), "is_method": True}
    [result] = ps.probe(repo, [method], timeout=30)
    assert result["outcome"] == "skipped"
    assert "bound method" in result["reason"]


def test_cli_refuses_without_run_acknowledgement(repo, tmp_path):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--candidates", str(_write_candidates(tmp_path))],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--run" in proc.stderr
    assert "EXECUTING" not in proc.stderr


def test_cli_run_mode_warns_and_probes(repo, tmp_path):
    out = tmp_path / "probes.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(repo),
            "--run",
            "--candidates",
            str(_write_candidates(tmp_path)),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "EXECUTING repository code" in proc.stderr
    data = json.loads(out.read_text())
    assert data["mode"] == "run"
    assert data["stats"]["candidates"] == 3
    assert data["stats"]["survived"] == 1
    assert data["stats"]["inconclusive"] >= 1


def test_cli_only_probes_the_named_candidate(repo, tmp_path):
    out = tmp_path / "probes.json"
    cands = _write_candidates(tmp_path)
    argv = [str(repo), "--run", "--candidates", str(cands), "--only", "sanitize_label"]
    assert ps.main([*argv, "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert [p["function"] for p in data["probes"]] == ["sanitize_label"]


def test_cli_rejects_unreadable_candidates(repo, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert ps.main([str(repo), "--run", "--candidates", str(bad)]) == 1
    assert ps.main([str(tmp_path / "absent"), "--run", "--candidates", str(bad)]) == 1
