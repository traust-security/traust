"""The location-path gate: catches reports whose producer skipped validation.

Staged enforcement, so both halves are pinned: warnings by default (exit 0) and
failure under --strict, which is the flip once the identity migration lands.
"""

import json
from pathlib import Path

from traust.cli.check_location_paths import main


def _report(tmp_path: Path, paths: list[str], name: str = "repo-security-audit.json") -> Path:
    p = tmp_path / name
    p.write_text(
        json.dumps(
            {
                "title": "t",
                "metadata": {
                    "date": "2026-08-18",
                    "scope": "s",
                    "repository": "https://github.com/org/repo",
                    "commit": "a" * 40,
                    "harness_version": "0.294.0",
                },
                "findings": [
                    {
                        "id": "FIND-001",
                        "title": "x",
                        "severity": "low",
                        "locations": [{"path": q} for q in paths],
                    }
                ],
            }
        )
    )
    return p


def test_clean_report_passes(tmp_path, capsys):
    assert main([str(_report(tmp_path, ["src/app.go", "SECURITY.md"]))]) == 0
    assert "names an artifact" in capsys.readouterr().out


def test_pseudo_paths_are_accepted(tmp_path):
    assert main([str(_report(tmp_path, ["repo:maintenance"]))]) == 0


def test_repo_root_markers_are_reported(tmp_path, capsys):
    for marker in (".", "/", "./", "/./"):
        rc = main([str(_report(tmp_path, [marker]))])
        out = capsys.readouterr().out
        assert rc == 0, "default is warn-only until the migration"
        assert "repo-root marker" in out, marker


def test_strict_fails_on_a_repo_root_marker(tmp_path):
    assert main([str(_report(tmp_path, ["."])), "--strict"]) == 1


def test_prose_in_a_path_is_reported(tmp_path, capsys):
    prose = "no normalisation of //, %2e, %2f performed in shim (WASM-SHIM-005). " * 4
    main([str(_report(tmp_path, [prose]))])
    assert "longer than" in capsys.readouterr().out


def test_newline_in_a_path_is_reported(tmp_path, capsys):
    main([str(_report(tmp_path, ["a.go\nthen b.go"]))])
    assert "contains a newline" in capsys.readouterr().out


def test_walks_a_tree_and_dedupes_symlinked_reports(tmp_path, capsys):
    real = tmp_path / "real"
    real.mkdir()
    _report(real, ["."], "a-security-audit.json")
    link_dir = tmp_path / "linked"
    link_dir.symlink_to(real)  # the findings tree carries gap-plan symlinks

    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "checked 1 report(s)" in out, out
