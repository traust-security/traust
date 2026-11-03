from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.values import HttpsRepoUrl

from traust.cli.__main__ import main


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def command(home: Path, operation: str, *args: str) -> tuple[int, Any]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = main(["dashboard", operation, "--config-home", str(home), *args])
    return rc, json.loads(stdout.getvalue()) if stdout.getvalue().strip() else stderr.getvalue()


@pytest.mark.parametrize("view", ["scoreboard", "executive-summary", "threat-register"])
def test_grouped_capture_history_read_and_compare_preserve_original_bytes(
    home: Path, tmp_path: Path, view: str
) -> None:
    original = tmp_path / "original"
    rc, first = command(home, "capture", view, "--note", "Published policy", "--out", str(original))
    assert rc == 0, first
    artifact_id = first["artifact_id"]
    retained = {p.name: p.read_bytes() for p in original.iterdir()}
    assert (
        json.loads(retained[f"{artifact_id}.snapshot.json"])["methodology_note"]
        == "Published policy"
    )

    rc, second = command(
        home, "capture", view, "--note", "Second report", "--out", str(tmp_path / "second")
    )
    assert rc == 0, second
    assert second["artifact_id"] != artifact_id
    history_dir = tmp_path / "history"
    rc, history = command(home, "history", view, "--out", str(history_dir))
    assert rc == 0, history
    assert {row["artifact_id"] for row in history["snapshots"]} == {
        artifact_id,
        second["artifact_id"],
    }
    assert {row["methodology_note"] for row in history["snapshots"]} == {
        "Published policy",
        "Second report",
    }
    assert {Path(p).suffix for p in history["written"]} == {".json", ".md", ".html"}

    restored = tmp_path / "restored"
    rc, read = command(home, "read-report", artifact_id, "--out", str(restored))
    assert rc == 0, read
    assert {p.name: p.read_bytes() for p in restored.iterdir()} == retained
    rc, comparison = command(
        home, "compare", second["artifact_id"], "--out", str(tmp_path / "comparison")
    )
    assert rc == 0, comparison
    assert comparison["comparison"]["baseline_artifact_id"] == artifact_id
    assert comparison["comparison"]["compared_artifact_id"] == second["artifact_id"]
    for rendered in [*history_dir.glob("*.html"), *(tmp_path / "comparison").glob("*.html")]:
        text = rendered.read_text()
        assert "<script" not in text
        assert "default-src 'none'" in text
    assert {p.name: p.read_bytes() for p in original.iterdir()} == retained


def test_grouped_current_comparison_reports_actual_population_change(
    home: Path, tmp_path: Path
) -> None:
    rc, first = command(
        home,
        "capture",
        "scoreboard",
        "--note",
        "Before registration",
        "--out",
        str(tmp_path / "before"),
    )
    assert rc == 0, first
    assert first["model"]["repositories"] == 0
    core = Context.from_file(home / "traust.yaml")
    core.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/app", ["github.com"]), public=True
    )
    rc, result = command(home, "compare", first["artifact_id"], "--against", "current")
    assert rc == 0, result
    changes = {row["path"]: row for row in result["changes"]}
    assert (changes["/repositories"]["before"], changes["/repositories"]["after"]) == (0, 1)
    rc, read = command(home, "read-report", first["artifact_id"])
    assert rc == 0, read
    assert json.loads(read["snapshot"]["document"]["model_json"])["repositories"] == 0


def test_first_report_has_no_previous_comparison_and_refusal_writes_nothing(
    home: Path, tmp_path: Path
) -> None:
    rc, first = command(
        home, "capture", "threat-register", "--note", "First", "--out", str(tmp_path / "first")
    )
    assert rc == 0, first
    out = tmp_path / "comparison"
    rc, _ = command(home, "compare", first["artifact_id"], "--out", str(out))
    assert rc == 2
    assert not out.exists()
    rc, _ = command(
        home, "capture", "scoreboard", "--note", " \n ", "--out", str(tmp_path / "blank")
    )
    assert rc == 2
    assert not (tmp_path / "blank").exists()
    rc, history = command(home, "history", "scoreboard")
    assert rc == 0 and history["snapshots"] == []


def test_executive_panels_and_segments_survive_capture_and_history(
    home: Path, tmp_path: Path
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "services").mkdir(parents=True)
    (inputs / "services/scope-repos.csv").write_text(
        "URL\nhttps://github.com/example-org/service.git\n"
    )
    core = Context.from_file(home / "traust.yaml")
    core.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example-org/service", ("github.com",)), public=True
    )
    scope = ("--by-segment", "--inputs-root", str(inputs), "--panel", "isolation")
    rc, captured = command(
        home,
        "capture",
        "executive-summary",
        *scope,
        "--note",
        "Segment-scoped leadership report",
        "--out",
        str(tmp_path / "captured"),
    )
    assert rc == 0, captured
    assert captured["model"]["segments"]["rows"][0]["repositories"] == 1
    assert captured["model"]["isolation"]["reviews"] == []
    rc, history = command(home, "history", "executive-summary", *scope)
    assert rc == 0, history
    assert [row["artifact_id"] for row in history["snapshots"]] == [captured["artifact_id"]]
    rc, unscoped = command(home, "history", "executive-summary")
    assert rc == 0, unscoped
    assert unscoped["snapshots"] == []
    rc, read = command(home, "read-report", captured["artifact_id"])
    assert rc == 0, read
    assert json.loads(read["snapshot"]["document"]["model_json"]) == captured["model"]
