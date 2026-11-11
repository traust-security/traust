"""`traust portfolio file`: the CLI layer only. The URL, sha and path are parsed and become one
`sync.find_file` call; the text (or null for no such file) is printed as JSON; a refused input or
a typed door error is exit 2 with its reason. The forge read itself is traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoPath

from traust.cli import portfolio_onboard

REPO = "https://github.com/example-org/operator"
SHA = "0123456789abcdef0123456789abcdef01234567"
CSV = "bundle/manifests/example.clusterserviceversion.yaml"


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(calls=[], result="kind: ClusterServiceVersion\n")

    def find_file(*args: Any) -> str | None:
        stub.calls.append(args)
        if isinstance(stub.result, Exception):
            raise stub.result
        return stub.result

    services = SimpleNamespace(sync=SimpleNamespace(find_file=find_file))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = portfolio_onboard.file(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_file_at_a_pinned_commit(doors, home):
    rc, out = run(home, "--repo", REPO + ".git/", "--sha", SHA, CSV)

    assert rc == 0
    assert out == {"repo": REPO, "sha": SHA, "path": CSV, "file": "kind: ClusterServiceVersion\n"}
    [(url, path, sha)] = doors.calls
    assert url == HttpsRepoUrl.parse(REPO, ["github.com"])
    assert path == RepoPath(CSV) and sha == GitSha(SHA)


def test_no_such_file_is_null(doors, home):
    doors.result = None

    rc, out = run(home, "--repo", REPO, "--sha", SHA, CSV)

    assert rc == 0 and out["file"] is None


@pytest.mark.parametrize(
    "argv,reason",
    [
        (("--repo", "https://evil.example/org/repo", "--sha", SHA, CSV), "evil.example"),
        (("--repo", REPO, "--sha", "main", CSV), "not a full lowercase git sha"),
        (("--repo", REPO, "--sha", SHA, "../etc/passwd"), "not a relative repository file path"),
    ],
)
def test_refused_input_exits_2_before_the_door(doors, home, argv, reason):
    rc, err = run(home, *argv)

    assert rc == 2 and reason in err
    assert doors.calls == []


def test_door_error_exits_2_with_the_reason(doors, home):
    doors.result = ConfigError("gh is not authenticated")

    rc, err = run(home, "--repo", REPO, "--sha", SHA, CSV)

    assert rc == 2 and "gh is not authenticated" in err
