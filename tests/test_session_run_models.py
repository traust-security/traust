"""`traust session run` resolves the role's model in-process on traust-core's model registry: an
unknown role or no registry is a bad request; an invalid registry fails loud (exit 2)."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from traust.cli import session

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(tmp_path))
    return tmp_path


def run(*argv: str) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = session.run(["--skill", "vuln-scan", *argv])
    return rc, json.loads(out.getvalue())


def test_the_roles_model_is_the_registrys_first_approved_at_its_floor(home: Path) -> None:
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    assert session.resolve_model("vuln-scan") == "claude-opus-5-5"


@pytest.mark.parametrize(
    ("registry", "message"),
    [(True, "unknown role 'no-such-role'"), (False, "no model registry (model-registry.yaml)")],
    ids=["unknown role", "no registry"],
)
def test_no_model_for_the_role_is_a_bad_request(
    home: Path, capsys: pytest.CaptureFixture[str], registry: bool, message: str
) -> None:
    if registry:
        (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    rc, result = run("--role", "no-such-role")
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", "bad_request")
    assert message in capsys.readouterr().err


def test_an_invalid_registry_exits_2_with_the_config_error(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / "model-registry.yaml").write_text("version: 1\nroles: not-a-mapping\n")
    with pytest.raises(SystemExit) as exit:
        session.run(["--skill", "vuln-scan", "--role", "vuln-scan"])
    assert (
        exit.value.code == 2 and "spend not resolvable: model registry" in capsys.readouterr().err
    )
