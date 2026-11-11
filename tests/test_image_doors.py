"""`traust adapters image-sbom|image-packages`: the CLI layer only. Each op is one
`ExposureService` door; the SBOM parser and image rows are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.dependencies import NoImageSbomError

from traust.cli import image

DIGEST = "sha256:" + "d" * 64
IMAGE = f"registry.example.com/console-rhel9@{DIGEST}"
REF = uuid.uuid4()


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _row(ecosystem: str, name: str, version: str) -> SimpleNamespace:
    return SimpleNamespace(
        package=SimpleNamespace(ecosystem=ecosystem, name=name),
        dependency=SimpleNamespace(version=version),
    )


ROWS = [
    _row("rpm", "openssl-libs", "3.0.7-27.el9"),
    _row("rpm", "glibc", "2.34-100.el9"),
    _row("go", "golang.org/x/net", "v0.23.0"),
]


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    recorded = SimpleNamespace(model_dump=lambda **_: {"digest": DIGEST, "sbom_id": "s-1"})
    stub = SimpleNamespace(
        ingest=Door(recorded),
        packages=Door(ROWS),
        register_repository=Door(SimpleNamespace(id=uuid.uuid4())),
        register_ref=Door(SimpleNamespace(id=REF)),
    )
    services = SimpleNamespace(
        exposure=SimpleNamespace(ingest_image_sbom=stub.ingest, image_dependencies=stub.packages),
        portfolio=SimpleNamespace(
            register_repository=stub.register_repository, register_ref=stub.register_ref
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


@pytest.fixture
def sbom(tmp_path: Path) -> Path:
    path = tmp_path / "console.cdx.json"
    path.write_text('{"bomFormat": "CycloneDX"}')
    return path


def run(entry: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = entry(["--config-home", str(home), *argv])
        except SystemExit as e:
            rc = e.code
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_image_sbom_records_the_bytes_on_the_digest(doors, home, sbom):
    rc, out = run(image.sbom, home, IMAGE, "--sbom", str(sbom), "--platform", "linux/amd64")
    assert rc == 0
    assert out == {"digest": DIGEST, "sbom_id": "s-1"}
    assert doors.ingest.calls == [(sbom.read_bytes(), DIGEST, "linux/amd64", None)]
    assert doors.register_ref.calls == []


def test_image_sbom_links_the_declared_source(doors, home, sbom):
    rc, _ = run(
        image.sbom,
        home,
        IMAGE,
        "--sbom",
        str(sbom),
        "--repo-url",
        "https://github.com/org/console",
        "--sha",
        "a" * 40,
    )
    assert rc == 0
    assert doors.ingest.calls[0][3] == REF
    assert doors.register_repository.calls[0][1] is False


def test_image_sbom_source_needs_both_flags(doors, home, sbom):
    rc, err = run(image.sbom, home, IMAGE, "--sbom", str(sbom), "--sha", "a" * 40)
    assert rc == 2
    assert "--repo-url and --sha go together" in err
    assert doors.ingest.calls == []


def test_image_sbom_refuses_a_tag(doors, home, sbom):
    rc, err = run(image.sbom, home, "registry.example.com/console:v2.12", "--sbom", str(sbom))
    assert rc == 2
    assert "pin the image by digest" in err
    assert doors.ingest.calls == []


def test_image_sbom_conflict_is_exit_2(doors, home, sbom):
    doors.ingest.result = ConflictError(f"image {DIGEST} already recorded with sbom s-0")
    rc, err = run(image.sbom, home, IMAGE, "--sbom", str(sbom))
    assert rc == 2
    assert "already recorded" in err


def test_image_sbom_missing_file_is_exit_2(doors, home, tmp_path):
    rc, err = run(image.sbom, home, IMAGE, "--sbom", str(tmp_path / "absent.json"))
    assert rc == 2
    assert "absent.json" in err
    assert doors.ingest.calls == []


def test_image_packages_counts_per_ecosystem(doors, home):
    rc, out = run(image.packages, home, DIGEST)
    assert rc == 0
    assert out == {"digest": DIGEST, "total": 3, "by_ecosystem": {"rpm": 2, "go": 1}}
    assert doors.packages.calls == [(DIGEST,)]


def test_image_packages_list(doors, home):
    rc, out = run(image.packages, home, IMAGE, "--list")
    assert rc == 0
    assert out["packages"][0] == {
        "ecosystem": "rpm",
        "name": "openssl-libs",
        "version": "3.0.7-27.el9",
    }


def test_image_packages_unrecorded_is_exit_2(doors, home):
    doors.packages.result = NoImageSbomError(DIGEST)
    rc, err = run(image.packages, home, DIGEST)
    assert rc == 2
    assert DIGEST in err


def test_image_packages_empty_sbom(doors, home):
    doors.packages.result = []
    rc, out = run(image.packages, home, DIGEST)
    assert rc == 0
    assert out == {"digest": DIGEST, "total": 0, "by_ecosystem": {}}
