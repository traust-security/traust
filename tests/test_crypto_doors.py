"""`traust adapters crypto-source|crypto-image|crypto-cluster` end to end on traust-core,
in-process on SQLite and Postgres; podman and oc are fakes, nothing is pulled or exec'd."""

from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Iterator, Sequence
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.validation import (
    ValidationAction,
    ValidationActionKind,
    ValidationTarget,
)
from traust_core.v1.providers.process import ProcessResult

from tests.test_products_doors import _postgres
from traust.cli import crypto
from traust.context import load

FIXTURES = Path(__file__).parent / "fixtures" / "crypto"
REPO = "https://github.com/org/app"
SHA = "a" * 40
DIGEST = "sha256:" + "d" * 64
IMAGE = f"registry.example.com/ubi9-minimal@{DIGEST}"
TLS13 = (FIXTURES / "cluster" / "s_client-tls13.txt").read_bytes()
LEGACY = json.loads((FIXTURES / "legacy-crypto-probe.json").read_text())


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


class FakeProcess:
    """podman and oc, as far as the image and cluster tiers drive them."""

    def __init__(self, pods: dict[str, list[str]] | None = None) -> None:
        self.pods = pods or {}
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append(argv)
        if argv[0] == "podman":
            out = {
                "image": (FIXTURES / "image" / "podman-image-inspect.json").read_bytes(),
                "create": b"c" * 64 + b"\n",
            }.get(argv[1], b"")
            if argv[1] == "cp":
                return ProcessResult(tuple(argv), 125, b"", b"no such file or directory", 0)
            return ProcessResult(tuple(argv), 0, out, b"", 0)
        if argv[3] == "get":
            namespace = argv[argv.index("-n") + 1]
            return ProcessResult(tuple(argv), 0, "\n".join(self.pods[namespace]).encode(), b"", 0)
        if "s_client" in argv[-1]:
            return ProcessResult(tuple(argv), 0, TLS13, b"", 0)
        if "crypto-policies" in argv[-1]:
            out = b"FIPS\n---\n1\n---\nOpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2)\n"
            return ProcessResult(tuple(argv), 0, out, b"", 0)
        return ProcessResult(tuple(argv), 0, b"/proc/1/exe: go1.22.5\n", b"", 0)

    def execs(self) -> list[str]:
        return [c[c.index("-n") + 1] for c in self.calls if len(c) > 3 and c[3] == "exec"]


@pytest.fixture
def process(monkeypatch: pytest.MonkeyPatch) -> FakeProcess:
    fake = FakeProcess({"openshift-kube-apiserver": ["kube-apiserver-0"], "app": ["web-0"]})
    monkeypatch.setattr(
        crypto,
        "load",
        lambda home: Context(load(home).config, process=fake),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    return fake


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue()
    return rc, json.loads(text) if text else None, err.getvalue()


def source(home: Path, *argv: str) -> tuple[int, Any, str]:
    return run(crypto.source, home, str(FIXTURES / "repo"), "--repo-url", REPO, "--sha", SHA, *argv)


def test_source_without_a_recorded_sbom_says_how_to_record_one(home: Path) -> None:
    rc, out, err = source(home)
    assert (rc, out) == (2, None)
    assert f"commit {SHA} has no manifest SBOM recorded" in err
    assert "syft dir:" in err and "--sbom" in err


def test_source_is_the_checkout_plus_the_sbom_crypto_packages_and_reruns_alike(home: Path) -> None:
    rc, first, _ = source(home, "--sbom", str(FIXTURES / "manifest-sbom.cdx.json"))
    assert rc == 0
    # legacy minus the image's rpmdb openssl-libs, which `syft dir:` never lists (X8)
    assert {f["probe_id"] for f in first["facts"]} == {f["probe_id"] for f in LEGACY}
    assert len(first["facts"]) == len(LEGACY) - 1
    rc, again, _ = source(home)
    assert (rc, again) == (0, first)


def test_source_writes_the_census_to_out(home: Path, tmp_path: Path) -> None:
    out = tmp_path / "out" / "census.json"
    rc, summary, _ = source(
        home, "--sbom", str(FIXTURES / "manifest-sbom.cdx.json"), "--out", str(out)
    )
    assert rc == 0
    written = json.loads(out.read_text())
    assert summary == {"wrote": str(out), "facts": len(written["facts"]), "gaps": 0}


def test_source_refuses_a_malformed_sha(home: Path) -> None:
    rc, _, err = run(crypto.source, home, str(FIXTURES / "repo"), "--repo-url", REPO, "--sha", "x")
    assert rc == 2 and "ERROR" in err


def test_image_must_be_pinned_by_digest(home: Path) -> None:
    with pytest.raises(SystemExit) as exit_:
        run(crypto.image, home, "registry.example.com/ubi9-minimal:latest")
    assert exit_.value.code == 2


def test_image_without_a_recorded_sbom_never_touches_the_runtime(
    home: Path, process: FakeProcess
) -> None:
    rc, _, err = run(crypto.image, home, IMAGE)
    assert rc == 2 and f"image {DIGEST} has no SBOM recorded" in err
    assert process.calls == []


def test_image_is_what_it_ships_plus_its_sbom_crypto_packages(
    home: Path, process: FakeProcess
) -> None:
    sbom = FIXTURES / "image" / "syft-image-scan.cdx.json"
    rc, census, _ = run(crypto.image, home, IMAGE, "--sbom", str(sbom), "--no-pull")
    assert rc == 0
    assert census["digest"] == DIGEST
    probes = {f["probe_id"] for f in census["facts"]}
    assert "IMG_ENV" in probes
    assert any(f.get("package") == "openssl-libs" for f in census["facts"])
    assert not any(c[1] == "pull" for c in process.calls)
    assert any(c[:3] == ["podman", "image", "inspect"] for c in process.calls)


def targets(tmp_path: Path, **extra: Any) -> Path:
    doc = {"clusters": [{"context": "lab", "namespaces": ["app"]}], **extra}
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def cluster(home: Path, path: Path, *namespaces: str) -> tuple[int, Any, str]:
    return run(
        crypto.cluster,
        home,
        "--context",
        "lab",
        "--namespaces",
        *namespaces,
        "--targets",
        str(path),
    )


def test_cluster_probes_only_the_namespaces_the_engagement_allows(
    home: Path, process: FakeProcess, tmp_path: Path
) -> None:
    rc, census, _ = cluster(home, targets(tmp_path), "openshift-kube-apiserver", "app")
    assert rc == 0
    decisions = {s["namespace"]: s["decision"] for s in census["scope"]}
    assert decisions["app"] == {"allowed": True, "reason": "ok"}
    assert not decisions["openshift-kube-apiserver"]["allowed"]
    assert set(process.execs()) == {"app"}
    assert any(g.startswith("scope denied: openshift-kube-apiserver") for g in census["gaps"])


def test_cluster_with_nothing_in_scope_execs_nothing(
    home: Path, process: FakeProcess, tmp_path: Path
) -> None:
    rc, census, _ = cluster(home, targets(tmp_path), "openshift-etcd")
    assert rc == 0 and census["facts"] == []
    assert process.calls == []


def test_cluster_after_the_engagement_expired_execs_nothing(
    home: Path, process: FakeProcess, tmp_path: Path
) -> None:
    rc, census, _ = cluster(home, targets(tmp_path, expires="2020-01-01"), "app")
    assert rc == 0 and process.calls == []
    assert census["scope"][0]["decision"]["reason"] == "engagement expired 2020-01-01"


@pytest.mark.parametrize(
    "body",
    ["clusters: [", "clusters: [{namespaces: [app]}]", "off_limits: [{colour: red}]"],
    ids=["not-yaml", "cluster-without-context", "unknown-off-limit-field"],
)
def test_cluster_refuses_a_malformed_targets_file(
    home: Path, process: FakeProcess, tmp_path: Path, body: str
) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text(body)
    rc, _, err = cluster(home, path, "app")
    assert rc == 2 and f"targets {path}" in err
    assert process.calls == []


def test_cluster_refuses_unsafe_groups(home: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit_:
        run(
            crypto.cluster,
            home,
            *("--context", "lab", "--namespaces", "app", "--targets", str(targets(tmp_path))),
            *("--groups", "X25519;rm -rf /"),
        )
    assert exit_.value.code == 2


def test_engagement_scope_keeps_off_limits_and_explicit_control_plane(tmp_path: Path) -> None:
    path = targets(
        tmp_path,
        clusters=[{"context": "lab", "namespaces": ["app", "openshift-kube-apiserver"]}],
        off_limits=[{"namespace": "app", "verb": "exec"}],
    )
    scope = crypto.engagement_scope(path)
    exec_ = ValidationAction(kind=ValidationActionKind.K8S, verb="exec")
    today = date(2026, 10, 23)
    allowed = {
        ns: scope.permits(exec_, ValidationTarget(context="lab", namespace=ns), as_of=today)
        for ns in ("openshift-kube-apiserver", "app", "other")
    }
    assert allowed == {"openshift-kube-apiserver": True, "app": False, "other": False}


def test_engagement_scope_reads_the_validate_findings_example() -> None:
    example = (
        Path(__file__).parents[1] / "harnessing/5-validate/validate-findings/targets.example.yaml"
    )
    scope = crypto.engagement_scope(example)
    exec_ = ValidationAction(kind=ValidationActionKind.K8S, verb="exec")
    on = ValidationTarget(context="lab-hub", namespace="ramen-ops")
    assert scope.expires == date(2026, 7, 1)
    assert scope.permits(exec_, on, as_of=date(2026, 6, 30))
    assert not scope.permits(
        exec_, on.model_copy(update={"namespace": "openshift-etcd"}), as_of=date(2026, 6, 30)
    )
