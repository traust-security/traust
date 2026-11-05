"""`traust.context.load` is the one loader: every command gets a Context on which
`Context.services()` sees every registered provider."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, IntegrityError
from traust_core.v1.models.artifacts import PqcFactsArtifact
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.inventory import ProductSlug
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.process import ProcessResult, ProcessRunner

from traust import context
from traust.cli import compliance
from traust.context import load

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {"checkov", "gitleaks", "gitleaks-history", "govulncheck", "grype", "joern"}
TOOLS |= {"opengrep", "osv", "osv_sbom", "yara"}


@pytest.fixture(scope="module")
def core(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Context]:
    tmp = tmp_path_factory.mktemp("load")
    home = tmp / "config"
    shutil.copytree(ROOT / "tests" / "fixtures" / "config", home)
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp / "store")}))
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("XDG_CACHE_HOME", str(tmp / "cache"))
        yield load(home)


PROVIDERS: dict[str, Callable[[Context], Any]] = {
    "rule packs": lambda c: c.services().detection_quality.rule_packs(),
    "tools": lambda c: {b.capability.name for b in c.services().catalog.readiness(None)} >= TOOLS,
    "tool floors": lambda c: c.tools.get("gitleaks") and c.tool_floors.get("gitleaks"),
    "canaries": lambda c: c.canaries.check().detail,
    "adr source": lambda c: c.adr_source,
    "docs source": lambda c: c.doc_source,
    "fleet-fix applier": lambda c: c.fleet_fix_applier,
    "fleet-fix goldens": lambda c: c.fleet_fix_goldens,
    "sla policy": lambda c: c.default_sla_policy,
    "attack catalog": lambda c: c.attack_catalog,
}


@pytest.mark.parametrize("provider", PROVIDERS)
def test_the_context_sees_every_registered_provider(core: Context, provider: str) -> None:
    assert PROVIDERS[provider](core)


def test_the_context_is_the_only_loader() -> None:
    loaders = {n for n in vars(context) if n.startswith("load")}
    # load_caller is identity; load_spend_core is load() that requires the model registry
    # (exit 2 without it).
    assert loaders == {"load", "load_caller", "load_spend_core"}


def test_normal_app_docs_command_fetches_registered_product_guides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    data: dict[str, object] = {"home": str(tmp_path / "store")}
    path = home / "traust.yaml"
    path.write_text(yaml.safe_dump(data))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    product = load(home).services().portfolio.register_product(ProductSlug("platform"), "Platform")
    assert product.id is not None
    calls: list[tuple[str, ...]] = []
    body = (ROOT / "tests" / "fixtures" / "compliance-docs.html").read_bytes()

    def fetched(self: ProcessRunner, argv: Sequence[str], **_: Any) -> ProcessResult:
        calls.append(tuple(argv))
        return ProcessResult(tuple(argv), 0, body, b"", 0.0)

    monkeypatch.setattr(ProcessRunner, "run", fetched)
    args = [
        "platform",
        "--config-home",
        str(home),
        "--product-slug",
        "red_hat_enterprise_linux",
        "--version",
        "9",
        "--guide",
        "security_hardening",
    ]
    assert compliance.docs(args) == 0

    (guide,) = json.loads(capsys.readouterr().out)
    url = (
        "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9"
        "/html-single/security_hardening/index"
    )
    assert (guide["product_slug"], guide["version"], guide["guide"], guide["url"]) == (
        "red_hat_enterprise_linux",
        "9",
        "security_hardening",
        url,
    )
    assert "applications reject weak algorithms by default." in guide["text"]
    assert (
        f"[{url}#system-wide-crypto-policies_using-the-system-wide-cryptographic-policies]"
        in guide["text"]
    )
    assert "<code" not in guide["text"]
    assert len(calls) == 1 and calls[0][0] == "curl" and calls[0][-1] == url


def test_normal_app_refuses_unknown_configured_product(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (tmp_path / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "compliance": {
                    "docs_targets": {
                        str(uuid4()): {"product_slug": "red_hat_enterprise_linux", "version": "9"}
                    }
                },
            }
        )
    )
    with pytest.raises(SystemExit) as refused:
        load(tmp_path)
    assert refused.value.code == 2
    assert capsys.readouterr().out == ""


def test_normal_app_docs_command_refuses_unconfigured_registered_product(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (tmp_path / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    load(tmp_path).services().portfolio.register_product(ProductSlug("platform"), "Platform")
    calls: list[tuple[str, ...]] = []

    def unexpected(self: ProcessRunner, argv: Sequence[str], **_: Any) -> ProcessResult:
        calls.append(tuple(argv))
        raise AssertionError("unconfigured documentation must not start a transport")

    monkeypatch.setattr(ProcessRunner, "run", unexpected)
    assert compliance.docs(["platform", "--config-home", str(tmp_path)]) == 2
    assert capsys.readouterr().out == ""
    assert calls == []


@pytest.fixture
def pqc_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep the shipped rules and real core provider; control only the installed child."""
    pack = tmp_path / "pqc-readiness"
    shutil.copytree(context.skill_dir("pqc-readiness") / "rules", pack / "rules")
    (pack / "bin").mkdir()
    binary = pack / "bin" / "pqc-scan"
    report = {
        "summary": {"scanned_files": 1, "skipped_files": 0},
        "findings": [
            {
                "rule_id": "API_GO_CRYPTO_RSA",
                "location": {"file": "keys.go", "line": 2},
                "evidence": {"match": "crypto/rsa"},
            }
        ],
    }
    binary.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "with pathlib.Path(__file__).with_suffix('.calls').open('a') as calls:\n"
        "    calls.write('scan\\n')\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--out-dir') + 1])\n"
        f"(output / 'report.json').write_text({json.dumps(report)!r})\n"
        "(output / 'cbom.json').write_bytes(b'controlled-cbom')\n"
    )
    binary.chmod(0o700)
    binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(context, "skill_dir", lambda name: pack)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return pack


def _load_pqc_app(tmp_path: Path, *, allowed: bool = True) -> Context:
    (tmp_path / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "process": {"allowed_binaries": ["pqc-scan"] if allowed else []},
            }
        )
    )
    return load(tmp_path)


def _pqc_ref(core: Context) -> UUID:
    services = core.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/widget", core.config.forge_hosts),
        public=False,
    )
    ref = services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    services.exposure.ingest_sbom(b'{"bomFormat":"CycloneDX","components":[]}', ref.id)
    return ref.id


def test_app_pqc_prescan_persists_child_facts_and_replays_after_reload(
    tmp_path: Path, pqc_pack: Path
) -> None:
    core = _load_pqc_app(tmp_path)
    calls = pqc_pack / "bin" / "pqc-scan.calls"
    assert not calls.exists()
    ref_id = _pqc_ref(core)
    source = tmp_path / "source"
    source.mkdir()
    (source / "keys.go").write_text('package sample\nimport "crypto/rsa"\n')
    request = ToolRequest(workspace=source)
    services = core.services()
    first = services.pqc.prescan(ref_id, request)
    assert first.scanned
    assert first.cbom == b"controlled-cbom"
    assert [
        (fact.file, fact.line, fact.match)
        for fact in first.facts
        if fact.rule_id == "API_GO_CRYPTO_RSA"
    ] == [("keys.go", 2, "crypto/rsa")]
    (artifact,) = services.artifacts.list_for_assessment(first.assessment_id)
    document = services.artifacts.read(artifact.id, PqcFactsArtifact)
    stamps = json.loads(document.payload)["stamps"]
    assert (stamps["adapter_version"], stamps["pqc_scan_commit"]) == (
        "1.4.0",
        "be5c760adb7d1d4d99e39d35d87d2956079db76e",
    )
    assert (
        stamps["binary_sha256"]
        == hashlib.sha256((pqc_pack / "bin" / "pqc-scan").read_bytes()).hexdigest()
    )

    reloaded = load(tmp_path).services()
    repeated = reloaded.pqc.prescan(ref_id, request)
    assert not repeated.scanned
    assert repeated.assessment_id == first.assessment_id
    assert repeated.facts == first.facts
    (state,) = reloaded.pqc.scan_states(PqcFilter(repository_ref_ids=(ref_id,)))
    assert (state.assessment_id, state.basis, state.current) == (
        first.assessment_id,
        "source",
        True,
    )
    assert calls.read_text().splitlines() == ["scan"]


@pytest.mark.parametrize(
    ("installation", "error"),
    [
        ("missing", ConfigError),
        ("checksum-mismatch", IntegrityError),
        ("not-executable", ConfigError),
        ("not-allowed", ConfigError),
    ],
)
def test_app_pqc_prescan_refuses_unready_installation_without_recording_facts(
    tmp_path: Path, pqc_pack: Path, installation: str, error: type[Exception]
) -> None:
    binary = pqc_pack / "bin" / "pqc-scan"
    if installation == "missing":
        binary.unlink()
    elif installation == "checksum-mismatch":
        binary.with_suffix(".sha256").write_text("0" * 64)
    elif installation == "not-executable":
        binary.chmod(0o600)
    core = _load_pqc_app(tmp_path, allowed=installation != "not-allowed")
    ref_id = _pqc_ref(core)
    source = tmp_path / "source"
    source.mkdir()
    services = core.services()
    with pytest.raises(error):
        services.pqc.prescan(ref_id, ToolRequest(workspace=source))
    (state,) = services.pqc.scan_states(PqcFilter(repository_ref_ids=(ref_id,)))
    assert state.assessment_id is None
    assert not binary.with_suffix(".calls").exists()
