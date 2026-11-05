"""`traust.context.load` is the one loader: every command gets a Context on which
`Context.services()` sees every registered provider."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.inventory import ProductSlug
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


@pytest.mark.parametrize("explicit", [True], ids=["explicit-target"])
def test_normal_app_docs_command_fetches_registered_product_guides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    explicit: bool,
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    data: dict[str, object] = {"home": str(tmp_path / "store")}
    path = home / "traust.yaml"
    path.write_text(yaml.safe_dump(data))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    product = load(home).services().portfolio.register_product(ProductSlug("platform"), "Platform")
    assert product.id is not None
    if not explicit:
        data["compliance"] = {
            "docs_targets": {
                str(product.id): {
                    "product_slug": "red_hat_enterprise_linux",
                    "version": "9",
                    "guides": ["security_hardening"],
                }
            }
        }
        path.write_text(yaml.safe_dump(data))
    calls: list[tuple[str, ...]] = []
    body = (ROOT / "tests" / "fixtures" / "compliance-docs.html").read_bytes()

    def fetched(self: ProcessRunner, argv: Sequence[str], **_: Any) -> ProcessResult:
        calls.append(tuple(argv))
        return ProcessResult(tuple(argv), 0, body, b"", 0.0)

    monkeypatch.setattr(ProcessRunner, "run", fetched)
    args = ["platform", "--config-home", str(home)]
    if explicit:
        args += [
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
