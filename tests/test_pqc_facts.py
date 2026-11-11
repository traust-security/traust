"""Native ``traust pqc prescan`` over Core's real census, provider and stores.

SQLite and Postgres retain the legacy census/SBOM boundaries. Only the external
scanner executable is controlled; Core processes and publishes every document.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml
from traust_core.v1.models.artifacts import PqcFactsArtifact
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.providers.pqc import MAX_CBOM_BYTES, MAX_REPORT_BYTES

from tests.test_products_doors import _postgres
from traust import context
from traust.cli import pqc
from traust.cli.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures" / "crypto"
SBOM = FIXTURES / "manifest-sbom.cdx.json"
REPO = "https://github.com/org/app"
SHA = "a" * 40
CBOM = b'[\n  {"algorithm": "RSA", "bits": 2048}\n]\n'
REPORT = {"summary": {"scanned_files": 19, "skipped_files": 0}, "findings": []}


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {
        "home": str(tmp_path / "store"),
        "process": {"allowed_binaries": ["pqc-scan"]},
    }
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


@pytest.fixture(autouse=True)
def scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The normal load() registration, with a fixture child instead of the Rust binary."""
    pack = tmp_path / "pqc-readiness"
    shutil.copytree(context.skill_dir("pqc-readiness") / "rules", pack / "rules")
    (pack / "bin").mkdir()
    binary = pack / "bin" / "pqc-scan"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "binary = pathlib.Path(__file__)\n"
        "with binary.with_suffix('.calls').open('a') as calls:\n"
        "    calls.write('scan\\n')\n"
        "scenario = json.loads(binary.with_suffix('.scenario').read_text())\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--out-dir') + 1])\n"
        "if scenario.get('report') is not None:\n"
        "    (output / 'report.json').write_text(scenario['report'])\n"
        "if scenario.get('large_report'):\n"
        "    (output / 'report.json').write_bytes(b' ' * scenario['large_report'])\n"
        "if scenario.get('cbom', True):\n"
        f"    (output / 'cbom.json').write_bytes({CBOM!r})\n"
        "if scenario.get('large_cbom'):\n"
        "    (output / 'cbom.json').write_bytes(b' ' * scenario['large_cbom'])\n"
        "sys.exit(scenario.get('exit', 0))\n"
    )
    binary.chmod(0o700)
    binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    scenario(binary, report=json.dumps(REPORT))
    original_skill_dir = context.skill_dir
    monkeypatch.setattr(
        context,
        "skill_dir",
        lambda name: pack if name == "pqc-readiness" else original_skill_dir(name),
    )
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return binary


def scenario(scanner: Path, **settings: Any) -> None:
    scanner.with_suffix(".scenario").write_text(json.dumps(settings))


def prescan(home: Path, out: Path, *argv: str) -> tuple[int, dict | None, str]:
    args = [
        "pqc",
        "prescan",
        "--config-home",
        str(home),
        "--repo-url",
        REPO,
        "--sha",
        SHA,
        "--out",
        str(out),
        *argv,
    ]
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = main(args)
    text = stdout.getvalue()
    return rc, json.loads(text) if text else None, stderr.getvalue()


def facts(home: Path, out: Path, *argv: str) -> dict:
    rc, receipt, err = prescan(home, out, *argv)
    assert rc == 0, err
    assert receipt is not None
    assert receipt["out"] == str(out)
    doc = json.loads(out.read_bytes())
    assert receipt["facts"] == len(doc["facts"])
    artifact = (
        context.load(home)
        .services()
        .artifacts.latest_for_assessment(UUID(receipt["assessment_id"]), PqcFactsArtifact)
    )
    assert artifact is not None and out.read_bytes() == artifact.payload
    return doc


def assert_unscanned(home: Path) -> None:
    services = context.load(home).services()
    (state,) = services.pqc.scan_states(PqcFilter())
    assert state.assessment_id is None
    assert services.pqc.find(state.repository_ref_id) is None


def test_source_mode_maps_the_checkout_and_its_sbom_packages(home: Path, tmp_path: Path) -> None:
    doc = facts(
        home,
        tmp_path / "facts.json",
        "--repo-dir",
        str(FIXTURES / "repo"),
        "--sbom",
        str(SBOM),
    )
    by_rule = {f["rule_id"]: f for f in doc["facts"]}
    assert doc["coverage"]["assessment_basis"] == "source"
    assert doc["coverage"]["scanned_files"] == 19
    assert by_rule["HP_CHAIN_GO_TOOLCHAIN"]["file"] == "go.mod"
    assert by_rule["HP_CHAIN_GO_TOOLCHAIN"]["pqc_capable"] is True
    assert {"HP_CHAIN_PYTHON_CRYPTO_DEP", "HP_CHAIN_RUST_TLS_BACKEND"} <= by_rule.keys()
    assert "HP_SBOM_CRYPTO_COMPONENT" not in by_rule
    assert all(f["fips_mode"] for f in doc["facts"] if f["rule_id"].startswith("HP_CHAIN_"))


def test_source_mode_without_a_recorded_sbom_says_how_to_record_one(
    home: Path, scanner: Path, tmp_path: Path
) -> None:
    out, cbom = tmp_path / "facts.json", tmp_path / "cbom.json"
    rc, receipt, err = prescan(
        home, out, "--repo-dir", str(FIXTURES / "repo"), "--cbom-out", str(cbom)
    )
    assert (rc, receipt) == (2, None)
    assert f"commit {SHA} has no manifest SBOM recorded" in err
    assert "syft dir:" in err and "--sbom" in err
    assert not out.exists() and not cbom.exists()
    assert not scanner.with_suffix(".calls").exists()
    assert_unscanned(home)


def test_sbom_mode_is_every_crypto_package_without_executing_source_scanner(
    home: Path, scanner: Path, tmp_path: Path
) -> None:
    scenario(scanner, exit=23)
    doc = facts(home, tmp_path / "facts.json", "--from-sbom", str(SBOM))
    assert doc["coverage"]["assessment_basis"] == "sbom-only"
    assert doc["coverage"]["scanned_files"] is None
    assert {f["rule_id"] for f in doc["facts"]} == {"HP_SBOM_CRYPTO_COMPONENT"}
    details = {f["detail"] for f in doc["facts"]}
    assert {"cryptography==43.0.1", "golang.org/x/crypto v0.36.0"} <= details
    assert not any("flask" in d or "rails" in d for d in details)
    assert not scanner.with_suffix(".calls").exists()
    out, replay = tmp_path / "facts.json", tmp_path / "replayed.json"
    rc, repeated, err = prescan(home, replay, "--from-sbom", str(SBOM))
    assert rc == 0, err
    assert repeated["scanned"] is False
    assert replay.read_bytes() == out.read_bytes()
    assert not scanner.with_suffix(".calls").exists()


def test_source_uses_recorded_sbom_but_does_not_reuse_sbom_only_facts(
    home: Path, scanner: Path, tmp_path: Path
) -> None:
    out = tmp_path / "facts.json"
    assert prescan(home, out, "--from-sbom", str(SBOM))[0] == 0
    rc, receipt, err = prescan(home, out, "--repo-dir", str(FIXTURES / "repo"))
    assert rc == 0, err
    assert receipt["scanned"] is True
    doc = json.loads(out.read_bytes())
    assert doc["coverage"]["assessment_basis"] == "source"
    assert "HP_CHAIN_GO_TOOLCHAIN" in {f["rule_id"] for f in doc["facts"]}
    assert "HP_SBOM_CRYPTO_COMPONENT" not in {f["rule_id"] for f in doc["facts"]}
    assert scanner.with_suffix(".calls").read_text().splitlines() == ["scan"]


def test_exports_exact_persisted_facts_and_raw_cbom_and_reuses_after_reload(
    home: Path, scanner: Path, tmp_path: Path
) -> None:
    report = {
        **REPORT,
        "findings": [
            {
                "rule_id": "API_GO_CRYPTO_RSA",
                "location": {"file": "vendor/keys.go", "line": 7},
                "description": "RSA 2048 key",
                "evidence": {"match": "rsa.GenerateKey(random, 2048)"},
            }
        ],
    }
    scenario(scanner, report=json.dumps(report))
    out, cbom = tmp_path / "exports" / "facts.json", tmp_path / "exports" / "cbom.json"
    rc, first, err = prescan(
        home,
        out,
        "--repo-dir",
        str(FIXTURES / "repo"),
        "--sbom",
        str(SBOM),
        "--cbom-out",
        str(cbom),
        "--public",
    )
    assert rc == 0, err
    assert first["scanned"] is True and first["cbom_out"] == str(cbom)
    assert cbom.read_bytes() == CBOM
    services = context.load(home).services()
    (row,) = services.artifacts.list_for_assessment(
        UUID(first["assessment_id"]), kind=PqcFactsArtifact.schema
    )
    artifact = services.artifacts.read(row.id, PqcFactsArtifact)
    assert out.read_bytes() == artifact.payload == services.artifacts.payload(row.id)
    hit = next(
        f for f in json.loads(out.read_bytes())["facts"] if f["rule_id"] == "API_GO_CRYPTO_RSA"
    )
    assert (hit["file"], hit["line"], hit["match"]) == (
        "vendor/keys.go",
        7,
        "rsa.GenerateKey(random, 2048)",
    )
    assert hit["path_class"] == "vendor" and hit["provenance_hint"] == "vendored"
    assert hit["ir8547"]["qclass"] == "shor_112bit"
    assert hit["ir8547"]["clock"]["disallowed_after"] == 2035
    replay = tmp_path / "replay.json"
    rc, repeated, err = prescan(home, replay, "--repo-dir", str(FIXTURES / "repo"))
    assert rc == 0, err
    assert repeated["scanned"] is False
    assert repeated["assessment_id"] == first["assessment_id"]
    assert replay.read_bytes() == out.read_bytes()
    assert scanner.with_suffix(".calls").read_text().splitlines() == ["scan"]


@pytest.mark.parametrize("existing_outputs", [False, True])
def test_cached_cbom_request_is_explicitly_refused_without_writing_exports(
    home: Path, scanner: Path, tmp_path: Path, existing_outputs: bool
) -> None:
    assert (
        prescan(
            home, tmp_path / "first.json", "--repo-dir", str(FIXTURES / "repo"), "--sbom", str(SBOM)
        )[0]
        == 0
    )
    out, cbom = tmp_path / "requested.json", tmp_path / "requested-cbom.json"
    if existing_outputs:
        out.write_bytes(b"previous facts")
        cbom.write_bytes(b"previous CBOM")
    rc, receipt, err = prescan(
        home, out, "--repo-dir", str(FIXTURES / "repo"), "--cbom-out", str(cbom)
    )
    assert (rc, receipt) == (2, None)
    assert "CBOM unavailable" in err and "cached" in err
    if existing_outputs:
        assert out.read_bytes() == b"previous facts"
        assert cbom.read_bytes() == b"previous CBOM"
    else:
        assert not out.exists() and not cbom.exists()
    assert scanner.with_suffix(".calls").read_text().splitlines() == ["scan"]


@pytest.mark.parametrize(
    "settings",
    [
        {"report": json.dumps(REPORT), "exit": 17},
        {},
        {"report": "{broken"},
        {
            "report": json.dumps(
                {
                    **REPORT,
                    "findings": [
                        {
                            "rule_id": "API_GO_CRYPTO_RSA",
                            "location": {"file": "../keys.go", "line": 1},
                        }
                    ],
                }
            )
        },
        {"large_report": MAX_REPORT_BYTES + 1},
        {"report": json.dumps(REPORT), "large_cbom": MAX_CBOM_BYTES + 1},
    ],
    ids=[
        "nonzero-with-report",
        "missing-report",
        "malformed-report",
        "unsafe-path",
        "report-limit",
        "cbom-limit",
    ],
)
def test_scanner_failure_or_refused_output_never_exports_or_records_clean_facts(
    home: Path, scanner: Path, tmp_path: Path, settings: dict
) -> None:
    scenario(scanner, **settings)
    out, cbom = tmp_path / "facts.json", tmp_path / "cbom.json"
    rc, receipt, err = prescan(
        home,
        out,
        "--repo-dir",
        str(FIXTURES / "repo"),
        "--sbom",
        str(SBOM),
        "--cbom-out",
        str(cbom),
    )
    assert (rc, receipt) == (2, None)
    assert err
    assert not out.exists() and not cbom.exists()
    assert scanner.with_suffix(".calls").read_text().splitlines() == ["scan"]
    assert_unscanned(home)


def test_fresh_source_without_cbom_refuses_requested_export_but_keeps_native_facts(
    home: Path, scanner: Path, tmp_path: Path
) -> None:
    scenario(scanner, report=json.dumps(REPORT), cbom=False)
    out, cbom = tmp_path / "facts.json", tmp_path / "cbom.json"
    rc, receipt, err = prescan(
        home,
        out,
        "--repo-dir",
        str(FIXTURES / "repo"),
        "--sbom",
        str(SBOM),
        "--cbom-out",
        str(cbom),
    )
    assert (rc, receipt) == (2, None)
    assert "CBOM unavailable" in err
    assert not out.exists() and not cbom.exists()
    replay = tmp_path / "replay.json"
    rc, repeated, err = prescan(home, replay, "--repo-dir", str(FIXTURES / "repo"))
    assert rc == 0, err
    assert repeated["scanned"] is False
    assert replay.exists()
    assert scanner.with_suffix(".calls").read_text().splitlines() == ["scan"]


@pytest.mark.parametrize("alias", ["same-path", "parent-segment", "symlink"])
def test_facts_and_cbom_must_resolve_to_distinct_destinations_before_execution(
    home: Path, scanner: Path, tmp_path: Path, alias: str
) -> None:
    out = tmp_path / "exports.json"
    out.write_bytes(b"previous export")
    cbom = out
    if alias == "parent-segment":
        cbom = tmp_path / "unused" / ".." / out.name
    elif alias == "symlink":
        cbom = tmp_path / "cbom-link.json"
        cbom.symlink_to(out)
    rc, receipt, err = prescan(
        home,
        out,
        "--repo-dir",
        str(FIXTURES / "repo"),
        "--sbom",
        str(SBOM),
        "--cbom-out",
        str(cbom),
    )
    assert (rc, receipt) == (2, None)
    assert "--out" in err and "--cbom-out" in err
    assert out.read_bytes() == b"previous export"
    assert not scanner.with_suffix(".calls").exists()
    assert not (tmp_path / "store").exists()


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--repo-dir", str(FIXTURES / "repo"), "--from-sbom", str(SBOM)],
        ["--from-sbom", str(SBOM), "--sbom", str(SBOM)],
        ["--from-sbom", str(SBOM), "--cbom-out", "cbom.json"],
        ["--repo-dir", str(FIXTURES / "repo"), "--scanner", "pqc-scan"],
        ["--repo-dir", str(FIXTURES / "repo"), "--rules-dir", "rules"],
        ["--validate-facts", "facts.json"],
    ],
    ids=[
        "missing-source",
        "two-sources",
        "sbom-on-sbom",
        "cbom-on-sbom",
        "scanner-override",
        "rules-override",
        "legacy-validation",
    ],
)
def test_prescan_requires_exactly_one_source_and_rejects_legacy_overrides(
    tmp_path: Path, argv: list[str]
) -> None:
    with pytest.raises(SystemExit) as exit_, contextlib.redirect_stderr(io.StringIO()):
        pqc.prescan(
            ["--repo-url", REPO, "--sha", SHA, "--out", str(tmp_path / "facts.json"), *argv]
        )
    assert exit_.value.code == 2


@pytest.mark.parametrize("missing", ["--sha", "--repo-url", "--out"])
def test_commit_identity_and_output_are_required(tmp_path: Path, missing: str) -> None:
    args = {"--sha": SHA, "--repo-url": REPO, "--out": str(tmp_path / "facts.json")}
    del args[missing]
    argv = [part for pair in args.items() for part in pair]
    with pytest.raises(SystemExit) as exit_, contextlib.redirect_stderr(io.StringIO()):
        pqc.prescan(["--from-sbom", str(SBOM), *argv])
    assert exit_.value.code == 2
