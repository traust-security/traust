"""scripts/containerfile-build-args.py: pins from external-tools.yaml, the pin-set hash that
tags the split tools/runtime images, and validation against the tools image's inventory."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "containerfile-build-args.py"
_spec = importlib.util.spec_from_file_location("containerfile_build_args", _MODULE_PATH)
cba = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cba
_spec.loader.exec_module(cba)

REAL_TOOLS = [
    {"name": "opengrep", "expected": "1.25.0"},
    {"name": "gitleaks", "expected": "8.30.1"},
    {"name": "syft", "expected": "1.48.0"},
    {"name": "grype", "expected": "0.115.0"},
    {"name": "cosign", "expected": "3.1.1"},
    {"name": "govulncheck", "expected": "1.6.0"},
    {"name": "skopeo", "expected": "1.23.0"},
    {"name": "yara", "expected": "4.5.8"},
    {"name": "pip-audit", "expected": "2.10.1"},
    {"name": "go", "expected": "1.24.0"},
    # In the manifest but deliberately not installed into the tools image.
    {"name": "osv-scanner", "expected": "2.7.0", "provided_by": "adopter"},
    {"name": "joern", "expected": "4.0.600"},
]


def _manifest(tmp_path: Path, tools: list[dict]) -> Path:
    path = tmp_path / "external-tools.yaml"
    path.write_text(yaml.safe_dump({"tools": tools}))
    return path


def test_the_real_shipped_manifest_satisfies_the_tools_image_inventory() -> None:
    """Every binary Containerfile.tools installs has a real pin today — the bug this guards
    against (GO_VERSION defaulting to a Containerfile-local constant) can't regress silently."""
    pins = cba.load_pins()
    assert pins["GO_VERSION"] == "1.24.0"
    assert set(pins) == set(cba.NAME_TO_ARG.values())


def test_load_pins_reads_every_inventory_tool(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, REAL_TOOLS)
    pins = cba.load_pins(manifest)
    assert pins == {
        "OPENGREP_VERSION": "1.25.0",
        "GITLEAKS_VERSION": "8.30.1",
        "SYFT_VERSION": "1.48.0",
        "GRYPE_VERSION": "0.115.0",
        "COSIGN_VERSION": "3.1.1",
        "GOVULNCHECK_VERSION": "1.6.0",
        "SKOPEO_VERSION": "1.23.0",
        "YARA_VERSION": "4.5.8",
        "PIP_AUDIT_VERSION": "2.10.1",
        "GO_VERSION": "1.24.0",
    }


def test_a_tool_missing_from_the_manifest_is_a_missing_pin_not_a_default(tmp_path: Path) -> None:
    without_go = [t for t in REAL_TOOLS if t["name"] != "go"]
    manifest = _manifest(tmp_path, without_go)
    with pytest.raises(SystemExit, match="no 'expected' pin for 'go'"):
        cba.load_pins(manifest)


def test_a_pin_with_no_expected_value_is_a_missing_pin(tmp_path: Path) -> None:
    broken = [dict(t) for t in REAL_TOOLS]
    next(t for t in broken if t["name"] == "grype").pop("expected")
    manifest = _manifest(tmp_path, broken)
    with pytest.raises(SystemExit, match="no 'expected' pin for 'grype'"):
        cba.load_pins(manifest)


def test_joern_and_osv_scanner_are_not_required_not_installed_in_the_tools_image(
    tmp_path: Path,
) -> None:
    """joern (too large for the image) and osv-scanner (provided_by: adopter) stay out of
    TOOLS_IMAGE_INVENTORY on purpose — their presence or absence in the manifest must never
    gate the build."""
    without_either = [t for t in REAL_TOOLS if t["name"] not in ("joern", "osv-scanner")]
    manifest = _manifest(tmp_path, without_either)
    assert cba.load_pins(manifest)  # does not raise


def test_pin_set_hash_is_stable_under_comment_and_reorder_but_not_under_a_version_bump(
    tmp_path: Path,
) -> None:
    manifest_a = _manifest(tmp_path, REAL_TOOLS)
    reordered = list(reversed(REAL_TOOLS))
    manifest_b = tmp_path / "reordered.yaml"
    manifest_b.write_text(yaml.safe_dump({"tools": reordered}))
    assert cba.pin_set_hash(manifest_a) == cba.pin_set_hash(manifest_b)

    bumped = [dict(t) for t in REAL_TOOLS]
    next(t for t in bumped if t["name"] == "grype")["expected"] = "0.116.0"
    manifest_c = tmp_path / "bumped.yaml"
    manifest_c.write_text(yaml.safe_dump({"tools": bumped}))
    assert cba.pin_set_hash(manifest_a) != cba.pin_set_hash(manifest_c)


def test_pin_set_hash_ignores_non_image_fields_like_consumers_and_prose(tmp_path: Path) -> None:
    """A manifest edit that changes only prose/consumers/version_cmd (not `expected`) must not
    retag the image: the hash is purely over resolved name=version pairs."""
    plain = _manifest(tmp_path, REAL_TOOLS)
    annotated = [
        dict(t, consumers=["secure-code-audit"], version_cmd=[t["name"]]) for t in REAL_TOOLS
    ]
    annotated_manifest = tmp_path / "annotated.yaml"
    annotated_manifest.write_text(yaml.safe_dump({"tools": annotated}))
    assert cba.pin_set_hash(plain) == cba.pin_set_hash(annotated_manifest)


def test_resolved_versions_keys_by_tool_name_not_arg_name(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, REAL_TOOLS)
    versions = cba.resolved_versions(manifest)
    assert versions["grype"] == "0.115.0"
    assert versions["go"] == "1.24.0"
    assert "GRYPE_VERSION" not in versions


def test_a_duplicate_tool_row_prefers_the_last_entry_deterministically(tmp_path: Path) -> None:
    """PyYAML loads a list, and the dict built from it keeps the last entry for a repeated name
    — exercised explicitly so a manifest edit mistake (two `grype:` rows) has a defined,
    deterministic outcome instead of depending on dict-literal insertion order."""
    duplicated = [*REAL_TOOLS, {"name": "grype", "expected": "9.9.9"}]
    manifest = _manifest(tmp_path, duplicated)
    assert cba.load_pins(manifest)["GRYPE_VERSION"] == "9.9.9"
