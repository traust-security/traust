#!/usr/bin/env python3
"""Emit --build-arg flags for Containerfile.tools from the external-tools.yaml traust-core ships
(``SHIPPED_EXTERNAL_TOOLS``, the tool pins; run it in the project venv), and compute the
pin-set hash that tags both split images (Containerfile.tools, Containerfile.runtime).

Usage (the canonical build commands — scripts/build-toolchain-image.sh wraps these):
    podman build -f Containerfile.tools \
      $(python3 scripts/containerfile-build-args.py) \
      -t traust-toolchain:latest .

    python3 scripts/containerfile-build-args.py --pin-hash
    python3 scripts/containerfile-build-args.py --env > version.args   # Konflux build-args-file
    python3 scripts/containerfile-build-args.py --check   # validate only, exit 1 on a gap

The pin-set hash is sha256 over the *resolved* installed versions (name=version, sorted), not
the raw manifest bytes: a comment or prose edit to external-tools.yaml (e.g. the cosign
transparency-log caveat) must not force a rebuild and retag of an image whose installed
binaries haven't changed. The manifest's own raw-file digest is recorded separately by
traust-engine's Pack.load as the `external-tools` config digest in each order's run manifest —
a different, complementary provenance record, not a replacement for this hash.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required — pip install pyyaml", file=sys.stderr)
    sys.exit(1)

try:
    from traust_core.v1.context.config import SHIPPED_EXTERNAL_TOOLS as MANIFEST
except ImportError:
    print("ERROR: traust-core not importable — run under `uv run`", file=sys.stderr)
    sys.exit(1)

NAME_TO_ARG = {
    "opengrep": "OPENGREP_VERSION",
    "gitleaks": "GITLEAKS_VERSION",
    "syft": "SYFT_VERSION",
    "grype": "GRYPE_VERSION",
    "cosign": "COSIGN_VERSION",
    "govulncheck": "GOVULNCHECK_VERSION",
    "skopeo": "SKOPEO_VERSION",
    "yara": "YARA_VERSION",
    "pip-audit": "PIP_AUDIT_VERSION",
    "go": "GO_VERSION",
}

# Binaries Containerfile.tools actually installs. A manifest row can exist without being in the
# image (joern: too large for the base image; osv-scanner: provided_by: adopter, never
# installed) — those are valid gaps, not errors. Every name here MUST have a pin, or the build
# would silently fall back to a Containerfile-local default (the bug this validates against:
# GO_VERSION used to default to 1.23.0 regardless of the manifest's 1.24.0 pin).
TOOLS_IMAGE_INVENTORY = frozenset(NAME_TO_ARG)


class MissingPin(SystemExit):
    def __init__(self, tool: str, manifest: Path) -> None:
        super().__init__(
            f"ERROR: no 'expected' pin for {tool!r} in {manifest} — refusing to "
            "fall back to a Containerfile-local default"
        )


def load_pins(manifest: Path = MANIFEST) -> dict[str, str]:
    """Arg-name -> pinned version, for every tool in TOOLS_IMAGE_INVENTORY with an `expected`
    row in the manifest. Raises when the image's inventory and the manifest disagree."""
    tools = yaml.safe_load(manifest.read_text())["tools"]
    by_name = {spec["name"]: spec for spec in tools}
    pins: dict[str, str] = {}
    for name in TOOLS_IMAGE_INVENTORY:
        spec = by_name.get(name)
        if spec is None or not spec.get("expected"):
            raise MissingPin(name, manifest)
        pins[NAME_TO_ARG[name]] = str(spec["expected"])
    return pins


def resolved_versions(manifest: Path = MANIFEST) -> dict[str, str]:
    """Tool name -> pinned version (not the ARG name), for the pin-set hash and image labels."""
    pins = load_pins(manifest)
    arg_to_name = {v: k for k, v in NAME_TO_ARG.items()}
    return {arg_to_name[arg]: version for arg, version in pins.items()}


def pin_set_hash(manifest: Path = MANIFEST) -> str:
    """sha256 of the sorted, resolved `name=version` pairs — the tools image's tag and the
    `toolchain:<hash>` runner label. Stable under comment/reordering edits to the manifest;
    changes only when an installed tool's pinned version changes."""
    versions = resolved_versions(manifest)
    canonical = "\n".join(f"{name}={versions[name]}" for name in sorted(versions)).encode()
    return hashlib.sha256(canonical).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--env",
        action="store_true",
        help="emit KEY=VALUE lines (for Konflux version.args / .env files)",
    )
    ap.add_argument("--pin-hash", action="store_true", help="print the pin-set hash and exit")
    ap.add_argument(
        "--check",
        action="store_true",
        help="validate the manifest against the tools image's inventory and exit (no output)",
    )
    args = ap.parse_args()

    if args.check:
        load_pins()  # raises MissingPin (exits 1) on a gap
        return

    if args.pin_hash:
        print(pin_set_hash())
        return

    pins = load_pins()
    if args.env:
        for k, v in pins.items():
            print(f"{k}={v}")
    else:
        parts = [f"--build-arg {k}={v}" for k, v in pins.items()]
        print(" ".join(parts))


if __name__ == "__main__":
    main()
