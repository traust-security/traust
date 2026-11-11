"""Compliance test paths.

The control-to-check mapping ships with the security pack; the org parameters are an
adopter fact recorded into traust-core (the suite keeps a labeled-fiction copy, and
docs/examples/ carries the example adopters copy).
"""

from __future__ import annotations

from pathlib import Path

from traust.paths import HARNESS_ROOT, SECURITY_PACK_DIR

REGISTRY = "compliance-mapping.yaml"


def compliance_registry() -> Path:
    """The shipped control-to-check mapping."""
    return SECURITY_PACK_DIR / "compliance" / REGISTRY


def org_parameters() -> Path:
    """The suite's labeled-fiction org parameters."""
    return Path(__file__).parent / "fixtures" / "compliance" / "org-parameters.yaml"


def org_parameters_template() -> Path:
    return HARNESS_ROOT / "docs" / "examples" / "org-parameters.example.yaml"
