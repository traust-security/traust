"""config/traust.example.yaml: as copied it is the zero-config install; uncommented, every
section it documents is valid traust.yaml."""

from __future__ import annotations

import re
from pathlib import Path

from traust_core.v1.context import Config

EXAMPLE = Path(__file__).resolve().parents[1] / "config" / "traust.example.yaml"


def test_the_example_as_copied_is_the_zero_config_install(tmp_path: Path) -> None:
    (tmp_path / "traust.yaml").write_text(EXAMPLE.read_text())
    # Effective values only: the file also records which keys it set (core's preflight
    # checks `provided`), so model equality no longer holds for a copied file.
    assert Config.from_file(tmp_path / "traust.yaml").model_dump() == Config().model_dump()


def test_every_section_the_example_documents_is_valid(tmp_path: Path) -> None:
    _, _, body = EXAMPLE.read_text().partition("\n# database:")
    uncommented = "\n".join(
        re.sub(r"^# ?", "", line) for line in ("# database:" + body).splitlines()
    )
    (tmp_path / "traust.yaml").write_text(uncommented)
    config = Config.from_file(tmp_path / "traust.yaml")
    assert config.database.url and config.identity.trust_local and config.ledger.required
    assert config.budgets and config.forge_tokens and config.remediation.fork_org
    assert config.campaign.tracking_reference and config.locations.workspace
    assert config.overrides.rule_pack_allowlist == (tmp_path / "rule-pack-allowlist.yaml").resolve()
