"""The vendored MITRE ATLAS table: pinned, attributed, and loaded into traust-core by the context."""

import json
import re

from traust import context
from traust.paths import HARNESS_ROOT

TABLES = HARNESS_ROOT / "harnessing" / "attack-coverage" / "tables"
ATLAS_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


def _table() -> dict:
    return json.loads((TABLES / "atlas-techniques.json").read_text(encoding="utf-8"))


def test_the_table_is_pinned_to_the_recorded_release_and_carries_the_notice():
    table = _table()
    pinned = (TABLES / "atlas-data.sha256").read_text().split()[0]
    assert table["data_sha256"] == pinned
    assert f"/v{table['atlas_version']}/" in table["data_url"]
    assert "Apache License, Version 2.0" in table["attribution"] and "MITRE" in table["attribution"]


def test_every_entry_is_an_atlas_id_with_a_name_and_subtechniques_inherit_tactics():
    techniques = _table()["techniques"]
    assert len(techniques) >= 150
    assert all(ATLAS_ID.match(i) and t["name"] for i, t in techniques.items())
    subs = [i for i in techniques if "." in i.removeprefix("AML.")]
    assert subs and all(techniques[s]["tactics"] == techniques[s[:9]]["tactics"] for s in subs)


def test_the_context_registers_the_pinned_atlas_catalog(tmp_path):
    core = context.load(tmp_path)
    assert core.atlas_catalog is not None
    assert core.atlas_catalog.atlas_version == _table()["atlas_version"]
    assert core.atlas_catalog.invalid(["AML.T0051", "AML.T9999"]) == (
        "AML.T9999: not in pinned ATLAS table",
    )
