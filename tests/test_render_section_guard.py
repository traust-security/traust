"""`traust reporting render` refuses to erase threat-model prose.

A threat-model JSON that lacks members its Markdown has (the 2026-09-20
backfill wrote only system/provenance/threats) re-renders to a document with
empty sections. Overwriting the .md with that silently deletes the model's
context, assets and entry points, which is how the first OWASP write-back
went wrong. The guard makes that a refusal unless the caller says the
removal is intended.
"""

import json
from argparse import Namespace
from pathlib import Path

from traust_core.v1.models.artifacts import RenderFormat, ThreatModelArtifact

from traust.cli.groups.reporting import call_render
from traust.context import load

FULL = {
    "system": "example",
    "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": "repo @ abc1234"},
    "system_context": "Decodes user-supplied audio.",
    "assets": [{"asset": "host", "description": "decoder memory", "sensitivity": "critical"}],
    "entry_points": [
        {
            "entry_point": "upload",
            "description": "WAV decode",
            "trust_boundary": "file -> memory",
            "reachable_assets": "host",
        }
    ],
    "threats": [
        {
            "id": "T1",
            "threat": "RCE via audio parsing",
            "actor": ["remote_unauth"],
            "surface": "upload",
            "asset": "host",
            "impact": "critical",
            "likelihood": "likely",
            "status": "unmitigated",
            "controls": "none",
            "evidence": [],
            "attack_refs": ["T1203"],
        }
    ],
    "deprioritized": [{"threat": "physical access", "reason": "out of scope"}],
    "open_questions": ["Is the decoder sandboxed?"],
}
THIN = {k: FULL[k] for k in ("system", "provenance", "threats")}


def _render(tmp_path: Path, document: dict, existing: str | None, allow: bool = False):
    src = tmp_path / "repo-threat-model.json"
    src.write_text(json.dumps(document))
    out = tmp_path / "repo-threat-model.md"
    if existing is not None:
        out.write_text(existing)
    args = Namespace(config_home=None, report=src, out=out, allow_section_loss=allow)
    return call_render(args), out.read_text()


def _full_markdown(tmp_path: Path) -> str:
    rc, md = _render(tmp_path, FULL, None)
    assert rc == 0
    return md


def test_thin_json_does_not_overwrite_a_full_model(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    rc, md = _render(tmp_path, THIN, full_md)
    assert rc == 1
    assert md == full_md, "the existing .md must be left untouched"


def test_lost_sections_names_what_would_go(tmp_path: Path) -> None:
    reporting = load().reporting
    thin = reporting.render(ThreatModelArtifact.from_document(THIN), RenderFormat.MARKDOWN)
    lost = reporting.lost_sections(_full_markdown(tmp_path), thin)
    assert {"1. System context", "2. Assets", "3. Entry points & trust boundaries"} <= set(lost)
    assert "4. Threats" not in lost


def test_complete_json_overwrites_normally(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    rated = json.loads(json.dumps(FULL))
    rated["threats"][0]["status"] = "partially_mitigated"
    rc, md = _render(tmp_path, rated, full_md)
    assert rc == 0 and "partially_mitigated" in md


def test_intended_removal_needs_the_flag(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    fewer = {k: v for k, v in FULL.items() if k != "deprioritized"}
    assert _render(tmp_path, fewer, full_md)[0] == 1
    rc, md = _render(tmp_path, fewer, full_md, allow=True)
    assert rc == 0 and "physical access" not in md
