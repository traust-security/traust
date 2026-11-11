"""The LLM application checklist's shape and its wiring into both audit skills."""

import json
import re

from traust.paths import HARNESS_ROOT, schema_dir

CHECKLIST = (
    HARNESS_ROOT / "harnessing" / "3-audit" / "secure-code-audit" / "llm-application-review.md"
)


def test_the_checklist_covers_every_owasp_category():
    text = CHECKLIST.read_text(encoding="utf-8")
    headings = re.findall(r"^## (LLM\d\d) — ", text, re.M)
    assert headings == [f"LLM{n:02d}" for n in range(1, 11)]


def test_every_check_names_a_cwe_or_is_a_threat_model_item():
    rows = [
        ln
        for ln in CHECKLIST.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\| \d\d\.\d+ \|", ln)
    ]
    assert len(rows) >= 30
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        number, check, cwe = cells[0], cells[1], cells[2]
        if check.startswith("*Threat model:*"):
            assert cwe == "—", number
        else:
            assert re.fullmatch(r"CWE-\d+( / CWE-\d+)*", cwe), (number, cwe)


def test_both_skills_wire_the_pre_scan_and_the_checklist():
    for skill in ("secure-code-audit", "vuln-scan"):
        text = (HARNESS_ROOT / "harnessing" / "3-audit" / skill / "SKILL.md").read_text()
        assert "adapters llm-app" in text, skill
        assert "llm-application-review.md" in text, skill


def test_the_checklist_only_names_finding_fields_the_report_schema_has():
    report = json.loads((schema_dir() / "report.schema.json").read_text(encoding="utf-8"))
    fields = set(report["$defs"]["finding"]["properties"])
    named = set(re.findall(r"`(\w+_references|cwes)`", CHECKLIST.read_text(encoding="utf-8")))
    assert "owasp_llm_references" in named
    assert named <= fields, named - fields


def test_the_schema_field_takes_every_category_the_checklist_covers():
    report = json.loads((schema_dir() / "report.schema.json").read_text(encoding="utf-8"))
    field = report["$defs"]["finding"]["properties"]["owasp_llm_references"]
    assert field["items"]["enum"] == [f"LLM{n:02d}" for n in range(1, 11)]
