"""The per-technology review checks: every check cites a CWE and its standard requirement, and
both audit skills wire the reference."""

import re

from traust.paths import HARNESS_ROOT

CHECKS = HARNESS_ROOT / "harnessing" / "3-audit" / "secure-code-audit" / "framework-checks.md"
ROW = re.compile(
    r"^\| (?P<id>[A-Z]{2}\.\d+) \| (?P<check>.+?) \| (?P<cwe>[^|]+) \| (?P<req>[^|]+) \|"
)
CWE = re.compile(r"CWE-\d+( / CWE-\d+)*")
ASVS = re.compile(r"ASVS V\d+\.\d+( / ASVS V\d+\.\d+)*")
K_ID = re.compile(r"K(0[1-9]|10)( / K(0[1-9]|10))*")


def _rows() -> list[re.Match[str]]:
    return [m for ln in CHECKS.read_text(encoding="utf-8").splitlines() if (m := ROW.match(ln))]


def test_every_section_is_present_and_ids_unique():
    rows = _rows()
    ids = [m["id"] for m in rows]
    assert len(ids) == len(set(ids))
    assert {i.split(".")[0] for i in ids} == {
        "OP", "GR", "FA", "EX", "JV", "RW", "TN", "RL", "SN", "DF"
    }  # fmt: skip
    for prefix, floor in (
        ("OP", 10),
        ("GR", 8),
        ("FA", 10),
        ("EX", 12),
        ("JV", 14),
        ("RW", 11),
        ("TN", 6),
        ("RL", 12),
        ("SN", 6),
        ("DF", 1),
    ):
        assert sum(i.startswith(f"{prefix}.") for i in ids) >= floor, prefix


def test_web_sections_name_their_deterministic_evidence():
    text = CHECKS.read_text(encoding="utf-8")
    assert "traust adapters route-guards" in text
    for rule in ("traust-ts-xss-", "traust-ts-open-redirect-", "traust-ts-path-traversal-fs-taint"):
        assert rule in text, rule
    assert "backstage:httpRouter" in text and "tree-sitter-javascript" in text


def test_every_check_names_a_cwe_and_its_standard_requirement():
    for m in _rows():
        assert CWE.fullmatch(m["cwe"].strip()), (m["id"], m["cwe"])
        asvs, _, k = (p.strip() for p in m["req"].partition(";"))
        assert ASVS.fullmatch(asvs), (m["id"], m["req"])
        assert asvs.count("/") == m["cwe"].count("/"), m["id"]  # one section per CWE
        if k:
            assert m["id"].startswith("OP.") and K_ID.fullmatch(k), (m["id"], k)


def test_both_skills_wire_the_reference():
    for skill in ("secure-code-audit", "vuln-scan"):
        text = (HARNESS_ROOT / "harnessing" / "3-audit" / skill / "SKILL.md").read_text()
        assert "framework-checks.md" in text, skill
        assert '"framework-checks": "ran: <sections>"' in text, skill
        assert "adapters grpc-guards" in text or skill == "vuln-scan", skill


def test_the_grpc_section_names_the_matrix_command():
    assert "python3 -m traust.cli adapters grpc-guards" in CHECKS.read_text(encoding="utf-8")


def test_jvm_rust_and_ruby_sections_name_their_matrix_markers():
    text = CHECKS.read_text(encoding="utf-8")
    for marker in (
        "method-security-not-enabled",
        "spring-security:conditional-config",
        "spring-security:default",
        "quarkus:permit",
        "actix:registration-not-found",
        "skip_before_action:<callback>",
        "framework: tonic",
    ):
        assert marker in text, marker
    for lang in ("java", "rust", "ruby"):
        assert f"tree-sitter-{lang}" in text, lang


def test_the_ownership_checks_start_from_the_matrix_and_cover_query_ids_by_hand():
    text = CHECKS.read_text(encoding="utf-8")
    section = text.split("## Route ownership (CWE-639)", 1)[1].split("\n## ", 1)[0]
    # the reader classifies path ids only: query or body ids are a by-hand review, gapped
    assert "path only" in section and "query string or the body" in section
    assert "`coverage_gaps`" in section
    rows = {m["id"]: m.string for m in _rows()}
    for check in ("FA.4", "EX.4", "JV.5", "RW.4", "RL.3", "DF.1"):
        assert "(#route-ownership-cwe-639)" in rows[check], check
    skill = (CHECKS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert "take the object id from the\n   query string or body" in skill


def test_django_and_flask_ownership_rows_get_a_check_and_the_rest_a_gap():
    """Django/DRF and Flask rows carry judged ownership: their ownership is reviewed under
    DF.1, and only the rest of those frameworks' review is a coverage gap."""
    text = CHECKS.read_text(encoding="utf-8")
    selecting = text.split("## Selecting sections", 1)[1].split("\n## ", 1)[0]
    assert "`django-drf` or `flask` rows" in selecting
    assert "under DF.1" in selecting and "`framework-checks` coverage gap" in selecting
    ownership = text.split("## Route ownership (CWE-639)", 1)[1].split("\n## ", 1)[0]
    assert "Django/DRF, Flask" in ownership and "DF.1" in ownership
    assert "never credit" in ownership  # judge-only readers: `unknown` rows are read too
    rows = {m["id"]: m.string for m in _rows()}
    assert "no ownership reader yet" not in rows["RW.4"]
    skill = (CHECKS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert "Django/DRF, Flask and aiohttp also carry `ownership`" in skill.replace(
        "\n", " "
    ).replace("  ", " ")
    assert "RW.4, RL.3, DF.1" in skill


def test_aiohttp_ownership_rows_are_judged_never_a_gap():
    """aiohttp carries judged ownership (traust-core#424): FA.4 reads its rows, `unknown` ones
    too, and no longer calls aiohttp routes an ownership coverage gap."""
    text = CHECKS.read_text(encoding="utf-8")
    ownership = text.split("## Route ownership (CWE-639)", 1)[1].split("\n## ", 1)[0]
    flat = " ".join(ownership.split())
    assert "Django/DRF, Flask and aiohttp today" in flat
    assert "Django/DRF, Flask and aiohttp readers never credit protection" in flat
    rows = {m["id"]: m.string for m in _rows()}
    assert "aiohttp routes are an ownership coverage gap" not in rows["FA.4"]
    assert "never credits" in rows["FA.4"] and "`unknown` rows are read too" in rows["FA.4"]
