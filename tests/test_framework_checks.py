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
    assert {i.split(".")[0] for i in ids} == {"OP", "GR", "FA", "EX", "JV", "RW", "TN", "RL", "SN"}
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
    for check in ("FA.4", "EX.4", "JV.5", "RW.4", "RL.3"):
        assert "(#route-ownership-cwe-639)" in rows[check], check
    skill = (CHECKS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert "take the object id from the\n   query string or body" in skill
