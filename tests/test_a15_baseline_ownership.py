#!/usr/bin/env python3
"""A15 — only the three secure*audit skills may write an audit baseline.

The invariant existed only as prose until 2026-08-17, which is how findings
came to be appended into baselines by three non-audit producers
(impact-analysis, verify-remediation, vuln-scan). These tests pin
the detector so the gate cannot quietly stop catching it.
"""

from __future__ import annotations

from traust.cli import check_skill_alignment as C


class TestPythonWriteDetection:
    """The shared `_write(audit_path, audit)` form both routers use."""

    def test_catches_shared_write_helper(self) -> None:
        assert C.BASELINE_WRITE_PY_RE.search("            _write(audit_path, audit)")

    def test_catches_direct_write_text(self) -> None:
        assert C.BASELINE_WRITE_PY_RE.search("audit_path.write_text(json.dumps(audit, indent=2))")

    def test_catches_baseline_named_target(self) -> None:
        assert C.BASELINE_WRITE_PY_RE.search("_write(baseline_path, baseline)")

    def test_ignores_reads(self) -> None:
        # Producers MUST still be able to read the baseline (to dedupe).
        for benign in (
            'audit = _load(audit_path, "baseline audit")',
            "data = json.loads(audit_path.read_text())",
            'if audit_path.name.endswith("-security-audit.json"):',
        ):
            assert not C.BASELINE_WRITE_PY_RE.search(benign), benign

    def test_ignores_layer_writes(self) -> None:
        # Writing a LAYER is the correct behaviour and must never be flagged.
        for ok in (
            "_write(layer_path, layer)",
            "layer_path.write_text(json.dumps(layer, indent=2))",
        ):
            assert not C.BASELINE_WRITE_PY_RE.search(ok), ok


class TestProseDetection:
    def test_catches_append_instruction(self) -> None:
        assert C.BASELINE_WRITE_MD_RE.search(
            "are **appended to the original `<repo>-security-audit.json` as new findings**"
        )

    def test_catches_fold_into_baseline(self) -> None:
        assert C.BASELINE_WRITE_MD_RE.search(
            "- Fold new findings into the baseline — **direct ledger entry"
        )

    def test_catches_routing_prose(self) -> None:
        assert C.BASELINE_WRITE_MD_RE.search(
            "It routes every `regressions[]` entry into the baseline audit"
        )

    def test_ignores_dedupe_prose(self) -> None:
        for benign in (
            "known findings are deduped against the baseline",
            "reads the baseline to establish coverage",
            "the baseline remains authoritative",
        ):
            assert not C.BASELINE_WRITE_MD_RE.search(benign), benign


class TestOwnerSkillsExcluded:
    def test_exactly_three_owners(self) -> None:
        assert (
            frozenset({"secure-code-audit", "secure-rpm-audit", "secure-container-audit"})
            == C.BASELINE_OWNER_SKILLS
        )


class TestLiveTree:
    def test_no_violators_remain(self, monkeypatch) -> None:
        """Zero baseline writers outside the three secure*audit skills.

        If this grows, a new baseline write landed.
        """
        without_a15 = {k: v for k, v in C.EXEMPTIONS.items() if k[0] != "A15"}
        monkeypatch.setattr(C, "EXEMPTIONS", without_a15)
        found = C.a15_baseline_ownership_failures(used=[])
        paths = sorted({f.split()[1].split(":")[0] for f in found})
        assert paths == [], (
            "A15 is fully burned down — every violator was cleared: "
            "route_impact_findings.py (B3, v0.284.0), route_regressions.py "
            "(B4, v0.285.0), /vuln-scan and /track-findings prose (B5/B6, "
            f"v0.290.0). A new entry here means a baseline write landed: {paths}"
        )

    def test_gate_is_green_without_any_exemption(self) -> None:
        """A15 now stands on its own — no grandfathering left."""
        assert C.a15_baseline_ownership_failures(used=[]) == []
        assert all(not f.startswith("A15") for f in C.alignment_failures())

    def test_no_a15_exemptions_remain(self) -> None:
        """The burn-down list must stay empty.

        An exemption reappearing means someone reintroduced a baseline write and
        grandfathered it rather than fixing it. If that is ever legitimate, the
        entry must cite a workstream — but the default is that it is not.
        """
        a15 = {p: r for (rule, p), r in C.EXEMPTIONS.items() if rule == "A15"}
        assert a15 == {}, f"A15 exemptions reappeared: {a15}"


class TestB9PhrasingsThatSlippedThrough:
    """The seven phrasings the B9 audit (2026-08-18) found the gate passing.

    A15 reported clean with zero exemptions while seven non-owner skills still
    instructed a baseline append. Every miss was a phrasing detail, not a new
    idea — which is the point: the gate was checking a wording, not a claim. Each
    string below is verbatim from the SKILL.md that carried it.
    """

    CAUGHT = [
        # verb inflection: "appends", not append/appended
        ("track-findings", "appends each regression to the baseline audit"),
        # interposed word: "append **it** to"
        ("validate-findings", "append it to the repo's `*-security-audit.json` baseline with"),
        # "to the baseline", not "into the baseline"
        ("verify-remediation", "**appends the transcribed finding to the baseline"),
        # possessive target
        ("verify-remediation", "routes every regression into the repo's baseline audit"),
        # adjectival form, no verb at all
        ("create-fuzzing", "the amended `*-security-audit.json` finding"),
        # plural possessive in a skill description
        ("dependency-watch", "route affected repos' findings into their baselines"),
        # bare "routed into its baseline"
        ("impact-analysis", "finding is routed into its baseline + disposition ledger"),
        ("vuln-scan", "findings are appended to the baseline audit directly"),
    ]

    def test_every_b9_phrasing_is_now_caught(self) -> None:
        missed = [(skill, s) for skill, s in self.CAUGHT if not C.BASELINE_WRITE_MD_RE.search(s)]
        assert not missed, f"A15 prose detector still misses: {missed}"

    def test_sentences_stating_the_rule_are_not_flagged(self) -> None:
        """The fixes themselves say "baseline" and "never written" — the negative
        lookaside is what keeps the gate from flagging its own remedy."""
        for s in (
            "the baseline is never written (gate A15)",
            "carried on its event and never written to the baseline (gate A15)",
            "This router no longer appends to the baseline (gate A15), so",
            "only /secure-code-audit may write the baseline",
            "non-audit producers must not append to the baseline",
            "carries the finding on its event instead of the baseline",
            # The gate flagged this change's own remedial wording; the lookaside
            # has to cover how a fix is phrased, not only how a violation is.
            "sanctioned entry as an event-carried finding rather than a write to the baseline audit",
            "carried on its ledger event, never writing the baseline",
        ):
            assert C.BASELINE_WRITE_MD_NEG_RE.search(s), s

    def test_the_rule_stating_sentences_appear_in_the_fixed_skills(self) -> None:
        """Guards the fix, not just the detector: if someone reverts a skill to
        the old flow, the A15 marker goes with it and the gate fires again."""
        from pathlib import Path

        Path(__file__).resolve().parents[1]
        for skill in (
            "validate-findings",
            "verify-remediation",
            "create-fuzzing",
            "vuln-scan",
            "impact-analysis",
            "dependency-watch",
            "track-findings",
        ):
            from traust.paths import skill_dir

            text = (skill_dir(skill) / "SKILL.md").read_text(encoding="utf-8")
            assert "A15" in text, f"{skill} lost its A15 marker"
