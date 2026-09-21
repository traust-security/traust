#!/usr/bin/env python3
"""Unit tests for traust.cli.countersign (countersign workbench)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from traust_contracts.v1.models.layer import LayerActor
from traust_engine.ledger import compute_event_id
from traust_engine.ledger.service import LedgerService as _RealLedgerService
from traust_ledger._internal.events.builders import build_human_event as _bhe
from traust_ledger._internal.events.builders import build_severity_event as _bse

from traust.cli.build_cumulative import derive_disposition
from traust.cli.countersign import (
    RATIONALE_PLACEHOLDER,
    discover_pending,
    parse_annotated_queue,
    record_decisions,
    render_card,
)

REF = "TEST_REPO-abc1234-010"
NOW = "2026-07-11T22:00:00+00:00"
ACTOR = {
    "kind": "human",
    "identity": "reviewer1",
    "identity_verified": True,
    "identity_provider": "ldap",
    "employee_status": "active",
    "display_name": "A. Reviewer",
}


def build_human_event(finding_ref, decision, rationale, actor, recorded_at):
    """Event construction now lives in the ledger SDK; wrap it for the tests."""
    if isinstance(actor, dict):
        actor = LayerActor(**actor)
    return _bhe(finding_ref, decision, rationale, actor, recorded_at).to_dict()


_real_key = _RealLedgerService.review_item_key


def _write_layer(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@pytest.fixture(autouse=True)
def _fake_ledger():
    """Faithful in-process fake of the ledger SDK (no LAAS_TOKEN/signing).

    countersign builds the event through the ledger SDK's real builders and
    appends it to the layer file, exactly as the gated `countersign` verb
    would; read/patch/resolve operate on the real file. Gate enforcement is
    the SDK's concern and is tested there.
    """

    def _fake_resolve(layer_path, key, decision, note=""):
        data = json.loads(Path(layer_path).read_text())
        for item in data.get("needs_review", []):
            if _real_key(item) == key:
                item["status"] = decision
                if note:
                    item["resolution_note"] = note
                break
        _write_layer(Path(layer_path), data)

    def _fake_patch(layer_path, updates, **_kw):
        data = json.loads(Path(layer_path).read_text())
        meta = data.setdefault("metadata", {})
        for k, v in updates.items():
            if isinstance(v, dict) and isinstance(meta.get(k), dict):
                meta[k].update(v)
            else:
                meta[k] = v
        _write_layer(Path(layer_path), data)

    def _fake_countersign(
        layer_path,
        finding_ref,
        *,
        rationale,
        recorded_at,
        decision=None,
        severity=None,
        actor=None,
    ):
        if isinstance(actor, dict):
            actor = LayerActor(**actor)
        if severity is not None:
            ev = _bse(finding_ref, severity, rationale, actor, recorded_at)
        else:
            ev = _bhe(finding_ref, decision, rationale, actor, recorded_at)
        data = json.loads(Path(layer_path).read_text())
        payload = ev.to_dict()
        if payload["event_id"] not in {e["event_id"] for e in data["events"]}:
            data["events"].append(payload)
            _write_layer(Path(layer_path), data)
        return {"status": "accepted"}

    with patch("traust.cli.countersign.LedgerService") as mock_cls:
        mock_cls.review_item_key = _real_key
        inst = MagicMock()
        inst.resolve_review_item.side_effect = _fake_resolve
        inst.patch_layer_file.side_effect = _fake_patch
        inst.countersign.side_effect = _fake_countersign
        mock_cls.return_value = inst
        yield


def _machine_fp_event(ref=REF, at="2026-07-11T21:00:00+00:00"):
    return {
        "event_id": compute_event_id("TRIAGE.json", ref, "false_positive", None),
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": "triage_report",
            "ref": "TRIAGE.json",
            "actor": {
                "kind": "machine",
                "identity": "triage/0.27.0",
                "ldap_verified": False,
            },
        },
        "disposition": {"validity": "false_positive"},
        "rationale": "guard exists at handler.go:47 before use; rule 2",
        "evidence_refs": ["handler.go:47"],
    }


def _audit(ref=REF):
    return {
        "title": "Security Assessment — Test",
        "metadata": {
            "date": "2026-07-09",
            "scope": "test scope here",
            "commit": "abc1234def",
            "repository": "https://example.invalid/repo",
        },
        "findings": [
            {
                "id": ref,
                "title": "Null deref after fopen",
                "severity": "low",
                "category": "null-deref",
                "cwes": ["CWE-476"],
                "locations": [{"path": "entry.c", "lines": "51"}],
                "description": "Claims fread derefs null f after fopen failure. "
                "There is an explicit guard.",
                "remediation": "n/a — refuted",
                "validation_status": "not_verified",
            }
        ],
        "executive_summary": {
            "prose": "x" * 60,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1},
        },
    }


def _layer(ref=REF):
    return {
        "metadata": {
            "audit_report": "t-security-audit.json",
            "repository": "https://example.invalid/repo",
            "created": "2026-07-11T21:00:00+00:00",
            "harness_version": "0.29.0",
        },
        "events": [_machine_fp_event(ref)],
        "needs_review": [],
    }


def _repo_dir(tmp: Path, ref=REF) -> Path:
    d = tmp / "findings" / "prod" / "repo"
    d.mkdir(parents=True)
    (d / "t-security-audit.json").write_text(json.dumps(_audit(ref)))
    (d / "t-findings-layer.json").write_text(json.dumps(_layer(ref)))
    return d


class TestDiscovery(unittest.TestCase):
    def test_awaiting_signoff_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            _repo_dir(Path(tmp))
            items = discover_pending([Path(tmp) / "findings"])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["kind"], "awaiting_signoff")
        self.assertEqual(items[0]["finding"]["id"], REF)
        self.assertIn("guard exists", items[0]["refutation"]["rationale"])

    def test_countersigned_finding_not_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            layer = json.loads((d / "t-findings-layer.json").read_text())
            layer["events"].append(
                build_human_event(REF, "false_positive", "agreed, guard is real", ACTOR, NOW)
            )
            (d / "t-findings-layer.json").write_text(json.dumps(layer))
            items = discover_pending([Path(tmp) / "findings"])
        self.assertEqual(items, [])

    def test_pending_needs_review_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            layer = json.loads((d / "t-findings-layer.json").read_text())
            layer["needs_review"].append(
                {
                    "queued_at": NOW,
                    "source_ref": "TRIAGE.json",
                    "quote": "undetermined finding",
                    "author": "triage/0.27.0",
                    "queue_reason": "undetermined_finding",
                    "status": "pending",
                }
            )
            (d / "t-findings-layer.json").write_text(json.dumps(layer))
            kinds = {i["kind"] for i in discover_pending([Path(tmp) / "findings"])}
        self.assertEqual(kinds, {"awaiting_signoff", "needs_review"})


class TestCards(unittest.TestCase):
    def test_card_is_self_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            _repo_dir(Path(tmp))
            item = discover_pending([Path(tmp) / "findings"])[0]
            card = render_card(item, 1, 1, Path(tmp))
        self.assertIn("THE CLAIM", card)
        self.assertIn("Null deref after fopen", card)
        self.assertIn("entry.c", card)
        self.assertIn("THE REFUTATION", card)
        self.assertIn("guard exists at handler.go:47", card)
        self.assertIn("IF YOU SIGN", card)
        self.assertIn(f"<!-- countersign finding={REF} ", card)
        self.assertIn("DECISION:", card)


class TestQueueParsing(unittest.TestCase):
    def _card(self, decision_line, rationale=RATIONALE_PLACEHOLDER):
        return (
            "<!-- countersign finding="
            + REF
            + " layer=findings/prod/repo/t-findings-layer.json -->\n"
            "### 1/1 — x\n" + decision_line + "\n"
            f"RATIONALE: {rationale}\n\n---\n"
        )

    def test_marked_fp_parsed_with_placeholder_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "q.md"
            q.write_text(self._card("DECISION: [x] false_positive   [ ] keep_open   [ ] defer"))
            ds = parse_annotated_queue(q)
        self.assertEqual(len(ds), 1)
        self.assertEqual(ds[0]["decision"], "false_positive")
        self.assertEqual(ds[0]["rationale"], "")

    def test_keep_open_with_rationale(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "q.md"
            q.write_text(
                self._card(
                    "DECISION: [ ] false_positive   [X] keep_open   [ ] defer",
                    "I reproduced the crash locally; the guard is bypassed.",
                )
            )
            ds = parse_annotated_queue(q)
        self.assertEqual(ds[0]["decision"], "keep_open")
        self.assertIn("reproduced the crash", ds[0]["rationale"])

    def test_unmarked_card_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "q.md"
            q.write_text(self._card("DECISION: [ ] false_positive   [ ] keep_open   [ ] defer"))
            self.assertEqual(parse_annotated_queue(q), [])


class TestRecording(unittest.TestCase):
    def test_countersign_clears_awaiting_and_sets_fp(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            receipt = record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "false_positive",
                        "rationale": "",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            layer = json.loads(lp.read_text())
            cur = json.loads((d / "t-findings-current.json").read_text())
        self.assertEqual(len(layer["events"]), 2)
        human = layer["events"][-1]
        self.assertEqual(human["source"]["actor"]["identity"], "reviewer1")
        self.assertTrue(human["source"]["actor"]["identity_verified"])
        # blank rationale adopts the machine rationale, explicitly framed
        self.assertIn("I adopt", human["rationale"])
        self.assertIn("guard exists", human["rationale"])
        f = cur["findings"][0]
        self.assertEqual(f["validation_status"], "false_positive")
        self.assertNotIn("refuted_awaiting_signoff", f["disposition"])
        self.assertEqual(f["disposition"]["assurance"], "human_reviewed")
        self.assertTrue(any("rebuilt" in r for r in receipt))

    def test_keep_open_records_confirmed_and_clears_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "keep_open",
                        "rationale": "The guard is bypassable via symlink race.",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            cur = json.loads((d / "t-findings-current.json").read_text())
        f = cur["findings"][0]
        self.assertEqual(f["validation_status"], "confirmed")
        self.assertNotIn("refuted_awaiting_signoff", f["disposition"])

    def test_keep_open_without_rationale_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            with self.assertRaises(ValueError):
                record_decisions(
                    [
                        {
                            "layer": str(d / "t-findings-layer.json"),
                            "finding": REF,
                            "decision": "keep_open",
                            "rationale": "",
                        }
                    ],
                    ACTOR,
                    NOW,
                    root=Path(tmp),
                )

    def test_recording_is_idempotent_per_day(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            dec = [
                {
                    "layer": str(lp),
                    "finding": REF,
                    "decision": "false_positive",
                    "rationale": "agreed.",
                }
            ]
            record_decisions(dec, ACTOR, NOW, root=Path(tmp))
            record_decisions(dec, ACTOR, NOW, root=Path(tmp))
            layer = json.loads(lp.read_text())
        # same signer + day + decision dedupes in the SDK — no second event
        self.assertEqual(len(layer["events"]), 2)

    def test_defer_records_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "defer",
                        "rationale": "",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            layer = json.loads(lp.read_text())
        self.assertEqual(len(layer["events"]), 1)


class TestAttentionCards(unittest.TestCase):
    def _exec_confirmed(self, at="2026-07-12T09:00:00+00:00"):
        return {
            "event_id": compute_event_id("v.json", REF, "confirmed", None),
            "finding_ref": REF,
            "recorded_at": at,
            "occurred_at": at,
            "source": {
                "type": "validation_report",
                "ref": "v.json",
                "actor": {
                    "kind": "machine",
                    "identity": "validate-findings",
                    "ldap_verified": False,
                },
            },
            "disposition": {"validity": "confirmed"},
            "rationale": "reproducing PoC exercised the null deref",
        }

    def test_fp_overridden_surfaces_as_attention(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            layer = json.loads(lp.read_text())
            # human FP then execution confirmation -> overridden
            layer["events"].append(
                build_human_event(
                    REF,
                    "false_positive",
                    "not reachable imo",
                    ACTOR,
                    "2026-07-12T08:00:00+00:00",
                )
            )
            layer["events"].append(self._exec_confirmed())
            lp.write_text(json.dumps(layer))
            items = discover_pending([Path(tmp) / "findings"])
        kinds = [i["kind"] for i in items]
        self.assertIn("fp_overridden", kinds)
        self.assertNotIn("awaiting_signoff", kinds)
        from traust.cli.countersign import render_attention_card

        item = next(i for i in items if i["kind"] == "fp_overridden")
        text = render_attention_card(item, 1, 1, Path(tmp))
        self.assertIn("OVERRIDDEN", text)
        self.assertNotIn("DECISION:", text)  # informational, no markers

    def test_fp_reassertion_blocked_card_has_decision_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            layer = json.loads(lp.read_text())
            layer["events"].append(self._exec_confirmed())
            layer["events"].append(
                build_human_event(
                    REF,
                    "false_positive",
                    "still think fp",
                    ACTOR,
                    "2026-07-12T10:00:00+00:00",
                )
            )
            lp.write_text(json.dumps(layer))
            items = discover_pending([Path(tmp) / "findings"])
            item = next(i for i in items if i["kind"] == "fp_reassertion_blocked")
            from traust.cli.countersign import render_attention_card

            text = render_attention_card(item, 1, 1, Path(tmp))
        self.assertIn("SECOND SIGNER", text)
        self.assertIn("DECISION:", text)
        self.assertIn(f"<!-- countersign finding={REF} ", text)


class TestMergeFlagSemantics(unittest.TestCase):
    def test_human_confirmed_clears_awaiting_signoff(self):
        finding = {"id": REF, "validation_status": "not_verified"}
        events = [
            _machine_fp_event(),
            build_human_event(REF, "keep_open", "reviewed; still real", ACTOR, NOW),
        ]
        d = derive_disposition(finding, events, NOW)
        self.assertEqual(d["validity"], "confirmed")
        self.assertNotIn("refuted_awaiting_signoff", d)


class TestHumanOverrides(unittest.TestCase):
    """harness >= 0.128.0: severity up/downgrades + validity flips both
    directions for findings that need not be in the derived queue."""

    def test_severity_override_records_and_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            receipt = record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "severity=high",
                        "rationale": "Reachable pre-auth on the default install; "
                        "low undersells it.",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            layer = json.loads(lp.read_text())
            cur = json.loads((d / "t-findings-current.json").read_text())
        ev = layer["events"][-1]
        self.assertEqual(ev["disposition"], {"severity": "high"})
        self.assertIn(":severity:high", ev["source"]["ref"])
        f = cur["findings"][0]
        self.assertEqual(f["severity"], "low")  # never rewritten
        self.assertEqual(f["effective_severity"], "high")
        ov = f["disposition"]["severity_override"]
        self.assertEqual((ov["severity"], ov["by"]), ("high", "reviewer1"))
        summ = cur["disposition_summary"]["severity_overrides"]
        self.assertEqual(summ[0]["finding"], REF)
        self.assertEqual((summ[0]["from"], summ[0]["severity"]), ("low", "high"))
        self.assertTrue(any("severity" in r for r in receipt))

    def test_severity_downgrade_latest_wins_and_same_day_levels_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "severity=high",
                        "rationale": "up first",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "severity=informational",
                        "rationale": "changed my mind: dead code path",
                    }
                ],
                ACTOR,
                "2026-07-11T23:00:00+00:00",
                root=Path(tmp),
            )
            layer = json.loads(lp.read_text())
            cur = json.loads((d / "t-findings-current.json").read_text())
        sev_evs = [e for e in layer["events"] if e["disposition"].get("severity")]
        self.assertEqual(len(sev_evs), 2)  # distinct ids per level
        self.assertEqual(cur["findings"][0]["effective_severity"], "informational")

    def test_overrides_require_own_rationale(self):
        for decision in ("reopen", "override_false_positive", "severity=medium"):
            with tempfile.TemporaryDirectory() as tmp:
                d = _repo_dir(Path(tmp))
                with self.assertRaises(ValueError, msg=decision):
                    record_decisions(
                        [
                            {
                                "layer": str(d / "t-findings-layer.json"),
                                "finding": REF,
                                "decision": decision,
                                "rationale": "",
                            }
                        ],
                        ACTOR,
                        NOW,
                        root=Path(tmp),
                    )

    def test_reopen_flips_signed_fp_back_to_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "false_positive",
                        "rationale": "",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "reopen",
                        "rationale": "New PoC path via the exported symbol — the "
                        "guard is not on that path.",
                    }
                ],
                ACTOR,
                "2026-07-12T09:00:00+00:00",
                root=Path(tmp),
            )
            cur = json.loads((d / "t-findings-current.json").read_text())
        self.assertEqual(cur["findings"][0]["validation_status"], "confirmed")

    def test_override_fp_flips_open_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _repo_dir(Path(tmp))
            lp = d / "t-findings-layer.json"
            # settle the pending machine refutation first (keep_open),
            # then a later human override flips it to FP
            record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "keep_open",
                        "rationale": "guard bypassable",
                    }
                ],
                ACTOR,
                NOW,
                root=Path(tmp),
            )
            receipt = record_decisions(
                [
                    {
                        "layer": str(lp),
                        "finding": REF,
                        "decision": "override_false_positive",
                        "rationale": "Retested: the bypass needs a config no "
                        "shipped profile enables.",
                    }
                ],
                ACTOR,
                "2026-07-12T09:00:00+00:00",
                root=Path(tmp),
            )
            cur = json.loads((d / "t-findings-current.json").read_text())
        self.assertEqual(cur["findings"][0]["validation_status"], "false_positive")
        self.assertTrue(any("evidence-class precedence" in r for r in receipt))

    def test_queue_file_override_cards_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "queue.md"
            q.write_text(
                "\n---\n".join(
                    [
                        f"<!-- countersign finding={REF} layer=findings/p/r/t-findings-layer.json -->\n"
                        "DECISION: [x] severity=critical\n"
                        "RATIONALE: internet-reachable, chains to RCE",
                        f"<!-- countersign finding={REF}2 layer=findings/p/r/t-findings-layer.json -->\n"
                        "DECISION: [x] reopen\n"
                        "RATIONALE: reproduced on 4.20",
                        f"<!-- countersign finding={REF}3 layer=findings/p/r/t-findings-layer.json -->\n"
                        "DECISION: [x] override_false_positive\n"
                        "RATIONALE: unreachable config",
                    ]
                )
            )
            ds = parse_annotated_queue(q)
        self.assertEqual(
            [d["decision"] for d in ds],
            ["severity=critical", "reopen", "override_false_positive"],
        )


if __name__ == "__main__":
    unittest.main()


# --- rebaseline-alias cards (v0.53.0) --------------------------------------

from traust.cli import countersign as cs


def _alias_layer(tmp_path, confirmed=False, rejected=False):
    import json as _json

    audit = {
        "title": "r security audit",
        "metadata": {"repository": "https://github.com/o/r"},
        "executive_summary": {
            "prose": "p" * 60,
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        },
        "findings": [
            {
                "id": "R-bbb2222-001",
                "title": "New finding",
                "severity": "high",
                "cwes": ["CWE-287"],
                "locations": [{"path": "a.go"}],
                "description": "d" * 60,
                "remediation": "fix them",
            }
        ],
    }
    layer = {
        "metadata": {
            "audit_report": "r-security-audit.json",
            "created": "2026-07-16T00:00:00+00:00",
            "harness_version": "0.53.0",
            "finding_aliases": {
                "old__release-1:FIND-001": {
                    "new_id": "R-bbb2222-001",
                    "matched_by": "path_set",
                    "mapped_at": "2026-07-16T00:00:00+00:00",
                    "from_report": "old__release-1-security-audit.json",
                    "confirmed": confirmed,
                    **({"rejected": True} if rejected else {}),
                }
            },
        },
        "events": [],
        "needs_review": [],
    }
    aj = tmp_path / "r-security-audit.json"
    lj = tmp_path / "r-findings-layer.json"
    aj.write_text(_json.dumps(audit))
    lj.write_text(_json.dumps(layer))
    return aj, lj


def test_discover_pending_surfaces_unconfirmed_aliases(tmp_path):
    _, _lj = _alias_layer(tmp_path)
    items = cs.discover_pending([tmp_path])
    kinds = [i["kind"] for i in items]
    assert kinds == ["rebaseline_alias"]
    assert items[0]["alias_key"] == "old__release-1:FIND-001"
    assert items[0]["new_finding"]["id"] == "R-bbb2222-001"


def test_discover_pending_skips_settled_aliases(tmp_path):
    _alias_layer(tmp_path, confirmed=True)
    assert cs.discover_pending([tmp_path]) == []


def test_record_confirm_and_reject_mapping(tmp_path):
    import json as _json

    _, lj = _alias_layer(tmp_path)
    actor = {"identity": "tester", "identity_verified": True, "kind": "human"}
    receipt = cs.record_decisions(
        [
            {
                "layer": str(lj),
                "finding": "old__release-1:FIND-001",
                "decision": "confirm_mapping",
                "rationale": "same bug",
            }
        ],
        actor,
        "2026-07-16T12:00:00+00:00",
        root=tmp_path,
    )
    layer = _json.loads(lj.read_text())
    al = layer["metadata"]["finding_aliases"]["old__release-1:FIND-001"]
    assert al["confirmed"] is True and al["confirmed_by"] == "tester"
    assert al["note"] == "same bug"
    assert any("confirm" in r for r in receipt)
    # settled mapping cannot be re-decided
    receipt2 = cs.record_decisions(
        [
            {
                "layer": str(lj),
                "finding": "old__release-1:FIND-001",
                "decision": "reject_mapping",
                "rationale": "",
            }
        ],
        actor,
        "2026-07-16T13:00:00+00:00",
        root=tmp_path,
    )
    assert any("settled" in r for r in receipt2)


def test_decision_line_parses_mapping_decisions():
    m = cs.DECISION_LINE.search("DECISION: [x] confirm_mapping   [ ] defer")
    assert m and m.group("decision") == "confirm_mapping"


# --------------------------------------------------------------------------
# Recording a decision must also CLOSE the queue entry it answers. Until
# 2026-08-25 it did not: the event was appended and the needs_review item stayed
# pending forever, so the queue grew without bound while confirmations stayed flat.
# --------------------------------------------------------------------------


def _layer_with_review(tmp_path, ref="FIND-001", reason="undetermined_finding"):
    import json

    layer = {
        "metadata": {"audit_report": "r-security-audit.json"},
        "events": [],
        "needs_review": [
            {
                "queued_at": "2026-08-01T00:00:00+00:00",
                "source_ref": "https://example.com/mr/1#note_1",
                "quote": "looks like a false positive to me",
                "author": "someone",
                "status": "pending",
                "queue_reason": reason,
                "suggested_finding_ref": ref,
            }
        ],
    }
    p = tmp_path / "r-findings-layer.json"
    p.write_text(json.dumps(layer))
    return p


def _actor():
    return {
        "kind": "human",
        "identity": "tester",
        "identity_verified": True,
        "identity_provider": "ldap",
    }


def test_recording_a_decision_closes_the_queue_entry(tmp_path, monkeypatch):
    import json

    from traust.cli import countersign as cs

    p = _layer_with_review(tmp_path)
    monkeypatch.setattr(cs, "baseline_for", lambda _p: None)
    receipt = cs.record_decisions(
        [
            {
                "layer": str(p),
                "finding": "FIND-001",
                "decision": "false_positive",
                "rationale": "not reachable",
            }
        ],
        _actor(),
        "2026-08-25T00:00:00+00:00",
        root=tmp_path,
    )

    layer = json.loads(p.read_text())
    item = layer["needs_review"][0]
    assert item["status"] == "confirmed", "the queue entry must not stay pending"
    assert item["resolution_note"] == "not reachable"
    assert any("queue" in line for line in receipt)
    assert layer["events"], "and the event is still recorded"


def test_deferring_leaves_the_queue_entry_pending(tmp_path, monkeypatch):
    import json

    from traust.cli import countersign as cs

    p = _layer_with_review(tmp_path)
    monkeypatch.setattr(cs, "baseline_for", lambda _p: None)
    cs.record_decisions(
        [{"layer": str(p), "finding": "FIND-001", "decision": "defer"}],
        _actor(),
        "2026-08-25T00:00:00+00:00",
        root=tmp_path,
    )
    assert json.loads(p.read_text())["needs_review"][0]["status"] == "pending"


def test_an_unrelated_finding_does_not_close_the_entry(tmp_path, monkeypatch):
    import json

    from traust.cli import countersign as cs

    p = _layer_with_review(tmp_path, ref="FIND-001")
    monkeypatch.setattr(cs, "baseline_for", lambda _p: None)
    cs.record_decisions(
        [
            {
                "layer": str(p),
                "finding": "FIND-999",
                "decision": "false_positive",
                "rationale": "other finding",
            }
        ],
        _actor(),
        "2026-08-25T00:00:00+00:00",
        root=tmp_path,
    )
    assert json.loads(p.read_text())["needs_review"][0]["status"] == "pending"
