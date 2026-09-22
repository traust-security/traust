"""Tests for harnessing/financial-tracking/scripts/build_financial_report.py — financial reporting
over the existing spend chain."""

import json
import sqlite3

import build_financial_report as bfr
import pytest
from traust_engine.metrics import history as metrics_ledger


def _db(tmp_path, rows=(("openshift", "etcd", "findings", "Hybrid Platforms"),)):
    p = tmp_path / "findings.db"
    con = sqlite3.connect(p)
    # `preferred` is a STRING enum in the real findings.db, not a bool
    con.execute(
        "CREATE TABLE repos (product TEXT, base_slug TEXT, "
        "tree TEXT, business_unit TEXT, repo_url TEXT, "
        "preferred TEXT)"
    )
    for i, (prod, slug, tree, bu) in enumerate(rows):
        con.execute(
            "INSERT INTO repos VALUES (?,?,?,?,?,'audit_json')",
            (prod, slug, tree, bu, f"https://x/{i}"),
        )
    # a non-baseline row that must NOT inflate the repo denominator
    con.execute(
        "INSERT INTO repos VALUES ('p','s','findings','BU','https://x/other','findings_current')"
    )
    # current_finding is the contract's spine; the fixture needs only its severity.
    con.execute("CREATE TABLE current_finding (severity TEXT)")
    for sev in ("critical", "high", "low"):
        con.execute("INSERT INTO current_finding VALUES (?)", (sev,))
    con.commit()
    con.close()
    return p


class TestBuResolution:
    def test_maps_product_slug_and_tree(self, tmp_path):
        m = bfr.bu_maps(_db(tmp_path))
        assert m["product"]["openshift"] == "Hybrid Platforms"
        assert m["slug"]["etcd"] == "Hybrid Platforms"
        assert m["tree"]["findings"] == "Hybrid Platforms"

    def test_missing_db_degrades_to_empty(self, tmp_path):
        m = bfr.bu_maps(tmp_path / "nope.db")
        assert m == {"product": {}, "slug": {}, "tree": {}}

    def test_detects_bu_from_a_findings_path(self, tmp_path):
        maps = bfr.bu_maps(_db(tmp_path))
        rec = {
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "input": {
                            "file_path": "/w/analysis-results/findings/openshift/etcd/"
                            "etcd-security-audit.json"
                        },
                    }
                ]
            }
        }
        assert bfr.detect_bu(rec, maps) == "Hybrid Platforms"

    def test_bookkeeping_dirs_are_not_products(self, tmp_path):
        maps = bfr.bu_maps(_db(tmp_path))
        rec = {"x": "analysis-results/findings/_manifest/PROGRESS.md"}
        assert bfr.detect_bu(rec, maps) is None

    def test_no_path_means_no_signal(self, tmp_path):
        maps = bfr.bu_maps(_db(tmp_path))
        assert bfr.detect_bu({"message": {"content": "hello"}}, maps) is None

    def test_unknown_product_does_not_invent_a_bu(self, tmp_path):
        maps = bfr.bu_maps(_db(tmp_path))
        rec = {"x": "analysis-results/nosuchtree/nosuchprod/nosuchrepo/x.json"}
        assert bfr.detect_bu(rec, maps) is None


class TestLedgerSeriesAndSplit:
    def _rows(self):
        return [
            {
                "source": "spend-attribution:vuln-scan",
                "metrics": {"date": "2026-07-02", "skill": "vuln-scan", "cost_usd": 10.0},
            },
            {
                "source": "spend-attribution:unattributed",
                "metrics": {"date": "2026-07-03", "skill": "unattributed", "cost_usd": 90.0},
            },
            {
                "source": "model-spend:vuln-scan",  # declared: ignored
                "metrics": {"date": "2026-07-02", "skill": "vuln-scan", "cost_usd": 5.0},
            },
        ]

    def test_series_ignores_declared_rows(self, tmp_path, monkeypatch):
        monkeypatch.setattr(metrics_ledger, "rows", lambda: self._rows())
        s, _ = bfr.ledger_series(tmp_path, reprice=False)
        assert s["2026-07"]["vuln-scan"] == 10.0
        assert "5.0" not in json.dumps(s)

    def test_lane_split_excludes_unattributed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(metrics_ledger, "rows", lambda: self._rows())
        series, _ = bfr.ledger_series(tmp_path, reprice=False)
        lane, un = bfr.lane_split(series["2026-07"])
        assert (lane, un) == (10.0, 90.0)


class TestUnitEconomics:
    def test_ratios(self):
        ue = bfr.unit_economics(100.0, {"repos": 4, "findings": 8, "crit_high": 2})
        assert ue["usd_per_repo"] == 25.0
        assert ue["usd_per_finding"] == 12.5
        assert ue["usd_per_crit_high"] == 50.0

    def test_zero_denominator_is_none_not_a_crash(self):
        ue = bfr.unit_economics(100.0, {"repos": 0, "findings": 0, "crit_high": 0})
        assert ue["usd_per_repo"] is None

    def test_counts_read_from_db(self, tmp_path):
        c = bfr.campaign_counts(_db(tmp_path))
        assert c["repos"] == 1 and c["findings"] == 3 and c["crit_high"] == 2


class TestInvoiceSeam:
    def test_loads_periods(self, tmp_path):
        p = tmp_path / "inv.csv"
        p.write_text("period,amount_usd,note\n2026-07,1000.50,july\n")
        got = bfr.load_invoices(p)
        assert got["2026-07"]["amount_usd"] == 1000.50

    def test_bad_rows_are_skipped_not_fatal(self, tmp_path):
        p = tmp_path / "inv.csv"
        p.write_text("period,amount_usd\n2026-07,notanumber\n2026-08,5\n")
        got = bfr.load_invoices(p)
        assert "2026-07" not in got and got["2026-08"]["amount_usd"] == 5.0

    def test_missing_file_is_empty(self, tmp_path):
        assert bfr.load_invoices(tmp_path / "nope.csv") == {}


class TestUnverifiedPriceCaveat:
    def test_parser_still_detects_a_comment_marker(self, tmp_path):
        """The registry flags an unverified rate in a trailing COMMENT,
        not a field. claude-opus-5 carried that marker until 2026-08-06,
        when the rate was corrected to the published 5/25 and the marker
        removed — so this now asserts the PARSER works, against a
        fixture, rather than depending on a specific model staying
        broken."""
        p = tmp_path / "model-registry.yaml"
        p.write_text(
            "models:\n"
            "  some-model: {price_per_mtok_in: 1.0}  # price unverified\n"
            "  ok-model:   {price_per_mtok_in: 2.0}  # published rate\n"
        )
        got = bfr.unverified_models(p)
        assert got == ["some-model"], got

    def test_shipped_registry_has_no_unverified_rate(self):
        """Guards the 2026-08-06 correction: every priced model should
        match a published rate. If a marker reappears, a rate is in
        doubt again and every dollar figure inherits that doubt."""
        assert bfr.unverified_models() == [], (
            "a model rate is marked unverified again — confirm it "
            "against the published rate card before trusting any total"
        )

    def test_missing_registry_degrades_quietly(self, tmp_path):
        assert bfr.unverified_models(tmp_path / "nope.yaml") == []


class TestRender:
    def _report(self, **over):
        r = {
            "period_label": "2026-07",
            "generated": "now",
            "harness_version": "t",
            "period": {
                "month": "2026-07",
                "lane_usd": 100.0,
                "unattributed_usd": 20.0,
                "total_usd": 120.0,
                "by_lane": {"vuln-scan": 100.0},
            },
            "unit_economics": bfr.unit_economics(
                100.0, {"repos": 2, "findings": 4, "crit_high": 1}
            ),
            "trend": {"2026-07": {"lane": 100.0, "unattributed": 20.0, "total": 120.0}},
            "caveats": {"unverified_models": ["claude-opus-5"], "invoice_supplied": False},
        }
        r.update(over)
        return r

    def test_estimate_caveat_leads_the_report(self):
        body = "\n".join(bfr.render(self._report()))
        head = body.split("## Period cost")[0]
        assert "list-price estimates" in head
        assert "claude-opus-5" in head
        assert "unverified" in head

    def test_says_plainly_when_no_invoice_was_supplied(self):
        body = "\n".join(bfr.render(self._report()))
        assert "No invoice supplied" in body

    def test_invoice_variance_shown_when_supplied(self):
        body = "\n".join(
            bfr.render(
                self._report(
                    invoice={
                        "estimate": 120.0,
                        "invoiced": 150.0,
                        "variance": 30.0,
                        "variance_pct": "+25.0%",
                    }
                )
            )
        )
        assert "vs invoiced" in body and "+25.0%" in body

    def test_bu_section_states_coverage_and_keeps_unknown(self):
        body = "\n".join(
            bfr.render(
                self._report(
                    by_bu={
                        "by_bu": {"Hybrid Platforms": 40.0, bfr.BU_UNKNOWN: 80.0},
                        "total_usd": 120.0,
                        "resolved_usd": 40.0,
                        "coverage_pct": "33.3%",
                        "unpriced_models": [],
                    }
                )
            )
        )
        assert "Coverage 33.3%" in body
        assert bfr.BU_UNKNOWN in body  # never hidden
        assert "never redistributed" in body

    def test_bu_and_lane_axes_are_flagged_as_non_reconciling(self):
        """The two tables split the same total differently; a reader
        must not treat a BU figure as a lane figure."""
        body = "\n".join(
            bfr.render(
                self._report(
                    by_bu={
                        "by_bu": {"X": 1.0},
                        "total_usd": 1.0,
                        "resolved_usd": 1.0,
                        "coverage_pct": "100%",
                        "unpriced_models": [],
                    }
                )
            )
        )
        assert "different axes" in body

    def test_unit_economics_denominator_caveat_present(self):
        body = "\n".join(bfr.render(self._report()))
        assert "census" in body and "understates" in body


class TestRegressions:
    def test_preferred_is_a_string_enum_not_a_boolean(self, tmp_path):
        """Shipped bug: `WHERE preferred=1` matched nothing, so a fully
        populated corpus reported 0 repos and 'cost per repo: n/a'."""
        c = bfr.campaign_counts(_db(tmp_path))
        assert c["repos"] == 1, "audit_json baselines must be counted"

    def test_findings_current_rows_do_not_inflate_the_denominator(self, tmp_path):
        c = bfr.campaign_counts(_db(tmp_path))
        assert c["repos"] == 1  # the findings_current row is excluded

    def test_trend_delta_compares_to_the_older_month(self):
        """Shipped bug: iterating newest-first while carrying `prev`
        forward inverted the sign — a month read as an increase
        measured against a month that had not happened."""
        report = {
            "period_label": "x",
            "generated": "n",
            "harness_version": "t",
            "period": {
                "month": "2026-08",
                "lane_usd": 100.0,
                "unattributed_usd": 0.0,
                "total_usd": 100.0,
                "by_lane": {},
            },
            "unit_economics": bfr.unit_economics(
                100.0, {"repos": 1, "findings": 1, "crit_high": 1}
            ),
            "trend": {
                "2026-07": {"lane": 1000.0, "unattributed": 0.0, "total": 1000.0},
                "2026-08": {"lane": 100.0, "unattributed": 0.0, "total": 100.0},
            },
            "caveats": {"unverified_models": [], "invoice_supplied": False},
        }
        lines = bfr.render(report)
        aug = next(l for l in lines if l.startswith("| 2026-08 |"))
        jul = next(l for l in lines if l.startswith("| 2026-07 |"))
        assert "-900.00" in aug, aug  # August fell vs July
        assert aug.count("+") == 0, aug
        assert jul.rstrip().endswith("— |"), jul  # oldest row has no delta


class TestRepricing:
    """Tokens are the fact; dollars are derived. A wrong rate must be
    fixable without rewriting the append-only ledger."""

    @staticmethod
    def _reg():
        from traust.context import load_engine

        return load_engine().models.registry()

    def _rows(self, stored):
        return [
            {
                "source": "spend-attribution:vuln-scan",
                "metrics": {
                    "date": "2026-07-02",
                    "skill": "vuln-scan",
                    "model": "claude-opus-5",
                    "cost_usd": stored,
                    "tokens_in": 1_000_000,
                    "tokens_out": 1_000_000,
                    "cache_read": 0,
                    "cache_creation": 0,
                },
            }
        ]

    def test_derives_from_tokens_not_the_stored_amount(self, tmp_path, monkeypatch):
        """The shipped bug: rows appended under a 3x-too-high rate would
        report that rate forever if cost_usd were trusted."""
        monkeypatch.setattr(metrics_ledger, "rows", lambda: self._rows(90.0))  # bad stored value
        series, stats = bfr.ledger_series(tmp_path, reprice=True, reg=self._reg())
        # 1M in @ $5 + 1M out @ $25 = $30 at the published rate
        assert series["2026-07"]["vuln-scan"] == pytest.approx(30.0, abs=0.01)
        assert stats["repriced"] == 1
        assert stats["drift_usd"] == pytest.approx(-60.0, abs=0.01)

    def test_reprice_false_returns_what_was_recorded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(metrics_ledger, "rows", lambda: self._rows(90.0))
        series, _ = bfr.ledger_series(tmp_path, reprice=False)
        assert series["2026-07"]["vuln-scan"] == 90.0

    def test_unpriced_model_is_named_not_zeroed(self, tmp_path, monkeypatch):
        rows = self._rows(5.0)
        rows[0]["metrics"]["model"] = "no-such-model"
        monkeypatch.setattr(metrics_ledger, "rows", lambda: rows)
        series, stats = bfr.ledger_series(tmp_path, reprice=True, reg=self._reg())
        if stats["unpriced"]:
            assert "no-such-model" in stats["unpriced"]
            # falls back to the stored value rather than dropping to $0
            assert series["2026-07"]["vuln-scan"] == 5.0

    def test_opus5_priced_at_the_published_rate(self):
        """Direct regression on the corrected rate. 1M in + 1M out on
        claude-opus-5 is $30 at the published $5/$25; it was $90 under
        the stale Opus 4.1-era $15/$75."""
        from traust_engine.registry import models as model_registry

        from traust.context import load_engine

        reg = load_engine().models.registry()
        usd = model_registry.cost_usd(reg, "claude-opus-5", 1_000_000, 1_000_000, 0, 0)
        assert usd == pytest.approx(30.0, abs=0.01), (
            f"claude-opus-5 prices to ${usd} for 1M+1M — expected $30.00 "  # estate-data-ok: public list price, not a corpus figure
            f"($5/$25 published). $90 means the stale 15/75 rate is back."
        )
