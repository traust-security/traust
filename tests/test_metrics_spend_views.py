"""`traust metrics collect-spend` (live view) and `attribute-spend` (table, `--json`) on traust-core's
`SpendService.usage_summary`, against what traust-engine's `collect_spend.collect` and
`attribute_spend.collect_attributed` + `render` printed for the same transcripts (captured before
the engine's copy was deleted).

Attribution runs on the skills that exist (as `--append` does); the engine's `attribute-spend`
passed none, so it attributed nothing (bug fixed here).
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.context import Context
from traust_core.v1.providers.transcripts import SessionTranscripts

from traust.cli.groups import metrics

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
WORKSPACE = Path("/w/workspace")
DAY1, DAY2 = "2026-10-05", "2026-10-06"


def request(ts: str, model: str, tokens_in: int, tokens_out: int, **usage: int) -> dict[str, Any]:
    tokens = {"input_tokens": tokens_in, "output_tokens": tokens_out, **usage}
    return {"timestamp": f"{ts}Z", "message": {"model": model, "usage": tokens}}


def signal(ts: str, content: Any) -> dict[str, Any]:
    return {"timestamp": f"{ts}Z", "message": {"content": content}}


def skill_call(ts: str, name: str) -> dict[str, Any]:
    return signal(ts, [{"type": "tool_use", "name": "Skill", "input": {"skill": name}}])


SESSIONS = {
    "s1": [
        request(f"{DAY1}T08:00:00", "claude-opus-5-5", 1200, 300),
        skill_call(f"{DAY1}T08:01:00", "triage"),
        request(f"{DAY1}T08:02:00", "claude-opus-5-5", 800, 90, cache_read_input_tokens=40_000),
        # a prompt over claude-haiku-5-5's 100k long-prompt threshold
        request(f"{DAY1}T08:03:00", "claude-haiku-5-5", 95_000, 700, cache_read_input_tokens=9_000),
        request(f"{DAY1}T08:04:00", "<synthetic>", 5, 5),
        request(
            f"{DAY2}T09:00:00", "claude-sonnet-5-5", 2000, 400, cache_creation_input_tokens=3000
        ),
    ],
    "s2": [
        signal(f"{DAY1}T10:00:00", "<command-name>/secure-code-audit</command-name>"),
        request(f"{DAY1}T10:01:00", "claude-opus-5-5", 600, 1100),
        request(f"{DAY1}T10:02:00", "claude-not-in-the-registry", 100, 70),
        signal(f"{DAY1}T10:03:00", "read harnessing/5-validate/validate-findings/SKILL.md"),
        request(f"{DAY1}T10:04:00", "claude-haiku-5-5", 3000, 45),
    ],
}


@pytest.fixture
def projects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    for name, records in SESSIONS.items():
        lines = [json.dumps(r) for r in records]
        (project / f"{name}.jsonl").write_text("\n".join([*lines, '{"usage": torn']) + "\n")
    monkeypatch.setattr(Context, "session_transcripts", SessionTranscripts(tmp_path / "projects"))
    return project


@pytest.fixture
def config(tmp_path: Path) -> Path:
    home = tmp_path / "config"
    home.mkdir()
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    (home / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return home


def args(config: Path, **kw: Any) -> Any:
    values = {"workspace": WORKSPACE, "date": None, "month": None, "json": False}
    return SimpleNamespace(config_home=config, append=False, reconcile=False, **{**values, **kw})


def stdout(fn: Any, *a: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


LIVE = {
    DAY1: [
        "  claude-haiku-5-5: out=745 in=98,000 cache_read=9,000 cache_new=0 (2 msgs, 2 sessions)",  # estate-data-ok: synthetic transcripts
        "  claude-not-in-the-registry: out=70 in=100 cache_read=0 cache_new=0 (1 msgs, 1 sessions)",
        "  claude-opus-5-5: out=1,490 in=2,600 cache_read=40,000 cache_new=0 (3 msgs, 2 sessions)",  # estate-data-ok: synthetic transcripts
    ],
    DAY2: [
        "  claude-sonnet-5-5: out=400 in=2,000 cache_read=0 cache_new=3,000 (1 msgs, 1 sessions)"  # estate-data-ok: synthetic transcripts
    ],
    "2026-10-07": ["  no usage recorded"],
}

TABLE_HEAD = [
    "",
    "_Inferred from session transcripts (which skill the session was running), not self-reported "
    "by agents — the declared side records 0 tokens by contract. `unattributed` is always shown._",
    "",
    "| Lane | Est. USD | Share | Output tokens | Cache read | Messages | Sessions |",
    "|---|---:|---:|---:|---:|---:|---:|",
]
UNPRICED = [
    "",
    "⚠ unpriced models excluded from the USD column (no registry price): "
    "claude-not-in-the-registry",
]
TABLES = {
    "2026-10": [
        "| triage | 0.08 | 68.8% | 1,190 | 49,000 | 3 | 1 |",  # estate-data-ok: synthetic transcripts
        "| secure-code-audit | 0.02 | 21.5% | 1,170 | 0 | 2 | 1 |",  # estate-data-ok: synthetic transcripts
        "| unattributed | 0.01 | 9.5% | 300 | 0 | 1 | 1 |",
        "| validate-findings | 0.00 | 0.3% | 45 | 0 | 1 | 1 |",
        "",
        "**Total priced: $0.11**",  # estate-data-ok: synthetic transcripts
        "**Harness lanes: $0.10 (90.5%)** · unattributed $0.01 (9.5%)",  # estate-data-ok: synthetic transcripts
        *UNPRICED,
        "",
        "_Share of output tokens is a cross-check on the USD split; total output 2,705._",  # estate-data-ok: synthetic transcripts
    ],
    DAY1: [
        "| triage | 0.06 | 63.8% | 790 | 49,000 | 2 | 1 |",  # estate-data-ok: synthetic transcripts
        "| secure-code-audit | 0.02 | 24.8% | 1,170 | 0 | 2 | 1 |",  # estate-data-ok: synthetic transcripts
        "| unattributed | 0.01 | 11.0% | 300 | 0 | 1 | 1 |",
        "| validate-findings | 0.00 | 0.3% | 45 | 0 | 1 | 1 |",
        "",
        "**Total priced: $0.10**",  # estate-data-ok: synthetic transcripts
        "**Harness lanes: $0.09 (89.0%)** · unattributed $0.01 (11.0%)",  # estate-data-ok: synthetic transcripts
        *UNPRICED,
        "",
        "_Share of output tokens is a cross-check on the USD split; total output 2,305._",  # estate-data-ok: synthetic transcripts
    ],
    "2026-09": [
        "",
        "**Total priced: $0.00**",  # estate-data-ok: synthetic transcripts
        "**Harness lanes: 0 output tokens (0.0%)** · unattributed 0 (0.0%) — no USD: no model in "
        "this window has a registry price",
        "",
        "_Share of output tokens is a cross-check on the USD split; total output 1._",
    ],
}


def usage(tokens_in: int, tokens_out: int, cache_read: int = 0, cache_new: int = 0) -> dict:
    return {
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_new,
        "messages": 1,
        "sessions": 1,
    }


BUCKETS = {
    DAY1: {
        "secure-code-audit": {
            "claude-not-in-the-registry": usage(100, 70),
            "claude-opus-5-5": usage(600, 1100),
        },
        "triage": {
            "claude-haiku-5-5": usage(95000, 700, 9000)
            | {
                "long_prompt": {
                    "tokens_in": 95000,
                    "tokens_out": 700,
                    "cache_read": 9000,
                    "cache_creation": 0,
                }
            },
            "claude-opus-5-5": usage(800, 90, 40000),
        },
        "unattributed": {"claude-opus-5-5": usage(1200, 300)},
        "validate-findings": {"claude-haiku-5-5": usage(3000, 45)},
    },
    DAY2: {"triage": {"claude-sonnet-5-5": usage(2000, 400, cache_new=3000)}},
}


@pytest.mark.parametrize("day", [DAY1, DAY2, "2026-10-07"])
def test_the_live_view_matches_the_engine_collector(projects: Path, config: Path, day: str) -> None:
    expected = [f"session spend — {day} (final) across 1 project dir(s)", *LIVE[day]]
    assert stdout(metrics.call_collect_spend, args(config, date=day)) == (
        0,
        "\n".join(expected) + "\n",
    )


@pytest.mark.parametrize(("date", "month"), [(None, "2026-10"), (DAY1, None), (None, "2026-09")])
def test_the_attribution_table_matches_the_engine_render(
    projects: Path, config: Path, date: str | None, month: str | None
) -> None:
    label = date or month
    expected = [f"# Per-lane spend attribution — {label}", *TABLE_HEAD, *TABLES[label]]
    rc, out = stdout(metrics.call_attribute_spend, args(config, date=date, month=month))
    assert (rc, out) == (0, "\n".join(expected) + "\n")


def test_the_attribution_json_matches_the_engine_buckets(projects: Path, config: Path) -> None:
    rc, out = stdout(metrics.call_attribute_spend, args(config, month="2026-10", json=True))
    assert rc == 0 and json.loads(out) == BUCKETS


def test_attribution_lands_on_every_known_lane(projects: Path, config: Path) -> None:
    rc, out = stdout(metrics.call_attribute_spend, args(config, month="2026-10", json=True))
    lanes = {s for skills in json.loads(out).values() for s in skills}
    assert rc == 0 and lanes == {"unattributed", "triage", "secure-code-audit", "validate-findings"}


def test_without_transcripts_the_live_view_exits_1_and_attribution_3(
    projects: Path, config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = Path("/elsewhere")
    assert metrics.call_collect_spend(args(config, workspace=elsewhere)) == 1
    assert metrics.call_attribute_spend(args(config, workspace=elsewhere)) == 3
    err = capsys.readouterr().err
    assert f"under {projects.parent} for /elsewhere" in err
