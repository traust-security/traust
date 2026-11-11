"""``traust metrics …`` — spend."""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    SpendDimension,
    SpendFilter,
    UsageDimension,
    UsageRollup,
)

from traust.cli.groups._registry import OpSpec, passthrough_op
from traust.context import load_spend_core, workspace_dir
from traust.paths import skill_dirs

UNATTRIBUTED = "unattributed"


def add_collect_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: today for live view)")
    ap.add_argument(
        "--append",
        action="store_true",
        help="record completed days in traust-core as spend per day, model and skill (idempotent)",
    )


def call_collect_spend(args) -> int:
    core = load_spend_core(args.config_home)
    transcripts = core.session_transcripts
    ws = args.workspace or workspace_dir(core)
    dirs = transcripts.project_dirs(ws)
    if not dirs:
        print(
            f"no Claude Code project transcripts under {transcripts.projects} for {ws}",
            file=sys.stderr,
        )
        return 1

    today = datetime.date.today().isoformat()

    if args.append:
        source = transcripts.source(ws, skill_names())
        if not source.usages:
            print("recorded 0 day×model×skill spend event(s)")
            return 0
        start = min(u.occurred_at for u in source.usages).astimezone(datetime.UTC)
        window = TimeWindow(
            start=start.replace(hour=0, minute=0, second=0, microsecond=0),
            end=datetime.datetime.now(datetime.UTC),
        )
        recorded = core.services().spend.collect(source, window)
        print(f"recorded {recorded} day×model×skill spend event(s)")
        return 0

    day = args.date or today
    source = transcripts.source(ws, ())
    rows = core.spend_views.usage_summary(source, _window(day, None), (UsageDimension.MODEL,))
    print(
        f"session spend — {day} ({'live' if day == today else 'final'}) "
        f"across {len(dirs)} project dir(s)"
    )
    if not rows:
        print("  no usage recorded")
        return 0
    for r in rows:
        t = r.tokens
        print(
            f"  {r.model}: out={t.tokens_out:,} in={t.tokens_in:,} "
            f"cache_read={t.cache_read:,} cache_new={t.cache_creation:,} "
            f"({r.messages} msgs, {r.sessions} sessions)"
        )
    return 0


def skill_names() -> set[str]:
    return {d.name for d in skill_dirs()}


COLLECT_SPEND = OpSpec(
    add_args=add_collect_spend_args,
    call=call_collect_spend,
    help="Collect workstation session spend from Claude Code transcripts (~/.claude/projects); "
    "`traust session run` sessions settle against their order instead",
)


def add_attribute_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="one day, YYYY-MM-DD")
    ap.add_argument("--month", default=None, help="one month, YYYY-MM")
    ap.add_argument(
        "--reconcile",
        action="store_true",
        help="prove traust-core's recorded spend splits by skill losslessly; exit 1 if not",
    )
    ap.add_argument("--json", action="store_true")


def call_attribute_spend(args) -> int:
    month = args.month
    if not month and not args.date:
        month = datetime.date.today().strftime("%Y-%m")

    if args.reconcile:
        return _reconcile(args, month)

    core = load_spend_core(args.config_home)
    transcripts = core.session_transcripts
    ws = args.workspace or workspace_dir(core)
    if not transcripts.project_dirs(ws):
        print(f"no session transcripts under {transcripts.projects} for {ws}", file=sys.stderr)
        return 3

    source = transcripts.source(ws, skill_names())
    window = _window(args.date, month)
    spend = core.spend_views
    if args.json:
        by = (UsageDimension.DAY, UsageDimension.SKILL, UsageDimension.MODEL)
        print(
            json.dumps(_buckets(spend.usage_summary(source, window, by)), indent=1, sort_keys=True)
        )
        return 0
    lanes = spend.usage_summary(source, window, (UsageDimension.SKILL,))
    print("\n".join(render_attribution(lanes, args.date or month or "all")))
    return 0


def _window(day: str | None, month: str | None) -> TimeWindow:
    start = datetime.datetime.fromisoformat(day or f"{month}-01").replace(tzinfo=datetime.UTC)
    if day:
        return TimeWindow(start=start, end=start + datetime.timedelta(days=1))
    return TimeWindow.month_of(start)


def _buckets(rows: list[UsageRollup]) -> dict:
    """{date: {lane: {model: usage}}}, in the field names `--json` has always printed."""
    out: dict = {}
    for r in rows:
        t = r.tokens
        bucket = {
            "input_tokens": t.tokens_in,
            "output_tokens": t.tokens_out,
            "cache_read_input_tokens": t.cache_read,
            "cache_creation_input_tokens": t.cache_creation,
            "messages": r.messages,
            "sessions": r.sessions,
        }
        if r.long_prompt:
            bucket["long_prompt"] = r.long_prompt.model_dump()
        out.setdefault(str(r.day), {}).setdefault(r.skill or UNATTRIBUTED, {})[r.model] = bucket
    return out


def render_attribution(lanes: list[UsageRollup], label: str) -> list[str]:
    """The per-lane table: priced lanes by cost, unpriced models named, never counted as $0."""
    costs = {r.skill or UNATTRIBUTED: r.cost_usd for r in lanes if r.cost_usd is not None}
    tot_usd = sum(costs.values())
    tot_out = sum(r.tokens.tokens_out for r in lanes) or 1
    lines = [
        f"# Per-lane spend attribution — {label}",
        "",
        "_Inferred from session transcripts (which skill the session "
        "was running), not self-reported by agents — the declared "
        "side records 0 tokens by contract. `unattributed` is "
        "always shown._",
        "",
        "| Lane | Est. USD | Share | Output tokens | Cache read | Messages | Sessions |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in sorted(
        lanes, key=lambda r: -costs.get(r.skill or UNATTRIBUTED, r.tokens.tokens_out / 1e9)
    ):
        usd = r.cost_usd
        share = f"{usd / tot_usd * 100:.1f}%" if usd is not None and tot_usd else "—"
        lines.append(
            f"| {r.skill or UNATTRIBUTED} | {f'{usd:,.2f}' if usd is not None else 'n/a'} | "
            f"{share} | {r.tokens.tokens_out:,} | {r.tokens.cache_read:,} | "
            f"{r.messages:,} | {r.sessions} |"
        )
    lines += ["", f"**Total priced: ${tot_usd:,.2f}**"]
    lane_usd = sum(v for k, v in costs.items() if k != UNATTRIBUTED)
    unattributed_usd = costs.get(UNATTRIBUTED, 0)
    if tot_usd:
        lines += [
            f"**Harness lanes: ${lane_usd:,.2f} ({lane_usd / tot_usd * 100:.1f}%)** · "
            f"unattributed ${unattributed_usd:,.2f} ({unattributed_usd / tot_usd * 100:.1f}%)"
        ]
    else:
        # Nothing priced: the lane vs unattributed split is the headline, so in output tokens.
        lane_tok = sum(r.tokens.tokens_out for r in lanes if r.skill is not None)
        un_tok = sum(r.tokens.tokens_out for r in lanes if r.skill is None)
        lines += [
            f"**Harness lanes: {lane_tok:,} output tokens "
            f"({lane_tok / tot_out * 100:.1f}%)** · unattributed "
            f"{un_tok:,} ({un_tok / tot_out * 100:.1f}%) — "
            f"no USD: no model in this window has a registry price"
        ]
    if unpriced := sorted({m for r in lanes for m in r.unpriced}):
        lines += [
            "",
            f"⚠ unpriced models excluded from the USD column "
            f"(no registry price): {', '.join(unpriced)}",
        ]
    lines += [
        "",
        f"_Share of output tokens is a cross-check on the USD split; total output {tot_out:,}._",
    ]
    return lines


def _reconcile(args, month: str | None) -> int:
    window = _window(args.date, month)
    split = (
        load_spend_core(args.config_home)
        .services()
        .spend.attribute_by(SpendFilter(window=window), SpendDimension.SKILL)
    )
    if args.json:
        print(json.dumps(split.model_dump(mode="json") | {"lossless": split.lossless}, indent=1))
    else:
        t = split.total
        print(
            f"recorded spend by skill, {window.start.date()} to {window.end.date()}:"
            f"\n  total: {t.events} events, {t.tokens_out:,} output tokens, ${t.cost_usd:,.2f}"
            f"\n  unattributed: ${split.unattributed.cost_usd:,.2f}\n  lossless: {split.lossless}"
        )
    return 0 if split.lossless else 1


ATTRIBUTE_SPEND = OpSpec(
    add_args=add_attribute_spend_args,
    call=call_attribute_spend,
    help="Attribute session spend to harness lanes from transcripts",
)


LANE_COSTS = passthrough_op(
    "lane_costs", "Median settled cost per order per lane over the last --days", "main"
)
