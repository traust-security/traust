"""Legacy adapter for the exported work-routing corpus (not production policy).

Adapted from generate.py and generate_primary.py at the SDK revision recorded in
fixtures/routing/baseline.json. Execute the checked-out CLI's original AST nodes;
do not duplicate its rules or import its deployment/I/O dependencies. Inputs and
outputs retain the SDK fixture shape. Only temporary event/graph files are used.
"""

import ast
import datetime
import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

URL = "https://github.com/example/repository"
REFERENCE_NAMES = {
    "CHURN_FULL_LINES",
    "CHURN_FULL_RATIO",
    "SENSITIVE_MIN_LINES",
    "TIER_CEILING_DAYS",
    "TIGHTENED_CEILING_DAYS",
    "P0_MIN_LIVE",
    "_rule3_lane",
    "_over_ceiling",
    "DECISION_TABLE",
    "decide",
    "risk_tier",
    "EVENT_SOURCES",
    "event_lane",
    "load_events",
    "_parse_date",
    "RELEASE_REMODEL_CHANGES",
    "EXPOSURE_ORDER",
    "lookup_designation",
    "never_audited_rows",
}


def verify_digest(raw: bytes, expected: str, label: str) -> None:
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(
            f"{label}: SHA-256 changed (expected {expected}, got {actual}). "
            "Review the source/fixture diff before updating baseline.json; "
            "see tests/fixtures/routing/README.md."
        )


def _assigned(node: ast.stmt, name: str) -> bool:
    return isinstance(node, ast.Assign) and any(
        isinstance(part, ast.Name) and part.id == name
        for target in node.targets
        for part in ast.walk(target)
    )


def load_reference(source: Path):
    """Load actual legacy definitions and its event/table block, without main I/O.

    The test suite separately checks the whole-file hash. Keeping that check out
    of this adapter lets a drift failure report alongside named behavior failures.
    """
    tree = ast.parse(source.read_bytes(), filename=str(source))
    selected, found = [], set()
    for node in tree.body:
        names = {node.name} if isinstance(node, ast.FunctionDef) else set()
        if isinstance(node, ast.Assign):
            names = {n.id for n in node.targets if isinstance(n, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        if names & REFERENCE_NAMES:
            selected.append(node)
            found.update(names & REFERENCE_NAMES)
    if found != REFERENCE_NAMES:
        raise ValueError(f"missing legacy definitions: {sorted(REFERENCE_NAMES - found)}")
    namespace = {
        "Path": Path,
        "sqlite3": sqlite3,
        "json": json,
        "_dt": datetime,
        # This corpus supplies canonical URLs; identity normalization is not tested.
        "normalize_repo_url": lambda value: value,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    starts = [i for i, n in enumerate(main.body) if _assigned(n, "event_rows")]
    stops = [i for i, n in enumerate(main.body) if _assigned(n, "cc_urls")]
    if len(starts) != 1 or len(stops) != 1 or starts[0] >= stops[0]:
        raise ValueError("legacy event/table block moved; review the parity adapter's boundaries")
    # Same anchors as the original generator: include event precedence/status
    # handling, stop before additive IaC companions. No policy is rewritten here.
    loops = compile(
        ast.Module(body=main.body[starts[0] : stops[0]], type_ignores=[]), str(source), "exec"
    )
    return namespace, loops


def run_primary(reference_ns, loops, supplied: dict, directory: Path) -> dict:
    """Translate one fixture and execute the legacy loops/bootstrap helper.

    Translation follows the original generator, including event indexes, multiple
    decisions and bootstrap. This is not a proposed single-Route SDK interface.
    """
    ns = reference_ns.copy()
    audit = supplied.get("Audit")
    entries = []
    if audit is not None:
        risk = audit.get("Risk", {})
        entry = {
            "repo_key": "example/repository",
            "repo_url": URL,
            "live_crit_high": risk.get("LiveCriticalHigh", 0),
            "archived": risk.get("Archived", False),
            "dormant": risk.get("Dormant", False),
            "status": audit["Status"],
            "exposure": audit.get("Exposure", ""),
            "audit_age_days": audit.get("AuditAgeDays"),
            "changed": audit.get("PushChanged", False),
        }
        change = audit.get("Change")
        if change is not None:
            for fixture_key, entry_key in (
                ("ChangedLines", "C"),
                ("SensitiveChange", "S"),
                ("SensitiveChangedLines", "S_lines"),
                ("DependenciesOnly", "deps_only"),
            ):
                entry[entry_key] = change.get(
                    fixture_key,
                    False if fixture_key in ("SensitiveChange", "DependenciesOnly") else 0,
                )
            entry["ahead_by"] = change.get("CommitsAhead")
            ratio = change.get("CoverageChangeRatio")
            if ratio:
                if not entry["C"]:
                    raise ValueError("positive reference ratio needs nonzero changed lines")
                entry["lines_reviewed"] = entry["C"] / ratio
        entries.append(entry)

    event_path = directory / "events.jsonl"
    events = supplied.get("Events", [])
    event_path.write_text(
        "".join(
            json.dumps({"repo": URL, "source": e["Source"], "consumed": e.get("Consumed", False)})
            + "\n"
            for e in events
        ),
        encoding="utf-8",
    )
    ns.update(
        entries=entries,
        events=ns["load_events"](event_path),
        by_url={e["repo_url"]: e for e in entries},
        by_key={e["repo_key"]: e for e in entries},
        args=SimpleNamespace(no_threat_model=True),
        today=datetime.date(2026, 9, 28),  # Original generator's fixed clock.
    )
    exec(loops, ns)
    graph = directory / "graph.db"
    con = sqlite3.connect(graph)
    inventory = supplied.get("Inventory")
    try:
        con.execute("CREATE TABLE nodes (id TEXT)")
        if inventory is not None:
            con.execute("INSERT INTO nodes VALUES (?)", ("repo:" + URL.removeprefix("https://"),))
        con.commit()
    finally:
        con.close()
    designation = inventory.get("Designation", "") if inventory is not None else ""
    bootstrap = (
        []
        if supplied.get("DisableBootstrap", False)
        else ns["never_audited_rows"](
            graph, {e["repo_url"] for e in entries}, [(URL, designation)] if designation else []
        )
    )
    kept_indexes = [
        i
        for i, e in enumerate(events)
        if not e.get("Consumed", False) and e["Source"] in ns["EVENT_SOURCES"]
    ]
    honored = [
        {"EventIndex": i, "Queued": e["queued"], "Disposition": e.get("disposition", "")}
        for i, e in zip(kept_indexes, ns["events_honored"], strict=True)
    ]
    queued_indexes = iter(e["EventIndex"] for e in honored if e["Queued"])
    rows = ns["event_rows"] + ns["table_rows"] + bootstrap
    return {
        "Decisions": [
            {
                "Rule": r["rule"],
                "Lane": r["lane"],
                "Reason": r["reason"],
                "RiskTier": r["tier"],
                "Exposure": r.get("exposure", ""),
                "Status": r["status"],
                "EventIndex": next(queued_indexes) if "event_source" in r else None,
            }
            for r in rows
        ],
        "EventsHonored": honored,
    }
