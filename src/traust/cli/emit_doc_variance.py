#!/usr/bin/env python3
"""Doc-variance register writer (doc-variance lane — the ONLY write path).

Appends variance records to a per-repo `<repo>-doc-variance.json`
register, schema-gated on every write (contracts/schemas/doc-variance.schema.json:
official docs.redhat.com sources only — the URL pattern is enforced
there, so informal inputs physically cannot mint records here).
Append-and-update discipline mirrors the disposition ledger's spirit:

- new record ids append; re-emitting an existing id with identical
  content is a no-op (idempotent re-runs);
- changing an existing record requires --update and preserves the old
  record under `superseded_by` semantics via disposition="superseded"
  plus a fresh id — history is never silently rewritten;
- every write re-validates the WHOLE register and refuses invalid.

Consumers: the doc-variance run reports, the threat-register variance
cut (P3), and audits/scans that convert records to findings
(finding_refs back-join). Emitters: the doc-variance verification
stage, and the threat-model / secure-code-audit emitter contracts (P3).

Usage:
    python3 emit_doc_variance.py --register <path> --records <json-file>
        [--repo-url <url>] [--update]
    (records file: a JSON array of record objects, or {"records": [...]})
Exit 0 on success; 1 on any refusal (invalid record, id conflict).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT, schema_path

SCHEMA = schema_path("doc-variance")


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def load_register(path: Path, repo_url: str | None) -> dict:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    if not repo_url:
        sys.exit("new register needs --repo-url")
    return {
        "metadata": {"repository": repo_url, "created": _now(), "harness_version": _hv()},
        "records": [],
    }


def _hv() -> str:
    """Harness version from pyproject.toml — the single version source."""
    try:
        pyproject = (HARNESS_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        return m.group(1) if m else "unknown"
    except OSError:
        return "unknown"


def emit(register_path: Path, new_records: list[dict], repo_url: str | None, update: bool) -> dict:
    reg = load_register(register_path, repo_url)
    by_id = {r["id"]: i for i, r in enumerate(reg["records"])}
    added = unchanged = updated = 0
    for rec in new_records:
        rid = rec.get("id", "")
        if rid in by_id:
            existing = reg["records"][by_id[rid]]
            if existing == rec:
                unchanged += 1
                continue
            if not update:
                sys.exit(
                    f"record {rid} exists with different content — "
                    f"pass --update to supersede (silent rewrite "
                    f"refused)"
                )
            superseded = dict(existing)
            superseded["disposition"] = "superseded"
            superseded["disposition_note"] = f"superseded {_now()} by {rid}-r{len(reg['records'])}"
            reg["records"][by_id[rid]] = superseded
            rec = dict(rec, id=f"{rid}-r{len(reg['records'])}")
            reg["records"].append(rec)
            updated += 1
        else:
            reg["records"].append(rec)
            added += 1
    reg["metadata"]["updated"] = _now()

    try:
        import jsonschema
    except ImportError:
        sys.exit("jsonschema required — the writer IS the validated path")
    try:
        jsonschema.validate(reg, json.loads(SCHEMA.read_text(encoding="utf-8")))
    except jsonschema.ValidationError as e:
        sys.exit(
            f"register would be invalid — refused: {e.message} "
            f"(at {'/'.join(str(x) for x in e.absolute_path)})"
        )

    register_path.parent.mkdir(parents=True, exist_ok=True)
    register_path.write_text(json.dumps(reg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {
        "added": added,
        "unchanged": unchanged,
        "updated": updated,
        "total": len(reg["records"]),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--register", type=Path, required=True)
    ap.add_argument("--records", type=Path, required=True)
    ap.add_argument("--repo-url", default=None)
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args(argv)
    payload = json.loads(args.records.read_text(encoding="utf-8"))
    records = payload if isinstance(payload, list) else payload.get("records") or []
    if not records:
        sys.exit("no records in the input — nothing to emit is an error, not a success")
    stats = emit(args.register, records, args.repo_url, args.update)
    print(
        f"{args.register.name}: +{stats['added']} added, "
        f"{stats['updated']} superseded, {stats['unchanged']} "
        f"unchanged -> {stats['total']} total"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["ledger", "doc-variance", *sys.argv[1:]]))
