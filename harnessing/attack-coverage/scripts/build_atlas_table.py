#!/usr/bin/env python3
"""build_atlas_table.py — vendor a pinned, distilled MITRE ATLAS technique table.

Downloads ONE tagged release of ATLAS.yaml from mitre-atlas/atlas-data, verifies its sha256
when a pin is recorded, and distills it to tables/atlas-techniques.json: technique and
sub-technique ID, name and tactics (a sub-technique takes its parent's). The distilled table is
the only ATLAS artifact committed, and the one traust-core checks threat models' atlas_refs
against. Re-running against the same pin is byte-stable.

To move to a new ATLAS release: bump ATLAS_TAG, run with --refresh-pin, review the diff, commit.

License: ATLAS data is (c) 2021-2026 MITRE, licensed under the Apache License, Version 2.0
(https://github.com/mitre-atlas/atlas-data/blob/main/LICENSE); the notice travels in the table.

Usage:  python3 build_atlas_table.py [--refresh-pin]
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import yaml

SKILL_DIR = Path(__file__).resolve().parent.parent
TABLES = SKILL_DIR / "tables"

ATLAS_TAG = "v2026.09"
DATA_URL = f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{ATLAS_TAG}/dist/ATLAS.yaml"
PIN_FILE = TABLES / "atlas-data.sha256"
OUT = TABLES / "atlas-techniques.json"

ATTRIBUTION = (
    "MITRE ATLAS(TM) data, Copyright 2021-2026 MITRE, licensed under the Apache License, "
    "Version 2.0 (https://github.com/mitre-atlas/atlas-data/blob/main/LICENSE). This table is "
    "a distilled subset (technique IDs, names and tactics) of the tagged release named here."
)


def main():
    refresh = "--refresh-pin" in sys.argv
    print(f"fetching MITRE ATLAS {ATLAS_TAG} …")
    raw = urllib.request.urlopen(DATA_URL, timeout=120).read()
    sha = hashlib.sha256(raw).hexdigest()
    if PIN_FILE.exists() and not refresh:
        pinned = PIN_FILE.read_text().split()[0]
        if sha != pinned:
            print(
                f"FATAL: ATLAS.yaml sha256 {sha} != pinned {pinned} "
                "(pass --refresh-pin only for a deliberate upgrade)",
                file=sys.stderr,
            )
            return 1
    data = yaml.safe_load(raw)
    (matrix,) = data["matrices"]
    entries = {t["id"]: t for t in matrix["techniques"]}
    techniques = {}
    for tid, t in sorted(entries.items()):
        parent = t.get("specializes")
        tactics = t.get("tactics") or (entries[parent].get("tactics") if parent else []) or []
        techniques[tid] = {"name": t["name"], "tactics": sorted(tactics)}
    table = {
        "source": "MITRE ATLAS (mitre-atlas/atlas-data)",
        "atlas_version": ATLAS_TAG.removeprefix("v"),
        "data_version": str(data["version"]),
        "data_url": DATA_URL,
        "data_sha256": sha,
        "attribution": ATTRIBUTION,
        "techniques": techniques,
    }
    OUT.write_text(json.dumps(table, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    PIN_FILE.write_text(f"{sha}  ATLAS-{ATLAS_TAG}.yaml\n", encoding="utf-8")
    print(f"wrote {OUT.name}: {len(techniques)} techniques and sub-techniques")
    return 0


if __name__ == "__main__":
    sys.exit(main())
