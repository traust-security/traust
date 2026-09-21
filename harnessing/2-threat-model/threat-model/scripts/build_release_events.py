#!/usr/bin/env python3
"""Release / dist-git event feeders — deterministic producers for the
continuous-operations router's event lane (rescan-cadence policy §2.4;
router-lane-coverage-plan item 4).

Appends `source: "release"` events to
analysis-results/findings/_manifest/rescan-events.jsonl in exactly the
shape the router's load_events()/event_lane() consume (source in
EVENT_SOURCES, `consumed: false`; a release event routes as
`release-passthrough` — a note to the branch/container/rpm audit
lanes, never a code-audit row). The feeder produces events only; it
never authors a finding, verdict, or audit.

Two legs, both diffed against one committed state file
(analysis-results/findings/_manifest/release-events-state.json — an
explicitly-committed manifest path, per rule S6, so re-runs on any
machine share the same seen-set):

  CONTAINER LEG  diffs the image inventories under
      the inputs inventory (`*-payload-repos.csv` for the OpenShift
      payloads and every operator-catalog version — the `Payload
      Image(s)` / `Payload Image Key(s)` columns, `;`-separated, full
      pullspecs where the inventory has them and bare image keys
      elsewhere) against the seen set. A never-seen digest/tag emits
      one release event carrying the image ref and the row's source
      repo when the CSV maps one. **CSV diff only in v1 — no registry
      polling** (no skopeo/network): a new digest is visible here only
      when the inventory refresh lands. v2 follow-up: quota-aware
      registry tag polling for the watched repos, same state file.

  DIST-GIT LEG  (below) carries no version identity at all — a moved
      HEAD is a commit sha, not a release — so its events classify as
      `release_change: "unknown"` and never trigger the version-gated
      threat-model lane. That is a real coverage limit, stated rather
      than papered over.

RELEASE IDENTITY (threat-model cadence plan Phase 2, 2026-08-05). The
router's threat-model-review lane fires on major/minor releases only,
so every event carries a structured version — never free text parsed
back out of `note`. The identity is the INVENTORY PATH, not the image
tag: measured 2026-08-05, image tokens are overwhelmingly bare keys and
the rest are digest-pinned, so ZERO carry a parseable version, while
every inventory CSV does
(`openshift/openshift-4.19-payload-repos.csv`,
`operator-catalog/rhacs-operator/4.9.2/…`). Each path normalizes to a
`family` (the path with its version replaced by `{V}` — 350 families)
plus a version tuple; the state file remembers the highest version
seen per family, and a new inventory file classifies as major / minor
/ patch / backfill / initial against it. Events stamp
`release_family`, `release_version`, `release_previous`, and
`release_change`.

  DIST-GIT LEG  reads $TRAUST_CONFIG_HOME/rpm-distgit-watch.yaml (operator-curated;
      ships as a documented example with an empty `active` list) and
      runs `git ls-remote` per active https URL (rule S3:
      GIT_ALLOW_PROTOCOL=https env + ^https:// gate + `--` separator;
      argv list, never a shell string). A moved HEAD emits one release
      event noting "dist-git commit — route secure-rpm-audit".
      Non-https URLs, network failures, and timeouts degrade to
      per-repo skip counts — never a crash, never a fabricated event.

Idempotent by construction: the first run (no state file) SEEDS the
state and emits nothing — the existing inventory is baseline, not
news; later runs emit only on inventory/HEAD movement, and a re-run
with no movement emits nothing. --dry-run computes and prints the
would-be events without touching the events file or the state.

Usage:
    python3 scripts/build_release_events.py
        [--inputs DIR] [--events FILE] [--state FILE]
        [--config FILE] [--dry-run]
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    inputs_dir,
    load_engine,
)
from traust.paths import optional_config_path

# Inventory CSV image columns, in the two shapes that exist in the tree
# (surveyed 2026-07-28): OpenShift payload CSVs carry `Payload
# Image(s)`, operator-catalog per-version CSVs carry `Payload Image
# Key(s)`. Values are `;`-separated.
IMAGE_COLUMNS = ("Payload Image Key(s)", "Payload Image(s)")
REPO_COLUMN = "GitHub URL"

_SHA7 = 7
_HEX_SHA_RX = re.compile(r"^[0-9a-f]{40}$")

# Release identity from the inventory PATH (see module docstring). The
# lookarounds keep `4.19` whole instead of matching `4.1`; the optional
# third group makes a two-part `4.19` parse as 4.19.0.
_INV_VERSION_RX = re.compile(r"(?<![\d.])(\d+)\.(\d+)(?:\.(\d+))?(?![\d.])")

# Bump kinds that mean "the threat surface plausibly moved". `patch`,
# `backfill` (a version BELOW the family's high-water mark — an old
# release inventoried late), `initial` (first sighting of a family, no
# predecessor to compare against) and `unknown` (unparseable path, or
# the dist-git leg, which has no version at all) deliberately do not.
REMODEL_CHANGES = ("major", "minor")


def parse_inventory_version(rel: str) -> tuple[str, tuple[int, int, int]] | None:
    """`operator-catalog/rhacs-operator/4.9.2/rhacs-operator-4.9.2-…csv`
    -> ("operator-catalog/rhacs-operator/{V}/rhacs-operator-{V}-…csv",
    (4, 9, 2)). None when the path carries no version. The version
    usually appears twice (directory + filename) and both are the same
    release, so the FIRST match is the version and every match is
    normalized out to form the family key."""
    m = _INV_VERSION_RX.search(rel)
    if not m:
        return None
    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return _INV_VERSION_RX.sub("{V}", rel), ver


def format_version(ver: tuple[int, int, int]) -> str:
    return ".".join(str(p) for p in ver)


def parse_version_str(raw: str | None) -> tuple[int, int, int] | None:
    if not isinstance(raw, str):
        return None
    m = _INV_VERSION_RX.fullmatch(raw.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def classify_bump(new: tuple[int, int, int], prev: tuple[int, int, int] | None) -> str:
    """-> major | minor | patch | backfill | none | initial. `prev` is
    the family's HIGH-WATER mark, so a late-inventoried older release
    reads as `backfill`, never as a bump."""
    if prev is None:
        return "initial"
    if new < prev:
        return "backfill"
    if new == prev:
        return "none"
    if new[0] != prev[0]:
        return "major"
    if new[1] != prev[1]:
        return "minor"
    return "patch"


def inventory_release_map(
    paths: list[Path], inputs_root: Path, seen_versions: dict[str, str]
) -> dict[str, dict]:
    """relpath -> {family, version, previous, change} for every
    inventory file, classified against the committed high-water marks.
    Paths with no parseable version get change 'unknown' so the caller
    never has to guess."""
    out: dict[str, dict] = {}
    for p in paths:
        try:
            rel = str(p.relative_to(inputs_root))
        except ValueError:
            rel = p.name
        parsed = parse_inventory_version(rel)
        if parsed is None:
            out[rel] = {"family": None, "version": None, "previous": None, "change": "unknown"}
            continue
        family, ver = parsed
        prev = parse_version_str(seen_versions.get(family))
        out[rel] = {
            "family": family,
            "version": format_version(ver),
            "previous": format_version(prev) if prev else None,
            "change": classify_bump(ver, prev),
        }
    return out


def advance_version_marks(
    release_map: dict[str, dict], seen_versions: dict[str, str]
) -> dict[str, str]:
    """New high-water marks after this run — max(seen, observed) per
    family, so a backfill never lowers the bar."""
    marks = dict(seen_versions)
    for info in release_map.values():
        fam, ver = info.get("family"), parse_version_str(info.get("version"))
        if not fam or ver is None:
            continue
        cur = parse_version_str(marks.get(fam))
        if cur is None or ver > cur:
            marks[fam] = format_version(ver)
    return marks


# ---------------------------------------------------------------------------
# container leg — pure CSV parsing/diffing (unit-testable, no network)
# ---------------------------------------------------------------------------


def looks_like_pullspec(token: str) -> bool:
    """A registry pullspec (digest- or tag-qualified) is globally
    unique on its own; a bare image key (e.g. `manager`) is only
    meaningful inside its inventory file."""
    if "@sha256:" in token:
        return True
    if "/" not in token:
        return False
    return ":" in token.rsplit("/", 1)[-1]


def inventory_csvs(inputs_root: Path) -> list[Path]:
    """Every payload/operator-catalog image inventory, deterministic
    order. The `*-payload-repos.csv` naming is shared by the OpenShift
    payload and operator-catalog trees."""
    return sorted(p for p in inputs_root.rglob("*-payload-repos.csv") if p.is_file())


def parse_inventory_csv(path: Path, inputs_root: Path) -> list[dict]:
    """-> [{key, image, repo, inventory}]. `key` is the identity the
    seen-set stores: the pullspec itself when the entry carries a
    digest/tag, else `<relpath>::<image key>` (a new inventory file —
    a new payload/operator version — makes its bare keys new). All
    CSV content is untrusted data: it feeds string fields only, never
    commands."""
    try:
        rel = str(path.relative_to(inputs_root))
    except ValueError:
        rel = path.name
    items: list[dict] = []
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            fields = reader.fieldnames or []
            img_col = next((c for c in IMAGE_COLUMNS if c in fields), None)
            if img_col is None:
                return []
            for row in reader:
                repo = (row.get(REPO_COLUMN) or "").strip()
                if not repo.startswith("https://"):
                    repo = ""
                for token in (row.get(img_col) or "").split(";"):
                    token = token.strip()
                    if not token or token.upper().startswith("N/A"):
                        continue
                    key = token if looks_like_pullspec(token) else f"{rel}::{token}"
                    items.append({"key": key, "image": token, "repo": repo, "inventory": rel})
    except OSError:
        return []
    return items


def diff_container(items: list[dict], seen: set[str]) -> list[dict]:
    """New-to-the-state items, deduped by key, deterministic order."""
    out, emitted = [], set()
    for it in items:
        if it["key"] in seen or it["key"] in emitted:
            continue
        emitted.add(it["key"])
        out.append(it)
    out.sort(key=lambda d: d["key"])
    return out


def container_event(item: dict, date: str, release: dict | None = None) -> dict:
    rel = release or {"family": None, "version": None, "previous": None, "change": "unknown"}
    ver = rel.get("version")
    prev = rel.get("previous")
    vnote = ""
    if ver:
        vnote = f", {rel['change']} release {ver}" + (f" (was {prev})" if prev else "")
    note = (
        f"release: new image {item['image']} "
        f"(inventory {item['inventory']}{vnote}) — route the "
        f"container/branch audit lane"
    )
    return {
        "source": "release",
        "repo": item["repo"],
        "refs": [],
        "note": note,
        "date": date,
        "consumed": False,
        "release_family": rel.get("family"),
        "release_version": ver,
        "release_previous": prev,
        "release_change": rel.get("change") or "unknown",
        "emitted_by": "build_release_events.py",
    }


# ---------------------------------------------------------------------------
# dist-git leg
# ---------------------------------------------------------------------------


def load_watch_config(path: Path) -> list[str]:
    """Active dist-git URLs from the operator-curated YAML. Missing
    file or missing/empty `active` list -> [] (the shipped example
    config is empty by default)."""
    if not path.is_file():
        return []
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML unavailable — dist-git leg skipped", file=sys.stderr)
        return []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        print(f"[!] unparseable watch config: {path} — dist-git leg skipped", file=sys.stderr)
        return []
    active = doc.get("active") or []
    return [u for u in active if isinstance(u, str)]


def distgit_head(url: str, timeout: int = 60) -> dict:
    """HEAD sha of one dist-git repo via `git ls-remote`. Rule S3:
    non-https URLs are rejected before any network use, the transport
    is pinned with GIT_ALLOW_PROTOCOL=https, and `--` separates the
    URL from options (argv list, rule S4). -> {ok, head?, error?}."""
    if not re.match(r"^https://", url):
        return {"ok": False, "error": "non-https URL rejected (S3 gate)"}
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--", url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "error": str(e)[:120]}
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[:120] or "git-error"}
    for line in proc.stdout.splitlines():
        sha = line.split("\t", 1)[0].strip()
        if _HEX_SHA_RX.match(sha):
            return {"ok": True, "head": sha}
    return {"ok": False, "error": "no HEAD sha in ls-remote output"}


def distgit_event(url: str, head: str, prev: str | None, date: str) -> dict:
    was = f" (was {prev[:_SHA7]})" if prev else ""
    note = f"dist-git commit {head[:_SHA7]}{was} — route secure-rpm-audit"
    # A dist-git HEAD is a commit, not a release: there is no version
    # to compare, so this leg is honestly `unknown` and never reaches
    # the version-gated threat-model-review lane.
    return {
        "source": "release",
        "repo": url,
        "refs": [],
        "note": note,
        "date": date,
        "consumed": False,
        "release_family": None,
        "release_version": None,
        "release_previous": None,
        "release_change": "unknown",
        "emitted_by": "build_release_events.py",
    }


# ---------------------------------------------------------------------------
# state (committed manifest path — rule S6; never a fixed /tmp name)
# ---------------------------------------------------------------------------


def load_state(path: Path) -> dict | None:
    """None = no state yet (first run seeds instead of emitting)."""
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(
            f"[!] unreadable state file {path} — refusing to run "
            f"(a corrupt seen-set would re-emit the whole "
            f"inventory); fix or remove it deliberately",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    # `inventory_versions` landed with the release-identity change
    # (2026-08-05). A pre-existing state file has no such key: it reads
    # as {} and this run SEEDS the high-water marks from the current
    # inventory. That emits nothing new — every current CSV is already
    # in container_seen — and the next genuinely-new inventory file
    # then classifies against a real predecessor.
    return {
        "container_seen": set(raw.get("container_seen") or []),
        "distgit_heads": dict(raw.get("distgit_heads") or {}),
        "inventory_versions": dict(raw.get("inventory_versions") or {}),
        "had_versions": bool(raw.get("inventory_versions")),
    }


def save_state(
    path: Path,
    container_seen: set[str],
    distgit_heads: dict[str, str],
    inventory_versions: dict[str, str] | None = None,
) -> None:
    doc = {
        "artifact": "release-events-state",
        "role": (
            "seen-set for scripts/build_release_events.py — "
            "committed manifest state, one per campaign tree"
        ),
        "updated_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "container_seen": sorted(container_seen),
        "distgit_heads": dict(sorted(distgit_heads.items())),
        "inventory_versions": dict(sorted((inventory_versions or {}).items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def append_events(path: Path, events: list[dict]) -> None:
    if not events:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--inputs", type=Path, default=None, help="inventory root (payload/operator-catalog CSVs)"
    )
    ap.add_argument(
        "--events", type=Path, default=None, help="router event file (appended, never rewritten)"
    )
    ap.add_argument(
        "--state",
        type=Path,
        default=None,
        help="seen-digests/HEADs state (committed manifest state, rule S6)",
    )
    ap.add_argument(
        "--config",
        type=Path,
        default=optional_config_path("rpm-distgit-watch.yaml"),
        help="operator-curated dist-git watch list",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="print would-be events; write neither the events file nor the state",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = analysis_results_dir(engine)
    manifest = results_root / "findings" / "_manifest"
    args.inputs = args.inputs or inputs_dir(engine)
    args.events = args.events or manifest / "rescan-events.jsonl"
    args.state = args.state or manifest / "release-events-state.json"

    today = _dt.date.today().isoformat()
    state = load_state(args.state)
    first_run = state is None
    if first_run:
        state = {
            "container_seen": set(),
            "distgit_heads": {},
            "inventory_versions": {},
            "had_versions": False,
        }
        print(
            f"[+] no state at {args.state} — SEEDING (baseline run, no events emitted)",
            file=sys.stderr,
        )

    # --- container leg (CSV diff only in v1 — no registry polling) ----
    items: list[dict] = []
    csvs: list[Path] = []
    if args.inputs.is_dir():
        csvs = inventory_csvs(args.inputs)
        for p in csvs:
            items.extend(parse_inventory_csv(p, args.inputs))
    else:
        print(f"[!] inputs root missing: {args.inputs} — container leg skipped", file=sys.stderr)
    # Release identity per inventory file, classified against the
    # committed high-water marks (see module docstring).
    release_map = inventory_release_map(csvs, args.inputs, state["inventory_versions"])
    next_versions = advance_version_marks(release_map, state["inventory_versions"])
    new_items = diff_container(items, state["container_seen"])
    container_events = (
        []
        if first_run
        else [container_event(it, today, release_map.get(it["inventory"])) for it in new_items]
    )
    next_seen = state["container_seen"] | {it["key"] for it in new_items}
    if not first_run and not state.get("had_versions"):
        print(
            f"[+] seeded release high-water marks for "
            f"{len(next_versions)} inventory family/families — this "
            f"run classifies new files as 'initial'; the next new "
            f"inventory version compares against a real predecessor",
            file=sys.stderr,
        )
    remodel = sum(1 for ev in container_events if ev.get("release_change") in REMODEL_CHANGES)

    # --- dist-git leg --------------------------------------------------
    watched = load_watch_config(args.config)
    distgit_events: list[dict] = []
    next_heads = dict(state["distgit_heads"])
    skips: dict[str, str] = {}
    for url in watched:
        res = distgit_head(url)
        if not res.get("ok"):
            skips[url] = res.get("error") or "?"
            continue  # keep the old HEAD: retried next run, no event
        prev = state["distgit_heads"].get(url)
        if prev != res["head"]:
            if prev is not None:
                distgit_events.append(distgit_event(url, res["head"], prev, today))
            # first observation of a URL just records HEAD (baseline)
            next_heads[url] = res["head"]

    events = container_events + distgit_events
    if args.dry_run:
        for ev in events:
            print(json.dumps(ev, sort_keys=True))
        print(
            f"[+] dry-run: {len(container_events)} container + "
            f"{len(distgit_events)} dist-git event(s) would be "
            f"appended ({remodel} major/minor — the only kind the "
            f"router's threat-model-review lane acts on); "
            f"{len(skips)} dist-git repo(s) skipped; "
            f"nothing written",
            file=sys.stderr,
        )
        for url, why in sorted(skips.items()):
            print(f"    skip {url}: {why}", file=sys.stderr)
        return 0

    append_events(args.events, events)
    save_state(args.state, next_seen, next_heads, next_versions)
    print(
        f"[+] {len(container_events)} container + "
        f"{len(distgit_events)} dist-git event(s) appended to "
        f"{args.events}"
        + (" (seed run)" if first_run else "")
        + f"; {remodel} classify as major/minor (threat-model-review "
        f"lane)",
        file=sys.stderr,
    )
    if skips:
        print(f"[!] {len(skips)} dist-git repo(s) skipped (degraded, not fatal):", file=sys.stderr)
        for url, why in sorted(skips.items()):
            print(f"    {url}: {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
