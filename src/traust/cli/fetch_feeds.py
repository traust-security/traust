#!/usr/bin/env python3
"""Pull-through cache for the product-definitions registry.

The security feeds (EPSS, KEV, Red Hat CVEs, the VEX index) moved to
traust-core: ``traust feeds fetch`` snapshots them through
``ExposureService.refresh_feeds``. What stays here is the one source that
is not a security feed: the product/ownership/notification registry
(ps_products, contacts, cc_lists; zero vulnerability data), read from
``<feeds cache>/product_definitions.json`` by the product registry and
the SLA view. It moves with them (*Skill port: sla-view*).

A copy younger than its max age is reused; a failed refresh falls back to
the stale copy with a loud warning, so off-VPN runs degrade instead of
breaking.

Cache layout (``traust.context.feeds_cache_dir``):
  product_definitions.json
  feeds-meta.json        retrieval timestamp + sha256

Usage:
    traust feeds fetch-products [--cache-dir DIR] [--max-age-hours N] [--offline]
Exit 0 when the registry is usable (fresh or stale-with-warning); 1 when
there is no usable copy or it isn't configured.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

from traust_core.v1.context import Context

from traust.context import add_config_home_arg, load, locations
from traust.registry.feeds_config import feeds_cache_dir

USER_AGENT = "traust fetch_feeds.py"
NAME = "product-definitions"
FILE = "product_definitions.json"
# Short TTL: the payload's contact/CC data turns over faster than the product ids.
MAX_AGE_HOURS = 24.0


def _url(core: Context) -> str | None:
    """Config-owned (``locations.product_definitions``): a deployment-specific registry, so no
    endpoint ships; unset means the source is absent and its consumers degrade."""
    return locations(core).product_definitions


def _now():
    return datetime.datetime.now(datetime.UTC)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_meta(cache: Path) -> dict:
    try:
        return json.loads((cache / "feeds-meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_meta(cache: Path, meta: dict):
    (cache / "feeds-meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def _age_hours(meta_entry: dict) -> float | None:
    try:
        t = datetime.datetime.strptime(meta_entry["retrieved_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.UTC
        )
    except (KeyError, ValueError):
        return None
    return (_now() - t).total_seconds() / 3600


def _counts(raw: bytes) -> dict:
    """Per-collection counts: the registry carries no version stamp, so they're its drift
    signal."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return {"counts": {k: len(v) for k, v in sorted(doc.items()) if isinstance(v, dict)}}


def fetch(url: str, cache: Path, max_age_hours: float, offline: bool = False) -> tuple[bool, str]:
    """Ensure a usable copy. Returns (usable, status)."""
    cache.mkdir(parents=True, exist_ok=True)
    meta = _read_meta(cache)
    path = cache / FILE
    age = _age_hours(meta.get(NAME) or {}) if path.is_file() else None
    if age is not None and age <= max_age_hours:
        return True, f"fresh ({age:.1f}h old)"
    stale = f"STALE ({'unknown age' if age is None else f'{age:.0f}h old'})"
    if offline:
        if path.is_file():
            return True, f"{stale} — offline, using cached copy"
        return False, "no cached copy and --offline"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        if path.is_file():
            return True, f"{stale} — refresh failed ({e}), using cached copy"
        return False, f"download failed and no cached copy: {e}"
    path.write_bytes(raw)
    meta[NAME] = {
        "url": url,
        "retrieved_at": _iso(_now()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        **_counts(raw),
    }
    _write_meta(cache, meta)
    return True, f"refreshed ({len(raw)} bytes)"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--max-age-hours", type=float, default=MAX_AGE_HOURS)
    ap.add_argument(
        "--offline", action="store_true", help="never touch the network; use the cached copy only"
    )
    args = ap.parse_args(argv)
    core = load(args.config_home)
    url = _url(core)
    if url is None:
        print(f"! {NAME}: not configured (locations.product_definitions) — UNUSABLE")
        return 1
    cache_dir = args.cache_dir or feeds_cache_dir(core=core)
    usable, status = fetch(url, cache_dir, args.max_age_hours, offline=args.offline)
    marker = "✓" if usable and not status.startswith("STALE") else "!"
    print(f"{marker} {NAME}: {status}" + ("" if usable else " — UNUSABLE"))
    return 0 if usable else 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["feeds", "fetch-products", *sys.argv[1:]]))
