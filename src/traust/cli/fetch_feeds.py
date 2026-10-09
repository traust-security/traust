#!/usr/bin/env python3
"""Pull-through cache for external reference feeds.

This is the FEED ROUTER (docs/routers.md §7) — the seventh router kind.
Like every other runner here it is orchestrator-neutral: an operator
session, cron, the Source Code Intelligence worker, Konflux, or an
enterprise scheduler all run it identically. It is deliberately not
bound to a CI pipeline in this repository; that would couple the refresh
to one orchestrator, which is what the router abstraction exists to
prevent. Consumers may also call it at the start of their own run.
A feed is re-downloaded only when its cached copy is older than the
feed's max age (--max-age-hours overrides for every requested feed); a
failed refresh falls back to the stale copy with a loud warning (and
`stale: true` in the metadata consumers embed), so offline runs degrade
instead of breaking.

Feeds (license intake — docs/external-dependencies.md feeds table):
  epss  FIRST EPSS daily scores     free incl. commercial, attribution
                                    requested ("EPSS at
                                    https://www.first.org/epss")
  kev   CISA Known Exploited Vulns  CC0-1.0
  rh-cve Red Hat Security Data CVEs  CC-BY-4.0, attribute Red Hat.
                                    Public endpoint. Paginated and
                                    INCREMENTAL: each run fetches only
                                    what published since the stored
                                    watermark and merges onto the cached
                                    copy, so the steady-state pull is a
                                    week of deltas (~77 KB) rather than
                                    the whole corpus.
  product-definitions              Product registry (ownership,
                                    contacts). INTERNAL: VPN-only
                                    internal product-definitions
                                    endpoint.

INTERNAL FEEDS ARE EXCLUDED FROM `--feed all`. They must be requested by
name or with --include-internal. `all` is what unattended lanes invoke
(harnessing/3-audit/dependency-watch runs this bare on a daily cadence) and
main() returns 1 when a requested feed is unusable — so a VPN-only feed
in the default set would fail that lane on every off-VPN run.

Cache layout (<workspace>/analysis-results/feeds/ by default — local
rebuildable artifact, same precedent as analysis-results/graph/):
  epss_scores-current.csv.gz
  known_exploited_vulnerabilities.json
  rh_cve.json            projected records (6 fields), merged across runs
  product_definitions.json
  feeds-meta.json        retrieval timestamps + sha256 per feed

The product-definitions payload is deliberately NOT vendored into the
harness tree (unlike the sha256-pinned ATT&CK table): it is internal
personnel/ownership data reachable only on VPN, so a committed copy
would buy no off-VPN capability.

Also importable: load_epss(), load_kev(), load_rh_cves(),
load_product_definitions(), feed_status() for consumers
(enrich_findings_cves.py, product_definitions.py,
reconcile_cve_provenance.py).

Usage:
    python3 fetch_feeds.py [--cache-dir DIR] [--max-age-hours N]
                           [--feed <name>|all] [--include-internal]
                           [--offline]
Exit 0 when every requested feed is usable (fresh or stale-with-warning);
1 when a feed has no usable copy at all.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import hashlib
import io
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, fields
from email.utils import parsedate_to_datetime
from pathlib import Path

from traust_engine import locations

from traust.context import add_config_home_arg, load_engine
from traust.registry.feeds_config import cached_sources, feeds_cache_dir, retry_defaults

USER_AGENT = "traust fetch_feeds.py"

DEFAULT_MAX_AGE_HOURS = 24.0

# Runaway guard for paginated feeds: a backfill of the whole campaign
# window is ~12 pages, so 60 is far above any real fetch.
MAX_FEED_PAGES = 60

DEFAULT_TIMEOUT_S = 120.0


class FeedError(RuntimeError):
    """A feed download gave up after exhausting its retry policy."""


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    timeout_s: float = DEFAULT_TIMEOUT_S
    backoff_base_s: float = 1.0
    max_wait_s: float = 60.0
    jitter_s: float = 0.0

    @classmethod
    def from_config(cls, defaults: dict | None, override: dict | None = None) -> RetryPolicy:
        merged = {**(defaults or {}), **(override or {})}
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in merged.items() if k in allowed})


def _retry_policy(name: str) -> RetryPolicy:
    """Global retry defaults from feeds.yaml, overridden by the feed's own `retry:`."""
    return RetryPolicy.from_config(retry_defaults(), _feeds().get(name, {}).get("retry"))


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After as delta-seconds or an HTTP-date; None when absent/unparseable."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.UTC)
    return max(0.0, (when - _now()).total_seconds())


def _backoff(policy: RetryPolicy, attempt: int) -> float:
    wait = min(policy.backoff_base_s * (2**attempt), policy.max_wait_s)
    return wait + (random.uniform(0, policy.jitter_s) if policy.jitter_s else 0.0)


def fetch_with_retry(url: str, policy: RetryPolicy) -> bytes:
    """GET ``url`` with bounded retries. Raises FeedError once attempts are spent.

    429 waits out Retry-After (capped by max_wait_s); 5xx and timeouts use
    capped exponential backoff; a non-429 4xx fails immediately (retrying a
    403/404 just burns the window). The caller falls back to the cached copy.
    """
    last = ""
    for attempt in range(policy.max_attempts):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=policy.timeout_s) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429 and not (500 <= e.code < 600):
                raise FeedError(f"{url}: HTTP {e.code}") from e
            last = f"HTTP {e.code}"
            after = _parse_retry_after(e.headers.get("Retry-After")) if e.headers else None
            delay = _backoff(policy, attempt) if after is None else min(after, policy.max_wait_s)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = str(e)
            delay = _backoff(policy, attempt)
        if attempt + 1 < policy.max_attempts:
            time.sleep(delay)
    raise FeedError(f"{url}: gave up after {policy.max_attempts} attempts ({last})")

# The vulnerability-data sources come from config/feeds.yaml — one
# registry shared with fetch_advisory.py (live tier) and check_drift.py
# (freshness + liveness rows), so adding a source is a config change and
# a dead source is a failing row rather than a silent 404.
_FEEDS_CACHE: dict | None = None


def _feeds() -> dict:
    """The feed registry (cached), resolved lazily from the config home.

    Lazy on purpose: building this at import read feeds.yaml before any
    $TRAUST_CONFIG_HOME was known, so merely importing this module required a
    configured deployment. It now resolves on first use.
    """
    global _FEEDS_CACHE
    if _FEEDS_CACHE is None:
        _FEEDS_CACHE = _build_feeds()
    return _FEEDS_CACHE


def _build_feeds() -> dict:
    feeds = dict(cached_sources())
    # Config-owned (no env): the endpoint comes from locations.product_definitions.
    # Only register the source when it is configured; otherwise it stays absent
    # and its consumers degrade to null contacts rather than erroring.
    url = locations.product_definitions_url(locations.configured_locations())
    if url:
        feeds["product-definitions"] = {**_PRODUCT_DEFINITIONS_SPEC, "url": url}
    return feeds


def __getattr__(name: str):
    # Preserve the public module-level ``FEEDS`` name now that the registry is
    # resolved lazily (it used to be a module global built at import).
    if name == "FEEDS":
        return _feeds()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# NOT a vulnerability feed, and deliberately NOT in config/feeds.yaml:
# this is the product/ownership/notification registry
# (ps_products, contacts, cc_lists; zero vulnerability data). It stays
# here rather than getting a registry file of its own because we do not
# author it — we are a read-only consumer. Data we author lives in
# <inputs>/progress-tracker; data we fetch lives in the
# cache. Same fetch mechanism, different category. Consumers:
# sla-view and the internal extension's owner-routing
# and defect-filing skills.
#
# product-definitions is a deployment-specific product/ownership registry, not a
# generic security feed, so its endpoint is NOT shipped. It currently targets a
# Red Hat-internal source; rather than bake an internal URL into an open-source
# package, the endpoint is config-owned via ``locations.product_definitions``
# (edit locations.yaml — no env override). When unset, the source is simply
# absent and its consumers degrade to null contacts.
#
# TODO(consumable-product-registry): give this a generic, documented payload
# schema so other adopters can point it at their own ownership/notification
# source, not just the Red Hat-shaped products.json.
_PRODUCT_DEFINITIONS_SPEC = {
    # url is injected from locations.product_definitions at build time (_build_feeds).
    "url": None,
    "file": "product_definitions.json",
    "mode": "file",
    # Pull-through cache; short TTL because the payload's contact/CC data turns
    # over faster than the product ids.
    "max_age_hours": 24.0,
    "internal": True,
}

# Top-level keys the compiled products.json must carry. A silent upstream
# shape change would otherwise present as "no product matched" across
# every findings package — the worst failure mode for a corroborating
# source — so the loader raises instead.
PRODUCT_DEFINITIONS_KEYS = ("ps_products", "ps_modules", "ps_update_streams")


def public_feeds() -> list:
    """Feed names safe for an unattended `--feed all` run."""
    return [n for n, s in _feeds().items() if not s.get("internal")]


def feed_max_age(name: str, override: float | None = None) -> float:
    if override is not None:
        return override
    return _feeds()[name].get("max_age_hours", DEFAULT_MAX_AGE_HOURS)


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


def _record_attempt(cache: Path, meta: dict, name: str, *, error: str) -> None:
    """Persist a failed refresh so consumers can see a feed went stale and why."""
    entry = dict(meta.get(name) or {})
    entry["last_attempt_at"] = _iso(_now())
    entry["last_error"] = error
    entry["stale"] = True
    meta[name] = entry
    _write_meta(cache, meta)


def _age_hours(meta_entry: dict) -> float | None:
    try:
        t = datetime.datetime.strptime(meta_entry["retrieved_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.UTC
        )
    except (KeyError, ValueError):
        return None
    return (_now() - t).total_seconds() / 3600


def _feed_extra(name: str, raw: bytes) -> dict:
    """Version identifiers embedded in the feed itself."""
    try:
        if name == "epss":
            head = gzip.decompress(raw)[:200].decode("utf-8", "replace")
            # first line: #model_version:v...,score_date:...
            if head.startswith("#"):
                return {"feed_version": head.splitlines()[0].lstrip("# ")}
        if name == "kev":
            doc = json.loads(raw.decode("utf-8"))
            return {
                "feed_version": doc.get("catalogVersion"),
                "date_released": doc.get("dateReleased"),
                "count": doc.get("count"),
            }
        # rh-cve stamps watermark/count/added_last_run in fetch() itself,
        # where the merge result is known; nothing to re-derive from raw.
        if name == "vex":
            # changes.csv is "path","timestamp" newest-first over a rolling
            # 12-month window. Stamping its span and row count makes the
            # drift row say what the index actually covers rather than
            # only when we downloaded it.
            text = raw.decode("utf-8", "replace")
            rows = [r for r in text.splitlines() if r.strip()]
            stamps = sorted(r.split('","')[-1].rstrip('"')[:10] for r in rows if '","' in r)
            return {
                "count": len(rows),
                "window_from": stamps[0] if stamps else None,
                "watermark": stamps[-1] if stamps else None,
            }
        if name == "product-definitions":
            doc = json.loads(raw.decode("utf-8"))
            # no upstream version stamp; per-collection counts are the
            # only drift signal available
            return {"counts": {k: len(v) for k, v in sorted(doc.items()) if isinstance(v, dict)}}
    except Exception:
        pass
    return {}


def _fetch_paginated(spec: dict, since: str | None, policy: RetryPolicy) -> tuple[list, str | None]:
    """Page a date-windowed JSON list endpoint. Returns (records, watermark).

    Pages *within* the window rather than assuming a window fits one page:
    Red Hat published 1000+ CVEs in the week of 2026-08-10 against a
    weekly median of 245, so a single-page fetch would have silently
    truncated the busiest weeks — the ones that matter most.
    """
    pag, inc = spec["paginate"], spec.get("incremental") or {}
    per_page = pag["per_page"]
    project = spec.get("project")
    out, page, watermark = [], 1, since
    while True:
        q = f"?{pag['page_param']}={page}&per_page={per_page}"
        if since and inc.get("since_param"):
            q += f"&{inc['since_param']}={since}"
        batch = json.loads(fetch_with_retry(spec["url"] + q, policy))
        if not isinstance(batch, list):
            raise ValueError(f"expected a JSON list, got {type(batch).__name__}")
        for rec in batch:
            out.append({k: rec.get(k) for k in project} if project else rec)
            wf = (rec.get(inc.get("watermark_field")) or "")[:10]
            if wf and (watermark is None or wf > watermark):
                watermark = wf
        if len(batch) < per_page:  # short page = last page
            break
        page += 1
        if page > MAX_FEED_PAGES:
            raise ValueError(
                f"exceeded {MAX_FEED_PAGES} pages — refusing to loop; "
                f"narrow the window or raise MAX_FEED_PAGES"
            )
    return out, watermark


def _validate_payload(spec: dict, raw: bytes) -> None:
    """Raise ValueError when `raw` isn't well-formed for the feed's file type.

    These feeds publish no checksum, so "corrupt" means "does not decode as its
    declared type" (gzip / JSON / UTF-8 text) — enough to stop a garbage 200
    from overwriting a good cached copy. The VEX archive, which DOES ship a
    checksum, is verified the strict way in XWING-2224. Dispatch is on the
    cache file's extension so no feed name is hardcoded.
    """
    if not raw:
        raise ValueError("empty payload")
    suffix = "".join(Path(spec.get("file") or spec.get("index_file") or "").suffixes)
    try:
        if suffix.endswith(".gz"):
            raw = gzip.decompress(raw)
            suffix = suffix[:-3]
        if suffix.endswith(".json"):
            json.loads(raw)
        elif suffix.endswith(".csv"):
            raw.decode("utf-8")
    except (OSError, EOFError, ValueError) as e:
        raise ValueError(f"corrupt payload: {e}") from e


def fetch(name: str, cache: Path, max_age_hours: float, offline: bool = False) -> tuple[bool, str]:
    """Ensure a usable copy of one feed. Returns (usable, status)."""
    spec = _feeds()[name]
    cache.mkdir(parents=True, exist_ok=True)
    meta = _read_meta(cache)
    entry = meta.get(name) or {}
    # An indexed-lazy source has no single payload file: its `index_file`
    # is the cadence-synced artifact and individual documents are fetched
    # on demand (load_vex). Freshness therefore tracks the index, which is
    # correct — the index is what tells us a cached document went stale.
    path = cache / (spec.get("file") or spec["index_file"])
    path.parent.mkdir(parents=True, exist_ok=True)
    age = _age_hours(entry) if path.is_file() else None

    if age is not None and age <= max_age_hours:
        return True, f"fresh ({age:.1f}h old)"
    if offline:
        if path.is_file():
            return True, (
                f"STALE ({'unknown age' if age is None else f'{age:.0f}h old'})"
                " — offline, using cached copy"
            )
        return False, "no cached copy and --offline"

    if spec.get("paginate"):
        inc = spec.get("incremental") or {}
        since = entry.get("watermark") or inc.get("backfill_from")
        try:
            fresh, watermark = _fetch_paginated(spec, since, _retry_policy(name))
        except (FeedError, urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
            _record_attempt(cache, meta, name, error=str(e))
            if path.is_file():
                return True, (
                    f"STALE ({'unknown age' if age is None else f'{age:.0f}h old'})"
                    f" — refresh failed ({e}), using cached copy"
                )
            return False, f"download failed and no cached copy: {e}"
        # Merge onto the cached copy: an incremental run returns only the
        # delta, so overwriting would silently discard every earlier
        # window. Keyed by CVE id, newest wins (records get re-scored).
        merged = {}
        if path.is_file():
            try:
                for rec in json.loads(path.read_text(encoding="utf-8")):
                    merged[rec.get("CVE")] = rec
            except (OSError, json.JSONDecodeError, AttributeError):
                merged = {}
        added = sum(1 for rec in fresh if rec.get("CVE") not in merged)
        for rec in fresh:
            merged[rec.get("CVE")] = rec
        records = [merged[k] for k in sorted(merged) if k]
        raw = (json.dumps(records, indent=1) + "\n").encode("utf-8")
        path.write_bytes(raw)
        meta[name] = {
            "url": spec["url"],
            "retrieved_at": _iso(_now()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "last_attempt_at": _iso(_now()),
            "last_error": None,
            "stale": False,
            "watermark": watermark,
            "count": len(records),
            "added_last_run": added,
            "window_from": since,
        }
        _write_meta(cache, meta)
        return True, (f"refreshed (+{added} new, {len(records)} total, watermark {watermark})")

    url = spec.get("url") or spec["index_url"]
    try:
        raw = fetch_with_retry(url, _retry_policy(name))
        _validate_payload(spec, raw)
    except (FeedError, urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        _record_attempt(cache, meta, name, error=str(e))
        if path.is_file():
            return True, (
                f"STALE ({'unknown age' if age is None else f'{age:.0f}h old'})"
                f" — refresh failed ({e}), using cached copy"
            )
        return False, f"download failed and no cached copy: {e}"

    path.write_bytes(raw)
    meta[name] = {
        "url": url,
        "retrieved_at": _iso(_now()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "last_attempt_at": _iso(_now()),
        "last_error": None,
        "stale": False,
        **_feed_extra(name, raw),
    }
    _write_meta(cache, meta)
    return True, f"refreshed ({len(raw)} bytes)"


# --------------------------------------------------------------------------
# consumer API
# --------------------------------------------------------------------------


def feed_status(cache: Path, max_age_hours: float | None = None) -> dict:
    """Per-feed presence/age/staleness.

    max_age_hours=None uses each feed's own threshold; pass a number to
    hold every feed to the same one.
    """
    meta = _read_meta(cache)
    out = {}
    for name, spec in _feeds().items():
        entry = meta.get(name) or {}
        # indexed-lazy sources are represented by their synced index
        present = (cache / (spec.get("file") or spec["index_file"])).is_file()
        age = _age_hours(entry) if present else None
        threshold = feed_max_age(name, max_age_hours)
        out[name] = {
            "present": present,
            "retrieved_at": entry.get("retrieved_at"),
            "feed_version": entry.get("feed_version"),
            "age_hours": None if age is None else round(age, 1),
            "max_age_hours": threshold,
            "internal": bool(spec.get("internal")),
            "last_error": entry.get("last_error"),
            "last_attempt_at": entry.get("last_attempt_at"),
            "stale": (not present or age is None or age > threshold),
        }
    return out


def load_epss(cache: Path) -> dict[str, dict]:
    """cve -> {'epss': float, 'percentile': float}"""
    raw = (cache / _feeds()["epss"]["file"]).read_bytes()
    text = gzip.decompress(raw).decode("utf-8", "replace")
    scores = {}
    rows = csv.reader(io.StringIO(text))
    for row in rows:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            scores[row[0]] = {"epss": float(row[1]), "percentile": float(row[2])}
        except (IndexError, ValueError):
            continue
    return scores


def load_kev(cache: Path) -> dict[str, dict]:
    """cve -> {'date_added', 'ransomware', 'name'}"""
    doc = json.loads((cache / _feeds()["kev"]["file"]).read_text(encoding="utf-8"))
    out = {}
    for v in doc.get("vulnerabilities") or []:
        cve = v.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "date_added": v.get("dateAdded"),
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "name": v.get("vulnerabilityName"),
        }
    return out


def load_rh_cves(cache: Path) -> dict[str, dict]:
    """cve -> {'public_date', 'component', 'title', 'severity', 'cvss3', 'cwe'}

    `bugzilla_description` is Red Hat's "component: title" convention (the
    component is repeated in most records). Splitting it here gives
    consumers the two join keys first-discovery reconciliation needs
    without every caller re-deriving the same parse.
    """
    path = cache / _feeds()["rh-cve"]["file"]
    doc = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for rec in doc:
        cve = rec.get("CVE")
        if not cve:
            continue
        bd = rec.get("bugzilla_description") or ""
        component, title = None, bd
        if ":" in bd:
            component = bd.split(":", 1)[0].strip()
            title = bd.split(":", 1)[1].strip()
            # the convention repeats the component; drop the echo
            if component and title.lower().startswith(component.lower() + ":"):
                title = title[len(component) + 1 :].strip()
        out[cve] = {
            "public_date": (rec.get("public_date") or "")[:10],
            "component": component,
            "title": title,
            "severity": rec.get("severity"),
            "cvss3": rec.get("cvss3_score"),
            "cwe": rec.get("CWE"),
        }
    return out


def load_vex(cache: Path, cve: str, offline: bool = False) -> dict:
    """One CVE's Red Hat VEX document, fetched on demand and cached.

    VEX answers "which Red Hat products does this advisory affect" —
    `known_affected`, `fixed`, and `known_not_affected` carrying
    machine-readable justification flags (`vulnerable_code_not_present`
    and friends). That last bucket is authoritative not-affected
    evidence from Red Hat Product Security, which is why this is fetched
    per advisory rather than derived.

    Lazy by design: the full corpus is a 293 MB zstd archive covering
    every Red Hat product, and our access pattern is advisory-at-a-time.
    A cached document is reused when the synced index (changes.csv) has
    not recorded a newer revision of it.
    """
    spec = _feeds()["vex"]
    ident = cve.strip().lower()
    if not re.fullmatch(r"cve-\d{4}-\d{4,}", ident):
        raise ValueError(f"not a CVE id: {cve!r}")
    year = ident.split("-")[1]
    doc_path = cache / spec["doc_cache_dir"] / year / f"{ident}.json"
    if doc_path.is_file() and (
        offline or not _vex_doc_is_stale(cache, f"{year}/{ident}.json", doc_path)
    ):
        return json.loads(doc_path.read_text(encoding="utf-8"))
    if offline:
        raise FileNotFoundError(f"{cve} not in the VEX cache and --offline")
    url = spec["doc_url_template"].format(year=year, ident_lower=ident)
    raw = fetch_with_retry(url, _retry_policy("vex"))
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.write_bytes(raw)
    return json.loads(raw.decode("utf-8"))


def _vex_doc_is_stale(cache: Path, rel: str, doc_path: Path) -> bool:
    """True when the synced index records a revision newer than our copy.

    Index absent => not stale: an un-synced index is a reason to trust the
    cached document, not to re-download every document on every call.
    """
    idx = cache / _feeds()["vex"]["index_file"]
    if not idx.is_file():
        return False
    mtime = datetime.datetime.fromtimestamp(doc_path.stat().st_mtime, datetime.UTC)
    needle = f'"{rel}"'
    try:
        with idx.open(encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(needle):
                    stamp = line.rstrip().split('","')[-1].rstrip('"')
                    try:
                        pub = datetime.datetime.fromisoformat(stamp)
                    except ValueError:
                        return True
                    return pub > mtime
    except OSError:
        return False
    return False


def vex_product_status(doc: dict) -> dict:
    """{status_bucket: [product_id, ...]} for a VEX document."""
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return {}
    return dict(vulns[0].get("product_status") or {})


def load_product_definitions(cache: Path) -> dict:
    """The compiled Red Hat Product Security product registry.

    Raises on a missing top-level collection: a silent upstream shape
    change must surface as an error, not as an empty lookup that reads
    like "this product has no security contacts".
    """
    doc = json.loads((cache / _feeds()["product-definitions"]["file"]).read_text(encoding="utf-8"))
    missing = [k for k in PRODUCT_DEFINITIONS_KEYS if not isinstance(doc.get(k), dict)]
    if missing:
        raise ValueError(
            f"product-definitions cache is missing/malformed top-level "
            f"key(s): {', '.join(missing)} — upstream shape changed; "
            f"re-run fetch_feeds.py and check "
            f"{_feeds()['product-definitions']['url']}"
        )
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="override every requested feed's own threshold",
    )
    ap.add_argument(
        "--feed",
        choices=(*_feeds(), "all"),
        default="all",
        help="'all' covers public feeds only; internal feeds "
        "must be named or enabled with --include-internal",
    )
    ap.add_argument(
        "--include-internal",
        action="store_true",
        help="include internal (VPN-only) feeds in --feed all",
    )
    ap.add_argument(
        "--offline", action="store_true", help="never touch the network; use cached copies only"
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    cache_dir = args.cache_dir or feeds_cache_dir(engine=engine)

    if args.feed == "all":
        names = list(_feeds()) if args.include_internal else public_feeds()
    else:
        names = [args.feed]
    ok = True
    for name in names:
        usable, status = fetch(
            name, cache_dir, feed_max_age(name, args.max_age_hours), offline=args.offline
        )
        marker = "✓" if usable and not status.startswith("STALE") else "!"
        print(f"{marker} {name}: {status}" + ("" if usable else " — UNUSABLE"))
        ok = ok and usable
    return 0 if ok else 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["feeds", "fetch", *sys.argv[1:]]))
