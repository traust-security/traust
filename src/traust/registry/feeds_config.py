"""Loader for ``config/feeds.yaml`` — the security-data source registry.

Every consumer of an external vulnerability source goes through here
rather than hardcoding an endpoint. The registry covers BOTH tiers:

``cached``  pulled to a local cache on a cadence (``fetch_feeds``)
``live``    queried per run, never cached (``fetch_advisory``)

Keeping them in one file is the point. When live sources lived as
hardcoded URLs plus an argparse literal there was no registry to inspect
and no check to fail, so ``fetch_advisory.py csaf`` could 404 on every
CVE indefinitely (measured 2026-08-25 — Red Hat keys CSAF advisories by
RHSA, not CVE). A source in this file gets a drift row for free.

Cache location resolves via :func:`traust.context.feeds_cache_dir` (first hit wins):

1. ``FEEDS_CACHE_DIR``            explicit operator/orchestrator control
2. ``locations.feeds_cache``      when set in ``locations.yaml``
3. ``<progress_tracker>/feeds``   default

It is deliberately NOT under ``analysis-results/``. That tree holds work
we produced — findings, ledgers, derived projections — and a mirror of
third-party licensed data is a different provenance class with opposite
retention and redistribution properties. Filing them together is how
~6 MB of CC-BY/CC0 feed data reached the harness repo's git history
(commit 67c1d38, 2026-08-25) and how internal personnel data landed one
``git add -A`` away from a repo slated for open-source release.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import config_path
from traust_engine import HarnessEngine

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dependency
    yaml = None


def registry_path() -> Path:
    """The required feeds.yaml, resolved from the one config home.

    Lazy (not a module constant): feeds.yaml is a shipped default seeded into
    $TRAUST_CONFIG_HOME by install_traust, never read from the code tree.
    """
    return config_path("feeds.yaml")


#: Cadence -> hours, for entries that name a cadence but no explicit age.
_CADENCE_HOURS = {"daily": 24.0, "weekly": 24.0 * 7, "monthly": 24.0 * 30}

DEFAULT_MAX_AGE_HOURS = 24.0


class FeedsConfigError(RuntimeError):
    """The registry is absent, unparseable, or structurally invalid.

    Raised rather than defaulted: a consumer that silently falls back to
    an empty registry reports "no feeds are stale" while tracking
    nothing, which is the failure mode this whole file exists to remove.
    """


def feeds_cache_dir(*, engine: HarnessEngine) -> Path:
    """Where cached feed data lives. Resolution lives in ``traust.context``."""
    from traust.context import feeds_cache_dir as resolve_feeds_cache_dir

    return resolve_feeds_cache_dir(engine)


def _load_raw(path: Path | None = None) -> dict:
    p = path or registry_path()
    if yaml is None:
        raise FeedsConfigError("PyYAML is required to read config/feeds.yaml — `uv sync`")
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise FeedsConfigError(f"cannot read {p}: {e}") from e
    except yaml.YAMLError as e:
        raise FeedsConfigError(f"cannot parse {p}: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), dict):
        raise FeedsConfigError(f"{p} must define a top-level `sources` mapping")
    return doc


def _validate(sid: str, spec: dict) -> None:
    tier = spec.get("tier")
    if tier not in ("cached", "live"):
        raise FeedsConfigError(f"source {sid!r}: tier must be 'cached' or 'live', got {tier!r}")
    if not isinstance(spec.get("license"), dict):
        raise FeedsConfigError(
            f"source {sid!r}: a `license` block is required — "
            "docs/external-dependencies.md holds the prose row and "
            "check-licensing walks the intake checklist"
        )
    if tier == "cached":
        mode = spec.get("mode")
        if mode not in ("file", "paginated-incremental", "indexed-lazy"):
            raise FeedsConfigError(f"source {sid!r}: unknown cached mode {mode!r}")
        needs = ("index_file",) if mode == "indexed-lazy" else ("url", "file")
        for key in needs:
            if not spec.get(key):
                raise FeedsConfigError(f"source {sid!r}: cached mode {mode!r} requires {key!r}")
    elif not spec.get("url_template"):
        raise FeedsConfigError(f"source {sid!r}: live sources require `url_template`")


def load(path: Path | None = None) -> dict[str, dict]:
    """Every source, id -> spec, validated. Raises FeedsConfigError."""
    doc = _load_raw(path)
    sources = doc["sources"]
    for sid, spec in sources.items():
        if not isinstance(spec, dict):
            raise FeedsConfigError(f"source {sid!r}: expected a mapping")
        _validate(sid, spec)
    return sources


def retry_defaults(path: Path | None = None) -> dict:
    """Global download-retry policy from feeds.yaml ``retry:`` (empty when unset).

    A feed's own ``retry:`` block overrides these; fetch_feeds merges the two.
    Returning {} rather than raising when absent keeps the built-in RetryPolicy
    defaults in force for a registry that predates this block.
    """
    retry = _load_raw(path).get("retry") or {}
    if not isinstance(retry, dict):
        raise FeedsConfigError("feeds.yaml `retry:` must be a mapping")
    return retry


def cached_sources(path: Path | None = None) -> dict[str, dict]:
    return {k: v for k, v in load(path).items() if v["tier"] == "cached"}


def live_sources(path: Path | None = None) -> dict[str, dict]:
    return {k: v for k, v in load(path).items() if v["tier"] == "live"}


def probeable_sources(path: Path | None = None) -> dict[str, dict]:
    """Sources carrying a `probe` — the liveness-checkable set.

    A source without a probe is not a failure; it is simply untracked for
    liveness, and check_drift reports that rather than assuming health.
    """
    return {k: v for k, v in load(path).items() if isinstance(v.get("probe"), dict)}


def max_age_hours(spec: dict, override: float | None = None) -> float:
    if override is not None:
        return override
    if spec.get("max_age_hours") is not None:
        return float(spec["max_age_hours"])
    return _CADENCE_HOURS.get(spec.get("cadence"), DEFAULT_MAX_AGE_HOURS)


def resolve_url(spec: dict, ident: str) -> str:
    """Fill a live source's url_template for one identifier.

    The placeholder set is deliberately tiny and purely lexical — no
    caller-supplied format strings, no eval — because a template is
    config-supplied and write access to config/feeds.yaml must not become
    request forgery against an arbitrary host.
    """
    # Year is a path component for the year-partitioned Red Hat trees
    # (VEX and CSAF advisories). Match anywhere rather than splitting on
    # '-': RHSA ids are RHSA-2024:6493, so a '-' split yields '2024:6493'
    # and silently produces a URL with an empty path segment.
    import re

    m = re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", str(ident))
    year = m.group(0) if m else ""
    return spec["url_template"].format(
        ident=ident,
        ident_lower=str(ident).lower(),
        ident_upper=str(ident).upper(),
        ident_lower_us=str(ident).lower().replace(":", "_"),
        year=year,
    )
