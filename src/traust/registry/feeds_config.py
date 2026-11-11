"""Loader for the security-data source registry: the ``feeds.yaml`` traust-core ships.

Every consumer of an external vulnerability source goes through here
rather than hardcoding an endpoint. The registry covers BOTH tiers:

``cached``  snapshotted into traust-core on a cadence (``traust feeds fetch``)
``live``    queried per run, never cached (``traust impact document``)

Keeping them in one file is the point. When live sources lived as
hardcoded URLs plus an argparse literal there was no registry to inspect
and no check to fail, so ``fetch_advisory.py csaf`` could 404 on every
CVE indefinitely (measured 2026-08-25 — Red Hat keys CSAF advisories by
RHSA, not CVE). A source in this file with a ``probe`` gets a
``feed-source:*`` freshness row for free (traust-core's ProviderCatalog). The registry is
the project's, not adopter config; ``feeds.osv_access`` in ``traust.yaml`` is the one knob.

Cache location resolves via :func:`traust.context.feeds_cache_dir` (first hit wins):

1. ``FEEDS_CACHE_DIR``            explicit operator/orchestrator control
2. ``locations.feeds_cache``      when set in ``traust.yaml``
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

from traust_core.v1.context import Context
from traust_core.v1.context.config import SHIPPED_FEEDS

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dependency
    yaml = None


#: Cadence -> hours, for entries that name a cadence but no explicit age.
_CADENCE_HOURS = {"daily": 24.0, "weekly": 24.0 * 7, "monthly": 24.0 * 30}

DEFAULT_MAX_AGE_HOURS = 24.0


class FeedsConfigError(RuntimeError):
    """The registry is absent, unparseable, or structurally invalid.

    Raised rather than defaulted: a consumer that silently falls back to
    an empty registry reports "no feeds are stale" while tracking
    nothing, which is the failure mode this whole file exists to remove.
    """


def feeds_cache_dir(*, core: Context) -> Path:
    """Where cached feed data lives. Resolution lives in ``traust.context``."""
    from traust.context import feeds_cache_dir as resolve_feeds_cache_dir

    return resolve_feeds_cache_dir(core)


def _load_raw(path: Path | None = None) -> dict:
    p = path or SHIPPED_FEEDS
    if yaml is None:
        raise FeedsConfigError("PyYAML is required to read feeds.yaml — `uv sync`")
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise FeedsConfigError(f"cannot read {p}: {e}") from e
    except yaml.YAMLError as e:
        raise FeedsConfigError(f"cannot parse {p}: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), dict):
        raise FeedsConfigError(f"{p} must define a top-level `sources` mapping")
    return doc


# How a live source is reached. `api` is the default; `disabled` (deps_dev) opts out of the
# source. Air-gapped osv is the adopter's switch: `feeds.osv_access` in traust.yaml.
ACCESS_MODES = ("api", "disabled")


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
    if spec.get("access", "api") not in ACCESS_MODES:
        raise FeedsConfigError(
            f"source {sid!r}: access must be one of {', '.join(ACCESS_MODES)}, "
            f"got {spec.get('access')!r}"
        )


def load(path: Path | None = None) -> dict[str, dict]:
    """Every source, id -> spec, validated. Raises FeedsConfigError."""
    doc = _load_raw(path)
    sources = doc["sources"]
    for sid, spec in sources.items():
        if not isinstance(spec, dict):
            raise FeedsConfigError(f"source {sid!r}: expected a mapping")
        _validate(sid, spec)
    return sources


def cached_sources(path: Path | None = None) -> dict[str, dict]:
    return {k: v for k, v in load(path).items() if v["tier"] == "cached"}


def live_sources(path: Path | None = None) -> dict[str, dict]:
    return {k: v for k, v in load(path).items() if v["tier"] == "live"}


def max_age_hours(spec: dict, override: float | None = None) -> float:
    if override is not None:
        return override
    if spec.get("max_age_hours") is not None:
        return float(spec["max_age_hours"])
    return _CADENCE_HOURS.get(spec.get("cadence"), DEFAULT_MAX_AGE_HOURS)
