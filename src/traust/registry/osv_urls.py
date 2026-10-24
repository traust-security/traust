"""OSV API URL resolution — single source from feeds.yaml."""

from __future__ import annotations


def _osv_base() -> str:
    from traust.registry.feeds_config import live_sources

    return live_sources()["osv"]["url_template"]


def osv_query_url() -> str:
    return _osv_base()


def osv_batch_url() -> str:
    return _osv_base().replace("/query", "/querybatch")


def osv_vuln_url(vid: str | None = None) -> str:
    base = _osv_base().replace("/query", "/vulns/{vid}")
    return base.format(vid=vid) if vid else base


def osv_access() -> str:
    """`api` (default) or `air-gapped` — the osv source's `access` in feeds.yaml."""
    from traust.registry.feeds_config import live_sources

    return live_sources()["osv"].get("access", "api")


def nuget_ids():
    """The resolver OsvClient uses to retry a NuGet lookup under nuget.org's
    casing (OSV matches NuGet ids case-sensitively), or ``None`` when
    feeds.yaml disables the nuget-packages source."""
    from traust_engine.osv import NugetIds

    from traust.registry.feeds_config import live_sources

    spec = live_sources().get("nuget-packages") or {}
    if spec.get("access", "api") == "disabled":
        return None
    return NugetIds()


def deps_dev_settings() -> tuple[str, str] | None:
    """(url_template, access) of the deps_dev source, or ``None`` when absent."""
    from traust.registry.feeds_config import live_sources

    spec = live_sources().get("deps_dev")
    if spec is None:
        return None
    return spec["url_template"], spec.get("access", "api")
