"""OSV API URL resolution — single source from the shipped feeds.yaml."""

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
    """`api` (default) or `air-gapped`: `feeds.osv_access` in traust.yaml."""
    from traust_core.v1.context import Config, resolve_config_home

    return Config.from_home(resolve_config_home()).feeds.osv_access


def deps_dev_settings() -> tuple[str, str] | None:
    """(url_template, access) of the deps_dev source, or ``None`` when absent."""
    from traust.registry.feeds_config import live_sources

    spec = live_sources().get("deps_dev")
    if spec is None:
        return None
    return spec["url_template"], spec.get("access", "api")
