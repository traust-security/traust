"""The hosts `traust adapters below-range` may fetch from, read from feeds.yaml.

Fix patches come from `role: fix-patches` sources and installed package source
from `role: package-source` sources. Each source contributes its url_template's
host and any `extra_hosts`; `redirect_hosts` are where a fetch from those hosts
may be redirected. A source with `access: disabled` contributes nothing.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

FIX_PATCHES = "fix-patches"
PACKAGE_SOURCE = "package-source"


@dataclass(frozen=True)
class Hosts:
    forges: frozenset[str]
    registries: frozenset[str]
    redirects: dict[str, frozenset[str]] = field(default_factory=dict)
    sources: tuple[str, ...] = ()


def applicability_hosts(sources: dict[str, dict] | None = None) -> Hosts | None:
    """The configured hosts, or None when feeds.yaml names no such source."""
    if sources is None:
        from traust.registry.feeds_config import live_sources

        sources = live_sources()
    forges: set[str] = set()
    registries: set[str] = set()
    redirects: dict[str, set[str]] = {}
    used: list[str] = []
    for sid, spec in sorted(sources.items()):
        role = spec.get("role")
        if role not in (FIX_PATCHES, PACKAGE_SOURCE):
            continue
        if spec.get("access", "api") == "disabled":
            continue
        host = urllib.parse.urlsplit(spec["url_template"]).hostname or ""
        hosts = {h for h in (host, *(spec.get("extra_hosts") or [])) if h}
        (forges if role == FIX_PATCHES else registries).update(hosts)
        for h in hosts:
            redirects.setdefault(h, set()).update(spec.get("redirect_hosts") or [])
        used.append(sid)
    if not used:
        return None
    return Hosts(
        frozenset(forges),
        frozenset(registries),
        {h: frozenset(r) for h, r in redirects.items()},
        tuple(used),
    )
