"""``traust portfolio …`` — the portfolio and its dependencies on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

OBSERVE = passthrough_op(
    "portfolio_observe", "Observe one repository at its forge; keep what it answered.", "main"
)

PLAN = passthrough_op("portfolio_onboard", "What onboard would register, writing nothing.", "plan")
ONBOARD = passthrough_op("portfolio_onboard", "Register a product's repositories.", "onboard")
OWNER_HINTS = passthrough_op("portfolio_onboard", "Who may own a repository.", "owner_hints")
FILE = passthrough_op("portfolio_onboard", "One file's text at a pinned commit.", "file")
IMPORT_OWNERS = passthrough_op(
    "portfolio_onboard", "Mirror the declared ownership source.", "import_owners"
)
IMPORT_RELEASE = passthrough_op(
    "portfolio_onboard", "Record a product version and its commits.", "import_release"
)
RELEASE_CHANGES = passthrough_op(
    "portfolio_onboard", "What a recorded product version changed.", "release_changes"
)
POPULATION = passthrough_op(
    "portfolio_population", "What the registered repositories had assessed.", "main"
)
DEPENDENCIES = passthrough_op(
    "portfolio_dependencies", "The packages in a commit's manifest SBOM.", "dependencies"
)
DEPENDENTS = passthrough_op(
    "portfolio_dependencies", "The commits a package reaches.", "dependents"
)
LIVENESS = passthrough_op(
    "portfolio_liveness", "Each registered repository's archived flag and push.", "main"
)
CHECKOUT_REFRESH = passthrough_op(
    "portfolio_checkout",
    "Fetch a repository's git mirror to its observed head (the repo_checkout_refresh asset).",
    "refresh",
)
MIRROR_EVICT = passthrough_op(
    "portfolio_checkout",
    "Drop git mirrors idle for the eviction window (the mirror_evict asset).",
    "evict",
)
