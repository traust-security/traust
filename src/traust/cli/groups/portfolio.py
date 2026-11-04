"""``traust portfolio …`` — the portfolio and its dependencies on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

OBSERVE = passthrough_op(
    "portfolio_observe", "Observe one repository at its forge; keep what it answered.", "main"
)
INVENTORY_DISCOVER = passthrough_op(
    "portfolio_observe",
    "Register configured input repositories and plan their first observation and audit.",
    "inventory_discover",
)
EVENT_INTAKE = passthrough_op(
    "portfolio_observe", "Plan unconsumed operator routing events.", "event_intake"
)
EVENT_VALIDATE = passthrough_op(
    "portfolio_observe",
    "Run an external report's authorized live-validation stage.",
    "event_validate",
)


PLAN = passthrough_op("portfolio_onboard", "What onboard would register, writing nothing.", "plan")
ONBOARD = passthrough_op("portfolio_onboard", "Register a product's repositories.", "onboard")
OWNER_HINTS = passthrough_op("portfolio_onboard", "Who may own a repository.", "owner_hints")
INVENTORY_EXPORT = passthrough_op(
    "portfolio_onboard", "Joined inventory, contacts and tracker routing.", "inventory_export"
)
IMPORT_REFERENCE = passthrough_op(
    "portfolio_onboard", "Retain adopter-declared inventory metadata.", "import_reference"
)
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
    "portfolio_liveness", "Each registered repository's latest forge availability and push.", "main"
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
GRAPH = passthrough_op(
    "portfolio_graph",
    "Export repository relationships, interactive map and hub statistics.",
    "main",
)
FACTS_COLLECT = passthrough_op(
    "portfolio_facts",
    "Collect pinned package and Kubernetes interface facts across the fleet.",
    "collect",
)
CRD_CONSUMERS = passthrough_op(
    "portfolio_facts",
    "Find API-group owners, consumers, RBAC grants and webhooks.",
    "crd_consumers",
)
IMPORTS_PACKAGE = passthrough_op(
    "portfolio_facts", "Find repositories importing a package.", "imports_package"
)
EXPORTS_OF = passthrough_op(
    "portfolio_facts", "List a repository's exported declarations.", "exports_of"
)
SHIPS_MODULE = passthrough_op(
    "portfolio_facts", "Find images shipping a module from their recorded SBOMs.", "ships_module"
)
INTERNAL_COUPLING = passthrough_op(
    "portfolio_facts",
    "Rank portfolio-owned packages by distinct dependent repositories.",
    "internal_coupling",
)
CROWN_JEWEL_DRAFT = passthrough_op(
    "portfolio_analytics",
    "Generate unsigned crown-jewel proposals for human review.",
    "crown_jewel_draft",
)
IAC_CENSUS = passthrough_op(
    "portfolio_analytics", "Export the fleet IaC census and baseline worklist.", "iac_census"
)
ORG_INDEX = passthrough_op(
    "portfolio_analytics",
    "Navigate source organizations, repositories and assessment artifacts.",
    "org_index",
)
RELEASE_DISCOVER = passthrough_op(
    "portfolio_releases",
    "Discover inventory and dist-git changes through the recorded feed.",
    "discover",
)
RELEASE_PASSTHROUGH = passthrough_op(
    "portfolio_releases", "Plan artifact audit lanes for observed releases.", "passthrough"
)
RELEASE_AUDIT = passthrough_op(
    "portfolio_releases", "Audit a pinned container or RPM release batch.", "audit"
)
