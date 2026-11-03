"""The app's single composition root: traust-core's Context with every provider registered.

Every entry point builds it here, once (:func:`load`), and threads it into its workers. Nothing
else in the app calls ``Context``.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import TypeVar

from traust_core.v1.context import (
    TRAUST_CONFIG_HOME_DEFAULT,
    Config,
    Context,
    Locations,
    resolve_config_home,
)
from traust_core.v1.context.config import CONFIG_FILE
from traust_core.v1.errors import AuthenticationError, ConfigError, DeploymentConfigMissing
from traust_core.v1.models.identity import Credential, Principal

from traust.paths import GITLEAKS_CONFIG, HARNESSING_DIR, OPENGREP_RULES_DIR, SECURITY_PACK_DIR

T = TypeVar("T")

SLA_POLICY = SECURITY_PACK_DIR / "sla-policy.yaml"  # the default until one is recorded
MODEL_REGISTRY = "model-registry.yaml"
# Security-pack content (home: traust-pack-security): the pinned ATT&CK release and its mapping.
_ATTACK = HARNESSING_DIR / "attack-coverage" / "tables"
ATTACK_TABLES = (_ATTACK / "attack-techniques.json", _ATTACK / "attack-mapping.json")
ATLAS_TABLE = _ATTACK / "atlas-techniques.json"  # the pinned MITRE ATLAS release

# ---------------------------------------------------------------------------
# Sanctioned environment overrides — read ONLY in this module, never in consumers.
#
# ``locations:`` in ``traust.yaml`` owns estate/campaign paths. These env vars are deliberate
# escape hatches for layouts that must not live in checked-in config, plus one
# secret that must never sit in a file or on argv.
# ---------------------------------------------------------------------------
#
# TRAUST_CONFIG_HOME
#   The config home, when no --config-home is given. Consumed by core's
#   ``resolve_config_home``.
#
# HARNESS_ROOT
#   Where the harness payload (harnessing/, packs/) sits when traust is installed as a wheel
#   and not run from its checkout (the runtime image sets it). Consumed by :mod:`traust.paths`.
#
# XDG_CACHE_HOME
#   Where the recall benchmark commits its canary repositories
#   (``<cache>/recall-bench/<canaries>``). Consumed by :func:`load`.
#
# AUDIT_RESULTS_ROOT
#   Point a one-off run or CI matrix job at an analysis-results tree without
#   editing ``traust.yaml``. Used when the job checks out results elsewhere
#   or shares a prebuilt tree across steps. Consumed by :func:`resolve_results_root`
#   (after an explicit ``--results-root`` CLI flag).
#
# FEEDS_CACHE_DIR
#   Pin the EPSS/KEV/product-definitions pull-through cache to a shared volume,
#   temp dir, or orchestrator-managed path. Feed mirrors are third-party licensed
#   data — intentionally kept out of ``analysis-results/`` (different provenance
#   and retention). Consumed by :func:`feeds_cache_dir`.
#
# TRAUST_OIDC_CLIENT_SECRET
#   A service account's client secret for ``traust auth service-account`` when no
#   ``--client-secret-file`` is given. Consumed by :func:`oidc_client_secret`.
#
# HARNESS_INTERNAL_VOCABULARY
#   The organization vocabulary the pre-publication scrub (``traust admin scan-internal-refs``)
#   and the config/ hygiene gate read when no ``--vocabulary`` is given. It names internal
#   hosts and tools, so it lives with the deployment, never in config. Consumed by
#   :func:`internal_vocabulary`.
#


def _audit_results_root_from_env() -> Path | None:
    raw = os.environ.get("AUDIT_RESULTS_ROOT")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def _feeds_cache_dir_from_env() -> Path | None:
    raw = os.environ.get("FEEDS_CACHE_DIR")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def _guarded(what: str, step: Callable[[], T]) -> T:
    try:
        return step()
    except ConfigError as e:
        print(f"{what} not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def load(
    config_home: Path | None = None,
    *,
    sla_policy: Path | None = None,
    invoices: Path | None = None,
    canaries: str = "canaries",
    rule_pack: Path | None = None,
    rule_drafts: Path | None = None,
) -> Context:
    """traust-core's Context from ``<config home>/traust.yaml`` with every provider registered
    once, or exit 2 when the config is invalid.

    No ``traust.yaml``: core's defaults (SQLite and artifacts under ``~/.traust``), the zero-setup
    laptop install. The ATT&CK coverage view is built on the pack's pinned tables; the SLA view on
    ``sla_policy``, else on the recorded policy, else on the pack's default; the spend view on
    the home's model registry when there is one, reconciled against ``invoices``. The tools read
    the pins and safe-exec profiles traust-core ships; detection quality scores the rule pack
    (``rule_pack``, else :func:`_rule_pack`, with ``overrides.rule_pack_allowlist``) against
    canaries from ``recall-benchmark/<canaries>`` and stages rule drafts in ``rule_drafts``, else
    ``locations.rule_drafts`` when one resolves.
    """
    home = resolve_config_home(config_home)
    core = _guarded(CONFIG_FILE, lambda: Context(_with_bundled_rules(Config.from_home(home))))
    _guarded("ATT&CK catalog", lambda: core.register_attack_catalog(*ATTACK_TABLES))
    _guarded("ATLAS catalog", lambda: core.register_atlas_catalog(ATLAS_TABLE))
    _guarded("SLA policy", lambda: core.register_default_sla_policy(SLA_POLICY))
    if sla_policy is not None:
        _guarded("SLA policy", lambda: core.register_sla_policy(sla_policy))
    if home is not None and (home / MODEL_REGISTRY).is_file():
        _register_spend(core, home / MODEL_REGISTRY, invoices)
    elif invoices is not None:
        print(f"invoices need the spend view: no {MODEL_REGISTRY} in {home}", file=sys.stderr)
        raise SystemExit(2)
    core.register_toolchain()
    pack, pack_version = (
        (rule_pack, f"local:{rule_pack}") if rule_pack else _rule_pack(core.config.locations)
    )
    core.register_rule_pack(pack, core.config.overrides.rule_pack_allowlist)
    files = home or TRAUST_CONFIG_HOME_DEFAULT
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    core.register_detection_quality(
        pack_version, files / "recall-benchmark" / canaries, cache / "recall-bench" / canaries
    )
    if drafts := rule_drafts or core.config.locations.rule_drafts_dir():
        core.register_rule_drafts(drafts)
    core.register_fleet_fix()
    core.register_compliance_sources()
    return core


def _with_bundled_rules(config: Config) -> Config:
    """``config`` with the pack's gitleaks config when ``locations.gitleaks_config`` is unset."""
    if config.locations.gitleaks_config:
        return config
    locations = config.locations.model_copy(update={"gitleaks_config": str(GITLEAKS_CONFIG)})
    return config.model_copy(update={"locations": locations})


def _rule_pack(locations: Locations) -> tuple[Path, str]:
    """The opengrep rule pack and its version: ``locations.opengrep_rules``, else the pack's."""
    if raw := locations.opengrep_rules:
        pack = Path(raw.removeprefix("file://"))
        return pack, f"local:{pack}"
    return OPENGREP_RULES_DIR, version("traust")


def load_spend_core(config_home: Path | None = None) -> Context:
    """``load_core`` pricing spend on ``<config home>/model-registry.yaml`` (template:
    config/model-registry.yaml); exit 2 when it is missing or invalid."""
    core = load(config_home)
    if core.model_catalog is None:
        home = resolve_config_home(config_home)
        _register_spend(core, (home or Path()) / MODEL_REGISTRY, None)
    return core


def _register_spend(core: Context, registry: Path, invoices: Path | None) -> None:
    try:
        core.register_model_catalog(registry)
        if invoices is not None:
            core.register_invoices(invoices)
    except ConfigError as e:
        print(f"spend not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def load_caller(core: Context) -> Principal:
    """Who is calling: the stored login (``traust auth``), verified by core's identity service."""
    if core.identity is None:
        raise ConfigError(
            "no identity: section in traust.yaml; a solo install adds"
            " `identity: {trust_local: true}` to accept its own `traust auth local` tokens"
        )
    login = core.credentials.load()
    if login is None:
        raise AuthenticationError("not logged in: run `traust auth login` or `traust auth local`")
    return core.identity.authenticate(Credential(token=login.grant.access_token))


def oidc_client_secret() -> str | None:
    raw = os.environ.get("TRAUST_OIDC_CLIENT_SECRET", "").strip()
    return raw or None


def internal_vocabulary() -> Path | None:
    raw = os.environ.get("HARNESS_INTERNAL_VOCABULARY", "").strip()
    return Path(raw).expanduser() if raw else None


def add_config_home_arg(parser) -> None:
    """Standard --config-home flag so every CLI resolves config the same way."""
    parser.add_argument(
        "--config-home",
        type=Path,
        default=None,
        help="TRAUST config home (default: $TRAUST_CONFIG_HOME)",
    )


def locations(src: Context) -> Locations:
    return src.config.locations


def _required(value: Callable[[], Path | None], name: str) -> Path:
    """A location from core, or :class:`DeploymentConfigMissing` naming it (what callers catch)."""
    try:
        return Locations.require(value(), name)
    except ConfigError as e:
        raise DeploymentConfigMissing(str(e)) from e


def analysis_results_dir(src: Context) -> Path:
    """Configured local analysis-results root (fail-loud when unset)."""
    return _required(locations(src).analysis_results_dir, "analysis_results")


def workspace_dir(src: Context) -> Path:
    """Configured workspace root (fail-loud when unset)."""
    return _required(locations(src).workspace_dir, "workspace")


def inputs_dir(src: Context) -> Path:
    """The repository-inventory tree: ``locations.inputs``, else ``<workspace>/inputs``."""
    return _required(locations(src).inputs_dir, "inputs")


def findings_db(src: Context) -> Path:
    """``<analysis-results>/graph/findings.db`` (fail-loud when unset)."""
    return _required(locations(src).findings_db, "analysis_results")


def progress_tracker_dir(src: Context) -> Path:
    """Configured progress-tracker root (fail-loud when unset)."""
    return _required(locations(src).progress_tracker_dir, "progress_tracker")


def rule_drafts_dir(src: Context) -> Path:
    """Configured rule-drafts root (fail-loud when unset)."""
    return _required(locations(src).rule_drafts_dir, "rule_drafts")


def feeds_cache_dir(src: Context) -> Path:
    """Feeds pull-through cache: ``FEEDS_CACHE_DIR`` > config > ``progress_tracker/feeds``."""
    override = _feeds_cache_dir_from_env()
    if override is not None:
        return override
    return locations(src).feeds_cache_dir() or progress_tracker_dir(src) / "feeds"


def findings_tree_dir(src: Context) -> Path:
    """``<analysis-results>/findings`` (fail-loud when analysis_results unset)."""
    return analysis_results_dir(src) / "findings"


def resolve_results_root(args=None, *, config_home: Path | None = None) -> Path:
    """``--results-root`` > ``$AUDIT_RESULTS_ROOT`` > ``locations.analysis_results``.

    Exits 2 when ``analysis_results`` is unset. Pass ``args`` from argparse after
    :func:`add_config_home_arg`.
    """
    if args is not None and getattr(args, "results_root", None):
        return Path(args.results_root).expanduser().resolve()
    if args is not None and config_home is None and getattr(args, "config_home", None):
        config_home = args.config_home
    override = _audit_results_root_from_env()
    if override is not None:
        return override
    try:
        return analysis_results_dir(load(config_home)).resolve()
    except DeploymentConfigMissing as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e
