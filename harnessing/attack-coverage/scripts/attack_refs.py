"""The pinned ATT&CK tables through traust-core's catalog, for validate-findings' chain.py."""

from functools import cache

from traust_core.v1.context.attack import load_attack_catalog
from traust_core.v1.models.assessment import AttackCatalog

from traust.context import ATTACK_TABLES


@cache
def catalog() -> AttackCatalog:
    return load_attack_catalog(*ATTACK_TABLES)


def capability_map() -> dict[str, tuple[str, ...]]:
    """capability -> technique ids (validate-findings chain annotation)."""
    return dict(catalog().capability_map)


def category_map() -> dict[str, tuple[str, ...]]:
    """finding category -> candidate technique ids."""
    return dict(catalog().category_map)


def validate_ids(ids) -> list[str]:
    """Why each id can't be cited (empty when all are live in the pinned release)."""
    return list(catalog().invalid(ids))
