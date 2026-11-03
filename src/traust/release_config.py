from __future__ import annotations

from pathlib import Path

import pydantic
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import AssetName
from traust_core.v1.models.release_inventory import ReleaseRouting

RELEASE_ROUTING = ReleaseRouting(
    passthrough=AssetName("release_passthrough"),
    container=AssetName("release_container_audit"),
    rpm=AssetName("release_rpm_audit"),
    threat_model=AssetName("threat_model_review"),
    priority=100,
)


class ReleaseWatch(Dto):
    active: tuple[str, ...] = ()
    products: dict[str, str] = pydantic.Field(default_factory=dict)


def read_release_watch(path: Path) -> ReleaseWatch:
    if not path.is_file():
        return ReleaseWatch()
    try:
        return ReleaseWatch.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    except (OSError, yaml.YAMLError, pydantic.ValidationError) as error:
        raise ConfigError(f"invalid release watch configuration: {path}: {error}") from error


def register_release_inventory(core: Context, config_home: Path) -> None:
    locations = core.config.locations
    if not (locations.inputs or locations.workspace):
        return
    inputs = locations.inputs_dir()
    watch = read_release_watch(config_home / "rpm-distgit-watch.yaml")
    core.register_release_inventory(inputs, watched=watch.active, products=watch.products)
