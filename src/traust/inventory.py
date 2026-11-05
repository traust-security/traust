"""Inventory descriptor — what each segment of the repository inventory *is*.

The inventory tree (``locations.inputs``) is one directory per *segment*.
Until 2026-09-07 three segment names were hardcoded across the graph builder,
the executive summary and the IaC inventory (one organisation's product
names), and every other segment fell through to the generic layout. The
descriptor replaces those names with a declared *kind*:

    <inputs>/inventory.yaml
    ---
    segments:
      openshift:        {kind: release-payload, label: OpenShift}
      operator-catalog: {kind: catalog,         label: Operator Catalog}
      services:         {kind: services,        label: Managed Services}

Kinds
    groups           ``<segment>/<group>/*-repos.csv`` (+ ``owners.csv``).
                     The default for every undeclared segment; what
                     ``add-inputs`` writes.
    release-payload  ``<segment>/<segment>-<version>-payload-repos.csv`` per
                     release, optional ``<segment>/<sub>/*-repos.csv`` product
                     sub-trees, ``owners.csv`` at segment and sub level.
    catalog          ``<segment>/<product>/<version>/*-payload-repos.csv`` per
                     product version, ``<segment>/<product>/*-repos.csv`` for
                     unversioned rows, ``owners.csv`` per product.
    services         Same layout as ``groups``; rows may carry
                     ``App/Sub-Service`` and ``Resource Type``. The first
                     segment of this kind is the tenancy-relevance set for the
                     IaC inventory.

Declaration order is the segment priority: when a repo ships in more than one
segment, the executive summary attributes it to the first declared one.
Undeclared segments follow in name order. A missing descriptor means every
segment is ``groups`` — the tree is read exactly as ``add-inputs`` wrote it.

Optional per-segment keys (used by the inventory-repositories skill, not by
the readers here): ``release_label`` (format with ``{label}`` / ``{version}``,
default ``"{label} {version}"``), ``payload_image`` (release-payload image
reference with ``{version}``), ``registries`` (catalog: bundle registries to
try, in order).
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.values import HttpsRepoUrl

DESCRIPTOR_NAME = "inventory.yaml"
KINDS = ("groups", "release-payload", "catalog", "services")
DEFAULT_KIND = "groups"


class InventoryDescriptorError(ValueError):
    """The descriptor exists but does not parse to the documented shape."""


@dataclass(frozen=True)
class Segment:
    name: str
    kind: str = DEFAULT_KIND
    label: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def display(self) -> str:
        return self.label or self.name.title()

    def release_label(self, version: str) -> str:
        fmt = self.extra.get("release_label") or "{label} {version}"
        return fmt.format(label=self.display, version=version)


@dataclass(frozen=True)
class InventoryDescriptor:
    path: Path | None
    declared: tuple[Segment, ...] = ()

    def segment(self, name: str) -> Segment:
        for s in self.declared:
            if s.name == name:
                return s
        return Segment(name)

    def kind(self, name: str) -> str:
        return self.segment(name).kind

    def label(self, name: str) -> str:
        return self.segment(name).display

    @property
    def order(self) -> list[str]:
        """Declared segment names in declaration (priority) order."""
        return [s.name for s in self.declared]

    def priority(self, present: list[str] | set[str]) -> list[str]:
        """``present`` segments, declared first in order, the rest by name."""
        declared = [s for s in self.order if s in present]
        return declared + sorted(s for s in present if s not in declared)

    def first_of_kind(self, kind: str) -> str | None:
        for s in self.declared:
            if s.kind == kind:
                return s.name
        return None


def load_descriptor(inputs: Path | None) -> InventoryDescriptor:
    """Read ``<inputs>/inventory.yaml``; absent → every segment is ``groups``."""
    if inputs is None:
        return InventoryDescriptor(None)
    path = Path(inputs) / DESCRIPTOR_NAME
    if not path.is_file():
        return InventoryDescriptor(None)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise InventoryDescriptorError(f"{path}: {e}") from e
    if not isinstance(doc, dict):
        raise InventoryDescriptorError(f"{path}: top level must be a mapping")
    segs = doc.get("segments") or {}
    if not isinstance(segs, dict):
        raise InventoryDescriptorError(f"{path}: `segments` must be a mapping")
    declared: list[Segment] = []
    for name, spec in segs.items():
        if spec is None:
            spec = {}
        if isinstance(spec, str):
            spec = {"kind": spec}
        if not isinstance(spec, dict):
            raise InventoryDescriptorError(
                f"{path}: segments.{name} must be a mapping or a kind string"
            )
        kind = spec.get("kind", DEFAULT_KIND)
        if kind not in KINDS:
            raise InventoryDescriptorError(
                f"{path}: segments.{name}.kind={kind!r}; expected one of {', '.join(KINDS)}"
            )
        extra = {k: v for k, v in spec.items() if k not in ("kind", "label")}
        declared.append(Segment(str(name), kind, spec.get("label"), extra))
    return InventoryDescriptor(path, tuple(declared))


# --- the repository URLs each segment lists ------------------------------------------------
# The input inventory is an adopter extension (E3): traust reads it, and registers what it lists
# through core's doors (`find_repository`, `register_repository`, `OpsService.plan`). Core keeps
# no segment model and no identity from these paths (R11).

_REPO_URL = TypeAdapter(HttpsRepoUrl)
_URL_COLUMNS = ("GitHub URL", "URL")
_NO_REPOSITORY_COLUMN = "GitHub Repository"  # `N/A (<image>)` on a base-image row


@dataclass(frozen=True)
class InputSegment:
    """One inventory segment and the repository URLs its ``*-repos.csv`` files list."""

    name: str
    repository_urls: tuple[str, ...]


@dataclass(frozen=True)
class InputSegmentInventory:
    """Every segment present under the inventory root, declared ones first."""

    segments: tuple[InputSegment, ...]


def repository_inventory(inputs: Path) -> InputSegmentInventory:
    """Each segment's repository URLs under ``inputs``, in descriptor priority order.

    Every ``*-repos.csv`` below a segment counts except ``owners*.csv``; its ``GitHub URL`` (else
    ``URL``) column names the repository. A missing tree, an invalid descriptor, an empty or
    headerless file, a file without a URL column, a row whose URL cell is empty or missing, or a
    URL that is not an https repository raises :class:`ConfigError` naming the file (and line);
    nothing is skipped silently. A blank line is no row and lists nothing.
    """
    if not inputs.is_dir():
        raise ConfigError(f"reading input segments: {inputs} is not a directory")
    try:
        descriptor = load_descriptor(inputs)
    except InventoryDescriptorError as e:
        raise ConfigError(f"reading input segment descriptor: {e}") from e
    try:
        present = {
            path.name: path
            for path in inputs.iterdir()
            if path.is_dir() and not path.name.startswith(".")
        }
    except OSError as e:
        raise ConfigError(f"listing input segments in {inputs}: {e}") from e
    return InputSegmentInventory(
        segments=tuple(
            InputSegment(name=name, repository_urls=_segment_urls(present[name]))
            for name in descriptor.priority(set(present))
        )
    )


def _no_repository(header: Sequence[str], row: Sequence[str]) -> bool:
    """Whether a row declares it has no repository, as a catalog's base-image row does: its
    `GitHub Repository` cell reads `N/A (<base-image-path>)`."""
    if _NO_REPOSITORY_COLUMN not in header:
        return False
    i = header.index(_NO_REPOSITORY_COLUMN)
    return i < len(row) and row[i].strip().upper().startswith("N/A")


def _segment_urls(directory: Path) -> tuple[str, ...]:
    urls: set[str] = set()
    try:
        paths = sorted(directory.rglob("*-repos.csv"))
    except OSError as e:
        raise ConfigError(f"listing repository inventories in {directory}: {e}") from e
    for path in paths:
        if path.name.startswith("owners"):
            continue
        try:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = csv.reader(stream, strict=True)
                header = next((row for row in rows if row), ())
                if not header:
                    raise ConfigError(f"{path}: no header row; expected a GitHub URL or URL column")
                columns = [header.index(column) for column in _URL_COLUMNS if column in header]
                if not columns:
                    raise ConfigError(f"{path}: expected a GitHub URL or URL column")
                for row in rows:
                    if not row:
                        continue  # a blank line: no row, so no repository to drop
                    if len(row) > len(header):
                        raise ConfigError(f"{path}:{rows.line_num}: too many CSV fields")
                    raw = next(
                        (row[i].strip() for i in columns if i < len(row) and row[i].strip()), ""
                    )
                    if not raw and _no_repository(header, row):
                        continue  # a catalog's base image: `N/A (<image>)`, no repository
                    if not raw:
                        raise ConfigError(f"{path}:{rows.line_num}: empty or missing URL cell")
                    try:
                        urls.add(str(_REPO_URL.validate_python(raw)))
                    except PydanticValidationError as e:
                        raise ConfigError(
                            f"{path}:{rows.line_num}: invalid repository URL: {e}"
                        ) from e
        except (OSError, UnicodeError, csv.Error) as e:
            raise ConfigError(f"reading repository inventory {path}: {e}") from e
    return tuple(sorted(urls))
