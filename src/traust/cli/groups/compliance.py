"""``traust compliance …`` — boundary doors on traust-core.

Posture is traust-core's compliance view: ``traust dashboard view compliance``."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

DECLARE = passthrough_op("compliance", "Record one compliance boundary declaration.", "declare")
SCOPES = passthrough_op("compliance", "The current declaration of each boundary.", "scopes")
RESOLVE = passthrough_op("compliance", "A boundary's repositories now.", "resolve")
