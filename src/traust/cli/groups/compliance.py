"""``traust compliance …`` — compliance-check's doors on traust-core.

Posture is traust-core's compliance view: ``traust dashboard view compliance``."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

DECLARE = passthrough_op("compliance", "Record one compliance boundary declaration.", "declare")
SCOPES = passthrough_op("compliance", "The current declaration of each boundary.", "scopes")
RESOLVE = passthrough_op("compliance", "A boundary's repositories now.", "resolve")
POLICY = passthrough_op("compliance", "Record the control mapping or ADR registers.", "policy")
EVALUATE = passthrough_op("compliance", "The deterministic runner over a boundary.", "evaluate")
EVIDENCE = passthrough_op("compliance", "Hash a judged artifact into the bundle.", "evidence")
CHECK = passthrough_op("compliance", "The citation gate over an assessment.", "check")
RECORD = passthrough_op("compliance", "Record a gated assessment.", "record")
LATEST = passthrough_op("compliance", "A boundary's newest recorded assessment.", "latest")
ADRS = passthrough_op("compliance", "The decisions governing a product.", "adrs")
DOCS = passthrough_op("compliance", "Fetch official guides for a registered product.", "docs")
CALIBRATE = passthrough_op("compliance", "Evaluate twice; score on an answer key.", "calibrate")
