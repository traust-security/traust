"""Strict validation-evidence rendering over Core-owned secret detectors."""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right

from traust_core.v1.models.redaction import SecretDetector

_SECRET_MAP_KEYS = ("data", "stringData")
# Only canonical emitted markers are opaque; a target-controlled prefix is not.
_REDACTED = re.compile(
    r"\[REDACTED:(?:(?:"
    + "|".join(re.escape(tag) for tag in SecretDetector.evidence_tags())
    + r"):[1-9][0-9]*b:sha256:[0-9a-f]{12}|secret-data:(?:0|[1-9][0-9]*)b)\]"
)


def redact_credentials(text: str) -> str:
    """Remove credentials without exposing a secret prefix in evidence.

    Structured Secret maps are scrubbed before text patterns. Returned markers
    survive repeated passes, including a Secret key named ``token`` or
    ``password``; their original evidence lengths/digests must not be rewritten.
    """
    if not text:
        return text
    out = _redact_secret_maps(text)
    for rule in SecretDetector.evidence_rules():
        markers = list(_REDACTED.finditer(out))
        marker_starts = [marker.start() for marker in markers]

        for match in reversed(tuple(rule.spans(out))):
            start, end = match.start, match.end
            index = bisect_right(marker_starts, start) - 1
            if index >= 0 and end <= markers[index].end():
                continue
            value = out[start:end]
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            marker = f"[REDACTED:{match.tag}:{len(value)}b:sha256:{digest}]"
            out = out[:start] + marker + out[end:]
    return out


def _redact_secret_maps(text: str) -> str:
    """Scrub every value of JSON Secret data/stringData, including custom keys.

    Preserve the existing conservative treatment of untyped objects with a
    data map, and traverse nested wrappers and SecretList items recursively.
    """
    if '"data"' not in text and '"stringData"' not in text:
        return text
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text

    def scrub(node):
        if isinstance(node, dict):
            is_secretish = (
                str(node.get("kind", "")).lower() in ("secret", "secretlist") or "data" in node
            )
            for key, value in list(node.items()):
                if key in _SECRET_MAP_KEYS and isinstance(value, dict) and is_secretish:
                    node[key] = {
                        data_key: (
                            data_value
                            if isinstance(data_value, str) and _REDACTED.fullmatch(data_value)
                            else f"[REDACTED:secret-data:{len(str(data_value))}b]"
                        )
                        for data_key, data_value in value.items()
                    }
                else:
                    scrub(value)
        elif isinstance(node, list):
            for item in node:
                scrub(item)

    scrub(doc)
    return json.dumps(doc, indent=1)
