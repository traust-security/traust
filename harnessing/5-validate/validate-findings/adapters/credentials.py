"""Credential policy for validation artifacts and observed transcripts.

Core's public ``RedactionPolicy.redact(bytes)`` keeps a five-character secret
prefix and uses publication markers. Validation evidence instead retains only
length/digest markers and must scrub arbitrary Kubernetes Secret-map keys.
Keep that stricter, skill-local policy here, separate from adapter execution
and artifact storage; no adapter owns its own pattern table.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right

_PATTERNS = (
    # PEM private-key blocks (RSA/EC/OPENSSH/PKCS8).
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "pem-privkey",
    ),
    # kubeconfig / service-account JSON embedded keys.
    (
        re.compile(
            r'(client-key-data|private_key)"?\s*[:=]\s*"?'
            r"([A-Za-z0-9+/\\n=_-]{40,})",
            re.I,
        ),
        "key-data",
    ),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "aws-akid"),
    (
        re.compile(
            r'(aws_secret_access_key|secretAccessKey)"?\s*[:=]\s*"?'
            r"([A-Za-z0-9+/=]{30,})",
            re.I,
        ),
        "aws-secret",
    ),
    (
        re.compile(
            r"(client[_-]?secret|clientSecret|client_secret_data)"
            r'"?\s*[:=]\s*"?([A-Za-z0-9~._+/=-]{20,})',
            re.I,
        ),
        "cloud-client-secret",
    ),
    (re.compile(r"\b(sha256~[A-Za-z0-9_-]{20,})\b"), "oc-token"),
    (re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{20,})", re.I), "bearer"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "jwt",
    ),
    (re.compile(r'("auth"\s*:\s*")([A-Za-z0-9+/=]{40,})'), "registry-auth"),
    # Base64-encoded PEM and dockerconfig material outside JSON Secret maps.
    (re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{40,}"), "b64-pem"),
    (re.compile(r"\beyJhdXRo[A-Za-z0-9+/=]{20,}"), "b64-dockerconfig"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "github-token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github-pat"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"), "gitlab-pat"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
    (
        re.compile(
            r'(aws_session_token)"?\s*[:=]\s*"?([A-Za-z0-9+/=]{40,})',
            re.I,
        ),
        "aws-session",
    ),
    # DSN/URL passwords are not necessarily under a credential-shaped key.
    (
        re.compile(r"(://[A-Za-z0-9._%+-]+:)([^@/\s'\"]{6,})@"),
        "url-credentials",
    ),
    # Include the entire key prefix: a word-boundary anchor missed
    # bind_password / MY_PASSWORD / admin_token (assessment 2026-07-31 F3).
    (
        re.compile(
            r"([A-Za-z0-9_.\-]*(?:password|passwd|token|api[_-]?key|secret))"
            r'"?\s*[:=]\s*"?([^\s\"\',;]{12,})',
            re.I,
        ),
        "generic-secret",
    ),
)
_SECRET_MAP_KEYS = ("data", "stringData")
_REDACTED = re.compile(r"\[REDACTED:[^\]\r\n]+\]")


def redact_credentials(text: str) -> str:
    """Remove credentials without exposing a secret prefix in evidence.

    Structured Secret maps are scrubbed before text patterns. Returned markers
    survive repeated passes, including a Secret key named ``token`` or
    ``password``; their original evidence lengths/digests must not be rewritten.
    """
    if not text:
        return text
    out = _redact_secret_maps(text)
    for pattern, tag in _PATTERNS:
        markers = list(_REDACTED.finditer(out))
        marker_starts = [marker.start() for marker in markers]

        def replace(
            match: re.Match[str],
            tag: str = tag,
            markers: list[re.Match[str]] = markers,
            marker_starts: list[int] = marker_starts,
        ) -> str:
            # Two captures mean a key/prefix and its secret value. Single
            # captures (e.g. the AWS key prefix) still redact the whole match.
            grouped = match.lastindex is not None and match.lastindex >= 2
            value = match.group(match.lastindex) if grouped else match.group(0)
            start, end = match.span(match.lastindex) if grouped else match.span()
            # Tags such as "github-token" resemble assignments. Ignore only
            # matches contained inside an existing marker, not a real secret
            # (e.g. a PEM block) that happens to contain a marker as well.
            index = bisect_right(marker_starts, start) - 1
            if index >= 0 and end <= markers[index].end():
                return match.group(0)
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            marker = f"[REDACTED:{tag}:{len(value)}b:sha256:{digest}]"
            if grouped:
                start, end = match.span(match.lastindex)
                start -= match.start()
                end -= match.start()
                return match.group(0)[:start] + marker + match.group(0)[end:]
            return marker

        out = pattern.sub(replace, out)
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
