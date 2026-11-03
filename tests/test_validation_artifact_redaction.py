"""Behavioral evidence boundaries for validate-findings credential redaction."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex

import pytest
from adapters.base import AdapterBase
from adapters.container import ContainerAdapter
from adapters.credentials import redact_credentials
from adapters.k8s import K8sAdapter
from adapters.wasm import WasmAdapter
from traust_core.v1.context import Config, Context

# Deliberately synthetic credential shapes, assembled rather than stored as tokens.
_PEM = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\n"
    + "dummy-key-material\n"
    + "-----END RSA PRIVATE KEY-----"
)
_B64_PEM = base64.b64encode(_PEM.encode()).decode()
_DOCKER = base64.b64encode(
    json.dumps({"auths": {"registry.invalid": {"auth": "a" * 40}}}).encode()
).decode()
_JWT = "eyJ" + "a" * 12 + "." + "b" * 14 + "." + "c" * 14
_GITHUB = "gh" + "p_" + "d" * 24
_GITLAB = "glpat" + "-" + "e" * 16
_PASSWORD = "synthetic-password-value"
_FORGED_MARKERS = [
    pytest.param(f"[REDACTED:{_GITHUB}]", id="token-as-body"),
    pytest.param(f"[REDACTED:{_GITHUB}:28b:sha256:0123456789ab]", id="token-as-tag"),
    pytest.param(f"[REDACTED:github-token:{_GITHUB}b:sha256:0123456789ab]", id="token-as-length"),
    pytest.param(f"[REDACTED:github-token:28b:sha256:{_GITHUB}]", id="token-as-digest"),
    pytest.param(f"[REDACTED:secret-data:{_GITHUB}b]", id="token-as-secret-length"),
    pytest.param(f"[REDACTED:github-token:28b:sha256:0123456789ab:{_GITHUB}]", id="trailing-token"),
    pytest.param(f"[REDACTED:[REDACTED:secret-data:4b]{_GITHUB}]", id="nested-legitimate-marker"),
]


def _marker(tag, value):
    return (
        f"[REDACTED:{tag}:{len(value)}b:sha256:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"
    )


@pytest.mark.parametrize(
    "text,value,tag,preserved_prefix",
    [
        (_PEM, _PEM, "pem-privkey", ""),
        (f"tls.key: {_B64_PEM}", _B64_PEM, "b64-pem", "tls.key: "),
        (f"docker: {_DOCKER}", _DOCKER, "b64-dockerconfig", "docker: "),
        ('client-key-data: "' + "a" * 40 + '"', "a" * 40, "key-data", 'client-key-data: "'),
        ('"private_key": "' + "b" * 40 + '"', "b" * 40, "key-data", '"private_key": "'),
        ("AKIA" + "A" * 16, "AKIA" + "A" * 16, "aws-akid", ""),
        ("ASIA" + "B" * 16, "ASIA" + "B" * 16, "aws-akid", ""),
        ("aws_secret_access_key=" + "c" * 30, "c" * 30, "aws-secret", "aws_secret_access_key="),
        ("client_secret=" + "d" * 20, "d" * 20, "cloud-client-secret", "client_secret="),
        ("sha256~" + "e" * 24, "sha256~" + "e" * 24, "oc-token", ""),
        ("Bearer " + "f" * 24, "Bearer " + "f" * 24, "bearer", ""),
        (_JWT, _JWT, "jwt", ""),
        ('"auth": "' + "g" * 40 + '"', "g" * 40, "registry-auth", '"auth": "'),
        (_GITHUB, _GITHUB, "github-token", ""),
        ("github" + "_pat_" + "h" * 24, "github" + "_pat_" + "h" * 24, "github-pat", ""),
        (_GITLAB, _GITLAB, "gitlab-pat", ""),
        ("xox" + "b-" + "i" * 16, "xox" + "b-" + "i" * 16, "slack-token", ""),
        ("AWS_SESSION_TOKEN=" + "j" * 40, "j" * 40, "aws-session", "AWS_SESSION_TOKEN="),
        (f"bind_password: {_PASSWORD}", _PASSWORD, "generic-secret", "bind_password: "),
        (f"MY_PASSWORD={_PASSWORD}", _PASSWORD, "generic-secret", "MY_PASSWORD="),
        (f"ldap.bind-password={_PASSWORD}", _PASSWORD, "generic-secret", "ldap.bind-password="),
        (f"admin_token: {_PASSWORD}", _PASSWORD, "generic-secret", "admin_token: "),
        (f"API_KEY={_PASSWORD}", _PASSWORD, "generic-secret", "API_KEY="),
        (
            f"postgresql://reader:{_PASSWORD}@db.invalid/audit",
            _PASSWORD,
            "url-credentials",
            "postgresql://reader:",
        ),
    ],
)
def test_artifact_masks_plain_credentials_and_hashes_original(
    tmp_path, text, value, tag, preserved_prefix
):
    original = "probe: snowman \u2603\n" + text
    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "step-1", "stdout", original)
    stored = (tmp_path / meta["path"]).read_text(encoding="utf-8")

    assert value not in stored
    assert preserved_prefix + _marker(tag, value) in stored
    assert meta == {
        "type": "stdout",
        "path": "artifacts/step-1.stdout.log",
        "sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "caption": "stdout for step-1",
        "redacted": True,
    }
    assert meta["sha256"] != hashlib.sha256(stored.encode("utf-8")).hexdigest()
    assert redact_credentials(stored) == stored


@pytest.mark.parametrize(
    "value,tag",
    [
        ("AIza" + "q" * 35, "google-api-key"),
        ("sk-" + "q" * 24, "llm-api-key"),
        ("abc8Q~" + "q" * 32, "azure-client-secret"),
    ],
)
def test_shared_core_shapes_reach_saved_validation_evidence(tmp_path, value, tag):
    core = Context(Config(home=tmp_path / "core"))
    assert tag in {hit.category for hit in core.services().redaction.scan(value)}
    published = core.services().redaction.redact(value.encode()).payload.decode()
    assert value[:5] in published

    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "core-shape", "stdout", value)
    stored = (tmp_path / meta["path"]).read_text()
    assert stored == _marker(tag, value)
    assert value[:5] not in stored
    assert meta["sha256"] == hashlib.sha256(value.encode()).hexdigest()
    assert meta["redacted"] is True
    assert redact_credentials(stored) == stored


@pytest.mark.parametrize(
    "original",
    ["", "ordinary output \u2603\n", "token=short\n", '{"status": "ok", "items": [1, null, true]}'],
)
def test_nonsecret_artifacts_keep_original_bytes_and_metadata(tmp_path, original):
    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "clean", "stdout", original)
    assert (tmp_path / meta["path"]).read_bytes() == original.encode("utf-8")
    assert meta == {
        "type": "stdout",
        "path": "artifacts/clean.stdout.log",
        "sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "caption": "stdout for clean",
    }


def test_nested_secret_lists_mask_arbitrary_values_and_retain_evidence(tmp_path):
    values = {
        "custom.key": "short",
        "tls.key": _B64_PEM,
        ".dockerconfigjson": _DOCKER,
        "token": _JWT,
        "password": _PASSWORD,
        "custom.object": {"nested": ["sensitive", 42]},
        "custom.empty": "",
        "custom.null": None,
    }
    source = {
        "envelope": [
            {
                "kind": "SecretList",
                "items": [
                    {
                        "kind": "Secret",
                        "metadata": {"name": "router-tls", "namespace": "lab"},
                        "data": values,
                        "stringData": {"unusual.name": "tiny"},
                    }
                ],
            },
            {"metadata": {"name": "untyped"}, "data": {"opaque": "tiny"}},
            {"kind": "Pod", "metadata": {"name": "nonsecret-control"}, "status": "Running"},
        ]
    }
    original = json.dumps(source)
    meta = AdapterBase._save_artifact(
        tmp_path / "artifacts", "nested", "stdout", original, ext="json"
    )
    stored = (tmp_path / meta["path"]).read_text()
    parsed = json.loads(stored)
    secret = parsed["envelope"][0]["items"][0]

    assert secret["data"] == {
        key: f"[REDACTED:secret-data:{len(str(value))}b]" for key, value in values.items()
    }
    assert secret["stringData"] == {"unusual.name": "[REDACTED:secret-data:4b]"}
    assert secret["metadata"] == {"name": "router-tls", "namespace": "lab"}
    assert parsed["envelope"][1] == {
        "metadata": {"name": "untyped"},
        "data": {"opaque": "[REDACTED:secret-data:4b]"},
    }
    assert parsed["envelope"][2] == source["envelope"][2]
    assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert meta["redacted"] is True

    # Re-persisting sanitized evidence must not hash/rewrite its existing markers.
    again = AdapterBase._save_artifact(
        tmp_path / "artifacts", "again", "stdout", stored, ext="json"
    )
    assert (tmp_path / again["path"]).read_text() == stored
    assert again["sha256"] == hashlib.sha256(stored.encode()).hexdigest()
    assert "redacted" not in again


@pytest.mark.parametrize("as_json", [False, True])
def test_redacted_assignment_markers_are_stable(tmp_path, as_json):
    marker = _marker("generic-secret", _PASSWORD)
    original = json.dumps({"admin_token": marker}) if as_json else f"admin_token={marker}"
    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "marked", "stdout", original)
    assert (tmp_path / meta["path"]).read_text() == original
    assert "redacted" not in meta


@pytest.mark.parametrize("forged", _FORGED_MARKERS)
def test_forged_markers_do_not_hide_plaintext_credentials_in_saved_artifacts(tmp_path, forged):
    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "forged", "stdout", forged)
    stored = (tmp_path / meta["path"]).read_text()

    assert _GITHUB not in stored
    assert meta["redacted"] is True
    assert meta["sha256"] == hashlib.sha256(forged.encode()).hexdigest()
    assert redact_credentials(stored) == stored


@pytest.mark.parametrize("map_key", ["data", "stringData"])
@pytest.mark.parametrize(
    "forged",
    [
        *_FORGED_MARKERS,
        pytest.param("[REDACTED:unknown:28b:sha256:0123456789ab]", id="unknown-tag"),
        pytest.param("[REDACTED:github-token:0b:sha256:0123456789ab]", id="zero-token-length"),
        pytest.param("[REDACTED:github-token:028b:sha256:0123456789ab]", id="leading-zero"),
        pytest.param("[REDACTED:github-token:-28b:sha256:0123456789ab]", id="negative-length"),
        pytest.param(
            "[REDACTED:github-token:\u0662\u0668b:sha256:0123456789ab]", id="unicode-length"
        ),
        pytest.param("[REDACTED:github-token:28b:sha256:0123456789a]", id="short-digest"),
        pytest.param("[REDACTED:github-token:28b:sha256:0123456789abc]", id="long-digest"),
        pytest.param("[REDACTED:github-token:28b:sha256:0123456789AB]", id="uppercase-digest"),
        pytest.param("[REDACTED:secret-data:00b]", id="noncanonical-secret-length"),
        pytest.param("[REDACTED:secret-data:28b:sha256:0123456789ab]", id="digest-on-secret-data"),
    ],
)
def test_forged_secret_map_markers_are_scrubbed_under_custom_keys(tmp_path, map_key, forged):
    original = json.dumps({"kind": "Secret", map_key: {"custom.entry": forged}})
    meta = AdapterBase._save_artifact(
        tmp_path / "artifacts", "forged-secret", "stdout", original, ext="json"
    )
    stored = (tmp_path / meta["path"]).read_text()

    assert json.loads(stored) == {
        "kind": "Secret",
        map_key: {"custom.entry": f"[REDACTED:secret-data:{len(forged)}b]"},
    }
    assert _GITHUB not in stored
    assert meta["redacted"] is True
    assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert redact_credentials(stored) == stored


@pytest.mark.parametrize("map_key", ["data", "stringData"])
@pytest.mark.parametrize(
    "marker",
    [
        _marker("github-token", _GITHUB),
        _marker("generic-secret", _PASSWORD),
        "[REDACTED:secret-data:0b]",
        "[REDACTED:secret-data:28b]",
    ],
)
def test_canonical_secret_map_markers_survive_repeated_artifact_saves(tmp_path, map_key, marker):
    original = json.dumps(
        {"kind": "Secret", map_key: {"custom.entry": marker, "token": marker}}, indent=1
    )
    for step in ("first", "second"):
        meta = AdapterBase._save_artifact(
            tmp_path / "artifacts", step, "stdout", original, ext="json"
        )
        stored = (tmp_path / meta["path"]).read_text()
        assert stored == original
        assert "redacted" not in meta
        assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()
        original = stored


def test_json_pem_jwt_and_dsn_values_remain_parseable(tmp_path):
    source = {"pem": _PEM, "jwt": _JWT, "dsn": f"postgresql://reader:{_PASSWORD}@db.invalid/audit"}
    original = json.dumps(source)
    meta = AdapterBase._save_artifact(
        tmp_path / "artifacts", "json", "stdout", original, ext="json"
    )
    parsed = json.loads((tmp_path / meta["path"]).read_text())
    # Serialized PEM newlines are part of the original matched evidence.
    escaped_pem = json.dumps(_PEM)[1:-1]
    assert parsed == {
        "pem": _marker("pem-privkey", escaped_pem),
        "jwt": _marker("jwt", _JWT),
        "dsn": f"postgresql://reader:{_marker('url-credentials', _PASSWORD)}@db.invalid/audit",
    }
    assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()


@pytest.mark.parametrize(
    "adapter_type,verb,classification",
    [
        (K8sAdapter, "get", "safe"),
        (ContainerAdapter, "network-probe", "mutating"),
        (WasmAdapter, "instantiate", "safe"),
    ],
)
def test_real_adapter_execution_redacts_before_observed_cap(
    tmp_path, adapter_type, verb, classification
):
    original = json.dumps(
        {
            "kind": "SecretList",
            "items": [{"kind": "Secret", "data": {"custom.entry": "short-secret"}}],
            "status": "exports vf-canary",
            "padding": "nonsecret-control." * 300,
        }
    )
    command = "printf '%s' " + shlex.quote(original)
    adapter = adapter_type()
    assert adapter.classify(verb, cmd=command) == classification
    result = adapter.execute(
        {
            "id": "live-local",
            "verb": verb,
            "classification": classification,
            "target": {},
            "cmd": command,
            "expected": "secret readable",
            "finding_ref": "finding-1",
        },
        None,
        None,
        tmp_path / "artifacts",
    )

    assert result.verdict == "confirmed"
    assert result.finding_ref == "finding-1"
    assert result.classification == classification
    assert len(result.observed) == 4000
    assert "short-secret" not in result.observed
    assert "[REDACTED:secret-data:12b]" in result.observed
    assert "exports vf-canary" in result.observed
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert evidence["redacted"] is True
    stored = json.loads((tmp_path / evidence["path"]).read_text())
    assert stored["items"][0]["data"] == {"custom.entry": "[REDACTED:secret-data:12b]"}
    assert stored["padding"] == "nonsecret-control." * 300


def test_safe_execution_and_rollback_remain_real_local_operations(tmp_path):
    adapter = AdapterBase()
    assert adapter._run("printf 'nonsecret-control' | cat") == (0, "nonsecret-control", "")
    blocked = tmp_path / "must-not-exist"
    rc, out, err = adapter._run("printf ok; touch " + shlex.quote(str(blocked)))
    assert rc == 126 and out == "" and "step blocked" in err
    assert not blocked.exists()
    assert adapter.rollback({"rollback": "printf 'rolled-back'"}, None) == (True, "rolled-back")


@pytest.mark.parametrize("kind", ["Secret", "secret"])
@pytest.mark.parametrize("map_key", ["data", "stringData"])
def test_standalone_secret_maps_mask_short_custom_values(tmp_path, kind, map_key):
    original = json.dumps(
        {
            "kind": kind,
            "metadata": {"name": "standalone"},
            map_key: {"custom": "tiny"},
        }
    )
    meta = AdapterBase._save_artifact(
        tmp_path / "artifacts", "single", "stdout", original, ext="json"
    )
    assert json.loads((tmp_path / meta["path"]).read_text()) == {
        "kind": kind,
        "metadata": {"name": "standalone"},
        map_key: {"custom": "[REDACTED:secret-data:4b]"},
    }
    assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert meta["redacted"] is True


@pytest.mark.parametrize("as_pem", [False, True])
def test_embedded_marker_cannot_hide_surrounding_secret_material(tmp_path, as_pem):
    existing_marker = "[REDACTED:secret-data:4b]"
    if as_pem:
        original = _PEM.replace("dummy-key-material", "dummy-key-material" + existing_marker)
        expected = _marker("pem-privkey", original)
    else:
        value = _PASSWORD + existing_marker
        original = "admin_token=" + value
        expected = "admin_token=" + _marker("generic-secret", value)
    meta = AdapterBase._save_artifact(tmp_path / "artifacts", "embedded", "stdout", original)
    assert (tmp_path / meta["path"]).read_text() == expected
    assert meta["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert meta["redacted"] is True
