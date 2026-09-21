"""`/drift-watch` must check signature *validity*, not just presence.

`check_signature_coverage` counted layers carrying a `merkle_root_signature` and
called that coverage. A signature that no longer matches its payload passed — and
that is the one failure mode nothing else detects.

It is reachable without touching a single event: `artifact_digests` lives in metadata,
so populating it changes the **format-4 signed payload** without moving the Merkle
root. Nothing drops the old signature, `sign()` leaves it in place, and the layer ends
up present-but-invalid — which D8 calls indistinguishable from tampering, and which is
strictly worse than being unsigned.

Cost, measured 2026-09-02: ~31ms/layer, so a few minutes for a full-corpus pass,
which reported every layer's signature verified with zero stale.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from traust.cli.check_drift import check_signature_coverage

REPO = Path(__file__).resolve().parent.parent
from traust.paths import optional_config_path

PUBKEY = optional_config_path("ledger-signing-key.pub")  # deployment key, skip-if-absent
SAMPLE = (
    REPO.parent
    / "analysis-results/findings/openshift-5.0-payload/api__release-5.0"
    / "api__release-5.0-findings-layer.json"
)


def _real_signing_key(p) -> bool:
    """True only for a genuine PEM public key. The config home always carries a
    ledger-signing-key.pub (load_context requires it), but tests/CI seed a
    placeholder; these signature-verification tests need the real deployment key
    that signed the corpus SAMPLE, so skip on anything that will not load."""
    if p is None or not p.is_file():
        return False
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        load_pem_public_key(p.read_bytes())
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not (_real_signing_key(PUBKEY) and SAMPLE.is_file()),
    reason="needs a real deployment signing key and a signed corpus layer",
)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    if not PUBKEY.is_file():
        pytest.skip("no deployment ledger-signing-key.pub in this checkout")
    """A miniature workspace: one genuinely signed layer plus the public key."""
    findings = tmp_path / "analysis-results" / "findings" / "probe"
    findings.mkdir(parents=True)
    deploy = tmp_path / "deploy" / "config"  # this test's TRAUST_CONFIG_HOME
    deploy.mkdir(parents=True)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(deploy))
    shutil.copy(PUBKEY, deploy / PUBKEY.name)
    layer = findings / SAMPLE.name
    shutil.copy(SAMPLE, layer)
    return tmp_path, layer


def _status(ws: Path) -> tuple[str, str]:
    rows = check_signature_coverage(ws)
    assert len(rows) == 1
    return rows[0]["status"], str(rows[0]["detail"])


def test_a_genuinely_signed_layer_is_fresh(workspace):
    ws, _ = workspace
    status, detail = _status(ws)
    assert status == "fresh"
    assert "signatures and Merkle roots verified" in detail, (
        "must name both checks — a signature alone does not detect an edited event"
    )


def test_a_stale_signature_is_drift(workspace):
    """The regression: populate artifact_digests, leave the signature alone.

    No event changes, so the Merkle root does not move and the signature survives —
    but the format-4 payload it covers has changed, so it no longer verifies.
    """
    ws, layer = workspace
    d = json.loads(layer.read_text())
    before = d["metadata"]["merkle_root_signature"]
    d["metadata"]["artifact_digests"] = {"x-triage.json": "c" * 64}
    layer.write_text(json.dumps(d, indent=2), encoding="utf-8")
    assert json.loads(layer.read_text())["metadata"]["merkle_root_signature"] == before

    status, detail = _status(ws)
    assert status == "drift"
    assert "DOES NOT VERIFY" in detail
    assert "stale, not absent" in detail


def test_an_unsigned_layer_is_still_reported(workspace):
    """The pre-existing check must not regress while validity is added."""
    ws, layer = workspace
    d = json.loads(layer.read_text())
    d["metadata"].pop("merkle_root_signature")
    layer.write_text(json.dumps(d, indent=2), encoding="utf-8")
    status, detail = _status(ws)
    assert status == "drift"
    assert "UNSIGNED" in detail


def test_without_a_public_key_it_says_so_rather_than_implying_validity(workspace):
    """Silence about an unchecked property is how this went unnoticed for a pass."""
    ws, _ = workspace
    (ws / "deploy" / "config" / PUBKEY.name).unlink()
    status, detail = _status(ws)
    assert status == "fresh"
    assert "validity NOT checked" in detail


def test_edited_event_content_is_caught_even_though_the_signature_still_verifies(
    workspace,
):
    """Signature and integrity catch different tampering; one alone is not enough.

    The signature binds the *declared* Merkle root. Editing an event leaves that
    declaration untouched, so the signature keeps verifying while the recomputed
    root no longer matches. Verified against a live round trip 2026-09-02: an
    edited `rationale` produced "metadata.merkle_root mismatch" from integrity and
    nothing at all from the signature check.
    """
    from traust_ledger.api.integrity import verify_merkle_signature

    ws, layer = workspace
    d = json.loads(layer.read_text())
    assert d.get("events"), "fixture must carry at least one event"
    d["events"][0]["rationale"] = "TAMPERED"
    layer.write_text(json.dumps(d, indent=2), encoding="utf-8")

    pub = ws / "deploy" / "config" / PUBKEY.name
    assert not [
        f
        for f in verify_merkle_signature(json.loads(layer.read_text()), str(pub))
        if f.severity.name == "ERROR"
    ], "precondition: the signature alone still verifies after the edit"

    status, detail = _status(ws)
    assert status == "drift"
    assert "MERKLE ROOT does not recompute" in detail
