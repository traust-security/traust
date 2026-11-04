"""Ledger bootstrap must not turn a broken installed signer into unsigned mode."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from tests.local_ops_support import LocalOpsRig


@pytest.fixture
def rig(tmp_path: Path) -> LocalOpsRig:
    return LocalOpsRig(tmp_path)


def config(rig: LocalOpsRig) -> dict:
    return yaml.safe_load((rig.config_home / "traust.yaml").read_text(encoding="utf-8"))


def save_config(rig: LocalOpsRig, value: dict) -> None:
    (rig.config_home / "traust.yaml").write_text(yaml.safe_dump(value), encoding="utf-8")


def faulting_cosign(
    rig: LocalOpsRig,
    *,
    status: int = 0,
    private: bytes | None = None,
    public: bytes | None = None,
) -> None:
    """Inject generation faults, never pretend these bytes are signing keys."""
    path = rig.bin_dir / "cosign"
    path.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "with Path(os.environ['LOCAL_OPS_EVENTS']).open('a') as stream:\n"
        "    stream.write('cosign\\n')\n"
        "assert os.environ['COSIGN_PASSWORD'] == ''\n"
        "assert sys.argv[1:3] == ['generate-key-pair', '--output-key-prefix']\n"
        "prefix = sys.argv[3]\n"
        f"private, public = {private!r}, {public!r}\n"
        "if private is not None:\n"
        "    Path(prefix + '.key').write_bytes(private)\n"
        "if public is not None:\n"
        "    Path(prefix + '.pub').write_bytes(public)\n"
        f"sys.exit({status})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def assert_no_continuation(rig: LocalOpsRig) -> None:
    events = rig.events.read_text(encoding="utf-8").splitlines()
    assert "database" not in events
    assert "auth" not in events
    assert not (rig.root / ".local-ops" / "env").exists()
    assert not (rig.root / ".local-ops" / "pack" / "assets.yaml").exists()


@pytest.mark.parametrize(
    ("private", "public"),
    [
        (None, None),
        (b"private left by failed generation", None),
        (b"private left by failed generation", b"public left by failed generation"),
    ],
)
def test_failed_cosign_aborts_even_if_it_leaves_files(
    rig: LocalOpsRig, private: bytes | None, public: bytes | None
) -> None:
    faulting_cosign(rig, status=23, private=private, public=public)

    result = rig.run("up")

    assert result.returncode != 0, result.stdout + result.stderr
    assert "cosign" in result.stderr
    assert "ledger" not in config(rig)
    assert rig.events.read_text(encoding="utf-8").splitlines().count("cosign") == 1
    assert_no_continuation(rig)
    if private is not None:
        assert (rig.root / ".local-ops/run/ledger/dev-key.key").read_bytes() == private


@pytest.mark.parametrize(
    ("private", "public"),
    [
        (None, None),
        (b"fault-injected private", None),
        (None, b"fault-injected public"),
        (b"fault-injected private", b""),
        (b"", b"fault-injected public"),
        (b"", b""),
    ],
)
def test_success_without_complete_nonempty_pair_aborts(
    rig: LocalOpsRig, private: bytes | None, public: bytes | None
) -> None:
    faulting_cosign(rig, private=private, public=public)

    result = rig.run("up")

    assert result.returncode != 0, result.stdout + result.stderr
    assert "cosign" in result.stderr
    assert "ledger" not in config(rig)
    assert_no_continuation(rig)


@pytest.mark.parametrize("cosign_present", [False, True])
@pytest.mark.parametrize("signed_config", [False, True])
def test_missing_public_on_subsequent_up_never_rotates_private_identity(
    rig: LocalOpsRig, cosign_present: bool, signed_config: bool
) -> None:
    first = rig.run("up")
    assert first.returncode == 0, first.stdout + first.stderr
    key = rig.root / ".local-ops/run/ledger/dev-key.key"
    key.parent.mkdir(parents=True)
    private = b"existing private identity must not be replaced"
    key.write_bytes(private)
    pub = key.with_suffix(".pub")
    if signed_config:
        cfg = config(rig)
        cfg["ledger"] = {"key_path": str(key), "public_key_path": str(pub)}
        save_config(rig, cfg)
    original = (rig.config_home / "traust.yaml").read_bytes()
    if cosign_present:
        faulting_cosign(rig, status=23)
    rig.events.write_text("", encoding="utf-8")

    result = rig.run("up")

    assert result.returncode != 0, result.stdout + result.stderr
    assert str(key) in result.stderr
    assert str(pub) in result.stderr
    assert "public-key" in result.stderr
    assert key.read_bytes() == private
    assert not pub.exists()
    assert (rig.config_home / "traust.yaml").read_bytes() == original
    assert "cosign" not in rig.events.read_text(encoding="utf-8").splitlines()
    assert not {"database", "auth"}.intersection(
        rig.events.read_text(encoding="utf-8").splitlines()
    )


@pytest.mark.parametrize("existing_half", ["public", "empty-private"])
def test_preexisting_incomplete_pair_is_not_regenerated(
    rig: LocalOpsRig, existing_half: str
) -> None:
    key = rig.root / ".local-ops/run/ledger/dev-key.key"
    key.parent.mkdir(parents=True)
    existing = key.with_suffix(".pub") if existing_half == "public" else key
    contents = b"orphan public identity" if existing_half == "public" else b""
    existing.write_bytes(contents)
    faulting_cosign(rig, status=23)

    result = rig.run("up")

    assert result.returncode != 0, result.stdout + result.stderr
    assert existing.read_bytes() == contents
    assert "cosign" not in rig.events.read_text(encoding="utf-8").splitlines()
    assert "ledger" not in config(rig)
    assert_no_continuation(rig)


def test_operator_ledger_and_keys_own_signing_even_with_broken_unused_rig_pair(
    rig: LocalOpsRig,
) -> None:
    first = rig.run("up")
    assert first.returncode == 0, first.stdout + first.stderr
    operator_dir = rig.root / "operator-ledger"
    operator_dir.mkdir()
    key = operator_dir / "operator.key"
    public = operator_dir / "operator.pub"
    previous = operator_dir / "previous.pub"
    keys = {key: b"operator private", public: b"operator public", previous: b"previous public"}
    for path, contents in keys.items():
        path.write_bytes(contents)
    ledger = {
        "key_path": str(key),
        "public_key_path": str(public),
        "previous_public_key_path": str(previous),
        "required": True,
    }
    cfg = config(rig)
    cfg["ledger"] = ledger
    cfg["process"]["allowed_binaries"].append("git")
    save_config(rig, cfg)
    unused = rig.root / ".local-ops/run/ledger/dev-key.key"
    unused.parent.mkdir(parents=True)
    unused.write_bytes(b"unused partial rig pair")
    faulting_cosign(rig, status=23)
    rig.events.write_text("", encoding="utf-8")

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert config(rig)["ledger"] == ledger
    assert "git" in config(rig)["process"]["allowed_binaries"]
    assert all(path.read_bytes() == contents for path, contents in keys.items())
    assert unused.read_bytes() == b"unused partial rig pair"
    assert not unused.with_suffix(".pub").exists()
    assert "cosign" not in rig.events.read_text(encoding="utf-8").splitlines()


def test_no_cosign_deliberately_configures_unsigned_and_continues(rig: LocalOpsRig) -> None:
    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert config(rig)["ledger"] == {}
    assert "cosign" in result.stdout + result.stderr
    assert "unsigned" in result.stdout + result.stderr
    assert not (rig.root / ".local-ops/run/ledger").exists()
    assert {"database", "auth"}.issubset(rig.events.read_text(encoding="utf-8").splitlines())


def test_failed_upgrade_keeps_existing_unsigned_placeholder(rig: LocalOpsRig) -> None:
    first = rig.run("up")
    assert first.returncode == 0, first.stdout + first.stderr
    original = (rig.config_home / "traust.yaml").read_bytes()
    faulting_cosign(rig, status=23)
    rig.events.write_text("", encoding="utf-8")

    result = rig.run("up")

    assert result.returncode != 0, result.stdout + result.stderr
    assert (rig.config_home / "traust.yaml").read_bytes() == original
    assert not {"database", "auth"}.intersection(
        rig.events.read_text(encoding="utf-8").splitlines()
    )
