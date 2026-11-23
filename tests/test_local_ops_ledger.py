"""Ledger bootstrap must not turn a broken installed signer into unsigned mode."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from traust_core.v1.providers.identity import LOCAL_TOKEN_LIFETIME, LocalIssuer

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


def test_existing_rig_pair_becomes_required_without_rotation(rig: LocalOpsRig) -> None:
    faulting_cosign(rig, private=b"original-private", public=b"original-public")
    setup = rig.run("up")
    assert setup.returncode == 0, setup.stderr
    old = config(rig)
    key, pub = (Path(old["ledger"][name]) for name in ("key_path", "public_key_path"))
    del old["ledger"]["required"]
    del old["recording"]
    save_config(rig, old)
    login = rig.root / ".local-ops/run/home/credentials.json"
    human = login.read_bytes()
    faulting_cosign(rig, status=23)

    upgraded = rig.run("up")
    assert upgraded.returncode == 0, upgraded.stderr
    assert config(rig)["ledger"] == {**old["ledger"], "required": True}
    assert config(rig)["recording"]["triage"] == ["sci_triage"]
    assert (key.read_bytes(), pub.read_bytes()) == (b"original-private", b"original-public")
    assert login.read_bytes() == human


@pytest.mark.parametrize("kind", ["local", "external", "unreadable"])
def test_up_preserves_existing_login_and_explains_expiry_recovery(
    rig: LocalOpsRig, kind: str
) -> None:
    setup = rig.run("up")
    assert setup.returncode == 0, setup.stderr
    login_path = rig.root / ".local-ops/run/home/credentials.json"
    if kind == "unreadable":
        login_path.write_bytes(b"operator-owned unreadable credentials")
    else:
        login = json.loads(login_path.read_text())
        issued = datetime.now(UTC) - 2 * LOCAL_TOKEN_LIFETIME
        if kind == "local":
            issuer = LocalIssuer(login_path.parent, SimpleNamespace(now=lambda: issued))
            login["grant"]["access_token"] = issuer.mint(
                login["client_id"]
            ).token.get_secret_value()
        else:
            login["issuer"] = "https://operator.example/issuer"
            login["client_id"] = "operator-chosen"
            login["grant"]["access_token"] = "operator-owned-token"
        login["grant"]["expires_at"] = (issued + LOCAL_TOKEN_LIFETIME).isoformat()
        login_path.write_text(json.dumps(login))
    original = login_path.read_bytes()
    rig.events.write_text("")

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert login_path.read_bytes() == original
    assert "auth" not in rig.events.read_text().splitlines()
    assert "human login preserved" in result.stdout
    assert "traust auth status" in result.stdout
    assert "traust auth local --identity" in result.stdout
    assert "external login" in result.stdout


@pytest.mark.parametrize("entry", ["missing", "existing", "dangling-symlink"])
def test_up_refuses_an_operator_home_without_changing_its_login(
    rig: LocalOpsRig, entry: str
) -> None:
    setup = rig.run("up")
    assert setup.returncode == 0, setup.stderr
    operator_home = rig.root / "operator-home"
    operator_home.mkdir()
    login_path = operator_home / "credentials.json"
    if entry == "existing":
        login_path.write_bytes(b"operator-owned credentials")
    elif entry == "dangling-symlink":
        login_path.symlink_to(operator_home / "not-present")
    cfg = config(rig)
    cfg["home"] = str(operator_home)
    save_config(rig, cfg)
    # A rig may not use a different credential home.
    (rig.root / ".local-ops/run/home/credentials.json").unlink()
    rig.events.write_text("")

    result = rig.run("up")

    assert result.returncode != 0
    assert "local rig bootstrap requires its own home and trusted local issuer" in result.stderr
    assert "auth" not in rig.events.read_text().splitlines()
    if entry == "existing":
        assert login_path.read_bytes() == b"operator-owned credentials"
    elif entry == "dangling-symlink":
        assert login_path.is_symlink() and not login_path.exists()
    else:
        assert not login_path.exists()


@pytest.mark.parametrize(
    "component",
    [
        ".local-ops",
        ".local-ops/run",
        ".local-ops/run/home",
        ".local-ops/run/home/local-key.pem",
        ".local-ops/run/home/local-jwks.json",
    ],
)
def test_up_refuses_symlinked_rig_paths_before_bootstrapping(
    rig: LocalOpsRig, tmp_path: Path, component: str
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"operator-owned")
    link = rig.root / component
    link.parent.mkdir(parents=True, exist_ok=True)
    target = outside / "issuer" if component.endswith((".pem", ".json")) else outside
    if target != outside:
        target.write_bytes(b"operator-owned issuer")
    link.symlink_to(target)

    result = rig.run("up")

    assert result.returncode != 0
    assert "local rig" in result.stderr and "symlink" in result.stderr
    assert sentinel.read_bytes() == b"operator-owned"
    if target != outside:
        assert target.read_bytes() == b"operator-owned issuer"
    assert sorted(path.name for path in outside.iterdir()) == (
        ["issuer", "sentinel"] if target != outside else ["sentinel"]
    )
    assert rig.events.read_text() == ""


def test_up_preserves_dangling_credential_symlink_in_rig_home(rig: LocalOpsRig) -> None:
    setup = rig.run("up")
    assert setup.returncode == 0, setup.stderr
    login_path = rig.root / ".local-ops/run/home/credentials.json"
    login_path.unlink()
    login_path.symlink_to(login_path.parent / "missing-operator-login")
    rig.events.write_text("")

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert login_path.is_symlink() and not login_path.exists()
    assert "auth" not in rig.events.read_text().splitlines()
    assert "human login preserved" in result.stdout


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


def test_tick_loop_can_resolve_the_persisted_review_salt(rig: LocalOpsRig) -> None:
    rig.env.pop("TRAUST_OPS_VALVE_SALT", None)
    setup = rig.run("up")
    assert setup.returncode == 0, setup.stderr
    salt = rig.root / ".local-ops/run/review-salt"
    engine = rig.bin_dir / "traust-engine"
    engine.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        "import os, sys\n"
        "from traust_core.v1.context import Config\n"
        "config = Path(sys.argv[sys.argv.index('--core') + 1])\n"
        f"expected = Path({str(salt)!r}).read_text()\n"
        "assert expected and Config.from_file(config).valve_salt() == expected\n"
    )
    engine.chmod(0o755)
    tick = rig.make("ops-run")
    assert tick.returncode == 0, tick.stderr
    assert salt.read_text() not in tick.stdout + tick.stderr


@pytest.mark.parametrize(
    ("use_rig_key", "configured_password", "expected"),
    [(True, None, ""), (True, "from-env", "from-env"), (False, None, None)],
)
def test_normal_rig_commands_supply_only_the_rig_keys_default_password(
    rig: LocalOpsRig, use_rig_key: bool, configured_password: str | None, expected: str | None
) -> None:
    # A stale dev-key path can coexist with an operator-owned ledger config.
    dev_key = rig.root / ".local-ops/run/ledger/dev-key.key"
    dev_key.parent.mkdir(parents=True)
    dev_key.touch()
    rig.config_home.mkdir()
    save_config(rig, {"ledger": {"key_path": str(dev_key if use_rig_key else "/operator.key")}})
    if configured_password is not None:
        (rig.root / ".local-ops/env").write_text(f"export COSIGN_PASSWORD={configured_password}\n")
    shell = rig.bin_dir / "check-env"
    shell.write_text(
        f"#!{sys.executable}\nimport os\nassert os.environ.get('COSIGN_PASSWORD') == {expected!r}\n"
    )
    shell.chmod(0o755)
    result = rig.run("sh", env={"SHELL": str(shell)})
    assert result.returncode == 0, result.stderr
