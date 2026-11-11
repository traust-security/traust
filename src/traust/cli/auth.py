"""``traust auth local|login|service-account|status|refresh|token|logout``: who you act as.

local            mint a token from this machine's own key (a solo install; core must trust local)
login            a person's token by device code from the deployment's identity provider,
                 or import one with --token-file
service-account  a machine token by client credentials (scheduled jobs, never a person)
status           the stored login, and who core says it is
refresh          renew the stored login with its refresh token
token            print the stored access token
logout           forget the stored login

One login per traust home (core's credential store); a deployment's provider is `identity.login`.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pydantic
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, TraustError
from traust_core.v1.models.identity import LOCAL_ISSUER, Login, TokenGrant
from traust_core.v1.providers.identity import LOCAL_TOKEN_LIFETIME

from traust.cli._doors import parser, run
from traust.context import load, load_caller, oidc_client_secret


def _provider(core: Context):
    if core.login is None:
        raise ConfigError("no identity.login in traust.yaml: name its issuer and client_id")
    return core.login


def _peek(token: str) -> dict[str, Any]:
    """A JWT's claims for display only; never trusted (core verifies when it matters)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, ValueError):
        return {}


def _saved(core: Context, login: Login) -> dict[str, Any]:
    core.credentials.save(login)
    claims = _peek(login.grant.access_token.get_secret_value())
    return {
        "issuer": login.issuer,
        "client_id": login.client_id,
        "identity": claims.get("email") or claims.get("azp") or claims.get("sub"),
        "expires_at": login.grant.expires_at,
    }


def local(argv: list[str] | None = None) -> int:
    ap = parser("auth", "local", "Mint a token from this machine's key and store it.")
    ap.add_argument("--identity", required=True, help="you@example.com, or a job name")
    ap.add_argument("--machine", action="store_true", help="a machine identity, never a person")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        credential = core.local_issuer.mint(args.identity, machine=args.machine)
        grant = TokenGrant(
            access_token=credential.token,
            expires_at=core.clock.now() + LOCAL_TOKEN_LIFETIME,
        )
        made = _saved(core, Login(issuer=LOCAL_ISSUER, client_id=args.identity, grant=grant))
        return {**made, "kind": "machine" if args.machine else "human"}

    return run(call)


def login(argv: list[str] | None = None) -> int:
    ap = parser("auth", "login", "Log in by device code, or import a token from a file.")
    ap.add_argument("--token-file", type=Path, help="store this token instead of logging in")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        if args.token_file is not None:
            token = args.token_file.read_text(encoding="utf-8").strip()
            issuer = _peek(token).get("iss") or (core.login.issuer if core.login else "imported")
            grant = TokenGrant(access_token=pydantic.SecretStr(token))
            return _saved(core, Login(issuer=issuer, client_id="", grant=grant))
        provider = _provider(core)

        def show(uri: str, code: str) -> None:
            print(f"Open {uri} and enter the code {code}", file=sys.stderr)

        grant = provider.device_code(show)
        return _saved(
            core, Login(issuer=provider.issuer, client_id=provider.client_id, grant=grant)
        )

    return run(call)


def service_account(argv: list[str] | None = None) -> int:
    ap = parser("auth", "service-account", "Get a machine token by client credentials.")
    ap.add_argument(
        "--client-secret-file",
        type=Path,
        help="the secret (default: $TRAUST_OIDC_CLIENT_SECRET); never on argv",
    )
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        provider = _provider(core)
        if args.client_secret_file is not None:
            secret = args.client_secret_file.read_text(encoding="utf-8").strip()
        else:
            secret = oidc_client_secret() or ""
        if not secret:
            raise ConfigError(
                "no client secret: --client-secret-file or $TRAUST_OIDC_CLIENT_SECRET"
            )
        grant = provider.client_credentials(pydantic.SecretStr(secret))
        made = _saved(
            core, Login(issuer=provider.issuer, client_id=provider.client_id, grant=grant)
        )
        claims = _peek(grant.access_token.get_secret_value())
        if claims.get("email"):
            # Core would verify this as a person: machine verdicts would be attributed to one.
            print(
                f"WARNING: the token carries an email claim ({claims['email']}) and will verify"
                " as a human; configure the provider to omit it for this service account",
                file=sys.stderr,
            )
        kind = (
            "unknown (opaque token)"
            if not claims
            else "human"
            if claims.get("email")
            else "machine"
        )
        return {**made, "kind": kind}

    return run(call)


def status(argv: list[str] | None = None) -> int:
    ap = parser("auth", "status", "Show the stored login and who core verifies it as.")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        stored = core.credentials.load()
        if stored is None:
            return {"logged_in": False}
        expires = stored.grant.expires_at
        out: dict[str, Any] = {
            "logged_in": True,
            "issuer": stored.issuer,
            "client_id": stored.client_id,
            "expires_at": expires,
            "expired": expires is not None and expires <= datetime.now(UTC),
        }
        try:
            caller = load_caller(core)
        except TraustError as e:
            return {**out, "verified": False, "reason": str(e)}
        return {**out, "verified": True, "actor": caller.ref, "roles": sorted(caller.roles)}

    return run(call)


def refresh(argv: list[str] | None = None) -> int:
    ap = parser("auth", "refresh", "Renew the stored login with its refresh token.")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load(args.config_home)
        stored = core.credentials.load()
        if stored is None or stored.grant.refresh_token is None:
            raise ConfigError("nothing to refresh: run `traust auth login`")
        grant = _provider(core).refresh(stored.grant.refresh_token)
        if grant.refresh_token is None:
            grant = grant.model_copy(update={"refresh_token": stored.grant.refresh_token})
        return _saved(core, stored.model_copy(update={"grant": grant}))

    return run(call)


def token(argv: list[str] | None = None) -> int:
    ap = parser("auth", "token", "Print the stored access token.")
    args = ap.parse_args(argv)

    def call() -> str:
        stored = load(args.config_home).credentials.load()
        if stored is None:
            raise ConfigError("not logged in: run `traust auth login` or `traust auth local`")
        return stored.grant.access_token.get_secret_value()

    return run(call)


def logout(argv: list[str] | None = None) -> int:
    ap = parser("auth", "logout", "Forget the stored login.")
    args = ap.parse_args(argv)

    def call() -> dict[str, bool]:
        load(args.config_home).credentials.clear()
        return {"logged_in": False}

    return run(call)
