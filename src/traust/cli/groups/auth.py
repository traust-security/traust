"""``traust auth …``: who you act as, over traust-core's identity provider."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

AUTH: dict[str, object] = {
    "local": passthrough_op("auth", "Mint a token from this machine's key.", "local"),
    "login": passthrough_op("auth", "Log in by device code, or import a token.", "login"),
    "service-account": passthrough_op(
        "auth", "Get a machine token by client credentials.", "service_account"
    ),
    "status": passthrough_op("auth", "Show the stored login and who it verifies as.", "status"),
    "refresh": passthrough_op("auth", "Renew the stored login.", "refresh"),
    "token": passthrough_op("auth", "Print the stored access token.", "token"),
    "logout": passthrough_op("auth", "Forget the stored login.", "logout"),
}
