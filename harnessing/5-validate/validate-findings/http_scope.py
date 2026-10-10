from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


def hostname(value: str) -> str:
    if (
        not value
        or any(char.isspace() for char in value)
        or any(char in value for char in "*?{}\\")
    ):
        raise ValueError("HTTP targets require an exact hostname or HTTP(S) URL")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("HTTP targets require HTTP(S)")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("HTTP targets cannot contain credentials or empty hosts")
    if parsed.port == 0:
        raise ValueError("invalid HTTP port")
    try:
        return str(ipaddress.ip_address(parsed.hostname))
    except ValueError:
        pass
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in host.split(".")
    ):
        raise ValueError("invalid hostname")
    return host


class HttpTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    context: str = Field(min_length=1)
    namespace: str | None = None
    resource: str | None = None
    name: str | None = None
    credentials: bool = False

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        return hostname(value)


class RouteGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    names: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    credentials: bool = False

    @field_validator("domains")
    @classmethod
    def valid_domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(hostname(value) for value in values)

    def accepts(self, name: str, host: str) -> bool:
        return (not self.names or name in self.names) and any(
            host == domain or host.endswith(f".{domain}") for domain in self.domains
        )


class NodeGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    names: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    address_types: tuple[Literal["InternalIP", "ExternalIP"], ...] = ("InternalIP",)
    credentials: bool = False

    @field_validator("networks")
    @classmethod
    def valid_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(str(ipaddress.ip_network(value)) for value in values)

    def accepts(self, name: str, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return (not self.names or name in self.names) and any(
            ip in ipaddress.ip_network(network) for network in self.networks
        )


def origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    host = hostname(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("expected an HTTP(S) origin")
    return parsed.scheme, host, parsed.port or (443 if parsed.scheme == "https" else 80)


class HttpDiscovery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    routes: tuple[RouteGrant, ...] = ()
    nodes: NodeGrant | None = None
    port_forward_credentials: bool = False
    kube_env: tuple[str, ...] = ()
    ca_bundle: str | None = None
    insecure_tls: bool = False
    session_check_path: str | None = None

    @field_validator("session_check_path")
    @classmethod
    def valid_session_check(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.startswith("/")
            or value.startswith("//")
            or any(ord(char) < 32 for char in value)
            or "\\" in value
        ):
            raise ValueError("session check must be an origin-relative path")
        return value


class HttpPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    http_targets: tuple[HttpTarget, ...] = ()
    http_discovery: HttpDiscovery = Field(default_factory=HttpDiscovery)

    def apply(self, document: dict, context: str) -> None:
        cluster = next(cluster for cluster in document["clusters"] if cluster["context"] == context)
        if any(target.context != context for target in self.http_targets):
            raise ValueError("HTTP policy targets must belong to the selected context")
        cluster["http_discovery"] = self.http_discovery.model_dump(mode="json")
        document["http_targets"] = [target.model_dump(mode="json") for target in self.http_targets]


def configure_http_targets(
    document: dict, context: str, api: str | None, policy_path: str | None
) -> None:
    if __package__:
        from .http_policy_io import configure_http_targets as configure
    else:
        from http_policy_io import configure_http_targets as configure
    configure(document, context, api, policy_path)
