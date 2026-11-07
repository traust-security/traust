from __future__ import annotations

import fnmatch
import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator
from traust_core.v1.models.validation import hostname, origin

if __package__:
    from .http_policy_io import context_api
    from .scope import Action, Scope
else:
    from http_policy_io import context_api
    from scope import Action, Scope


class HttpProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["route", "service", "node", "direct"] = "route"
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] = "GET"
    path: str = "/"
    port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    scheme: Literal["auto", "http", "https"] = "auto"
    hint: str = ""
    namespaces: tuple[str, ...] = ()
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    authenticate: bool = False
    csrf: bool = False
    service_account: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]*$")

    @field_validator("path")
    @classmethod
    def valid_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            not value.startswith("/")
            or value.startswith("//")
            or parsed.netloc
            or parsed.scheme
            or parsed.fragment
            or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("probe path must be relative to its authorized origin")
        return value

    @field_validator("namespaces")
    @classmethod
    def valid_namespaces(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            Metadata(name="valid", namespace=value)
        return values

    @field_validator("headers")
    @classmethod
    def valid_headers(cls, values: dict[str, str]) -> dict[str, str]:
        for name, value in values.items():
            if not name or not all(c.isascii() and (c.isalnum() or c == "-") for c in name):
                raise ValueError("invalid header name")
            normalized = name.lower().replace("-", "")
            if (
                normalized == "host"
                or normalized.endswith("key")
                or any(
                    part in normalized
                    for part in (
                        "auth",
                        "credential",
                        "cookie",
                        "session",
                        "token",
                        "csrf",
                        "xsrf",
                        "secret",
                        "password",
                        "bearer",
                    )
                )
            ):
                raise ValueError("authentication and destination headers are adapter-owned")
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("invalid header value")
        return values


class Metadata(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]*$")
    namespace: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]*$")
    uid: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


class NodeAddress(BaseModel):
    type: str
    address: str


class NodeStatus(BaseModel):
    addresses: list[NodeAddress] = Field(default_factory=list)


class RouteSpec(BaseModel):
    host: str
    tls: dict[str, object] | None = None


class ServicePort(BaseModel):
    port: int = Field(ge=1, le=65535, strict=True)
    targetPort: int | str | None = None
    name: str = ""
    appProtocol: str = ""
    protocol: str = "TCP"


class ServiceSpec(BaseModel):
    ports: list[ServicePort]
    selector: dict[str, str] = Field(default_factory=dict)
    type: str = "ClusterIP"


class ContainerPort(BaseModel):
    containerPort: int = Field(ge=1, le=65535, strict=True)
    name: str = ""
    protocol: str = "TCP"


class ContainerSpec(BaseModel):
    ports: list[ContainerPort] = Field(default_factory=list)


class PodSpec(BaseModel):
    containers: list[ContainerSpec] = Field(default_factory=list)


class PodStatus(BaseModel):
    phase: str = ""


class KubernetesObject(BaseModel):
    metadata: Metadata
    spec: dict = Field(default_factory=dict)
    status: dict = Field(default_factory=dict)


class KubernetesList(BaseModel):
    items: list[KubernetesObject]


@dataclass(frozen=True)
class Endpoint:
    origin: str
    context: str
    namespace: str | None
    resource: str
    name: str
    uid: str = ""
    credentials: bool = False
    remote_port: int | None = None
    resolved_api: str = ""

    @property
    def host(self) -> str:
        return hostname(self.origin)


_METHOD_VERBS = {
    "GET": "get",
    "HEAD": "get",
    "OPTIONS": "get",
    "POST": "create",
    "PUT": "update",
    "PATCH": "patch",
    "DELETE": "delete",
}


def authorize_api_request(endpoint: Endpoint, api: str, method: str, path: str) -> None:
    if (
        not endpoint.remote_port
        and endpoint.host == hostname(api)
        and (
            origin(endpoint.origin) != origin(api)
            or path not in {"/healthz", "/livez", "/readyz", "/version"}
            or method not in {"GET", "HEAD"}
        )
    ):
        raise PermissionError(
            "API probes are limited to health and version endpoints on the pinned API origin"
        )


class EndpointResolver:
    def __init__(self, scope: Scope, run: Callable[..., tuple[int, str, str]], binary: str) -> None:
        self.scope = scope
        self.run = run
        self.binary = binary

    def authorize(
        self,
        context: str,
        namespace: str | None,
        resource: str,
        name: str | None = None,
        verb: str = "get",
        *,
        url: str | None = None,
    ) -> None:
        allowed, reason = self.scope.is_in_scope(
            Action(
                adapter="k8s",
                context=context,
                namespace=namespace,
                resource=resource,
                name=name,
                verb=verb,
                url=url,
            )
        )
        if not allowed:
            raise PermissionError(reason)

    def api(self, context: str) -> str:
        cluster = self.scope.clusters.get(context)
        if (
            cluster is None
            or context == "__current__"
            or not context
            or any(ord(c) <= 32 for c in context)
        ):
            raise PermissionError("HTTP probes require a named engagement context")
        if self.scope.selected_contexts and context not in self.scope.selected_contexts:
            raise PermissionError("HTTP context is not selected for this run")
        if not self.scope.http_context_allowed(context):
            raise PermissionError("HTTP probes require an explicitly declared engagement context")
        if self.scope.expired():
            raise PermissionError("engagement expired")
        if not cluster.api:
            raise PermissionError("HTTP probes require an explicitly pinned engagement API")
        code, output, _ = self.run(
            [self.binary, f"--context={context}", "config", "view", "--minify", "-o", "json"],
            timeout=15,
        )
        if code or not output.strip():
            raise RuntimeError("cannot resolve the engagement context API")
        try:
            actual = context_api(output)
        except ValueError as exc:
            raise ValueError("invalid kubeconfig context view") from exc
        if origin(cluster.api) != origin(actual):
            raise PermissionError("engagement API does not match kubeconfig context")
        return actual

    def objects(
        self, context: str, namespace: str | None, resource: str, name: str | None = None
    ) -> list[KubernetesObject]:
        self.authorize(context, namespace, resource, name, "get" if name else "list")
        args = [self.binary, f"--context={context}"]
        if namespace is not None:
            Metadata(name="valid", namespace=namespace)
            args.extend(["--namespace", namespace])
        args.extend(["get", resource])
        if name:
            Metadata(name=name)
            args.append(name)
        args.extend(["-o", "json"])
        code, output, _ = self.run(args, timeout=20)
        if code:
            raise RuntimeError(f"discovery failed for {resource} in {context}/{namespace}")
        try:
            data = json.loads(output)
            objects = (
                [KubernetesObject.model_validate(data)]
                if name
                else KubernetesList.model_validate(data).items
            )
            models = {
                "routes": (RouteSpec, None),
                "services": (ServiceSpec, None),
                "nodes": (None, NodeStatus),
                "pods": (PodSpec, PodStatus),
            }
            spec_model, status_model = models[resource]
            for item in objects:
                if spec_model:
                    item.spec = spec_model.model_validate(item.spec).model_dump(exclude_none=True)
                if status_model:
                    item.status = status_model.model_validate(item.status).model_dump(
                        exclude_none=True
                    )
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"invalid {resource} discovery response") from exc
        for item in objects:
            if item.metadata.namespace != namespace or (name and item.metadata.name != name):
                raise PermissionError("discovery response does not match requested resource")
            self.authorize(context, namespace, resource, item.metadata.name)
        return objects

    def explicit(
        self, host: str, context: str, namespace: str | None, resource: str, name: str
    ) -> bool | None:
        matches = [
            target
            for target in self.scope.http_targets
            if target.host == host
            and target.context == context
            and (target.namespace is None or target.namespace == namespace)
            and (target.resource is None or target.resource == resource)
            and (target.name is None or target.name == name)
        ]
        return any(target.credentials for target in matches) if matches else None

    def _http_authorize(self, endpoint: Endpoint, probe: HttpProbe) -> None:
        for verb in ("port-forward+http", _METHOD_VERBS[probe.method]):
            self.authorize(
                endpoint.context,
                endpoint.namespace,
                endpoint.resource,
                endpoint.name or None,
                verb,
                url=(
                    endpoint.origin
                    if endpoint.resource == "http_targets" and endpoint.namespace is None
                    else None
                ),
            )

    def resolve(self, context: str, probe: HttpProbe) -> Endpoint:
        requested_route_origin = None
        if probe.mode == "route" and probe.url is not None:
            parsed = urlsplit(probe.url)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("route URL must be an origin; use probe.path for the request")
            requested_route_origin = origin(probe.url)
        api = self.api(context)
        if probe.mode == "direct":
            if not probe.url:
                raise ValueError("direct HTTP probe requires a URL")
            parsed = urlsplit(probe.url)
            scheme, _, direct_port = origin(probe.url)
            if (probe.scheme != "auto" and probe.scheme != scheme) or (
                probe.port is not None and probe.port != direct_port
            ):
                raise ValueError("direct URL does not match the requested scheme or port")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("direct URL must be an origin; use probe.path for the request")
            if len(probe.namespaces) > 1:
                raise ValueError("direct HTTP probe requires at most one namespace")
            namespace = probe.namespaces[0] if probe.namespaces else None
            host = hostname(probe.url)
            credentials = self.explicit(host, context, namespace, "http_targets", probe.name or "")
            if credentials is None:
                raise PermissionError("HTTP destination is not explicitly authorized")
            endpoint = Endpoint(
                f"{parsed.scheme.lower()}://{parsed.netloc}",
                context,
                namespace,
                "http_targets",
                probe.name or "",
                credentials=credentials,
            )
        elif probe.mode == "node":
            endpoint = self.node(context, probe)
        elif probe.mode == "route":
            endpoint = self.route(context, probe)
            if (
                requested_route_origin is not None
                and origin(endpoint.origin) != requested_route_origin
            ):
                raise PermissionError("resolved Route does not match the requested origin")
        else:
            endpoint = self.service(context, probe)
        authorize_api_request(endpoint, api, probe.method, probe.path)
        self._http_authorize(endpoint, probe)
        return replace(endpoint, resolved_api=api)

    @staticmethod
    def unique(candidates: list[Endpoint]) -> Endpoint:
        if len(candidates) != 1:
            raise RuntimeError(
                f"HTTP target resolution requires one endpoint, found {len(candidates)}"
            )
        return candidates[0]

    def node(self, context: str, probe: HttpProbe) -> Endpoint:
        grant = self.scope.clusters[context].http_discovery.nodes
        if grant is None:
            raise PermissionError("node HTTP discovery requires an explicit grant")
        if probe.name and grant.names and probe.name not in grant.names:
            raise PermissionError("node is outside the discovery grant")
        candidates = []
        for name in (probe.name,) if probe.name else (grant.names or (None,)):
            for node in self.objects(context, None, "nodes", name):
                if grant.names and node.metadata.name not in grant.names:
                    continue
                for address in node.status.get("addresses", []):
                    if address["type"] not in grant.address_types:
                        continue
                    try:
                        host = str(ipaddress.ip_address(address["address"]))
                    except ValueError as exc:
                        raise ValueError("invalid node IP address") from exc
                    credentials = self.explicit(host, context, None, "nodes", node.metadata.name)
                    if credentials is None and grant.accepts(node.metadata.name, host):
                        credentials = grant.credentials
                    if credentials is not None:
                        authority = f"[{host}]" if ":" in host else host
                        scheme = "https" if probe.scheme == "auto" else probe.scheme
                        candidates.append(
                            Endpoint(
                                f"{scheme}://{authority}:{probe.port or 10250}",
                                context,
                                None,
                                "nodes",
                                node.metadata.name,
                                node.metadata.uid,
                                credentials,
                            )
                        )
        return self.unique(candidates)

    def route(self, context: str, probe: HttpProbe) -> Endpoint:
        cluster = self.scope.clusters[context]
        candidates = []
        unauthorized = False
        seen = set()
        requested_origin = origin(probe.url) if probe.url is not None else None
        for namespace in probe.namespaces:
            grants = [g for g in cluster.http_discovery.routes if g.namespace == namespace]
            exact = [
                t
                for t in self.scope.http_targets
                if t.context == context
                and t.namespace == namespace
                and t.resource == "routes"
                and t.name
            ]
            names: set[str | None] = set()
            if probe.name:
                if any(not g.names or probe.name in g.names for g in grants) or any(
                    t.name == probe.name for t in exact
                ):
                    names.add(probe.name)
            else:
                for grant in grants:
                    names.update(grant.names or (None,))
                names.update(t.name for t in exact)
            # A list already contains every explicitly named route.
            if None in names:
                names = {None}
            for name in sorted(names, key=lambda value: value or ""):
                for route in self.objects(context, namespace, "routes", name):
                    route_name = route.metadata.name
                    if probe.hint and not any(
                        h.lower() in route_name.lower() for h in probe.hint.split("|") if h
                    ):
                        continue
                    host = hostname(route.spec["host"])
                    scheme = (
                        probe.scheme
                        if probe.scheme != "auto"
                        else ("https" if route.spec.get("tls") is not None else "http")
                    )
                    authority = f"[{host}]" if ":" in host else host
                    if probe.port:
                        authority += f":{probe.port}"
                    endpoint_origin = f"{scheme}://{authority}"
                    if requested_origin is not None and origin(endpoint_origin) != requested_origin:
                        if probe.name:
                            raise PermissionError(
                                "resolved Route does not match the requested origin"
                            )
                        continue
                    credentials = self.explicit(host, context, namespace, "routes", route_name)
                    if credentials is None:
                        matching = [g for g in grants if g.accepts(route_name, host)]
                        if matching:
                            credentials = any(g.credentials for g in matching)
                    if credentials is None:
                        if name is not None:
                            raise PermissionError("discovered route destination is not authorized")
                        unauthorized = True
                        continue
                    identity = (namespace, route_name)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    candidates.append(
                        Endpoint(
                            endpoint_origin,
                            context,
                            namespace,
                            "routes",
                            route_name,
                            route.metadata.uid,
                            credentials,
                        )
                    )
        if not candidates and unauthorized:
            raise PermissionError("discovered route destination is not authorized")
        return self.unique(candidates)

    def service(self, context: str, probe: HttpProbe) -> Endpoint:
        cluster = self.scope.clusters[context]
        candidates = []
        for namespace in probe.namespaces:
            if not any(
                fnmatch.fnmatchcase(namespace, pattern) for pattern in cluster.explicit_namespaces
            ):
                raise PermissionError(
                    "service port-forward requires an explicitly authorized namespace"
                )
            for service in self.objects(context, namespace, "services", probe.name):
                if probe.hint and not any(
                    h.lower() in service.metadata.name.lower() for h in probe.hint.split("|") if h
                ):
                    continue
                for port in service.spec["ports"]:
                    if port["protocol"] != "TCP" or (
                        probe.port and probe.port not in {port["port"], port.get("targetPort")}
                    ):
                        continue
                    if service.spec["type"] == "ExternalName" or not service.spec["selector"]:
                        raise PermissionError("port-forward requires a selector-backed Service")
                    candidates.append((namespace, service, port))
        if len(candidates) != 1:
            raise RuntimeError(
                f"HTTP target resolution requires one endpoint, found {len(candidates)}"
            )
        namespace, initial, port = candidates[0]
        if not initial.metadata.uid:
            raise PermissionError("selector-backed Service requires a stable UID")
        for verb in ("port-forward+http", "port-forward", _METHOD_VERBS[probe.method]):
            self.authorize(context, namespace, "services", initial.metadata.name, verb)
        service = self.objects(context, namespace, "services", initial.metadata.name)[0]
        if service.metadata.uid != initial.metadata.uid or service.spec != initial.spec:
            raise PermissionError("Service changed during endpoint resolution")
        selector = service.spec["selector"]
        pods = [
            pod
            for pod in self.objects(context, namespace, "pods")
            if pod.status.get("phase") == "Running"
            and all(pod.metadata.labels.get(k) == v for k, v in selector.items())
        ]
        if not pods:
            raise RuntimeError("no running selector-matched Pod for port-forward")
        pod = min(pods, key=lambda item: item.metadata.name)
        if not pod.metadata.uid:
            raise PermissionError("selector-matched Pod requires a stable UID")
        remote = port.get("targetPort")
        if remote is None:
            remote = port["port"]
        if isinstance(remote, str):
            matches = [
                p["containerPort"]
                for container in pod.spec["containers"]
                for p in container["ports"]
                if p["name"] == remote and p["protocol"] == "TCP"
            ]
            if len(matches) != 1:
                raise RuntimeError("cannot resolve named target port")
            remote = matches[0]
        if not isinstance(remote, int) or not 1 <= remote <= 65535:
            raise ValueError("invalid Pod target port")
        for verb in ("port-forward", "port-forward+http", _METHOD_VERBS[probe.method]):
            self.authorize(context, namespace, "pods", pod.metadata.name, verb)
        scheme = probe.scheme
        if scheme == "auto":
            scheme = (
                "https"
                if port["appProtocol"] == "https" or "https" in port["name"] or port["port"] == 443
                else "http"
            )
        host = f"{service.metadata.name}.{namespace}.svc" if scheme == "https" else "127.0.0.1"
        return Endpoint(
            f"{scheme}://{host}",
            context,
            namespace,
            "pods",
            pod.metadata.name,
            pod.metadata.uid,
            cluster.http_discovery.port_forward_credentials,
            remote,
        )
