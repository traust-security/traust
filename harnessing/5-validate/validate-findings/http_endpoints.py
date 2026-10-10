from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

if __package__:
    from .http_scope import hostname, origin
    from .scope import Action, Scope
else:
    from http_scope import hostname, origin
    from scope import Action, Scope


class HttpProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["route", "service", "node", "direct"] = "route"
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] = "GET"
    path: str = "/"
    port: int | None = Field(default=None, ge=1, le=65535)
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
        if not value.startswith("/") or value.startswith("//") or parsed.netloc or parsed.scheme:
            raise ValueError("probe path must be relative to its authorized origin")
        if any(ord(char) < 32 for char in value) or "\\" in value:
            raise ValueError("invalid HTTP path")
        return value

    @field_validator("headers")
    @classmethod
    def valid_headers(cls, values: dict[str, str]) -> dict[str, str]:
        for name, value in values.items():
            if not name or not all(
                char.isascii() and (char.isalnum() or char == "-") for char in name
            ):
                raise ValueError("invalid header name")
            if name.lower() in {"host", "authorization", "proxy-authorization", "cookie"}:
                raise ValueError("authentication and destination headers are adapter-owned")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
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


class ServiceSpec(BaseModel):
    ports: list[ServicePort]
    selector: dict[str, str] = Field(default_factory=dict)
    type: str = "ClusterIP"


class ContainerPort(BaseModel):
    containerPort: int = Field(ge=1, le=65535, strict=True)
    name: str = ""


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

    @property
    def host(self) -> str:
        return hostname(self.origin)


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
    ) -> None:
        allowed, reason = self.scope.is_in_scope(
            Action(
                adapter="k8s",
                context=context,
                namespace=namespace,
                resource=resource,
                name=name,
                verb=verb,
            )
        )
        if not allowed:
            raise PermissionError(reason)

    def api(self, context: str) -> str:
        cluster = self.scope.clusters.get(context)
        if cluster is None or context == "__current__":
            raise PermissionError("HTTP probes require a named engagement context")
        if self.scope.expires:
            import datetime

            if datetime.date.today() > self.scope.expires:
                raise PermissionError("engagement expired")
        code, output, _ = self.run(
            [
                self.binary,
                f"--context={context}",
                "config",
                "view",
                "--minify",
                "-o",
                "jsonpath={.clusters[0].cluster.server}",
            ],
            timeout=15,
        )
        if code or not output.strip():
            raise RuntimeError("cannot resolve the engagement context API")
        actual = output.strip()
        parsed = urlsplit(actual)
        hostname(actual)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("invalid cluster API URL")
        if cluster.api and origin(cluster.api) != origin(actual):
            raise PermissionError("engagement API does not match kubeconfig context")
        return actual

    def objects(
        self, context: str, namespace: str | None, resource: str, name: str | None = None
    ) -> list[KubernetesObject]:
        self.authorize(context, namespace, resource, name, "get" if name else "list")
        args = [self.binary, f"--context={context}"]
        if namespace is not None:
            if not namespace or any(char in namespace for char in "*?[]"):
                raise PermissionError("discovery requires a concrete authorized namespace")
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
        except (ValueError, TypeError) as exc:
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

    def resolve(self, context: str, probe: HttpProbe) -> Endpoint:
        api = self.api(context)
        cluster = self.scope.clusters[context]
        if probe.mode == "direct":
            if not probe.url:
                raise ValueError("direct HTTP probe requires a URL")
            parsed = urlsplit(probe.url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("direct HTTP probe requires HTTP(S)")
            host = hostname(probe.url)
            namespace = probe.namespaces[0] if len(probe.namespaces) == 1 else None
            self.authorize(context, namespace, "http_targets", probe.name, "port-forward+http")
            credentials = self.explicit(host, context, namespace, "http_targets", probe.name or "")
            if host == hostname(api):
                if probe.path not in {
                    "/healthz",
                    "/livez",
                    "/readyz",
                    "/version",
                } or probe.method not in {"GET", "HEAD"}:
                    raise PermissionError(
                        "direct API probes are limited to health and version endpoints"
                    )
                if credentials is None and origin(probe.url) == origin(api):
                    credentials = False
            if credentials is None:
                raise PermissionError("HTTP destination is not explicitly authorized")
            return Endpoint(
                f"{parsed.scheme}://{parsed.netloc}",
                context,
                namespace,
                "http_targets",
                probe.name or "",
                credentials=credentials,
            )
        if probe.mode == "node":
            grant = cluster.http_discovery.nodes
            if "explicit" not in self.scope.modes or grant is None:
                raise PermissionError("node HTTP discovery requires an explicit grant")
            if probe.name and grant.names and probe.name not in grant.names:
                raise PermissionError("node is outside the discovery grant")
            candidates = []
            names = (probe.name,) if probe.name else (grant.names or (None,))
            for name in names:
                for node in self.objects(context, None, "nodes", name):
                    if grant.names and node.metadata.name not in grant.names:
                        raise PermissionError("node is outside the discovery grant")
                    for address in node.status.get("addresses", []):
                        if address.get("type") not in grant.address_types:
                            continue
                        host = hostname(address["address"])
                        credentials = self.explicit(
                            host, context, None, "nodes", node.metadata.name
                        )
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
        if probe.mode == "route":
            candidates = []
            for grant in cluster.http_discovery.routes:
                if "explicit" not in self.scope.modes or grant.namespace not in probe.namespaces:
                    continue
                if probe.name and grant.names and probe.name not in grant.names:
                    raise PermissionError("route is outside the discovery grant")
                names = (probe.name,) if probe.name else (grant.names or (None,))
                for name in names:
                    for route in self.objects(context, grant.namespace, "routes", name):
                        if grant.names and route.metadata.name not in grant.names:
                            continue
                        if probe.hint and not any(
                            hint.lower() in route.metadata.name.lower()
                            for hint in probe.hint.split("|")
                        ):
                            continue
                        host = hostname(route.spec.get("host", ""))
                        credentials = self.explicit(
                            host, context, grant.namespace, "routes", route.metadata.name
                        )
                        if credentials is None and grant.accepts(route.metadata.name, host):
                            credentials = grant.credentials
                        if credentials is None:
                            raise PermissionError("discovered route destination is not authorized")
                        candidates.append(
                            Endpoint(
                                f"https://{host}",
                                context,
                                grant.namespace,
                                "routes",
                                route.metadata.name,
                                route.metadata.uid,
                                credentials,
                            )
                        )
            if candidates:
                return self.unique(candidates)
        return self.service(context, probe)

    @staticmethod
    def unique(candidates: list[Endpoint]) -> Endpoint:
        if len(candidates) != 1:
            raise RuntimeError(
                f"HTTP target resolution requires one endpoint, found {len(candidates)}"
            )
        return candidates[0]

    def service(self, context: str, probe: HttpProbe) -> Endpoint:
        candidates = []
        for namespace in probe.namespaces:
            for service in self.objects(context, namespace, "services", probe.name):
                if probe.hint and not any(
                    hint.lower() in service.metadata.name.lower() for hint in probe.hint.split("|")
                ):
                    continue
                ports = service.spec.get("ports", [])
                for port in ports:
                    remote = port.get("port")
                    if probe.port and probe.port not in {remote, port.get("targetPort")}:
                        continue
                    if not isinstance(remote, int) or not 1 <= remote <= 65535:
                        raise ValueError("invalid Service port")
                    if service.spec.get("type") == "ExternalName" or not service.spec.get(
                        "selector"
                    ):
                        raise PermissionError("port-forward requires a selector-backed Service")
                    candidates.append(
                        Endpoint(
                            "http://127.0.0.1",
                            context,
                            namespace,
                            "services",
                            service.metadata.name,
                            service.metadata.uid,
                            False,
                            remote,
                        )
                    )
        endpoint = self.unique(candidates)
        method_verb = {
            "GET": "get",
            "HEAD": "get",
            "OPTIONS": "get",
            "POST": "create",
            "PUT": "update",
            "PATCH": "patch",
            "DELETE": "delete",
        }[probe.method]
        for verb in ("port-forward+http", "port-forward", method_verb):
            self.authorize(context, endpoint.namespace, "services", endpoint.name, verb)
        service = self.objects(context, endpoint.namespace, "services", endpoint.name)[0]
        selector = service.spec.get("selector", {})
        pods = [
            pod
            for pod in self.objects(context, endpoint.namespace, "pods")
            if selector
            and all(pod.metadata.labels.get(key) == value for key, value in selector.items())
        ]
        running = [pod for pod in pods if pod.status.get("phase") == "Running"]
        if not running:
            raise RuntimeError("no running selector-matched Pod for port-forward")
        pod = sorted(running, key=lambda item: item.metadata.name)[0]
        target_ports = [
            port.get("targetPort", port.get("port"))
            for port in service.spec.get("ports", [])
            if port.get("port") == endpoint.remote_port
        ]
        remote = next(iter(target_ports), None)
        if isinstance(remote, str):
            matches = [
                port.get("containerPort")
                for container in pod.spec.get("containers", [])
                for port in container.get("ports", [])
                if port.get("name") == remote
            ]
            if len(matches) != 1:
                raise RuntimeError("cannot resolve named target port")
            remote = matches[0]
        if not isinstance(remote, int) or not 1 <= remote <= 65535:
            raise ValueError("invalid Pod target port")
        self.authorize(context, endpoint.namespace, "pods", pod.metadata.name, "port-forward")
        selected = next(
            port for port in service.spec["ports"] if port["port"] == endpoint.remote_port
        )
        scheme = probe.scheme
        if scheme == "auto":
            scheme = (
                "https"
                if selected.get("appProtocol") == "https"
                or "https" in selected.get("name", "")
                or selected["port"] == 443
                else "http"
            )
        tunnel_host = (
            f"{endpoint.name}.{endpoint.namespace}.svc" if scheme == "https" else "127.0.0.1"
        )
        return Endpoint(
            f"{scheme}://{tunnel_host}",
            context,
            endpoint.namespace,
            "pods",
            pod.metadata.name,
            pod.metadata.uid,
            self.scope.clusters[context].http_discovery.port_forward_credentials,
            remote,
        )
