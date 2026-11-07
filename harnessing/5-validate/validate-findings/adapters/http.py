"""Scoped HTTP requests and owned Kubernetes port-forwards."""

from __future__ import annotations

import contextlib
import os
import re
import selectors
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import asdict
from http.cookies import SimpleCookie
from typing import NamedTuple, Protocol
from urllib.parse import urlsplit

from traust_core.v1.models.validation import origin as http_origin

if __package__ and "." in __package__:
    from ..http_endpoints import Endpoint, EndpointResolver, HttpProbe, authorize_api_request
    from ..scope import Scope
else:
    from http_endpoints import Endpoint, EndpointResolver, HttpProbe, authorize_api_request
    from scope import Scope

from .base import AdapterBase
from .credentials import redact_credentials


class AuditSink(Protocol):
    def append(self, **fields: object) -> None: ...


class HttpResult(NamedTuple):
    code: int
    output: str
    error: str
    status: str | None


class HttpExecutor:
    def __init__(self, adapter: AdapterBase, scope: Scope, binary: str, audit: AuditSink) -> None:
        adapter.bind_scope(scope)
        self.adapter = adapter
        self.scope = scope
        self.binary = binary
        self.audit = audit
        self.resolver = EndpointResolver(scope, adapter._run_http_kube, binary)
        self._tunnel_address: tuple[str, int, int] | None = None
        self._tunnel_process: subprocess.Popen | None = None

    def _require_live_scope(self) -> None:
        if self.scope.expired():
            raise PermissionError("engagement expired")

    @contextlib.contextmanager
    def tunnel(self, endpoint: Endpoint) -> Iterator[str]:
        if self.binary not in {"oc", "kubectl"} or endpoint.resource != "pods":
            raise PermissionError("port-forward requires an authorized Kubernetes Pod")
        if not endpoint.namespace or not endpoint.uid or not endpoint.remote_port:
            raise PermissionError("port-forward requires a concrete Pod identity and port")
        self._require_live_scope()

        def verify_pod() -> None:
            self.resolver.authorize(
                endpoint.context, endpoint.namespace, "pods", endpoint.name, "port-forward"
            )
            pods = self.resolver.objects(
                endpoint.context, endpoint.namespace, "pods", endpoint.name
            )
            if (
                len(pods) != 1
                or pods[0].metadata.uid != endpoint.uid
                or pods[0].status.get("phase") != "Running"
            ):
                raise PermissionError("port-forward Pod identity or readiness changed")

        verify_pod()
        args = [
            self.binary,
            f"--context={endpoint.context}",
            "--namespace",
            endpoint.namespace,
            "port-forward",
            f"pod/{endpoint.name}",
            f":{endpoint.remote_port}",
            "--address=127.0.0.1",
        ]
        # KUBECONFIG and HOME belong to the operator. The same validated
        # plugin environment is used for discovery and port-forward.
        names = self.adapter._http_kube_env_names(endpoint.context)
        env = {key: value for key, value in os.environ.items() if key in names}
        self._require_live_scope()
        with subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        ) as process:
            drain = None
            try:
                deadline = time.monotonic() + 15
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    buffer = b""
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError("port-forward exited before readiness")
                        for key, _ in selector.select(timeout=0.2):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if not chunk:
                                raise RuntimeError("port-forward closed before readiness")
                            buffer += chunk
                            if len(buffer) > 65536:
                                raise RuntimeError("port-forward readiness output too large")
                            lines = buffer.split(b"\n")
                            buffer = lines.pop()
                            for line in lines:
                                match = re.fullmatch(
                                    rb"Forwarding from 127\.0\.0\.1:(\d+) -> (\d+)\r?", line
                                )
                                if not match:
                                    continue
                                port, remote = map(int, match.groups())
                                if not 1 <= port <= 65535 or remote != endpoint.remote_port:
                                    raise RuntimeError("invalid port-forward readiness")

                                # Keep draining the pipe after readiness so kubectl cannot
                                # stall on its per-connection messages.
                                def consume() -> None:
                                    while process.stdout.read(4096):
                                        pass

                                drain = threading.Thread(target=consume, daemon=True)
                                drain.start()
                                verify_pod()
                                destination = urlsplit(endpoint.origin)
                                host = destination.hostname
                                if not host or destination.scheme not in {"http", "https"}:
                                    raise ValueError("invalid tunnel origin")
                                origin_port = destination.port or (
                                    443 if destination.scheme == "https" else 80
                                )
                                self._tunnel_address = (host, origin_port, port)
                                self._tunnel_process = process
                                try:
                                    yield endpoint.origin
                                finally:
                                    self._tunnel_address = None
                                    self._tunnel_process = None
                                return
                raise TimeoutError("port-forward readiness timed out")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if drain is not None:
                    drain.join(timeout=3)

    def curl(
        self,
        argv: list[str],
        host: str,
        headers: tuple[str, ...] = (),
        *,
        ca_bundle: str | None = None,
        insecure_tls: bool = False,
        context: str | None = None,
        require_tunnel: bool = False,
    ) -> tuple[int, str, str]:
        if insecure_tls:
            cluster = self.scope.clusters.get(context)
            if (
                self.scope.environment != "lab"
                or not context
                or not self.scope.http_context_allowed(context)
                or cluster is None
                or not cluster.http_discovery.insecure_tls
            ):
                raise PermissionError("insecure TLS requires an explicit lab engagement grant")
        se = self.adapter._safe_exec()
        profile = se.profile("validation-step")
        # --disable must be the first curl option, before curl can read .curlrc.
        command = [argv[0], "--disable", "--noproxy", "*", *argv[1:]]
        verdict = se.validate_argv(command, profile, allowed_hosts=(host,))
        if not verdict.ok:
            raise PermissionError("HTTP execution policy denied the request")
        tunnel = self._tunnel_address
        if require_tunnel and not tunnel:
            raise RuntimeError("owned port-forward is no longer running")
        if tunnel and tunnel[0] != host:
            raise PermissionError("HTTP host does not match the owned tunnel")
        if tunnel and (self._tunnel_process is None or self._tunnel_process.poll() is not None):
            raise RuntimeError("owned port-forward is no longer running")
        self._require_live_scope()
        return se.run_segments(
            (tuple(command),),
            profile,
            timeout=30,
            allowed_hosts=(host,),
            curl_connect_to=tunnel,
            curl_stdin_headers=headers,
            curl_ca_bundle=ca_bundle,
            curl_insecure_tls=insecure_tls,
            curl_insecure_lab=insecure_tls,
        )

    def token(self, endpoint: Endpoint, probe: HttpProbe) -> str | None:
        if not probe.authenticate:
            return None
        self._require_live_scope()
        if not endpoint.credentials:
            raise PermissionError("credentials are not authorized for this HTTP endpoint")
        token = os.environ.get("VF_OAUTH_TOKEN")
        if not token:
            if not probe.service_account or not endpoint.namespace:
                raise RuntimeError("authenticated HTTP probe requires an available credential")
            self.resolver.authorize(
                endpoint.context,
                endpoint.namespace,
                "serviceaccounts/token",
                probe.service_account,
                "create",
            )
            self._require_live_scope()
            code, output, _ = self.adapter._run_http_kube(
                [
                    self.binary,
                    f"--context={endpoint.context}",
                    "--namespace",
                    endpoint.namespace,
                    "create",
                    "token",
                    probe.service_account,
                    "--duration=10m",
                ],
                timeout=15,
            )
            if code or not output.strip():
                raise RuntimeError("could not obtain the authorized ServiceAccount credential")
            token = output.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in token):
            raise ValueError("invalid credential")
        return token

    @staticmethod
    def _headers(headers: dict[str, str]) -> tuple[str, ...]:
        return tuple(f"{name}: {value}" for name, value in headers.items())

    def execute(self, context: str, probe: HttpProbe) -> HttpResult:
        endpoint = self.resolver.resolve(context, probe)
        if endpoint.context != context:
            raise PermissionError("resolved HTTP context does not match the selected context")
        cluster = self.scope.clusters.get(context)
        if not cluster or not cluster.api or not endpoint.resolved_api:
            raise PermissionError("resolved HTTP endpoint requires a pinned engagement API")
        if http_origin(cluster.api) != http_origin(endpoint.resolved_api):
            raise PermissionError("resolved HTTP API does not match the engagement API")
        expected_resource = {
            "route": "routes",
            "service": "pods",
            "node": "nodes",
            "direct": "http_targets",
        }[probe.mode]
        if endpoint.resource != expected_resource:
            raise PermissionError("resolved HTTP resource does not match the requested mode")
        if probe.namespaces and endpoint.namespace not in probe.namespaces:
            raise PermissionError("resolved HTTP namespace does not match the requested target")
        if probe.mode != "service" and probe.name and endpoint.name != probe.name:
            raise PermissionError("resolved HTTP name does not match the requested target")
        method_verb = {
            "GET": "get",
            "HEAD": "get",
            "OPTIONS": "get",
            "POST": "create",
            "PUT": "update",
            "PATCH": "patch",
            "DELETE": "delete",
        }[probe.method]
        direct_origin = (
            {"url": endpoint.origin}
            if endpoint.resource == "http_targets" and endpoint.namespace is None
            else {}
        )
        for verb in ("port-forward+http", method_verb):
            self.resolver.authorize(
                endpoint.context,
                endpoint.namespace,
                endpoint.resource,
                endpoint.name or None,
                verb,
                **direct_origin,
            )
        if (probe.authenticate or probe.csrf) and not endpoint.credentials:
            raise PermissionError("credentials and sessions are not authorized for this endpoint")
        parsed = urlsplit(endpoint.origin)
        if (
            (probe.authenticate or probe.csrf)
            and parsed.scheme != "https"
            and not endpoint.remote_port
        ):
            raise PermissionError("credentials require HTTPS outside an owned tunnel")
        policy = cluster.http_discovery
        if policy.insecure_tls and self.scope.environment != "lab":
            raise PermissionError("insecure TLS requires an explicit lab engagement grant")
        if probe.authenticate and not (policy.session_check_path and policy.session_check_contains):
            raise RuntimeError("authenticated probe requires an operator-configured identity check")
        authorize_api_request(endpoint, endpoint.resolved_api, probe.method, probe.path)
        if probe.csrf:
            authorize_api_request(endpoint, endpoint.resolved_api, "GET", "/")
        if probe.authenticate:
            authorize_api_request(endpoint, endpoint.resolved_api, "GET", policy.session_check_path)
        if probe.csrf or probe.authenticate:
            self.resolver.authorize(
                endpoint.context,
                endpoint.namespace,
                endpoint.resource,
                endpoint.name or None,
                "get",
                **direct_origin,
            )
        self.audit.append(event="http-endpoint", endpoint=asdict(endpoint))
        token = self.token(endpoint, probe)
        headers = dict(probe.headers)
        # Only the fixed synthetic spoof marker is public; arbitrary header values
        # can be credentials regardless of their names.
        secrets = [value for value in headers.values() if value and value != "vf-spoof-canary"]
        if token:
            headers["Authorization"] = f"Bearer {token}"
            secrets.append(token)
        tls = {
            "ca_bundle": policy.ca_bundle,
            "insecure_tls": policy.insecure_tls,
            "context": context,
            "require_tunnel": bool(endpoint.remote_port),
        }
        connection = (
            self.tunnel(endpoint)
            if endpoint.remote_port
            else contextlib.nullcontext(endpoint.origin)
        )
        with connection as origin:
            host = urlsplit(origin).hostname
            if not host:
                raise ValueError("invalid HTTP origin")
            if probe.csrf:
                args = [
                    "curl",
                    "-sS",
                    "--max-time",
                    "20",
                    "-D",
                    "-",
                    "-o",
                    "/dev/null",
                    "--url",
                    f"{origin}/",
                ]
                code, output, _ = self.curl(args, host, self._headers(headers), **tls)
                statuses = [
                    line.split()[1]
                    for line in output.splitlines()
                    if line.startswith("HTTP/") and len(line.split()) >= 2
                ]
                if code or not statuses or not statuses[-1].startswith("2"):
                    raise RuntimeError("HTTP session initialization failed")
                cookies = SimpleCookie()
                try:
                    for line in output.splitlines():
                        if line.lower().startswith("set-cookie:"):
                            cookies.load(line.partition(":")[2].strip())
                except Exception as exc:
                    raise RuntimeError("invalid HTTP session cookies") from exc
                csrf = next(
                    (item.value for name, item in cookies.items() if "csrf" in name.lower()), None
                )
                if not csrf:
                    raise RuntimeError("HTTP session initialization did not supply a CSRF cookie")
                secrets.extend(item.value for item in cookies.values() if item.value)
                headers["Cookie"] = "; ".join(
                    item.OutputString(attrs=[]) for item in cookies.values()
                )
                headers["X-CSRFToken"] = csrf
                headers["X-CSRF-Token"] = csrf
            if probe.authenticate:
                args = [
                    "curl",
                    "-sS",
                    "--max-time",
                    "20",
                    "-w",
                    "\nvf-identity-status:%{http_code}",
                    "--url",
                    f"{origin}{policy.session_check_path}",
                ]
                code, output, _ = self.curl(args, host, self._headers(headers), **tls)
                body, separator, status = output.rpartition("\nvf-identity-status:")
                if (
                    code
                    or not separator
                    or not re.fullmatch(r"2\d\d", status.strip())
                    or policy.session_check_contains not in body
                ):
                    raise RuntimeError("authenticated session identity check failed")
            method_args = ["--head"] if probe.method == "HEAD" else ["-X", probe.method]
            args = [
                "curl",
                "-sS",
                "--max-time",
                "20",
                "--compressed",
                *method_args,
                "--url",
                f"{origin}{probe.path}",
                "-w",
                "\nvf-http-status:%{http_code}",
            ]
            for attempt in range(3):
                code, output, error = self.curl(args, host, self._headers(headers), **tls)
                # Curl 7 means no connection was established, so no HTTP request
                # was sent. Never replay a mutating request or a response failure.
                if not (
                    code == 7
                    and endpoint.remote_port
                    and probe.method in {"GET", "HEAD", "OPTIONS"}
                    and attempt < 2
                ):
                    break
                time.sleep(attempt + 1)
        # Extract the curl-owned trailer before redacting arbitrary secrets or
        # appending stderr, neither of which is safe input for status parsing.
        match = re.search(r"\nvf-http-status:(\d{3})\Z", output)
        status = match.group(1) if match else None
        for secret in sorted(set(secrets), key=len, reverse=True):
            output = output.replace(secret, "[REDACTED]")
            error = error.replace(secret, "[REDACTED]")
        # HEAD responses can introduce new cookies not present in the session.
        output = re.sub(
            r"(?im)^(set-cookie|authorization|proxy-authorization):[^\r\n]*",
            r"\1: [REDACTED]",
            output,
        )
        return HttpResult(code, redact_credentials(output), redact_credentials(error), status)
