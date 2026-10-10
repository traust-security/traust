from __future__ import annotations

import contextlib
import os
import selectors
import shlex
import subprocess
import time
from collections.abc import Iterator
from dataclasses import asdict
from http.cookies import SimpleCookie
from typing import Protocol
from urllib.parse import urlsplit

if __package__ and "." in __package__:
    from ..http_endpoints import Endpoint, EndpointResolver, HttpProbe
    from ..scope import Scope
else:
    from http_endpoints import Endpoint, EndpointResolver, HttpProbe
    from scope import Scope

from .base import AdapterBase


class AuditSink(Protocol):
    def append(self, **fields: object) -> None: ...


class HttpExecutor:
    def __init__(self, adapter: AdapterBase, scope: Scope, binary: str, audit: AuditSink) -> None:
        self.adapter = adapter
        self.scope = scope
        self.binary = binary
        self.audit = audit
        self.resolver = EndpointResolver(scope, adapter._run, binary)
        self._tunnel_address: tuple[str, int] | None = None

    @contextlib.contextmanager
    def tunnel(self, endpoint: Endpoint) -> Iterator[str]:
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
        names = {"PATH", "HOME", "KUBECONFIG", "LANG"}
        names.update(self.scope.clusters[endpoint.context].http_discovery.kube_env)
        with subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={key: value for key, value in os.environ.items() if key in names},
        ) as process:
            try:
                deadline = time.monotonic() + 15
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    buffer = b""
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError("port-forward exited before readiness")
                        for key, _ in selector.select(timeout=0.2):
                            buffer += os.read(key.fileobj.fileno(), 4096)
                            if len(buffer) > 65536:
                                raise RuntimeError("port-forward readiness output too large")
                            lines = buffer.split(b"\n")
                            buffer = lines.pop()
                            for line in lines:
                                text = line.decode("utf-8", errors="replace")
                                if text.startswith("Forwarding from 127.0.0.1:"):
                                    address = text.split(" -> ", 1)[0].removeprefix(
                                        "Forwarding from "
                                    )
                                    port = urlsplit(f"http://{address}").port
                                    if port is None or not 1 <= port <= 65535:
                                        raise ValueError("invalid port-forward readiness")
                                    destination = urlsplit(endpoint.origin)
                                    self._tunnel_address = (destination.hostname, port)
                                    try:
                                        yield f"{destination.scheme}://{destination.hostname}:{port}"
                                    finally:
                                        self._tunnel_address = None
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

    def curl(self, argv: list[str], host: str) -> tuple[int, str, str]:
        engine = self.adapter._safe_exec()
        profile = engine.get_profile(
            "validation-step", profile_map=self.adapter._safe_exec_profile_map
        )
        argv = [argv[0], "--noproxy", "*", *argv[1:]]
        verdict = engine.vet_command_string(shlex.join(argv), profile, allowed_hosts=(host,))
        if not verdict.ok:
            raise PermissionError(f"HTTP execution policy: {verdict.reason}")
        command = list(verdict.segments[0])
        private_headers = []
        prepared = []
        index = 0
        while index < len(command):
            if command[index] == "-H" and command[index + 1].partition(":")[0].lower() in {
                "authorization",
                "cookie",
                "x-csrftoken",
                "x-csrf-token",
            }:
                private_headers.append(command[index + 1])
                index += 2
            else:
                prepared.append(command[index])
                index += 1
        if private_headers:
            prepared[1:1] = ["-H", "@-"]
        if self._tunnel_address:
            tunnel_host, port = self._tunnel_address
            if host != tunnel_host:
                raise PermissionError("HTTP host does not match the owned tunnel")
            prepared[1:1] = ["--connect-to", f"{tunnel_host}:{port}:127.0.0.1:{port}"]
        return engine.run_segments(
            [prepared],
            profile,
            timeout=30,
            input_="\n".join(private_headers) + "\n" if private_headers else None,
        )

    def token(self, endpoint: Endpoint, probe: HttpProbe) -> str | None:
        if not probe.authenticate:
            return None
        if not endpoint.credentials:
            raise PermissionError("credentials are not authorized for this HTTP endpoint")
        token = os.environ.get("VF_OAUTH_TOKEN")
        if token:
            return token
        if not probe.service_account or not endpoint.namespace:
            raise RuntimeError("authenticated HTTP probe requires an available credential")
        self.resolver.authorize(
            endpoint.context,
            endpoint.namespace,
            "serviceaccounts/token",
            probe.service_account,
            "create",
        )
        code, output, _ = self.adapter._run(
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
        return output.strip()

    def execute(self, context: str, probe: HttpProbe) -> tuple[int, str, str]:
        endpoint = self.resolver.resolve(context, probe)
        self.resolver.authorize(
            endpoint.context,
            endpoint.namespace,
            endpoint.resource,
            endpoint.name,
            "port-forward+http",
        )
        verb = {
            "GET": "get",
            "HEAD": "get",
            "OPTIONS": "get",
            "POST": "create",
            "PUT": "update",
            "PATCH": "patch",
            "DELETE": "delete",
        }[probe.method]
        self.resolver.authorize(
            endpoint.context, endpoint.namespace, endpoint.resource, endpoint.name, verb
        )
        if (
            probe.authenticate
            and urlsplit(endpoint.origin).scheme != "https"
            and not endpoint.remote_port
        ):
            raise PermissionError("credentials require HTTPS outside an owned tunnel")
        self.audit.append(event="http-endpoint", endpoint=asdict(endpoint))
        token = self.token(endpoint, probe)
        secrets = [token] if token else []
        headers = dict(probe.headers)
        policy = self.scope.clusters[context].http_discovery
        tls_args = ["--cacert", policy.ca_bundle] if policy.ca_bundle else []
        if policy.insecure_tls:
            tls_args.append("--insecure")
        if token:
            if any(ord(char) < 32 or ord(char) == 127 for char in token):
                raise ValueError("invalid credential")
            headers["Authorization"] = f"Bearer {token}"
        connection = (
            self.tunnel(endpoint)
            if endpoint.remote_port
            else contextlib.nullcontext(endpoint.origin)
        )
        with connection as origin:
            host = urlsplit(origin).hostname
            if probe.csrf:
                args = ["curl", *tls_args, "-sS", "--max-time", "20", "-D", "-", "-o", "/dev/null"]
                for name, value in headers.items():
                    args.extend(["-H", f"{name}: {value}"])
                code, output, _error = self.curl([*args, f"{origin}/"], host)
                statuses = [
                    line.split()[1]
                    for line in output.splitlines()
                    if line.startswith("HTTP/") and len(line.split()) >= 2
                ]
                if code or not statuses or not statuses[-1].startswith("2"):
                    raise RuntimeError("HTTP session initialization failed")
                cookies = SimpleCookie()
                for line in output.splitlines():
                    if line.lower().startswith("set-cookie:"):
                        cookies.load(line.partition(":")[2].strip())
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
            if probe.csrf and probe.authenticate:
                if not policy.session_check_path:
                    raise RuntimeError(
                        "authenticated session requires an operator-configured identity check"
                    )
                check_args = [
                    "curl",
                    *tls_args,
                    "-sS",
                    "--max-time",
                    "20",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                ]
                for name, value in headers.items():
                    if any(ord(char) < 32 or ord(char) == 127 for char in value):
                        raise ValueError("invalid session header")
                    check_args.extend(["-H", f"{name}: {value}"])
                code, status, _error = self.curl(
                    [*check_args, f"{origin}{policy.session_check_path}"], host
                )
                if code or not status.strip().startswith("2"):
                    raise RuntimeError("authenticated session identity check failed")
            method_args = ["--head"] if probe.method == "HEAD" else ["-X", probe.method]
            args = ["curl", *tls_args, "-sS", "--max-time", "20", "--compressed", *method_args]
            for name, value in headers.items():
                if any(ord(char) < 32 or ord(char) == 127 for char in value):
                    raise ValueError("invalid response-derived HTTP header")
                args.extend(["-H", f"{name}: {value}"])
            args.extend([f"{origin}{probe.path}", "-w", "\nvf-http-status:%{http_code}"])
            code, output, error = self.curl(args, host)
            for secret in secrets:
                output = output.replace(secret, "[REDACTED]")
                error = error.replace(secret, "[REDACTED]")
            return code, output, error
