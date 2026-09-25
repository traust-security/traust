from __future__ import annotations

import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock

import pytest
from adapters.http import HttpExecutor
from adapters.k8s import K8sAdapter
from execute import AuditLog, run
from http_endpoints import Endpoint, EndpointResolver, HttpProbe
from http_policy_io import expiry_date
from http_scope import HttpDiscovery, origin
from scope import Action, ClusterScope, Scope

from tests.test_http_endpoints import restricted


@pytest.fixture
def scope() -> Scope:
    return Scope(
        modes={"explicit"},
        clusters={
            "lab": ClusterScope(
                context="lab",
                namespaces=["app"],
                explicit_namespaces={"app"},
                http_discovery=HttpDiscovery.model_validate(
                    {"nodes": {"names": ["worker-0"], "networks": ["10.0.0.0/24"]}}
                ),
            )
        },
    )


def test_structured_rollback_rejected(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock()
    rollback = Mock()
    monkeypatch.setattr(K8sAdapter, "execute", execute)
    monkeypatch.setattr(K8sAdapter, "rollback", rollback)
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "blocked",
                        "adapter": "k8s",
                        "verb": "port-forward+http",
                        "target": {
                            "context": "lab",
                            "namespace": "app",
                            "http": {"method": "POST"},
                        },
                        "rollback": "oc delete pods --all -n outside",
                    }
                ]
            }
        )
    )
    results, _ = run(plan, scope, tmp_path, profile_map=restricted())
    assert results[0].verdict == "blocked_by_scope"
    execute.assert_not_called()
    rollback.assert_not_called()


def test_node_names_limit_general_scope(scope: Scope) -> None:
    assert not scope.is_in_scope(
        Action(adapter="k8s", context="lab", resource="nodes", name="other", verb="get")
    )[0]
    assert not scope.is_in_scope(
        Action(adapter="k8s", context="lab", resource="nodes", verb="list")
    )[0]
    assert scope.is_in_scope(
        Action(adapter="k8s", context="lab", resource="nodes", name="worker-0", verb="get")
    )[0]


@pytest.mark.parametrize(
    "value", ["null", "", "tomorrow", "2026-99-99", "2099-01-01\noff_limits: []"]
)
def test_invalid_expiry(value: str) -> None:
    with pytest.raises(ValueError, match="ISO"):
        expiry_date(value)


def test_origin_defaults() -> None:
    assert origin("http://example.com") == origin("http://example.com:80")
    assert origin("http://example.com") != origin("http://example.com:443")


def test_nested_data_validated(scope: Scope) -> None:
    command = Mock(
        side_effect=[
            (0, "https://api.example:6443", ""),
            (
                0,
                json.dumps({"metadata": {"name": "worker-0"}, "status": {"addresses": [None]}}),
                "",
            ),
        ]
    )
    with pytest.raises(ValueError, match="discovery response"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab", HttpProbe(mode="node", name="worker-0")
        )


@pytest.mark.parametrize("response", ["HTTP/1.1 403 Forbidden\r\n", "HTTP/1.1 200 OK\r\n"])
def test_csrf_failure_stops_probe(scope: Scope, tmp_path: Path, response: str) -> None:
    executor = HttpExecutor(K8sAdapter(), scope, "oc", AuditLog(tmp_path / "audit"))
    executor.resolver.resolve = Mock(
        return_value=Endpoint("https://web.example", "lab", "app", "routes", "web")
    )
    executor.curl = Mock(return_value=(0, response, ""))
    with pytest.raises(RuntimeError, match="session initialization"):
        executor.execute("lab", HttpProbe(csrf=True))
    executor.curl.assert_called_once()


def test_private_headers_not_in_process_arguments(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_engine._util import safe_exec

    adapter = K8sAdapter()
    adapter.bind_profile_map(restricted())
    executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit"))
    launch = Mock(return_value=(0, "", ""))
    monkeypatch.setattr(safe_exec, "run_segments", launch)
    executor.curl(["curl", "-H", "Authorization: Bearer canary", "http://127.0.0.1/"], "127.0.0.1")
    argv = launch.call_args.args[0][0]
    assert not any("canary" in value for value in argv)
    assert "Authorization: Bearer canary" in launch.call_args.kwargs["input_"]
    assert argv[argv.index("--noproxy") + 1] == "*"


@pytest.mark.skipif(not shutil.which("curl"), reason="curl is required")
def test_real_head_bypasses_proxy(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "12345")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
            monkeypatch.setenv("no_proxy", "")
            adapter = K8sAdapter()
            adapter.bind_profile_map(restricted())
            executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit"))
            executor.resolver.resolve = Mock(
                return_value=Endpoint(
                    f"http://127.0.0.1:{server.server_port}", "lab", "app", "routes", "web"
                )
            )
            code, output, _ = executor.execute("lab", HttpProbe(method="HEAD"))
            assert code == 0
            assert "vf-http-status:200" in output
        finally:
            server.shutdown()
            thread.join(timeout=3)


@pytest.mark.skipif(
    not shutil.which("curl") or not shutil.which("openssl"), reason="TLS tools required"
)
def test_real_tls_ca_and_session(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ssl
    import subprocess

    certificate = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:web.app.svc",
        ],
        check=True,
        capture_output=True,
    )
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received.append(dict(self.headers))
            authenticated = self.headers.get("Authorization") == "Bearer token-canary"
            session_valid = "session=session-canary" in self.headers.get("Cookie", "")
            self.send_response(
                200 if authenticated and (self.path == "/" or session_valid) else 403
            )
            self.send_header("Content-Length", str(len(b"token-canary session-canary csrf-canary")))
            if self.path == "/":
                self.send_header("Set-Cookie", "custom-csrf=csrf-canary; Secure")
                self.send_header("Set-Cookie", "session=session-canary; Secure")
            self.end_headers()
            self.wfile.write(b"token-canary session-canary csrf-canary")

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
            scope.clusters["lab"].http_discovery = HttpDiscovery(
                ca_bundle=str(certificate), session_check_path="/identity"
            )
            adapter = K8sAdapter()
            adapter.bind_profile_map(restricted())
            executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit"))
            executor.resolver.resolve = Mock(
                return_value=Endpoint(
                    f"https://web.app.svc:{server.server_port}",
                    "lab",
                    "app",
                    "routes",
                    "web",
                    credentials=True,
                )
            )
            executor._tunnel_address = ("web.app.svc", server.server_port)
            original_curl = executor.curl

            def checked_curl(argv: list[str], host: str) -> tuple[int, str, str]:
                result = original_curl(argv, host)
                assert result[0] == 0, result[2]
                return result

            executor.curl = checked_curl
            code, output, _ = executor.execute(
                "lab", HttpProbe(path="/probe", authenticate=True, csrf=True)
            )
            assert code == 0
            assert "canary" not in output
            assert received[0]["Authorization"] == "Bearer token-canary"
            assert "custom-csrf=csrf-canary" in received[1]["Cookie"]
            assert "session=session-canary" in received[1]["Cookie"]
        finally:
            server.shutdown()
            thread.join(timeout=3)


@pytest.mark.parametrize("failure", ["exit", "timeout", "kill"])
def test_tunnel_failure_cleanup(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import io
    import subprocess

    from adapters import http

    process = Mock(stdout=io.BytesIO())
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    process.poll.return_value = 1 if failure == "exit" else None
    if failure == "kill":
        process.wait.side_effect = [subprocess.TimeoutExpired("oc", 3), 0]
    selector = Mock()
    selector.__enter__ = Mock(return_value=selector)
    selector.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(http.selectors, "DefaultSelector", Mock(return_value=selector))
    monkeypatch.setattr(http.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(
        http.time, "monotonic", Mock(side_effect=[0, 1 if failure == "exit" else 16])
    )
    executor = HttpExecutor(K8sAdapter(), scope, "oc", AuditLog(tmp_path / "audit"))
    with (
        pytest.raises((RuntimeError, TimeoutError)),
        executor.tunnel(
            Endpoint("http://127.0.0.1", "lab", "app", "pods", "web", remote_port=8080)
        ),
    ):
        pytest.fail("tunnel should not become ready")
    if failure != "exit":
        process.terminate.assert_called_once()
    if failure == "kill":
        process.kill.assert_called_once()


@pytest.mark.parametrize("command", ["oc get nodes other", "oc get nodes", "oc get node/other"])
def test_declared_node_name_does_not_authorize_command(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    execute = Mock()
    monkeypatch.setattr(K8sAdapter, "execute", execute)
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "node",
                        "adapter": "k8s",
                        "verb": "get",
                        "target": {"context": "lab", "resource": "nodes", "name": "worker-0"},
                        "cmd": command,
                    }
                ]
            }
        )
    )
    results, _ = run(plan, scope, tmp_path, profile_map=restricted())
    assert results[0].verdict == "blocked_by_scope"
    execute.assert_not_called()
