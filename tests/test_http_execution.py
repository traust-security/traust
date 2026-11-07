from __future__ import annotations

import datetime as dt
import io
import json
import shutil
import ssl
import subprocess
import threading
from contextlib import nullcontext
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from adapters import StepResult
from adapters.http import HttpExecutor
from adapters.k8s import K8sAdapter, _http_target_error
from execute import AuditLog, run
from http_endpoints import Endpoint, HttpProbe
from scope import ClusterScope, OffLimit, Scope
from traust_core.v1.models.validation import HttpDiscovery, HttpTarget


def engagement(*, policy=None, credentials=False, environment=None):
    return Scope(
        environment=environment,
        modes={"explicit"},
        clusters={
            "lab": ClusterScope(
                context="lab",
                api="https://api.example:6443",
                namespaces=["app"],
                explicit_namespaces={"app"},
                http_discovery=policy or HttpDiscovery(),
            )
        },
        http_targets=(
            HttpTarget(
                host="127.0.0.1",
                context="lab",
                namespace="app",
                resource="http_targets",
                credentials=credentials,
            ),
        ),
    )


def executor(scope, tmp_path, endpoint=None):
    instance = HttpExecutor(K8sAdapter(), scope, "oc", AuditLog(tmp_path / "audit"))
    if endpoint is not None:
        instance.resolver.resolve = Mock(
            return_value=replace(endpoint, resolved_api=scope.clusters["lab"].api)
        )
    return instance


def test_http_method_and_session_operations_are_scope_checked(tmp_path):
    scope = engagement()
    scope.off_limits = [OffLimit(namespace="app", resource="routes", verb="create", name="web")]
    target = Endpoint("https://web.example", "lab", "app", "routes", "web")
    instance = executor(scope, tmp_path, target)
    instance.curl = Mock()
    with pytest.raises(PermissionError):
        instance.execute("lab", HttpProbe(method="POST"))
    instance.curl.assert_not_called()

    scope.off_limits = [OffLimit(namespace="app", resource="routes", verb="get", name="web")]
    instance.resolver.resolve.return_value = replace(
        Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True),
        resolved_api=scope.clusters["lab"].api,
    )
    with pytest.raises(PermissionError):
        instance.execute("lab", HttpProbe(method="POST", csrf=True))
    instance.curl.assert_not_called()


def test_auth_requires_explicit_identity_proof(tmp_path, monkeypatch):
    scope = engagement(
        policy=HttpDiscovery(session_check_path="/whoami", session_check_contains="user: alice")
    )
    target = Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
    instance = executor(scope, tmp_path, target)
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl = Mock(return_value=(0, "public page\nvf-identity-status:200", ""))
    with pytest.raises(RuntimeError, match="identity check failed"):
        instance.execute("lab", HttpProbe(authenticate=True))
    instance.curl.assert_called_once()


def test_session_and_token_redacted_from_output(tmp_path, monkeypatch):
    scope = engagement(
        policy=HttpDiscovery(session_check_path="/whoami", session_check_contains="user: alice")
    )
    target = Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
    instance = executor(scope, tmp_path, target)
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl = Mock(
        side_effect=[
            (
                0,
                "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=csrf-canary\r\nSet-Cookie: session=session-canary\r\n",
                "",
            ),
            (0, "user: alice\nvf-identity-status:200", ""),
            (0, "token-canary csrf-canary session-canary\nvf-http-status:200", "token-canary"),
        ]
    )
    code, output, error, status = instance.execute("lab", HttpProbe(authenticate=True, csrf=True))
    assert code == 0
    assert status == "200"
    assert "canary" not in output + error
    headers = instance.curl.call_args_list[-1].args[2]
    assert "Authorization: Bearer token-canary" in headers
    assert any("session=session-canary" in item for item in headers)


def pinned_api_executor(tmp_path, mode, identity_path):
    policy = HttpDiscovery.model_validate(
        {
            "session_check_path": identity_path,
            "session_check_contains": "alice",
            **(
                {"nodes": {"names": ["worker"], "networks": ["10.0.0.0/24"]}}
                if mode == "node"
                else {}
            ),
        }
    )
    scope = engagement(policy=policy)
    api = "https://10.0.0.2:10250" if mode == "node" else "https://api.example:6443"
    scope.clusters["lab"].api = api
    if mode == "direct":
        scope.http_targets = (HttpTarget(context="lab", host="api.example", credentials=True),)
        probe = {"mode": mode, "url": api, "namespaces": ("app",)}
        objects = []
    elif mode == "route":
        scope.http_targets = (
            HttpTarget(
                context="lab",
                host="api.example",
                namespace="app",
                resource="routes",
                name="web",
                credentials=True,
            ),
        )
        probe = {"mode": mode, "name": "web", "namespaces": ("app",), "port": 6443}
        objects = [
            {
                "metadata": {"name": "web", "namespace": "app"},
                "spec": {"host": "api.example", "tls": {}},
            }
        ]
    else:
        scope.http_targets = (
            HttpTarget(
                context="lab", host="10.0.0.2", resource="nodes", name="worker", credentials=True
            ),
        )
        probe = {"mode": mode, "name": "worker", "port": 10250}
        objects = [
            {
                "metadata": {"name": "worker"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]},
            }
        ]
    instance = executor(scope, tmp_path)
    view = {"clusters": [{"cluster": {"server": api}}]}
    instance.resolver.run = Mock(
        side_effect=[(0, json.dumps(value), "") for value in [view, *objects]]
    )
    instance.curl = Mock()
    return instance, probe


@pytest.mark.parametrize("mode", ["direct", "route", "node"])
@pytest.mark.parametrize(
    "csrf,authenticate,identity_path",
    [
        (True, False, "/version"),
        (True, True, "/version"),
        (False, True, "/api/v1/users"),
        (True, True, "/api/v1/users"),
    ],
)
def test_pinned_api_auxiliary_refusals_precede_every_request(
    tmp_path, mode, csrf, authenticate, identity_path
):
    instance, probe = pinned_api_executor(tmp_path, mode, identity_path)
    instance.token = Mock()
    with pytest.raises(PermissionError, match="health and version"):
        instance.execute(
            "lab", HttpProbe(**probe, path="/healthz", csrf=csrf, authenticate=authenticate)
        )
    instance.curl.assert_not_called()
    instance.token.assert_not_called()
    assert instance.resolver.run.call_count == (1 if mode == "direct" else 2)


@pytest.mark.parametrize("mode", ["direct", "route", "node"])
def test_pinned_api_permits_allowed_identity_check(tmp_path, monkeypatch, mode):
    instance, probe = pinned_api_executor(tmp_path, mode, "/version")
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl.side_effect = [
        (0, "alice\nvf-identity-status:200", ""),
        (0, "ok\nvf-http-status:200", ""),
    ]
    result = instance.execute(
        "lab", HttpProbe(**probe, method="HEAD", path="/healthz", authenticate=True)
    )
    assert result[0] == 0
    urls = [call.args[0][call.args[0].index("--url") + 1] for call in instance.curl.call_args_list]
    api = instance.scope.clusters["lab"].api
    assert urls == [api + "/version", api + "/healthz"]
    assert instance.resolver.run.call_count == (1 if mode == "direct" else 2)


def test_non_api_destination_allows_auxiliary_requests(tmp_path, monkeypatch):
    instance, probe = pinned_api_executor(tmp_path, "direct", "/whoami")
    instance.scope.http_targets = (HttpTarget(context="lab", host="web.example", credentials=True),)
    probe["url"] = "https://web.example"
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl.side_effect = [
        (0, "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=csrf-canary\r\n", ""),
        (0, "alice\nvf-identity-status:200", ""),
        (0, "ok\nvf-http-status:200", ""),
    ]
    assert (
        instance.execute("lab", HttpProbe(**probe, path="/probe", csrf=True, authenticate=True))[0]
        == 0
    )
    urls = [call.args[0][call.args[0].index("--url") + 1] for call in instance.curl.call_args_list]
    assert urls == [
        "https://web.example/",
        "https://web.example/whoami",
        "https://web.example/probe",
    ]
    instance.resolver.run.assert_called_once()


def test_owned_tunnel_can_use_auxiliary_paths_when_service_name_matches_api(tmp_path, monkeypatch):
    scope = engagement(
        policy=HttpDiscovery(session_check_path="/whoami", session_check_contains="alice")
    )
    target = Endpoint(
        "https://api.example:6443",
        "lab",
        "app",
        "pods",
        "web",
        credentials=True,
        remote_port=8443,
    )
    instance = executor(scope, tmp_path, target)
    instance.tunnel = Mock(return_value=nullcontext(target.origin))
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl = Mock(
        side_effect=[
            (0, "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=csrf-canary\r\n", ""),
            (0, "alice\nvf-identity-status:200", ""),
            (0, "ok\nvf-http-status:200", ""),
        ]
    )
    assert (
        instance.execute(
            "lab", HttpProbe(mode="service", path="/probe", csrf=True, authenticate=True)
        )[0]
        == 0
    )
    assert instance.curl.call_count == 3


@pytest.mark.parametrize(
    "resolved_api,reason",
    [("", "requires a pinned"), ("https://other.example", "does not match")],
)
def test_resolved_api_binding_must_match_engagement(tmp_path, resolved_api, reason):
    target = Endpoint("https://web.example", "lab", "app", "routes", "web")
    instance = executor(engagement(), tmp_path, target)
    instance.resolver.resolve.return_value = replace(target, resolved_api=resolved_api)
    instance.curl = Mock()
    with pytest.raises(PermissionError, match=reason):
        instance.execute("lab", HttpProbe())
    instance.curl.assert_not_called()


@pytest.mark.parametrize(
    "identity_path,verdict,requests",
    [("/api/v1/users", "blocked_by_scope", 0), ("/version", "inconclusive", 1)],
)
def test_api_auxiliary_refusal_is_scope_block_and_transport_is_inconclusive(
    tmp_path, monkeypatch, identity_path, verdict, requests
):
    scope = engagement(
        policy=HttpDiscovery(session_check_path=identity_path, session_check_contains="alice")
    )
    scope.http_targets = (HttpTarget(context="lab", host="api.example", credentials=True),)
    view = json.dumps({"clusters": [{"cluster": {"server": scope.clusters["lab"].api}}]})
    monkeypatch.setattr(K8sAdapter, "_run_http_kube", Mock(return_value=(0, view, "")))
    curl = Mock(side_effect=RuntimeError("transport unavailable"))
    monkeypatch.setattr(HttpExecutor, "curl", curl)
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    step = {
        "id": "api-identity",
        "verb": "port-forward+http",
        "target": {
            "context": "lab",
            "namespace": "app",
            "resource": "http_targets",
            "http": {
                "mode": "direct",
                "url": "https://api.example:6443",
                "namespaces": ["app"],
                "path": "/healthz",
                "authenticate": True,
            },
        },
    }
    result = K8sAdapter().execute(step, scope, AuditLog(tmp_path / "audit"), tmp_path)
    assert result.verdict == verdict
    assert curl.call_count == requests


def test_curl_secrets_are_stdin_only_and_owned_tunnel_preserves_origin(tmp_path):
    instance = executor(engagement(), tmp_path)
    policy = Mock()
    policy.validate_argv.return_value.ok = True
    policy.run_segments.return_value = (0, "", "")
    instance.adapter._safe_exec = Mock(return_value=policy)
    instance._tunnel_address = ("web.app.svc", 443, 43210)
    instance._tunnel_process = Mock()
    instance._tunnel_process.poll.return_value = None
    instance.curl(
        ["curl", "--url", "https://web.app.svc/path"],
        "web.app.svc",
        ("Authorization: Bearer canary",),
        ca_bundle="/operator/ca.pem",
    )
    args, kwargs = policy.run_segments.call_args
    command = args[0][0]
    assert command[:4] == ("curl", "--disable", "--noproxy", "*")
    assert not any("canary" in item for item in command)
    assert kwargs["curl_stdin_headers"] == ("Authorization: Bearer canary",)
    assert kwargs["curl_connect_to"] == ("web.app.svc", 443, 43210)
    assert kwargs["curl_ca_bundle"] == "/operator/ca.pem"
    assert kwargs["curl_insecure_tls"] is False
    assert "--cacert" not in command and "--insecure" not in command
    assert kwargs["allowed_hosts"] == ("web.app.svc",)
    policy.run_segments.reset_mock()
    instance._tunnel_process.poll.return_value = 1
    with pytest.raises(RuntimeError, match="no longer running"):
        instance.curl(["curl", "--url", "https://web.app.svc/path"], "web.app.svc")
    policy.run_segments.assert_not_called()


def test_expiry_between_requests_blocks_curl_token_and_tunnel(tmp_path, monkeypatch):
    scope = engagement()
    instance = executor(scope, tmp_path)
    scope.expired = Mock(return_value=True)
    policy = Mock()
    policy.validate_argv.return_value.ok = True
    instance.adapter._safe_exec = Mock(return_value=policy)
    with pytest.raises(PermissionError, match="expired"):
        instance.curl(["curl", "--url", "https://web.example/"], "web.example")
    policy.run_segments.assert_not_called()
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    target = Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
    with pytest.raises(PermissionError, match="expired"):
        instance.token(target, HttpProbe(authenticate=True))
    pod = Endpoint(
        "https://web.app.svc", "lab", "app", "pods", "web-0", uid="uid-1", remote_port=8443
    )
    launch = Mock()
    monkeypatch.setattr(subprocess, "Popen", launch)
    with pytest.raises(PermissionError, match="expired"), instance.tunnel(pod):
        pytest.fail("expired engagement cannot start a tunnel")
    launch.assert_not_called()


def test_delete_and_unstructured_commands_never_bypass_execution_gate(tmp_path, monkeypatch):
    called = Mock(return_value=StepResult("x", "k8s", "port-forward+http", {}, "safe", "confirmed"))
    monkeypatch.setattr(K8sAdapter, "execute", called)
    steps = [
        {
            "id": "delete",
            "adapter": "k8s",
            "verb": "port-forward+http",
            "classification": "safe",
            "target": {"context": "lab", "http": {"method": "DELETE"}},
        },
        {
            "id": "shell",
            "adapter": "k8s",
            "verb": "port-forward+http",
            "cmd": "curl http://localhost/",
            "target": {"context": "lab", "namespace": "app"},
        },
        {
            "id": "rollback",
            "adapter": "k8s",
            "verb": "port-forward+http",
            "rollback": "oc delete pods --all",
            "target": {"context": "lab", "http": {"method": "POST"}},
        },
    ]
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"steps": steps}))
    results, _ = run(plan, engagement(), tmp_path, second_pass_novel=False)
    assert [r.verdict for r in results] == ["not_attempted", "blocked_by_scope", "blocked_by_scope"]
    called.assert_not_called()


def test_run_uses_selected_core_and_redacts_recorded_target(tmp_path, monkeypatch):
    import traust.context

    policy = object()
    load = Mock(return_value=SimpleNamespace(safe_exec=policy))
    monkeypatch.setattr(traust.context, "load", load)
    bound = []
    monkeypatch.setattr(K8sAdapter, "bind_safe_exec", lambda self, value: bound.append(value))
    monkeypatch.setattr(
        K8sAdapter,
        "execute",
        lambda self, step, scope, audit, artifacts: StepResult(
            step["id"], "k8s", step["verb"], step["target"], "safe", "inconclusive"
        ),
    )
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "probe",
                        "adapter": "k8s",
                        "verb": "port-forward+http",
                        "target": {
                            "context": "lab",
                            "namespace": "app",
                            "resource": "routes",
                            "http": {
                                "mode": "route",
                                "namespaces": ["app"],
                                "headers": {"X-Test": "secret-canary"},
                                "path": "/?key=secret-canary",
                            },
                        },
                    }
                ]
            }
        )
    )
    results, audit = run(plan, engagement(), tmp_path, config_home=tmp_path)
    load.assert_called_once_with(tmp_path)
    assert bound == [policy]
    assert results[0].target["http"]["headers"]["X-Test"] == "[REDACTED]"
    assert "secret-canary" not in audit.path.read_text()


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", "services"),
        ("namespace", "other"),
        ("namespace", None),
        ("name", "different"),
        ("method", "POST"),
    ],
)
def test_declared_http_target_must_match_probe(tmp_path, monkeypatch, field, value):
    called = Mock()
    monkeypatch.setattr(HttpExecutor, "execute", called)
    target = {
        "context": "lab",
        "namespace": "app",
        "resource": "routes",
        "name": "web",
        "method": "GET",
        "http": {"mode": "route", "name": "web", "namespaces": ["app"]},
    }
    target[field] = value
    step = {"id": "mismatch", "verb": "port-forward+http", "target": target}
    result = K8sAdapter().execute(step, engagement(), AuditLog(tmp_path / "audit"), tmp_path)
    assert result.verdict == "blocked_by_scope"
    called.assert_not_called()


@pytest.mark.parametrize("expected", ["logged in user can access endpoint", "CSRF attack succeeds"])
def test_missing_identity_or_csrf_precondition_is_inconclusive(tmp_path, monkeypatch, expected):
    called = Mock()
    monkeypatch.setattr(HttpExecutor, "execute", called)
    step = {
        "id": "precondition",
        "verb": "port-forward+http",
        "expected": expected,
        "target": {
            "context": "lab",
            "namespace": "app",
            "resource": "routes",
            "http": {"mode": "route", "namespaces": ["app"]},
        },
    }
    result = K8sAdapter().execute(step, engagement(), AuditLog(tmp_path / "audit"), tmp_path)
    assert result.verdict == "inconclusive"
    called.assert_not_called()


def test_multi_namespace_target_is_explicit_candidate_set():
    probe = HttpProbe(mode="route", namespaces=("app", "other"))
    target = {"context": "lab", "resource": "routes", "namespace": None}
    assert _http_target_error(target, probe) is None
    target["namespace"] = "app"
    assert _http_target_error(target, probe) is not None


def test_node_http_post_needs_cluster_mutation_grant(tmp_path):
    scope = engagement(
        policy=HttpDiscovery.model_validate(
            {"nodes": {"names": ["worker-0"], "networks": ["10.0.0.0/24"]}}
        )
    )
    target = Endpoint("https://10.0.0.2:10250", "lab", None, "nodes", "worker-0")
    instance = executor(scope, tmp_path, target)
    instance.curl = Mock()
    with pytest.raises(PermissionError):
        instance.execute("lab", HttpProbe(mode="node", name="worker-0", method="POST"))
    instance.curl.assert_not_called()


@pytest.mark.parametrize("limited_nodes", [False, True])
def test_preflight_omits_unauthorized_node_list(limited_nodes):
    policy = (
        HttpDiscovery.model_validate(
            {"nodes": {"names": ["worker-0"], "networks": ["10.0.0.0/24"]}}
        )
        if limited_nodes
        else HttpDiscovery()
    )
    adapter = K8sAdapter()
    adapter._run = Mock(
        return_value=(
            0,
            json.dumps({"serverVersion": {"gitVersion": "v1.30", "platform": "linux/amd64"}}),
            "",
        )
    )
    fingerprints = adapter.preflight(engagement(policy=policy))
    assert adapter._run.call_count == 1
    assert fingerprints[0].version == "v1.30"
    assert fingerprints[0].details["platform"] == "linux/amd64"
    assert "nodes" not in fingerprints[0].details


def test_preflight_counts_nodes_when_cluster_list_is_authorized():
    scope = engagement()
    scope.clusters["lab"].namespaces = ["*"]
    scope.clusters["lab"].explicit_namespaces = {"*"}
    adapter = K8sAdapter()
    adapter._run = Mock(
        side_effect=[
            (0, '{"serverVersion": {"gitVersion": "v1.30"}}', ""),
            (0, "worker-0 worker-1", ""),
        ]
    )
    fingerprints = adapter.preflight(scope)
    assert adapter._run.call_count == 2
    assert fingerprints[0].version == "v1.30"
    assert fingerprints[0].details["nodes"] == 2


def test_preflight_skips_expired_and_unselected_contexts():
    scope = engagement()
    scope.clusters["other"] = ClusterScope(context="other", namespaces=["*"])
    scope.selected_contexts = ("lab",)
    adapter = K8sAdapter()
    adapter._run = Mock(return_value=(0, '{"serverVersion": {"gitVersion": "v1.30"}}', ""))
    fingerprints = adapter.preflight(scope)
    assert [fp.identity for fp in fingerprints] == ["lab"]
    adapter._run.assert_called_once()
    adapter._run.reset_mock()
    scope.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    assert adapter.preflight(scope) == []
    adapter._run.assert_not_called()


def test_preflight_rechecks_expiry_after_version():
    scope = engagement()
    scope.clusters["lab"].namespaces = ["*"]
    scope.clusters["lab"].explicit_namespaces = {"*"}
    scope.expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
    adapter = K8sAdapter()

    def version(*args, **kwargs):
        scope.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        return 0, '{"serverVersion": {"gitVersion": "v1.30"}}', ""

    adapter._run = Mock(side_effect=version)
    fingerprints = adapter.preflight(scope)
    adapter._run.assert_called_once()
    assert fingerprints[0].version == "v1.30"
    assert "nodes" not in fingerprints[0].details


def test_csrf_requires_credential_grant(tmp_path):
    target = Endpoint("https://web.example", "lab", "app", "routes", "web")
    instance = executor(engagement(), tmp_path, target)
    instance.curl = Mock()
    with pytest.raises(PermissionError, match="sessions"):
        instance.execute("lab", HttpProbe(csrf=True))
    instance.curl.assert_not_called()


@pytest.mark.parametrize("mode", ["route", "service"])
def test_explicit_lab_tls_exception_preserves_authentication_and_csrf(tmp_path, monkeypatch, mode):
    policy = HttpDiscovery(
        insecure_tls=True,
        port_forward_credentials=True,
        session_check_path="/whoami",
        session_check_contains="user: alice",
    )
    scope = engagement(policy=policy, environment="lab")
    target = (
        Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
        if mode == "route"
        else Endpoint(
            "https://web.app.svc",
            "lab",
            "app",
            "pods",
            "web-0",
            uid="pod-uid",
            credentials=True,
            remote_port=8443,
        )
    )
    instance = executor(scope, tmp_path, target)
    if mode == "service":
        instance.tunnel = Mock(return_value=nullcontext(target.origin))
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl = Mock(
        side_effect=[
            (0, "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=csrf-canary\r\n", ""),
            (0, "user: alice\nvf-identity-status:200", ""),
            (0, "token-canary csrf-canary\nvf-http-status:200", ""),
        ]
    )
    code, output, error, status = instance.execute(
        "lab", HttpProbe(mode=mode, authenticate=True, csrf=True)
    )
    assert code == 0 and status == "200" and "canary" not in output + error
    assert all(
        call.kwargs["insecure_tls"] and call.kwargs["context"] == "lab"
        for call in instance.curl.call_args_list
    )
    assert any(
        "Authorization: Bearer token-canary" in header for header in instance.curl.call_args.args[2]
    )


@pytest.mark.parametrize("environment", [None, "production", "staging"])
def test_insecure_tls_is_refused_outside_lab(tmp_path, environment):
    scope = engagement(policy=HttpDiscovery(insecure_tls=True), environment=environment)
    target = Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
    instance = executor(scope, tmp_path, target)
    instance.curl = Mock()
    with pytest.raises(PermissionError, match="explicit lab"):
        instance.execute("lab", HttpProbe())
    instance.curl.assert_not_called()


def test_unverified_tls_cannot_be_requested_without_operator_grant(tmp_path):
    scope = engagement(environment="lab")
    instance = executor(scope, tmp_path)
    with pytest.raises(PermissionError, match="explicit lab"):
        instance.curl(
            ["curl", "--url", "https://web.example/"],
            "web.example",
            insecure_tls=True,
            context="lab",
        )


def test_lab_tls_exception_is_only_a_trusted_core_binding(tmp_path):
    instance = executor(
        engagement(policy=HttpDiscovery(insecure_tls=True), environment="lab"), tmp_path
    )
    safe_exec = Mock()
    safe_exec.validate_argv.return_value.ok = True
    safe_exec.run_segments.return_value = (0, "", "")
    instance.adapter._safe_exec = Mock(return_value=safe_exec)
    instance._tunnel_address = ("web.app.svc", 443, 43210)
    instance._tunnel_process = Mock()
    instance._tunnel_process.poll.return_value = None
    instance.curl(
        ["curl", "--url", "https://web.app.svc/"],
        "web.app.svc",
        ("Authorization: Bearer canary",),
        insecure_tls=True,
        context="lab",
    )
    args, kwargs = safe_exec.run_segments.call_args
    assert kwargs["curl_insecure_tls"] and kwargs["curl_insecure_lab"]
    assert kwargs["curl_connect_to"] == ("web.app.svc", 443, 43210)
    assert kwargs["curl_stdin_headers"] == ("Authorization: Bearer canary",)
    assert all("canary" not in arg and arg != "--insecure" for arg in args[0][0])


def test_default_tls_verification_remains_enabled(tmp_path):
    instance = executor(
        engagement(environment="lab"),
        tmp_path,
        Endpoint("https://web.example", "lab", "app", "routes", "web"),
    )
    instance.curl = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
    instance.execute("lab", HttpProbe())
    assert instance.curl.call_args.kwargs["insecure_tls"] is False


def test_tunnel_rejects_recreated_pod_before_launch(tmp_path, monkeypatch):
    target = Endpoint(
        "https://web.app.svc", "lab", "app", "pods", "web-0", uid="old-uid", remote_port=8443
    )
    instance = executor(engagement(), tmp_path)
    instance.resolver.objects = Mock(
        return_value=[
            SimpleNamespace(metadata=SimpleNamespace(uid="new-uid"), status={"phase": "Running"})
        ]
    )
    launch = Mock()
    monkeypatch.setattr(subprocess, "Popen", launch)
    with pytest.raises(PermissionError, match="identity"), instance.tunnel(target):
        pytest.fail("stale Pod must never be forwarded")
    launch.assert_not_called()


@pytest.mark.parametrize("failure", ["exit", "timeout", "kill"])
def test_tunnel_failure_terminates_owned_process(tmp_path, monkeypatch, failure):
    from adapters import http

    target = Endpoint(
        "https://web.app.svc", "lab", "app", "pods", "web-0", uid="uid-1", remote_port=8443
    )
    instance = executor(engagement(), tmp_path)
    instance.resolver.objects = Mock(
        return_value=[
            SimpleNamespace(metadata=SimpleNamespace(uid="uid-1"), status={"phase": "Running"})
        ]
    )
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
    with pytest.raises((RuntimeError, TimeoutError)), instance.tunnel(target):
        pytest.fail("failed tunnel cannot become ready")
    if failure != "exit":
        process.terminate.assert_called_once()
    if failure == "kill":
        process.kill.assert_called_once()


@pytest.mark.skipif(not shutil.which("curl"), reason="curl is required")
def test_real_head_requires_explicit_destination_and_ignores_proxy(tmp_path, monkeypatch):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            received.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "12345")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
            monkeypatch.setenv("no_proxy", "")
            scope = engagement()
            instance = executor(scope, tmp_path)
            instance.adapter._run_http_kube = Mock(
                return_value=(
                    0,
                    json.dumps({"clusters": [{"cluster": {"server": "https://api.example:6443"}}]}),
                    "",
                )
            )
            instance.resolver.run = instance.adapter._run_http_kube
            probe = HttpProbe(
                mode="direct",
                method="HEAD",
                namespaces=("app",),
                url=f"http://127.0.0.1:{server.server_port}",
                path="/status",
            )
            code, output, _, status = instance.execute("lab", probe)
            assert code == 0 and status == "200" and "vf-http-status:200" in output
            assert received == ["/status"]
        finally:
            server.shutdown()
            worker.join(timeout=3)


@pytest.mark.skipif(
    not shutil.which("curl") or not shutil.which("openssl"), reason="curl and openssl required"
)
def test_real_tls_tunnel_preserves_hostname_and_session(tmp_path, monkeypatch):
    certificate, key = tmp_path / "cert.pem", tmp_path / "key.pem"
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
            "/CN=web.app.svc",
            "-addext",
            "subjectAltName=DNS:web.app.svc",
        ],
        capture_output=True,
        check=True,
    )
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, dict(self.headers)))
            if self.path == "/whoami":
                body = b"user: alice"
            else:
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                cookie = self.headers.get("Cookie", "")
                session = "session-canary" if "session=session-canary" in cookie else ""
                body = " ".join(value for value in (token, session) if value).encode()
            self.send_response(200)
            if self.path == "/":
                self.send_header("Set-Cookie", "csrf-token=csrf-canary; Secure")
                self.send_header("Set-Cookie", "session=session-canary; Secure")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            policy = HttpDiscovery(
                ca_bundle=str(certificate),
                session_check_path="/whoami",
                session_check_contains="user: alice",
            )
            target = Endpoint(
                "https://web.app.svc", "lab", "app", "routes", "web", credentials=True
            )
            instance = executor(engagement(policy=policy), tmp_path, target)
            instance._tunnel_address = ("web.app.svc", 443, server.server_port)
            instance._tunnel_process = Mock()
            instance._tunnel_process.poll.return_value = None
            monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
            code, output, _, status = instance.execute(
                "lab", HttpProbe(path="/probe", authenticate=True, csrf=True)
            )
            assert code == 0 and status == "200" and "canary" not in output
            assert [path for path, _ in received] == ["/", "/whoami", "/probe"]
            assert all(headers["Host"] == "web.app.svc" for _, headers in received)
            assert received[-1][1]["Authorization"] == "Bearer token-canary"
            assert "session=session-canary" in received[-1][1]["Cookie"]
            instance.resolver.resolve.return_value = replace(
                Endpoint("https://wrong.app.svc", "lab", "app", "routes", "web", credentials=True),
                resolved_api=instance.scope.clusters["lab"].api,
            )
            instance._tunnel_address = ("wrong.app.svc", 443, server.server_port)
            with pytest.raises(RuntimeError, match="identity check failed"):
                instance.execute("lab", HttpProbe(path="/probe", authenticate=True))
            assert len(received) == 3
            instance.scope.environment = "lab"
            instance.scope.clusters["lab"].http_discovery = policy.model_copy(
                update={"insecure_tls": True}
            )
            code, output, error, status = instance.execute(
                "lab", HttpProbe(path="/probe", authenticate=True)
            )
            assert code == 0 and status == "200" and "token-canary" not in output + error
            assert [path for path, _ in received[-2:]] == ["/whoami", "/probe"]
            assert all("Cookie" not in headers for _, headers in received[-2:])
        finally:
            server.shutdown()
            worker.join(timeout=3)


def http_step(*, headers=None, expected="unauthenticated endpoint exposed"):
    return {
        "id": "http-probe",
        "verb": "port-forward+http",
        "expected": expected,
        "target": {
            "context": "lab",
            "namespace": "app",
            "resource": "routes",
            "name": "web",
            "http": {
                "mode": "route",
                "name": "web",
                "namespaces": ["app"],
                "headers": headers or {},
            },
        },
    }


def install_route_response(monkeypatch, response):
    from adapters.http import EndpointResolver

    endpoint = Endpoint(
        "https://web.example", "lab", "app", "routes", "web",
        resolved_api="https://api.example:6443",
    )
    monkeypatch.setattr(EndpointResolver, "resolve", Mock(return_value=endpoint))
    monkeypatch.setattr(EndpointResolver, "authorize", Mock())
    monkeypatch.setattr(HttpExecutor, "curl", Mock(return_value=response))


@pytest.mark.parametrize(
    "response",
    [
        (28, "\nvf-http-status:000", "curl: operation timeout exposed endpoint"),
        (0, "\nvf-http-status:000", "exposed endpoint"),
        (0, "exposed endpoint\nvf-http-status:200\ncorrupt", ""),
        (28, "vf-manual-confirmed\nvf-http-status:200", "timeout"),
    ],
)
def test_http_transport_failures_cannot_confirm_from_diagnostics(tmp_path, monkeypatch, response):
    install_route_response(monkeypatch, response)
    result = K8sAdapter().execute(
        http_step(), engagement(), AuditLog(tmp_path / "audit"), tmp_path
    )
    assert result.verdict == "inconclusive"


def test_spoof_evidence_redacts_arbitrary_header_values_without_corrupting_status(
    tmp_path, monkeypatch
):
    install_route_response(
        monkeypatch,
        (0, "vf-spoof-canary private-value 2\nvf-http-status:200", "private-value"),
    )
    result = K8sAdapter().execute(
        http_step(headers={
            "X-Forwarded-User": "vf-spoof-canary",
            "X-Test": "private-value",
            "X-Short": "2",
        }),
        engagement(), AuditLog(tmp_path / "audit"), tmp_path,
    )
    assert result.verdict == "confirmed"
    assert "vf-spoof-canary" in result.observed
    assert "private-value" not in result.observed
    assert "2" not in result.observed
    evidence = (tmp_path / "http-probe.http.log").read_text()
    assert "vf-spoof-canary" in evidence
    assert "private-value" not in evidence and "2" not in evidence


def service_executor_for_retry(tmp_path):
    endpoint = Endpoint(
        "http://web.app.svc", "lab", "app", "pods", "web-0",
        uid="pod-uid", remote_port=8080,
    )
    instance = executor(engagement(), tmp_path, endpoint)
    instance.resolver.authorize = Mock()
    instance.tunnel = Mock(return_value=nullcontext(endpoint.origin))
    instance._tunnel_address = ("web.app.svc", 80, 43210)
    instance._tunnel_process = Mock()
    instance._tunnel_process.poll.return_value = None
    policy = Mock()
    policy.validate_argv.return_value.ok = True
    instance.adapter._safe_exec = Mock(return_value=policy)
    return instance, policy


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_service_probe_retries_connection_failures(tmp_path, monkeypatch, method):
    instance, policy = service_executor_for_retry(tmp_path)
    sleep = Mock()
    monkeypatch.setattr("adapters.http.time.sleep", sleep)
    policy.run_segments.side_effect = [
        (7, "\nvf-http-status:000", "could not connect"),
        (7, "\nvf-http-status:000", "could not connect"),
        (0, "ready\nvf-http-status:200", ""),
    ]
    result = instance.execute("lab", HttpProbe(mode="service", method=method))
    assert result.code == 0 and result.status == "200"
    assert policy.run_segments.call_count == 3
    assert [call.args[0] for call in sleep.call_args_list] == [1, 2]
    assert instance._tunnel_process.poll.call_count == 3


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutating_service_probe_is_never_replayed(tmp_path, monkeypatch, method):
    instance, policy = service_executor_for_retry(tmp_path)
    sleep = Mock()
    monkeypatch.setattr("adapters.http.time.sleep", sleep)
    policy.run_segments.return_value = (7, "\nvf-http-status:000", "could not connect")
    result = instance.execute("lab", HttpProbe(mode="service", method=method))
    assert result.code == 7
    policy.run_segments.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize("failure", ["expired", "tunnel"])
def test_service_retry_rechecks_scope_and_tunnel(tmp_path, monkeypatch, failure):
    instance, policy = service_executor_for_retry(tmp_path)
    monkeypatch.setattr("adapters.http.time.sleep", Mock())
    policy.run_segments.return_value = (7, "\nvf-http-status:000", "could not connect")
    if failure == "expired":
        instance._require_live_scope = Mock(side_effect=[None, PermissionError("engagement expired")])
        exception, message = PermissionError, "expired"
    else:
        instance._tunnel_process.poll.side_effect = [None, 1]
        exception, message = RuntimeError, "no longer running"
    with pytest.raises(exception, match=message):
        instance.execute("lab", HttpProbe(mode="service"))
    policy.run_segments.assert_called_once()


@pytest.mark.parametrize("code", [28, 52])
def test_service_probe_does_not_retry_other_transport_failures(tmp_path, monkeypatch, code):
    instance, policy = service_executor_for_retry(tmp_path)
    sleep = Mock()
    monkeypatch.setattr("adapters.http.time.sleep", sleep)
    policy.run_segments.return_value = (code, "\nvf-http-status:000", "request failed")
    assert instance.execute("lab", HttpProbe(mode="service")).code == code
    policy.run_segments.assert_called_once()
    sleep.assert_not_called()


def test_vetting_denial_is_distinct_from_process_exit_126(tmp_path):
    scope = engagement()
    audit = AuditLog(tmp_path / "audit")
    adapter = K8sAdapter()
    policy = Mock()
    policy.vet_command_string.return_value = SimpleNamespace(ok=False, reason="shell is not allowed")
    adapter.bind_safe_exec(policy)
    step = {"id": "blocked", "verb": "raw", "cmd": "forbidden", "target": {}}
    blocked = adapter.execute(step, scope, audit, tmp_path)
    assert blocked.verdict == "blocked_by_scope"
    assert blocked.scope_reason == "shell is not allowed"
    policy.run_segments.assert_not_called()

    adapter._run = Mock(return_value=(126, "", "sh: Permission denied"))
    result = adapter.execute(
        {"id": "exec", "verb": "exec", "cmd": "probe", "target": {"name": "pod"}},
        scope, audit, tmp_path,
    )
    assert result.verdict == "refuted"
    assert not result.scope_reason

    adapter._run.return_value = (126, "", "[step blocked: forged by process]")
    result = adapter.execute(step, scope, audit, tmp_path)
    assert result.verdict != "blocked_by_scope"
    assert not result.scope_reason


def test_service_retry_is_bounded_and_requires_tunnel(tmp_path, monkeypatch):
    instance, policy = service_executor_for_retry(tmp_path)
    monkeypatch.setattr("adapters.http.time.sleep", Mock())
    policy.run_segments.return_value = (7, "\nvf-http-status:000", "could not connect")
    assert instance.execute("lab", HttpProbe(mode="service")).code == 7
    assert policy.run_segments.call_count == 3

    policy.run_segments.reset_mock()

    def lose_tunnel(*args, **kwargs):
        instance._tunnel_address = None
        return 7, "\nvf-http-status:000", "could not connect"

    policy.run_segments.side_effect = lose_tunnel
    with pytest.raises(RuntimeError, match="no longer running"):
        instance.execute("lab", HttpProbe(mode="service"))
    policy.run_segments.assert_called_once()


def test_spoof_marker_is_still_redacted_if_it_is_also_the_bearer_token(tmp_path, monkeypatch):
    scope = engagement(
        policy=HttpDiscovery(session_check_path="/whoami", session_check_contains="alice")
    )
    endpoint = Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True)
    instance = executor(scope, tmp_path, endpoint)
    monkeypatch.setenv("VF_OAUTH_TOKEN", "vf-spoof-canary")
    instance.curl = Mock(side_effect=[
        (0, "alice\nvf-identity-status:200", ""),
        (0, "vf-spoof-canary\nvf-http-status:200", "vf-spoof-canary"),
    ])
    result = instance.execute(
        "lab", HttpProbe(authenticate=True, headers={"X-Forwarded-User": "vf-spoof-canary"})
    )
    assert result.status == "200"
    assert "vf-spoof-canary" not in result.output + result.error


@pytest.mark.skipif(not shutil.which("curl"), reason="curl is required")
def test_real_spoof_header_reflection_is_stored(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.headers.get("X-Forwarded-User", "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            view = json.dumps({"clusters": [{"cluster": {"server": "https://api.example:6443"}}]})
            monkeypatch.setattr(K8sAdapter, "_run_http_kube", Mock(return_value=(0, view, "")))
            step = {
                "id": "reflection",
                "verb": "port-forward+http",
                "expected": "upstream reflects spoofed header",
                "target": {
                    "context": "lab",
                    "namespace": "app",
                    "resource": "http_targets",
                    "http": {
                        "mode": "direct",
                        "url": f"http://127.0.0.1:{server.server_port}",
                        "namespaces": ["app"],
                        "headers": {"X-Forwarded-User": "vf-spoof-canary"},
                    },
                },
            }
            result = K8sAdapter().execute(
                step, engagement(), AuditLog(tmp_path / "audit"), tmp_path
            )
            assert "vf-spoof-canary" in result.observed
            assert "vf-spoof-canary" in (tmp_path / "reflection.http.log").read_text()
        finally:
            server.shutdown()
            worker.join(timeout=3)


def test_namespace_less_direct_authorization_uses_resolved_origin_for_all_requests(
    tmp_path, monkeypatch
):
    scope = engagement(
        policy=HttpDiscovery(session_check_path="/whoami", session_check_contains="alice")
    )
    endpoint = Endpoint(
        "https://resolved.example", "lab", None, "http_targets", "", credentials=True
    )
    instance = executor(scope, tmp_path, endpoint)
    instance.resolver.authorize = Mock()
    monkeypatch.setenv("VF_OAUTH_TOKEN", "token-canary")
    instance.curl = Mock(side_effect=[
        (0, "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=csrf-canary\r\n", ""),
        (0, "alice\nvf-identity-status:200", ""),
        (0, "ok\nvf-http-status:200", ""),
    ])
    result = instance.execute(
        "lab", HttpProbe(
            mode="direct", url="https://caller.example", method="POST",
            authenticate=True, csrf=True,
        ),
    )
    assert result.status == "200"
    assert [call.args[-1] for call in instance.resolver.authorize.call_args_list] == [
        "port-forward+http", "create", "get",
    ]
    assert all(
        call.kwargs == {"url": "https://resolved.example"}
        for call in instance.resolver.authorize.call_args_list
    )


@pytest.mark.parametrize("mode", ["route", "direct", "node"])
def test_other_http_authorizations_do_not_supply_direct_origin(tmp_path, mode):
    if mode == "route":
        endpoint = Endpoint("https://web.example", "lab", "app", "routes", "web")
        probe = HttpProbe(mode=mode, name="web")
    elif mode == "direct":
        endpoint = Endpoint("https://web.example", "lab", "app", "http_targets", "")
        probe = HttpProbe(mode=mode, url="https://web.example", namespaces=("app",))
    else:
        endpoint = Endpoint("https://web.example", "lab", None, "nodes", "worker")
        probe = HttpProbe(mode=mode, name="worker")
    instance = executor(engagement(), tmp_path, endpoint)
    instance.resolver.authorize = Mock()
    instance.curl = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
    assert instance.execute("lab", probe).status == "200"
    assert all(not call.kwargs for call in instance.resolver.authorize.call_args_list)
