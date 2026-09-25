from __future__ import annotations

import datetime
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from adapters.http import HttpExecutor
from adapters.k8s import K8sAdapter
from execute import AuditLog, run
from http_endpoints import EndpointResolver, HttpProbe
from http_scope import HttpDiscovery, HttpTarget, hostname
from scope import ClusterScope, OffLimit, Scope
from traust_engine._util.safe_exec import Profile


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
                    {
                        "routes": [
                            {
                                "namespace": "app",
                                "domains": ["apps.lab.example"],
                                "credentials": True,
                            }
                        ],
                        "nodes": {"networks": ["10.0.0.0/24", "fd00::/64"]},
                    }
                ),
            )
        },
    )


@pytest.fixture
def route() -> dict:
    return {
        "metadata": {"name": "console", "namespace": "app", "uid": "route-1"},
        "spec": {"host": "console.apps.lab.example"},
    }


def runner(items: list[dict]) -> Mock:
    return Mock(
        side_effect=[(0, "https://api.lab.example:6443", ""), (0, json.dumps({"items": items}), "")]
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://EXAMPLE.COM:443/path", "example.com"),
        ("https://[fd00::1]:10250/pods", "fd00::1"),
        ("[::1]", "::1"),
        ("fd00::2", "fd00::2"),
    ],
)
def test_host_normalization(value: str, expected: str) -> None:
    assert hostname(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "*.example.com",
        "https://user@example.com",
        "file:///etc/passwd",
        "example.com:99999",
        "bad host",
        "evil.example\\@good.example",
    ],
)
def test_invalid_hosts(value: str) -> None:
    with pytest.raises(ValueError):
        hostname(value)


def test_explicit_targets_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "clusters": [{"context": "lab", "namespaces": ["app"]}],
                "http_targets": [{"context": "lab", "host": "https://[fd00::1]:10250"}],
            }
        )
    )
    loaded = Scope.from_targets_file(path)
    assert loaded.curl_hosts() == ("fd00::1",)
    assert json.loads(loaded.to_json())["http_targets"][0]["host"] == "fd00::1"
    loaded.merge_inferred({"http_targets": [{"context": "lab", "host": "evil.example"}]})
    assert loaded.curl_hosts() == ("fd00::1",)


def test_route_discovery(scope: Scope, route: dict) -> None:
    command = runner([route])
    endpoint = EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(namespaces=("app",)))
    assert endpoint.host == "console.apps.lab.example"
    assert endpoint.credentials
    assert endpoint.uid == "route-1"
    assert "--context=lab" in command.call_args.args[0]


@pytest.mark.parametrize("host", ["evil.example", "apps.lab.example.evil.example"])
def test_route_destination_is_not_a_grant(scope: Scope, route: dict, host: str) -> None:
    route["spec"]["host"] = host
    with pytest.raises(PermissionError, match="not authorized"):
        EndpointResolver(scope, runner([route]), "oc").resolve(
            "lab", HttpProbe(namespaces=("app",))
        )


def test_explicit_route_exception(scope: Scope, route: dict) -> None:
    route["spec"]["host"] = "special.example"
    scope.http_targets = (HttpTarget(host="special.example", context="lab", namespace="app"),)
    endpoint = EndpointResolver(scope, runner([route]), "oc").resolve(
        "lab", HttpProbe(namespaces=("app",))
    )
    assert not endpoint.credentials


def test_denied_namespace_is_never_queried(scope: Scope) -> None:
    scope.off_limits = [OffLimit(namespace="app")]
    command = runner([])
    with pytest.raises(PermissionError):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(namespaces=("app",)))
    assert command.call_count == 1


def test_denied_route_name(scope: Scope, route: dict) -> None:
    scope.off_limits = [OffLimit(resource="routes", name="console")]
    command = runner([route])
    with pytest.raises(PermissionError):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(namespaces=("app",)))
    assert command.call_count == 1


@pytest.mark.parametrize("address", ["10.0.0.2", "fd00::2"])
def test_node_addresses(scope: Scope, address: str) -> None:
    node = {
        "metadata": {"name": "worker"},
        "status": {"addresses": [{"type": "InternalIP", "address": address}]},
    }
    endpoint = EndpointResolver(scope, runner([node]), "oc").resolve("lab", HttpProbe(mode="node"))
    assert endpoint.host == address
    assert not endpoint.credentials
    assert scope.clusters["lab"].namespaces == ["app"]


def test_nodes_need_explicit_grant(scope: Scope) -> None:
    scope.clusters["lab"].http_discovery = HttpDiscovery()
    with pytest.raises(PermissionError, match="explicit grant"):
        EndpointResolver(scope, runner([]), "oc").resolve("lab", HttpProbe(mode="node"))


def test_api_mismatch(scope: Scope) -> None:
    scope.clusters["lab"].api = "https://other.example:6443"
    command = runner([])
    with pytest.raises(PermissionError, match="does not match"):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(mode="node"))
    assert command.call_count == 1


def test_expired_no_queries(scope: Scope) -> None:
    scope.expires = datetime.date.today() - datetime.timedelta(days=1)
    command = runner([])
    with pytest.raises(PermissionError, match="expired"):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(mode="node"))
    command.assert_not_called()


@pytest.mark.parametrize("response", ["not json", '{"items": {}}', '{"items": [{"spec": {}}]}'])
def test_malformed_discovery(scope: Scope, response: str) -> None:
    command = Mock(side_effect=[(0, "https://api.lab.example", ""), (0, response, "")])
    with pytest.raises(ValueError, match="discovery response"):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(namespaces=("app",)))


def test_ambiguous_routes(scope: Scope, route: dict) -> None:
    with pytest.raises(RuntimeError, match="found 2"):
        EndpointResolver(scope, runner([route, route]), "oc").resolve(
            "lab", HttpProbe(namespaces=("app",))
        )


def restricted() -> dict[str, Profile]:
    return {
        "validation-step": Profile(
            name="validation-step",
            description="test",
            allow=frozenset({"curl", "oc", "kubectl"}),
            allowed_path_heads=frozenset(),
            allow_pipelines=True,
            keep_env=(),
            keep_env_heads=("curl", "oc", "kubectl"),
            posture="restricted",
        )
    }


def test_executor_without_preflight(
    scope: Scope, route: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = runner([route])
    monkeypatch.setattr(K8sAdapter, "_run", calls)
    from traust_engine._util import safe_exec

    execute = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
    monkeypatch.setattr(safe_exec, "run_segments", execute)
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "http",
                        "adapter": "k8s",
                        "verb": "port-forward+http",
                        "target": {
                            "context": "lab",
                            "namespace": "app",
                            "resource": "routes",
                            "http": {"namespaces": ["app"], "path": "/healthz"},
                        },
                    }
                ]
            }
        )
    )
    results, _ = run(path, scope, tmp_path, profile_map=restricted())
    assert results[0].verdict != "blocked_by_scope"
    assert execute.call_count == 1
    assert "https://console.apps.lab.example/healthz" in execute.call_args.args[0][0]
    assert "http-endpoint" in (tmp_path / "validation-audit.jsonl").read_text()


def test_credentials_require_separate_grant(scope: Scope, route: dict, tmp_path: Path) -> None:
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.lab.example"]}]}
    )
    adapter = K8sAdapter()
    adapter._run = runner([route])
    executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit.jsonl"))
    with pytest.raises(PermissionError, match="credentials"):
        executor.execute("lab", HttpProbe(namespaces=("app",), authenticate=True))


@pytest.mark.parametrize("path", ["//evil.example/x", "https://evil.example/", "/x\r\nHeader: y"])
def test_probe_paths(path: str) -> None:
    with pytest.raises(ValueError):
        HttpProbe(path=path)


@pytest.mark.parametrize(
    "headers", [{"Host": "evil.example"}, {"X-Test": "a\r\nb"}, {"Authorization": "token"}]
)
def test_probe_headers(headers: dict) -> None:
    with pytest.raises(ValueError):
        HttpProbe(headers=headers)


def test_list_denied_before_discovery(scope: Scope) -> None:
    scope.clusters["lab"].verbs_denied = ["list"]
    command = runner([])
    with pytest.raises(PermissionError, match="list"):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(namespaces=("app",)))
    assert command.call_count == 1


def test_named_node_outside_grant_not_queried(scope: Scope) -> None:
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"nodes": {"names": ["worker"], "networks": ["10.0.0.0/24"]}}
    )
    command = runner([])
    with pytest.raises(PermissionError, match="outside"):
        EndpointResolver(scope, command, "oc").resolve("lab", HttpProbe(mode="node", name="other"))
    assert command.call_count == 1


def test_api_credentials_require_exact_origin(scope: Scope) -> None:
    with pytest.raises(PermissionError):
        EndpointResolver(scope, runner([]), "oc").resolve(
            "lab", HttpProbe(mode="direct", url="http://api.lab.example:8080", namespaces=("app",))
        )


def test_api_explicit_no_credentials_wins(scope: Scope) -> None:
    scope.http_targets = (HttpTarget(context="lab", host="api.lab.example", credentials=False),)
    endpoint = EndpointResolver(scope, runner([]), "oc").resolve(
        "lab",
        HttpProbe(
            mode="direct", url="https://api.lab.example:6443", namespaces=("app",), path="/healthz"
        ),
    )
    assert not endpoint.credentials


def test_service_target_port(scope: Scope) -> None:
    service = {
        "metadata": {"name": "web", "namespace": "app"},
        "spec": {"ports": [{"port": 8080, "targetPort": 9090}], "selector": {"app": "web"}},
    }
    pod = {
        "metadata": {"name": "web-pod", "namespace": "app", "labels": {"app": "web"}},
        "status": {"phase": "Running"},
    }
    command = Mock(
        side_effect=[
            (0, "https://api.lab.example", ""),
            (0, json.dumps({"items": [service]}), ""),
            (0, json.dumps(service), ""),
            (0, json.dumps({"items": [pod]}), ""),
        ]
    )
    endpoint = EndpointResolver(scope, command, "oc").resolve(
        "lab", HttpProbe(mode="service", namespaces=("app",), port=8080, scheme="https")
    )
    assert endpoint.remote_port == 9090
    assert endpoint.resource == "pods"
    assert endpoint.name == "web-pod"
    assert endpoint.origin.startswith("https:")


def test_token_subresource_deny(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from http_endpoints import Endpoint

    monkeypatch.delenv("VF_OAUTH_TOKEN", raising=False)
    scope.off_limits = [OffLimit(resource="serviceaccounts/token", verb="create")]
    adapter = K8sAdapter()
    adapter._run = Mock()
    executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit.jsonl"))
    with pytest.raises(PermissionError, match="off_limits"):
        executor.token(
            Endpoint("https://web.example", "lab", "app", "routes", "web", credentials=True),
            HttpProbe(authenticate=True, service_account="default"),
        )
    adapter._run.assert_not_called()


def test_node_execution_without_wildcard(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_engine._util import safe_exec

    node = {
        "metadata": {"name": "worker"},
        "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]},
    }
    monkeypatch.setattr(K8sAdapter, "_run", runner([node]))
    execute = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
    monkeypatch.setattr(safe_exec, "run_segments", execute)
    adapter = K8sAdapter()
    adapter.bind_profile_map(restricted())
    result = adapter.execute(
        {
            "id": "node",
            "verb": "port-forward+http",
            "target": {
                "context": "lab",
                "resource": "nodes",
                "http": {"mode": "node", "path": "/pods"},
            },
        },
        scope,
        AuditLog(tmp_path / "audit.jsonl"),
        tmp_path,
    )
    assert result.verdict != "blocked_by_scope"
    execute.assert_called_once()


def test_destructive_http_rechecked(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock()
    monkeypatch.setattr(K8sAdapter, "execute", execute)
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "http",
                        "adapter": "k8s",
                        "verb": "port-forward+http",
                        "classification": "safe",
                        "target": {
                            "context": "lab",
                            "namespace": "app",
                            "resource": "routes",
                            "http": {"method": "DELETE", "namespaces": ["app"]},
                        },
                    }
                ]
            }
        )
    )
    results, _ = run(path, scope, tmp_path, profile_map=restricted())
    assert results[0].verdict == "not_attempted"
    assert results[0].classification == "destructive"
    execute.assert_not_called()


def test_csrf_roundtrip_uses_no_files(
    scope: Scope, route: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VF_OAUTH_TOKEN", "test-token")
    scope.clusters["lab"].http_discovery = scope.clusters["lab"].http_discovery.model_copy(
        update={"session_check_path": "/identity"}
    )
    adapter = K8sAdapter()
    adapter._run = runner([route])
    adapter.bind_profile_map(restricted())
    executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit.jsonl"))
    executor.curl = Mock(
        side_effect=[
            (0, "HTTP/1.1 200 OK\r\nSet-Cookie: csrf-token=canary; Secure\r\n", ""),
            (0, "200", ""),
            (0, "ok\nvf-http-status:200", ""),
        ]
    )
    executor.execute("lab", HttpProbe(namespaces=("app",), authenticate=True, csrf=True))
    first = executor.curl.call_args_list[0].args[0]
    second = executor.curl.call_args_list[1].args[0]
    assert "Authorization: Bearer test-token" in first
    assert "Cookie: csrf-token=canary" in second
    assert "-c" not in first and "-b" not in second


def test_tunnel_cleanup_on_error(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from adapters import http
    from http_endpoints import Endpoint

    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"Forwarding from 127.0.0.1:34567 -> 9090\n")
    os.close(write_fd)
    with os.fdopen(read_fd, "rb", buffering=0) as stdout:
        process = Mock(stdout=stdout)
        process.poll.return_value = None
        process.__enter__ = Mock(return_value=process)
        process.__exit__ = Mock(return_value=False)
        monkeypatch.setattr(http.subprocess, "Popen", Mock(return_value=process))
        executor = HttpExecutor(K8sAdapter(), scope, "oc", AuditLog(tmp_path / "audit.jsonl"))
        endpoint = Endpoint("http://127.0.0.1", "lab", "app", "pods", "web", remote_port=9090)
        with pytest.raises(RuntimeError, match="probe failed"), executor.tunnel(endpoint) as origin:
            assert origin == "http://127.0.0.1:34567"
            raise RuntimeError("probe failed")
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)


def test_generated_route_executes_under_estate_policy(
    scope: Scope, route: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ingest import Finding
    from plan import _http_adapted_step
    from traust_contracts import SafeExecProfiles
    from traust_engine._util import safe_exec

    scope.clusters["lab"].namespaces = ["*"]
    scope.clusters["lab"].explicit_namespaces = {"*"}
    finding = Finding(
        id="F1",
        title="console anonymous endpoint",
        severity="high",
        cwes=["CWE-306"],
        description="GET /api/status exposes console state",
    )
    step = _http_adapted_step("generated", finding, scope, None)
    assert step.target["http"]["namespaces"] == ["app"]
    assert not step.target["http"]["authenticate"]
    monkeypatch.setattr(K8sAdapter, "_run", runner([route]))
    execute = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
    monkeypatch.setattr(safe_exec, "run_segments", execute)
    section = SafeExecProfiles.model_validate(
        yaml.safe_load(
            (
                Path(__file__).resolve().parents[1] / "config/safe-exec-profiles.example.yaml"
            ).read_text()
        )
    )
    profiles = safe_exec.profiles_from_section(section)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"steps": [step.to_dict()]}))
    results, _ = run(path, scope, tmp_path, profile_map=profiles)
    assert not results[0].scope_reason
    execute.assert_called_once()


def test_executor_instances_do_not_leak_hosts(
    scope: Scope, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instances = []

    from adapters import StepResult

    def execute(
        adapter: K8sAdapter, step: dict, current_scope: Scope, audit: AuditLog, artifacts: Path
    ) -> StepResult:

        instances.append(adapter)
        return StepResult(
            step_id=step["id"],
            adapter="k8s",
            verb="get",
            target=step["target"],
            classification="safe",
            verdict="inconclusive",
        )

    monkeypatch.setattr(K8sAdapter, "execute", execute)
    scope.http_targets = (HttpTarget(context="lab", host="first.example"),)
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "one",
                        "adapter": "k8s",
                        "verb": "get",
                        "target": {"context": "lab", "namespace": "app", "resource": "pods"},
                    }
                ]
            }
        )
    )
    run(path, scope, tmp_path, profile_map=restricted())
    scope.http_targets = ()
    run(path, scope, tmp_path, profile_map=restricted())
    assert instances[0] is not instances[1]
    assert instances[0]._curl_hosts == ("first.example",)
    assert instances[1]._curl_hosts == ()


def test_api_path_cannot_bypass_resource_scope(scope: Scope) -> None:
    with pytest.raises(PermissionError, match="health and version"):
        EndpointResolver(scope, runner([]), "oc").resolve(
            "lab",
            HttpProbe(
                mode="direct",
                url="https://api.lab.example:6443",
                namespaces=("app",),
                path="/api/v1/namespaces/other/secrets",
                authenticate=True,
            ),
        )


def test_reflected_token_redacted(
    scope: Scope, route: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VF_OAUTH_TOKEN", "opaque-canary")
    adapter = K8sAdapter()
    adapter._run = runner([route])
    executor = HttpExecutor(adapter, scope, "oc", AuditLog(tmp_path / "audit.jsonl"))
    executor.curl = Mock(return_value=(0, "opaque-canary", "opaque-canary"))
    assert executor.execute("lab", HttpProbe(namespaces=("app",), authenticate=True)) == (
        0,
        "[REDACTED]",
        "[REDACTED]",
    )


def test_authenticated_claim_not_tested_anonymously(scope: Scope, tmp_path: Path) -> None:
    adapter = K8sAdapter()
    adapter._run = Mock()
    result = adapter.execute(
        {
            "id": "auth",
            "verb": "port-forward+http",
            "expected": "authenticated user reads another tenant",
            "target": {"context": "lab", "namespace": "app", "http": {"namespaces": ["app"]}},
        },
        scope,
        AuditLog(tmp_path / "audit.jsonl"),
        tmp_path,
    )
    assert result.verdict == "inconclusive"
    adapter._run.assert_not_called()
