from __future__ import annotations

import datetime
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from http_endpoints import EndpointResolver, HttpProbe
from http_policy_io import configure_http_targets, expiry_date
from scope import Action, ClusterScope, OffLimit, Scope
from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.artifacts import SchemaView
from traust_core.v1.models.validation import HttpDiscovery, HttpTarget, hostname, origin
from traust_core.v1.services.validation import _authorize_http_step

API = "https://api.example:6443"


def view(**cluster):
    return json.dumps({"clusters": [{"cluster": {"server": API, **cluster}}]})


def runner(*objects):
    return Mock(side_effect=[(0, view(), ""), *((0, json.dumps(obj), "") for obj in objects)])


@pytest.fixture
def scope():
    return Scope(
        modes={"explicit"},
        clusters={
            "lab": ClusterScope(
                context="lab", api=API, namespaces=["app"], explicit_namespaces={"app"}
            )
        },
    )


def route(host="console.example", tls=None):
    spec = {"host": host}
    if tls is not None:
        spec["tls"] = tls
    return {"metadata": {"name": "console", "namespace": "app", "uid": "route-1"}, "spec": spec}


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://EXAMPLE.com:443/x", "example.com"),
        ("[::1]", "::1"),
        ("https://[fd00::1]:10250", "fd00::1"),
    ],
)
def test_host_normalization(value, expected):
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
def test_bad_hosts(value):
    with pytest.raises(ValueError):
        hostname(value)


def test_origin_compares_default_ports():
    assert origin("https://example.com") == origin("https://EXAMPLE.com:443")
    assert origin("http://example.com") != origin("https://example.com")


def test_exact_route_requires_no_discovery(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.example",
            namespace="app",
            resource="routes",
            name="console",
            credentials=True,
        ),
    )
    command = runner(route(tls={}))
    endpoint = EndpointResolver(scope, command, "oc").resolve(
        "lab", HttpProbe(name="console", namespaces=("app",))
    )
    assert endpoint.origin == "https://console.example"
    assert endpoint.credentials and endpoint.uid == "route-1"
    assert command.call_args.args[0][-4:] == ["routes", "console", "-o", "json"]


def test_exact_route_rejects_changed_host(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.example",
            namespace="app",
            resource="routes",
            name="console",
        ),
    )
    with pytest.raises(PermissionError, match="not authorized"):
        EndpointResolver(scope, runner(route("other.example")), "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",))
        )


def test_route_replay_rejects_changed_origin_even_with_another_grant(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.apps.example",
            namespace="app",
            resource="routes",
            name="console",
        ),
    )
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {
            "routes": [{"namespace": "app", "domains": ["apps.example"]}],
        }
    )
    probe = HttpProbe(
        mode="route",
        name="console",
        namespaces=("app",),
        scheme="https",
        port=8443,
        url="https://console.apps.example:8443",
    )
    endpoint = EndpointResolver(scope, runner(route("console.apps.example", tls={})), "oc").resolve(
        "lab", probe
    )
    assert endpoint.origin == "https://console.apps.example:8443"
    with pytest.raises(PermissionError, match="requested origin"):
        EndpointResolver(scope, runner(route("other.apps.example", tls={})), "oc").resolve(
            "lab", probe
        )


def test_route_replay_selects_only_the_requested_discovered_origin(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {
            "routes": [{"namespace": "app", "domains": ["apps.example"], "credentials": True}],
        }
    )
    other = route("other.apps.example", tls={})
    other["metadata"]["name"] = "other"
    unrelated = route("outside.example", tls={})
    unrelated["metadata"]["name"] = "unrelated"
    command = runner({"items": [other, unrelated, route("console.apps.example", tls={})]})
    endpoint = EndpointResolver(scope, command, "oc").resolve(
        "lab", HttpProbe(namespaces=("app",), scheme="https", url="https://console.apps.example")
    )
    assert endpoint.name == "console" and endpoint.origin == "https://console.apps.example"
    assert endpoint.credentials is True


def test_route_replay_refuses_multiple_matching_resources(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {
            "routes": [{"namespace": "app", "domains": ["apps.example"]}],
        }
    )
    other = route("console.apps.example", tls={})
    other["metadata"]["name"] = "other"
    command = runner({"items": [route("console.apps.example", tls={}), other]})
    with pytest.raises(RuntimeError, match="found 2"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab",
            HttpProbe(namespaces=("app",), scheme="https", url="https://console.apps.example"),
        )


@pytest.mark.parametrize(("scheme", "port"), [("http", None), ("https", 8443)])
def test_route_replay_rejects_changed_scheme_or_port(scope, scheme, port):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.example",
            namespace="app",
            resource="routes",
            name="console",
        ),
    )
    with pytest.raises(PermissionError, match="requested origin"):
        EndpointResolver(scope, runner(route(tls={})), "oc").resolve(
            "lab",
            HttpProbe(
                name="console",
                namespaces=("app",),
                scheme=scheme,
                port=port,
                url="https://console.example",
            ),
        )


@pytest.mark.parametrize("url", ["https://console.example/path", "https://console.example/?x=1"])
def test_route_replay_requires_origin_only(scope, url):
    command = runner()
    with pytest.raises(ValueError, match="origin"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",), url=url)
        )
    command.assert_not_called()


def test_route_discovery_requires_domain_boundary(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
    )
    for host in ("bad.example", "apps.example.evil.example"):
        with pytest.raises(PermissionError, match="not authorized"):
            EndpointResolver(scope, runner({"items": [route(host)]}), "oc").resolve(
                "lab", HttpProbe(namespaces=("app",))
            )
    endpoint = EndpointResolver(
        scope, runner({"items": [route("console.apps.example")]}), "oc"
    ).resolve("lab", HttpProbe(namespaces=("app",)))
    assert endpoint.origin == "http://console.apps.example"


@pytest.mark.parametrize("stray_first", [True, False])
def test_route_listing_excludes_ungranted_hosts(scope, stray_first):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.example"], "credentials": True}]}
    )
    stray = route("outside.example")
    stray["metadata"]["name"] = "stray"
    approved = route("console.apps.example")
    items = [stray, approved] if stray_first else [approved, stray]
    endpoint = EndpointResolver(scope, runner({"items": items}), "oc").resolve(
        "lab", HttpProbe(namespaces=("app",))
    )
    assert endpoint.name == "console"
    assert endpoint.origin == "http://console.apps.example"
    assert endpoint.credentials is True


def test_route_listing_only_ungranted_hosts_is_denied(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
    )
    with pytest.raises(PermissionError, match="not authorized"):
        EndpointResolver(scope, runner({"items": [route("outside.example")]}), "oc").resolve(
            "lab", HttpProbe(namespaces=("app",))
        )


def test_named_route_with_ungranted_host_is_denied(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
    )
    with pytest.raises(PermissionError, match="not authorized"):
        EndpointResolver(scope, runner(route("outside.example")), "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",))
        )


def test_route_listing_still_rejects_multiple_authorized_candidates(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
    )
    other = route("other.apps.example")
    other["metadata"]["name"] = "other"
    with pytest.raises(RuntimeError, match="found 2"):
        EndpointResolver(
            scope, runner({"items": [route("console.apps.example"), other]}), "oc"
        ).resolve("lab", HttpProbe(namespaces=("app",)))


def test_deny_applies_before_named_route_query(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.example",
            namespace="app",
            resource="routes",
            name="console",
        ),
    )
    scope.off_limits = [OffLimit(resource="routes", name="console")]
    command = runner(route())
    with pytest.raises(PermissionError, match="off_limits"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",))
        )
    assert command.call_count == 1


def test_http_verb_denied_on_resolved_route(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab",
            host="console.example",
            namespace="app",
            resource="routes",
            name="console",
        ),
    )
    scope.clusters["lab"].verbs_denied = ["delete"]
    with pytest.raises(PermissionError, match="delete"):
        EndpointResolver(scope, runner(route()), "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",), method="DELETE")
        )


@pytest.mark.parametrize(
    "config", [{"proxy-url": "http://proxy.example"}, {"insecure-skip-tls-verify": True}]
)
def test_untrusted_kube_transport_rejected(scope, config):
    command = Mock(return_value=(0, view(**config), ""))
    with pytest.raises(PermissionError, match="proxy and insecure"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab", HttpProbe(mode="service", namespaces=("app",))
        )
    assert command.call_count == 1


def test_context_expiry_and_api_checked_before_discovery(scope):
    command = runner()
    scope.selected_contexts = ("other",)
    with pytest.raises(PermissionError, match="selected"):
        EndpointResolver(scope, command, "oc").api("lab")
    command.assert_not_called()
    scope.selected_contexts = ("lab",)
    scope.expires = datetime.date.today() - datetime.timedelta(days=1)
    with pytest.raises(PermissionError, match="expired"):
        EndpointResolver(scope, command, "oc").api("lab")
    command.assert_not_called()
    scope.expires = None
    scope.clusters["lab"].api = "https://other.example:6443"
    with pytest.raises(PermissionError, match="does not match"):
        EndpointResolver(scope, command, "oc").api("lab")


def test_direct_target_and_api_restriction(scope):
    scope.http_targets = (HttpTarget(context="lab", host="api.example"),)
    resolver = EndpointResolver(scope, runner(), "oc")
    with pytest.raises(PermissionError, match="health and version"):
        resolver.resolve(
            "lab", HttpProbe(mode="direct", url=API, namespaces=("app",), path="/api/v1/secrets")
        )


@pytest.mark.parametrize("namespace", ["app", None])
def test_direct_probe_matches_core_approval_and_binding(scope, namespace):
    scope.http_targets = (HttpTarget(context="lab", host="console.example", credentials=True),)
    probe = HttpProbe(
        mode="direct", url="https://console.example", namespaces=(namespace,) if namespace else ()
    )
    step = SchemaView(
        [],
        {
            "adapter": "k8s",
            "verb": "port-forward+http",
            "classification": "safe",
            "target": {
                "context": "lab",
                "namespace": namespace,
                "resource": "http_targets",
                "http": probe.model_dump(mode="json"),
            },
        },
        "step",
    )
    _authorize_http_step(step, scope._core_scope(), datetime.datetime.now(datetime.UTC))
    endpoint = EndpointResolver(scope, runner(), "oc").resolve("lab", probe)
    assert endpoint.origin == "https://console.example"
    assert endpoint.namespace == namespace
    assert endpoint.credentials is True


def test_namespace_less_direct_probe_still_requires_core_host_grant(scope):
    scope.http_targets = (HttpTarget(context="lab", host="other.example"),)
    probe = HttpProbe(mode="direct", url="https://console.example")
    step = SchemaView(
        [],
        {
            "adapter": "k8s",
            "verb": "port-forward+http",
            "classification": "safe",
            "target": {
                "context": "lab",
                "resource": "http_targets",
                "http": probe.model_dump(mode="json"),
            },
        },
        "step",
    )
    with pytest.raises(ForbiddenError):
        _authorize_http_step(step, scope._core_scope(), datetime.datetime.now(datetime.UTC))
    with pytest.raises(PermissionError, match="not explicitly authorized"):
        EndpointResolver(scope, runner(), "oc").resolve("lab", probe)


@pytest.mark.parametrize(
    "restriction,reason",
    [
        ("host", "not explicitly authorized"),
        ("binding", "explicitly declared"),
        ("selected", "selected"),
        ("expired", "expired"),
        ("namespace", "namespace"),
        ("action", "port-forward\\+http"),
        ("method", "delete"),
        ("off_limits", "off_limits"),
    ],
)
@pytest.mark.parametrize("namespace", ["app", None])
def test_direct_probe_preserves_policy_checks(scope, restriction, reason, namespace):
    scope.http_targets = (HttpTarget(context="lab", host="console.example"),)
    probe = HttpProbe(
        mode="direct",
        url="https://console.example",
        namespaces=(namespace,) if namespace else (),
        method="DELETE",
    )
    if restriction == "host":
        probe = probe.model_copy(update={"url": "https://other.example"})
    elif restriction == "binding":
        scope.explicit_contexts = frozenset()
    elif restriction == "selected":
        scope.selected_contexts = ("other",)
    elif restriction == "expired":
        scope.expires = datetime.date.today() - datetime.timedelta(days=1)
    elif restriction == "namespace":
        probe = probe.model_copy(update={"namespaces": ("other",)})
    elif restriction == "action":
        scope.clusters["lab"].verbs_denied = ["port-forward+http"]
    elif restriction == "method":
        scope.clusters["lab"].verbs_denied = ["delete"]
    else:
        scope.off_limits = [OffLimit(resource="http_targets", verb="delete")]
    with pytest.raises(PermissionError, match=reason):
        EndpointResolver(scope, runner(), "oc").resolve("lab", probe)


@pytest.mark.parametrize(
    "target",
    [
        HttpTarget(context="other", host="console.example"),
        HttpTarget(context="lab", host="console.example", namespace="other"),
        HttpTarget(context="lab", host="console.example", resource="routes"),
        HttpTarget(context="lab", host="console.example", name="other"),
    ],
)
@pytest.mark.parametrize("namespace", ["app", None])
def test_direct_probe_does_not_use_mismatched_target_grant(scope, target, namespace):
    scope.http_targets = (target,)
    with pytest.raises(PermissionError, match="not explicitly authorized"):
        EndpointResolver(scope, runner(), "oc").resolve(
            "lab",
            HttpProbe(
                mode="direct",
                url="https://console.example",
                namespaces=(namespace,) if namespace else (),
            ),
        )


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("path", ["/healthz", "/livez", "/readyz", "/version"])
@pytest.mark.parametrize("namespace", ["app", None])
def test_api_health_request_carries_actual_resolved_api(scope, method, path, namespace):
    scope.clusters["lab"].api = "https://API.EXAMPLE:6443"
    scope.http_targets = (HttpTarget(context="lab", host="api.example"),)
    command = runner()
    endpoint = EndpointResolver(scope, command, "oc").resolve(
        "lab",
        HttpProbe(
            mode="direct",
            url=API,
            namespaces=(namespace,) if namespace else (),
            method=method,
            path=path,
        ),
    )
    assert endpoint.resolved_api == API
    command.assert_called_once()


@pytest.mark.parametrize(
    "url,method,path",
    [
        ("https://api.example:443", "GET", "/healthz"),
        (API, "OPTIONS", "/healthz"),
        (API, "GET", "/healthz?verbose=true"),
        (API, "GET", "/"),
    ],
)
@pytest.mark.parametrize("namespace", ["app", None])
def test_api_origin_method_and_exact_path_are_required(scope, url, method, path, namespace):
    scope.http_targets = (HttpTarget(context="lab", host="api.example"),)
    with pytest.raises(PermissionError, match="health and version"):
        EndpointResolver(scope, runner(), "oc").resolve(
            "lab",
            HttpProbe(
                mode="direct",
                url=url,
                namespaces=(namespace,) if namespace else (),
                method=method,
                path=path,
            ),
        )


def test_api_restriction_also_applies_to_routes(scope):
    scope.http_targets = (
        HttpTarget(
            context="lab", host="api.example", namespace="app", resource="routes", name="console"
        ),
    )
    with pytest.raises(PermissionError, match="health and version"):
        EndpointResolver(scope, runner(route("api.example")), "oc").resolve(
            "lab", HttpProbe(name="console", namespaces=("app",), path="/api/v1/secrets")
        )


def test_named_node_scope_and_network(scope):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"nodes": {"names": ["worker"], "networks": ["10.0.0.0/24"]}}
    )
    assert scope.is_in_scope(
        Action(adapter="k8s", verb="get", context="lab", resource="nodes", name="worker")
    )[0]
    assert not scope.is_in_scope(
        Action(adapter="k8s", verb="list", context="lab", resource="nodes")
    )[0]
    node = {
        "metadata": {"name": "worker", "uid": "node-1"},
        "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]},
    }
    endpoint = EndpointResolver(scope, runner(node), "oc").resolve(
        "lab", HttpProbe(mode="node", name="worker", port=10250)
    )
    assert endpoint.origin == "https://10.0.0.2:10250"
    node["status"]["addresses"][0]["address"] = "10.1.0.2"
    with pytest.raises(RuntimeError, match="found 0"):
        EndpointResolver(scope, runner(node), "oc").resolve(
            "lab", HttpProbe(mode="node", name="worker")
        )


@pytest.mark.parametrize(
    "method,verb", [("POST", "create"), ("PUT", "update"), ("PATCH", "patch"), ("DELETE", "delete")]
)
def test_node_http_write_needs_cluster_wide_grant(scope, method, verb):
    scope.clusters["lab"].http_discovery = HttpDiscovery.model_validate(
        {"nodes": {"names": ["worker"], "networks": ["10.0.0.0/24"]}}
    )
    node = {
        "metadata": {"name": "worker", "uid": "node-1"},
        "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]},
    }
    with pytest.raises(PermissionError):
        EndpointResolver(scope, runner(node), "oc").resolve(
            "lab", HttpProbe(mode="node", name="worker", method=method)
        )
    scope.clusters["lab"].namespaces = ["*"]
    scope.clusters["lab"].explicit_namespaces = {"*"}
    scope.clusters["lab"].verbs_denied = [verb]
    with pytest.raises(PermissionError, match=verb):
        EndpointResolver(scope, runner(node), "oc").resolve(
            "lab", HttpProbe(mode="node", name="worker", method=method)
        )


def test_core_control_plane_guard_remains_required():
    scope = Scope(
        clusters={
            "lab": ClusterScope(
                context="lab", namespaces=["kube-system"], explicit_namespaces={"kube-system"}
            )
        }
    )
    allowed, reason = scope.is_in_scope(
        Action(adapter="k8s", context="lab", namespace="kube-system", resource="pods", verb="get")
    )
    assert not allowed
    assert "control-plane" in reason


def service_and_pod():
    service = {
        "metadata": {"name": "web", "namespace": "app", "uid": "service-1"},
        "spec": {"ports": [{"port": 443, "targetPort": "https"}], "selector": {"app": "web"}},
    }
    pod = {
        "metadata": {
            "name": "web-pod",
            "namespace": "app",
            "uid": "pod-1",
            "labels": {"app": "web"},
        },
        "spec": {"containers": [{"ports": [{"name": "https", "containerPort": 8443}]}]},
        "status": {"phase": "Running"},
    }
    return service, pod


def test_service_tunnel_targets_pod_and_preserves_tls_name(scope):
    service, pod = service_and_pod()
    command = runner({"items": [service]}, service, {"items": [pod]})
    endpoint = EndpointResolver(scope, command, "oc").resolve(
        "lab", HttpProbe(mode="service", namespaces=("app",), port=443)
    )
    assert (
        endpoint.origin,
        endpoint.resource,
        endpoint.name,
        endpoint.uid,
        endpoint.remote_port,
    ) == ("https://web.app.svc", "pods", "web-pod", "pod-1", 8443)
    assert endpoint.resolved_api == API


def test_service_requires_explicit_namespace_and_pod_uid(scope):
    scope.clusters["lab"].explicit_namespaces = set()
    command = runner()
    with pytest.raises(PermissionError, match="explicitly authorized"):
        EndpointResolver(scope, command, "oc").resolve(
            "lab", HttpProbe(mode="service", namespaces=("app",))
        )
    assert command.call_count == 1
    scope.clusters["lab"].explicit_namespaces = {"app"}
    service, pod = service_and_pod()
    pod["metadata"].pop("uid")
    with pytest.raises(PermissionError, match="UID"):
        EndpointResolver(
            scope, runner({"items": [service]}, service, {"items": [pod]}), "oc"
        ).resolve("lab", HttpProbe(mode="service", namespaces=("app",)))


def test_service_change_and_pod_deny(scope):
    service, pod = service_and_pod()
    altered = json.loads(json.dumps(service))
    altered["metadata"]["uid"] = "replacement"
    with pytest.raises(PermissionError, match="changed"):
        EndpointResolver(scope, runner({"items": [service]}, altered), "oc").resolve(
            "lab", HttpProbe(mode="service", namespaces=("app",))
        )
    scope.off_limits = [OffLimit(resource="pods", verb="port-forward")]
    with pytest.raises(PermissionError, match="off_limits"):
        EndpointResolver(
            scope, runner({"items": [service]}, service, {"items": [pod]}), "oc"
        ).resolve("lab", HttpProbe(mode="service", namespaces=("app",)))


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil"},
        {"X-CSRF-Token": "evil"},
        {"Authorization": "token"},
        {"X-Api-Key": "key"},
        {"X-Auth-Token": "token"},
        {"X-Session-Id": "id"},
        {"X-Test": "a\r\nb"},
    ],
)
def test_probe_rejects_adapter_owned_headers(headers):
    with pytest.raises(ValueError):
        HttpProbe(headers=headers)


def test_probe_allows_forwarded_header_for_spoofing():
    assert HttpProbe(headers={"X-Forwarded-For": "192.0.2.1"}).headers


@pytest.mark.parametrize("path", ["//evil/x", "https://evil/", "/x\r\nHeader: y", "/x#fragment"])
def test_probe_path_is_origin_relative(path):
    with pytest.raises(ValueError):
        HttpProbe(path=path)


def test_targets_load_and_selection_roundtrip(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "clusters": [{"context": "lab", "api": API, "namespaces": ["app"]}],
                "http_targets": [{"context": "lab", "host": "console.example"}],
            }
        )
    )
    scope = Scope.from_targets_file(path)
    scope.merge_inline(contexts=["lab"])
    assert json.loads(scope.to_json())["selected_contexts"] == ["lab"]
    assert scope.curl_hosts() == ("console.example", API)
    scope.merge_inferred({"http_targets": [{"context": "lab", "host": "evil.example"}]})
    assert all(target.host != "evil.example" for target in scope.http_targets)


def test_curl_hosts_exclude_unselected_and_inline_contexts(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "clusters": [
                    {"context": "lab", "api": API},
                    {"context": "other", "api": "https://api.other.example"},
                ],
                "http_targets": [
                    {"context": "lab", "host": "lab.example"},
                    {"context": "other", "host": "other.example"},
                ],
            }
        )
    )
    scope = Scope.from_targets_file(path)
    scope.merge_inline(contexts=["lab", "inline"])
    scope.clusters["inline"].api = "https://inline.example"
    assert scope.curl_hosts() == (API, "lab.example")
    assert not scope.http_context_allowed("inline")


def test_configure_binds_selected_context_and_scrubs_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example")
    monkeypatch.setattr("http_policy_io.shutil.which", lambda name: "/usr/bin/oc")
    execute = Mock(return_value=SimpleNamespace(returncode=0, stdout=view().encode()))
    factory = Mock(return_value=SimpleNamespace(run=execute))
    monkeypatch.setattr("http_policy_io.ProcessRunner", factory)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump({"http_targets": [{"context": "lab", "host": "console.example"}]})
    )
    document = {"clusters": [{"context": "lab", "namespaces": ["app"]}]}
    configure_http_targets(document, "lab", API, str(policy))
    assert document["clusters"][0]["api"] == API
    assert document["http_targets"][0]["host"] == "console.example"
    assert "HTTP_PROXY" not in factory.call_args.kwargs["keep_env"]
    assert execute.call_args.kwargs["max_output_bytes"] == 4 * 1024 * 1024
    with pytest.raises(ValueError, match="does not match"):
        configure_http_targets(document, "lab", "https://other.example", str(policy))


@pytest.mark.parametrize(
    "value", ["null", "", "tomorrow", "2026-99-99", "2099-01-01\noff_limits: []"]
)
def test_expiry_validation(value):
    with pytest.raises(ValueError, match="ISO"):
        expiry_date(value)


def test_expiry_rejects_naive_and_expired_instants():
    now = datetime.datetime.now(datetime.UTC)
    with pytest.raises(ValueError, match="timezone"):
        expiry_date("2099-01-01T12:00:00")
    with pytest.raises(ValueError, match="past"):
        expiry_date((now - datetime.timedelta(minutes=1)).isoformat())
    with pytest.raises(ValueError, match="past"):
        expiry_date((datetime.date.today() - datetime.timedelta(days=1)).isoformat())
    assert expiry_date(datetime.date.today().isoformat()) == datetime.date.today().isoformat()
    future = now + datetime.timedelta(hours=4)
    assert datetime.datetime.fromisoformat(expiry_date(future.isoformat())) == future


def test_scope_preserves_and_checks_lease_instant(tmp_path):
    now = datetime.datetime.now(datetime.UTC)
    expiry = now - datetime.timedelta(minutes=1)
    path = tmp_path / "targets.yaml"
    path.write_text(
        yaml.safe_dump(
            {"expires": expiry, "clusters": [{"context": "lab", "api": API, "namespaces": ["app"]}]}
        )
    )
    scope = Scope.from_targets_file(path)
    assert scope.expires_at == expiry
    assert json.loads(scope.to_json())["expires_at"] == expiry.isoformat()
    assert scope.expired()
    command = runner()
    with pytest.raises(PermissionError, match="expired"):
        EndpointResolver(scope, command, "oc").api("lab")
    command.assert_not_called()
    scope.expires_at = now + datetime.timedelta(hours=2)
    assert not scope.expired()
    assert scope._core_scope().expires is None
    assert scope._core_scope().expires_at == scope.expires_at


def test_scope_rejects_naive_datetime(tmp_path):
    path = tmp_path / "targets.yaml"
    path.write_text('expires: "2099-01-01T12:00:00"\n')
    with pytest.raises(ValueError, match="timezone"):
        Scope.from_targets_file(path)


@pytest.mark.parametrize("value", [None, ""])
def test_scope_rejects_explicit_empty_expiry(tmp_path, value):
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump({"expires": value}))
    with pytest.raises(ValueError, match="ISO"):
        Scope.from_targets_file(path)


@pytest.mark.parametrize(
    "name",
    [
        "HTTP_PROXY",
        "KUBECONFIG",
        "HOME",
        "PATH",
        "CURL_HOME",
        "SSL_CERT_FILE",
        "LD_PRELOAD",
        "PYTHONPATH",
        "AWS_CA_BUNDLE",
        "MY_ENDPOINT",
        "OTHER_CONFIG",
    ],
)
def test_kube_env_cannot_override_transport_or_configuration(name):
    with pytest.raises(ValueError, match="unsafe"):
        HttpDiscovery(kube_env=(name,))


def test_explicit_auth_plugin_environment_is_allowed():
    assert HttpDiscovery(kube_env=("AWS_PROFILE", "AZURE_CLIENT_ID")).kube_env == (
        "AWS_PROFILE",
        "AZURE_CLIENT_ID",
    )


@pytest.mark.parametrize("value", ["", "relative/ca.pem", "/tmp/ca\x00.pem", "/tmp/ca\n.pem"])
def test_ca_bundle_requires_absolute_safe_path(value):
    with pytest.raises(ValueError, match="absolute path"):
        HttpDiscovery(ca_bundle=value)


def test_ca_bundle_accepts_absolute_operator_path():
    assert HttpDiscovery(ca_bundle="/etc/pki/ca.pem").ca_bundle == "/etc/pki/ca.pem"


@pytest.mark.parametrize("value", ["", "   ", "x\ny", "a" * 257])
def test_session_identity_marker_is_bounded(value):
    with pytest.raises(ValueError):
        HttpDiscovery(session_check_contains=value)


def test_configure_rejects_kubeconfig_proxy_before_mutating(tmp_path, monkeypatch):
    monkeypatch.setattr("http_policy_io.shutil.which", lambda name: "/usr/bin/oc")
    execute = Mock(
        return_value=SimpleNamespace(
            returncode=0, stdout=view(**{"proxy-url": "http://evil"}).encode()
        )
    )
    monkeypatch.setattr(
        "http_policy_io.ProcessRunner", Mock(return_value=SimpleNamespace(run=execute))
    )
    document = {"clusters": [{"context": "lab"}]}
    with pytest.raises(PermissionError, match="proxy"):
        configure_http_targets(document, "lab", None, None)
    assert document == {"clusters": [{"context": "lab"}]}
