#!/usr/bin/env python3
"""
Tests for harnessing/5-validate/validate-findings/scope.py — the safety-critical
scope guard that gates every live action in the validate-findings harness.
"""

import datetime as _dt
import json

import pytest
from scope import Action, ClusterScope, OffLimit, Scope

from traust.paths import skill_dir

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lab_scope():
    s = Scope()
    s.modes.add("explicit")
    s.clusters["lab"] = ClusterScope(
        context="lab",
        namespaces=["ramen-ops", "ramen-system", "openshift-dr-*"],
        explicit_namespaces={"ramen-ops", "ramen-system", "openshift-dr-*"},
    )
    s.containers = ["ramen-*"]
    s.wasm_artifacts = ["./policy.wasm"]
    return s


# ---------------------------------------------------------------------------
# off_limits always wins
# ---------------------------------------------------------------------------


def test_off_limits_wins_over_allow(lab_scope):
    lab_scope.off_limits.append(OffLimit(namespace="ramen-ops", verb="delete"))
    a = Action(
        adapter="k8s", verb="delete", context="lab", namespace="ramen-ops", resource="secrets"
    )
    ok, reason = lab_scope.is_in_scope(a)
    assert ok is False
    assert "off_limits" in reason


def test_off_limits_wins_over_wildcard_ns():
    s = Scope()
    s.clusters["lab"] = ClusterScope(context="lab", namespaces=["*"], explicit_namespaces={"*"})
    s.off_limits.append(OffLimit(resource="persistentvolumeclaims", verb="delete"))
    a = Action(
        adapter="k8s",
        verb="delete",
        context="lab",
        namespace="app",
        resource="persistentvolumeclaims",
    )
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "off_limits" in reason


def test_off_limits_glob_match(lab_scope):
    lab_scope.off_limits.append(OffLimit(namespace="openshift-*"))
    a = Action(adapter="k8s", verb="get", context="lab", namespace="openshift-dr-hub")
    ok, reason = lab_scope.is_in_scope(a)
    assert ok is False
    assert "off_limits" in reason


# ---------------------------------------------------------------------------
# control-plane lock — never reachable via inferred/inline scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ns",
    [
        "kube-system",
        "openshift-etcd",
        "openshift-kube-apiserver",
        "openshift-kube-apiserver-operator",
        "openshift-authentication",
        "default",
    ],
)
def test_control_plane_blocked_under_inferred(ns):
    s = Scope()
    # simulate --infer-scope adding a control-plane ns (which it shouldn't,
    # but defence-in-depth: even if it did, the lock holds)
    s.merge_inferred({"clusters": {"__current__": [ns, "tenant-a"]}})
    a = Action(adapter="k8s", verb="get", context="__current__", namespace=ns)
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "control-plane" in reason


def test_control_plane_blocked_under_inline():
    s = Scope()
    s.merge_inline(contexts=["lab"], namespaces=["kube-system", "tenant-a"])
    a = Action(adapter="k8s", verb="get", context="lab", namespace="kube-system")
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "control-plane" in reason


def test_control_plane_unlockable_only_via_explicit_targets_file():
    s = Scope()
    s.modes.add("explicit")
    s.clusters["lab"] = ClusterScope(
        context="lab",
        namespaces=["openshift-etcd"],
        explicit_namespaces={"openshift-etcd"},  # mode-1 only
    )
    a = Action(adapter="k8s", verb="get", context="lab", namespace="openshift-etcd")
    ok, reason = s.is_in_scope(a)
    assert ok is True, reason


def test_inferred_cannot_unlock_even_when_layered_on_explicit():
    s = Scope()
    s.modes.add("explicit")
    s.clusters["lab"] = ClusterScope(
        context="lab",
        namespaces=["tenant-a"],
        explicit_namespaces={"tenant-a"},
    )
    s.merge_inferred({"clusters": {"lab": ["openshift-etcd"]}})
    a = Action(adapter="k8s", verb="get", context="lab", namespace="openshift-etcd")
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "control-plane" in reason


# ---------------------------------------------------------------------------
# basic allow / deny
# ---------------------------------------------------------------------------


def test_in_scope_namespace(lab_scope):
    a = Action(adapter="k8s", verb="apply-manifest", context="lab", namespace="ramen-ops")
    ok, _ = lab_scope.is_in_scope(a)
    assert ok is True


def test_namespace_glob(lab_scope):
    a = Action(adapter="k8s", verb="get", context="lab", namespace="openshift-dr-hub")
    ok, _ = lab_scope.is_in_scope(a)
    assert ok is True


def test_out_of_scope_namespace(lab_scope):
    a = Action(adapter="k8s", verb="get", context="lab", namespace="other-app")
    ok, reason = lab_scope.is_in_scope(a)
    assert ok is False
    assert "namespace" in reason


def test_unknown_context(lab_scope):
    a = Action(adapter="k8s", verb="get", context="prod", namespace="ramen-ops")
    ok, reason = lab_scope.is_in_scope(a)
    assert ok is False
    assert "context" in reason


def test_verb_denied():
    s = Scope()
    s.clusters["lab"] = ClusterScope(
        context="lab",
        namespaces=["*"],
        explicit_namespaces={"*"},
        verbs_denied=["delete"],
    )
    a = Action(adapter="k8s", verb="delete", context="lab", namespace="app")
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "verb" in reason


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------


def test_expired_engagement(lab_scope):
    lab_scope.expires = _dt.date.today() - _dt.timedelta(days=1)
    a = Action(adapter="k8s", verb="get", context="lab", namespace="ramen-ops")
    ok, reason = lab_scope.is_in_scope(a)
    assert ok is False
    assert "expired" in reason


def test_unexpired_engagement(lab_scope):
    lab_scope.expires = _dt.date.today() + _dt.timedelta(days=1)
    a = Action(adapter="k8s", verb="get", context="lab", namespace="ramen-ops")
    ok, _ = lab_scope.is_in_scope(a)
    assert ok is True


# ---------------------------------------------------------------------------
# container / wasm adapters
# ---------------------------------------------------------------------------


def test_container_glob(lab_scope):
    ok, _ = lab_scope.is_in_scope(
        Action(adapter="container", verb="exec", name="ramen-hub-operator")
    )
    assert ok is True
    ok, reason = lab_scope.is_in_scope(Action(adapter="container", verb="exec", name="nginx"))
    assert ok is False
    assert "container" in reason


def test_wasm_artifact(lab_scope):
    ok, _ = lab_scope.is_in_scope(
        Action(adapter="wasm", verb="invoke-export", artifact="./policy.wasm")
    )
    assert ok is True
    ok, _ = lab_scope.is_in_scope(
        Action(adapter="wasm", verb="invoke-export", artifact="./other.wasm")
    )
    assert ok is False


def test_no_scope_means_no_action():
    s = Scope()
    for ad in ("k8s", "container", "wasm"):
        ok, _ = s.is_in_scope(Action(adapter=ad, verb="get"))
        assert ok is False


# ---------------------------------------------------------------------------
# binding-mode reporting
# ---------------------------------------------------------------------------


def test_binding_mode():
    s = Scope()
    assert s.binding_mode == "none"
    s.merge_inline(contexts=["lab"], namespaces=["a"])
    assert s.binding_mode == "inline"
    s.merge_inferred({"clusters": {"lab": ["b"]}})
    assert s.binding_mode == "mixed"


def test_modes_additive_union():
    s = Scope()
    s.merge_inline(contexts=["lab"], namespaces=["tenant-a"])
    s.merge_inferred({"clusters": {"lab": ["tenant-b"]}})
    assert s.is_in_scope(Action(adapter="k8s", verb="get", context="lab", namespace="tenant-a"))[0]
    assert s.is_in_scope(Action(adapter="k8s", verb="get", context="lab", namespace="tenant-b"))[0]


def test_namespace_hints_round_trip_without_granting_scope(tmp_path):
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "clusters:\n"
        "  - context: lab\n"
        "    namespaces: [allowed]\n"
        "    namespace_hints: [allowed, outside, kube-system]\n"
        "off_limits:\n"
        "  - namespace: allowed\n",
        encoding="utf-8",
    )
    scope = Scope.from_targets_file(targets)
    cluster = scope.clusters["lab"]
    assert cluster.namespace_hints == ["allowed", "outside", "kube-system"]
    assert cluster.namespaces == ["allowed"]
    assert cluster.explicit_namespaces == {"allowed"}
    assert (
        json.loads(scope.to_json())["clusters"]["lab"]["namespace_hints"] == cluster.namespace_hints
    )
    for namespace in cluster.namespace_hints:
        allowed, _ = scope.is_in_scope(
            Action(
                adapter="k8s",
                context="lab",
                namespace=namespace,
                resource="routes",
                verb="get",
            )
        )
        assert not allowed


@pytest.mark.parametrize(
    "hints",
    [
        "app",
        None,
        {"name": "app"},
        [None],
        [True],
        [42],
        [["app"]],
        [""],
        ["*"],
        ["app-*"],
        ["Upper"],
        ["-app"],
        ["app-"],
        ["app.example"],
        ["a" * 64],
        ["é"],
    ],
)
def test_malformed_namespace_hints_fail_closed(tmp_path, hints):
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        json.dumps(
            {"clusters": [{"context": "lab", "namespaces": ["allowed"], "namespace_hints": hints}]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="namespace_hints"):
        Scope.from_targets_file(targets)


@pytest.mark.parametrize("hints", [[], ["a", "1", "app-1", "a" * 63]])
def test_concrete_namespace_hints_do_not_extend_scope(tmp_path, hints):
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        json.dumps(
            {"clusters": [{"context": "lab", "namespaces": ["allowed"], "namespace_hints": hints}]}
        ),
        encoding="utf-8",
    )
    scope = Scope.from_targets_file(targets)
    assert scope.clusters["lab"].namespace_hints == hints
    assert scope.clusters["lab"].namespaces == ["allowed"]
    assert scope.clusters["lab"].explicit_namespaces == {"allowed"}
    for hint in hints:
        allowed, _ = scope.is_in_scope(
            Action(
                adapter="k8s",
                context="lab",
                namespace=hint,
                resource="routes",
                verb="get",
            )
        )
        assert not allowed


def test_wildcard_scope_still_honors_off_limits_for_hints(tmp_path):
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "clusters:\n"
        "  - context: lab\n"
        "    namespaces: ['*']\n"
        "    namespace_hints: [allowed, denied]\n"
        "off_limits:\n"
        "  - namespace: denied\n",
        encoding="utf-8",
    )
    scope = Scope.from_targets_file(targets)
    for namespace, expected in (("allowed", True), ("denied", False)):
        allowed, _ = scope.is_in_scope(
            Action(
                adapter="k8s",
                context="lab",
                namespace=namespace,
                resource="routes",
                verb="get",
            )
        )
        assert allowed is expected


# ---------------------------------------------------------------------------
# targets.example.yaml round-trip
# ---------------------------------------------------------------------------


def test_load_targets_example():
    pytest.importorskip("yaml")
    path = skill_dir("validate-findings") / "targets.example.yaml"
    s = Scope.from_targets_file(path)
    assert s.binding_mode == "explicit"
    assert "lab-hub" in s.clusters
    # The example ships a real engagement window (expiry is mandatory), and
    # the expiry gate preempts every other rule — pin BOTH sides of the
    # window instead of depending on today's date.
    assert s.expires is not None
    a = Action(adapter="k8s", verb="get", context="lab-spoke-1", namespace="openshift-etcd")
    s.expires = _dt.date.today() - _dt.timedelta(days=1)
    ok, reason = s.is_in_scope(a)
    assert ok is False
    assert "expired" in reason
    # Inside the window, the off_limits/control-plane rules decide:
    # off_limits from example is the openshift-etcd ns.
    s.expires = _dt.date.today() + _dt.timedelta(days=1)
    ok, reason = s.is_in_scope(a)
    assert ok is False
    # spoke has ns=* but off_limits + control-plane lock both apply
    assert "off_limits" in reason or "control-plane" in reason
    # delete PVC denied everywhere
    a2 = Action(
        adapter="k8s",
        verb="delete",
        context="lab-spoke-1",
        namespace="app",
        resource="persistentvolumeclaims",
    )
    ok2, reason2 = s.is_in_scope(a2)
    assert ok2 is False
    assert "off_limits" in reason2
