"""Regression tests for harness-security-assessment-2026-07-31 F1-F4
(all four were execution-confirmed bypasses of validate-findings)."""

import base64
import json
from pathlib import Path

import execute
from adapters import kubeargv
from adapters.credentials import redact_credentials
from adapters.k8s import K8sAdapter
from scope import Action, ClusterScope, OffLimit, Scope

# ------------------------------------------------------------------ F1


def test_raw_verb_delete_classifies_destructive():
    a = K8sAdapter()
    assert a.classify("raw", cmd="oc delete project openshift-etcd") == "destructive"


def test_raw_verb_apply_classifies_mutating():
    a = K8sAdapter()
    assert a.classify("raw", cmd="kubectl apply -f x.yaml") == "mutating"


def test_raw_verb_get_stays_safe():
    a = K8sAdapter()
    assert a.classify("raw", cmd="oc get pods -n app") == "safe"


def test_verb_table_is_floor_not_pass():
    a = K8sAdapter()
    # a destructive verb never gets downgraded by innocuous cmd text
    assert a.classify("delete", cmd="echo hello") == "destructive"


def test_unknown_kube_subcommand_never_safe():
    assert kubeargv.classify_worst("oc frobnicate everything") == "mutating"


# ------------------------------------------------------------------ F2


def _lab_scope(namespaces=("app",), off_limits=(), explicit=True):
    s = Scope()
    s.modes.add("explicit" if explicit else "inferred")
    cs = ClusterScope(
        context="lab",
        namespaces=list(namespaces),
        explicit_namespaces=set(namespaces) if explicit else set(),
    )
    s.clusters["lab"] = cs
    s.off_limits = list(off_limits)
    return s


def test_cluster_scoped_denied_without_star():
    s = _lab_scope(namespaces=("app",))
    ok, _reason = s.is_in_scope(Action(adapter="k8s", verb="get", context="lab", namespace=None))
    assert not ok


def test_cluster_scoped_allowed_with_star():
    s = _lab_scope(namespaces=("*",))
    ok, _ = s.is_in_scope(Action(adapter="k8s", verb="get", context="lab", namespace=None))
    assert ok


def test_off_limits_fires_on_unknown_resource():
    ol = OffLimit(resource="secrets", verb="delete")
    s = _lab_scope(namespaces=("app",), off_limits=(ol,))
    # raw step: resource undeterminable -> deny rule must fire
    ok, reason = s.is_in_scope(
        Action(adapter="k8s", verb="delete", context="lab", namespace="app", resource=None)
    )
    assert not ok and "off_limits" in reason


def test_openshift_prefix_namespaces_locked():
    s = _lab_scope(namespaces=("openshift-*",), explicit=False)
    for ns in ("openshift-config", "openshift-ingress", "openshift-monitoring"):
        ok, reason = s.is_in_scope(Action(adapter="k8s", verb="get", context="lab", namespace=ns))
        assert not ok, ns
        assert "control-plane" in reason


def test_cluster_control_plane_resources_locked_for_writes():
    # inferred "*" (e.g. gen_targets.py ROE) must NOT unlock
    s = _lab_scope(namespaces=("*",), explicit=False)
    ok, reason = s.is_in_scope(
        Action(
            adapter="k8s",
            verb="delete",
            context="lab",
            namespace=None,
            resource="customresourcedefinitions",
        )
    )
    assert not ok and "control-plane" in reason
    # reads stay allowed
    ok, _ = s.is_in_scope(
        Action(
            adapter="k8s",
            verb="get",
            context="lab",
            namespace=None,
            resource="customresourcedefinitions",
        )
    )
    assert ok
    # mode-1 explicit "*" is the sanctioned unlock
    s2 = _lab_scope(namespaces=("*",), explicit=True)
    ok, _ = s2.is_in_scope(
        Action(
            adapter="k8s",
            verb="delete",
            context="lab",
            namespace=None,
            resource="customresourcedefinitions",
        )
    )
    assert ok


def test_kubeconfig_override_flag_denied():
    step = {
        "adapter": "k8s",
        "verb": "raw",
        "target": {"context": "lab", "namespace": "app"},
        "cmd": ("oc --kubeconfig /home/u/.kube/hub.kubeconfig delete ns --all"),
    }
    _actions, deny = execute._step_actions(step)
    assert deny and "--kubeconfig" in deny


def test_argv_namespaces_all_checked():
    step = {
        "adapter": "k8s",
        "verb": "raw",
        "target": {"context": "lab", "namespace": "app"},
        "cmd": "oc -n openshift-config get secret pull-secret -o json",
    }
    actions, deny = execute._step_actions(step)
    assert deny is None
    real_ns = {a.namespace for a in actions}
    assert "openshift-config" in real_ns
    s = _lab_scope(namespaces=("app",))
    verdicts = [s.is_in_scope(a)[0] for a in actions]
    assert not all(verdicts)  # the real namespace fails scope


def test_all_namespaces_flag_maps_to_cluster_scope():
    step = {
        "adapter": "k8s",
        "verb": "raw",
        "target": {"context": "lab", "namespace": "app"},
        "cmd": "kubectl get secrets -A -o json",
    }
    actions, deny = execute._step_actions(step)
    assert deny is None
    assert any(a.namespace is None for a in actions[1:])
    s = _lab_scope(namespaces=("app",))
    assert not all(s.is_in_scope(a)[0] for a in actions)


# ------------------------------------------------------------------ F3

# Credential-shaped fixtures are assembled at runtime so no secret-looking
# literal sits in the tree for forge scanners to flag; every value is a dummy.
_PEM_B64 = base64.b64encode(("-----BEGIN RSA " + "PRIVATE KEY-----\n" + "a" * 29).encode()).decode()
_DOCKERCFG_B64 = base64.b64encode(
    json.dumps({"auths": {"quay.io": {"auth": "a" * 28}}}, separators=(",", ":")).encode()
).decode()
_ADMIN_TOKEN = "abcdef" + "0123456789" + "abcdef"
_AWS_SESSION_TOKEN = "FQoGZXIvYXdz" + "EBYaD" + "dummy" * 5 + "0="
SECRET_DUMP = json.dumps(
    {
        "kind": "SecretList",
        "items": [
            {
                "kind": "Secret",
                "metadata": {"name": "router-tls", "namespace": "openshift-ingress"},
                "data": {"tls.key": _PEM_B64, ".dockerconfigjson": _DOCKERCFG_B64},
            },
            {
                "kind": "Secret",
                "metadata": {"name": "ldap", "namespace": "openshift-config"},
                "stringData": {
                    "bind_password": "hunter2hunter2",
                    "MY_PASSWORD": "correcthorsebattery",
                    "admin_token": _ADMIN_TOKEN,
                    "AWS_SESSION_TOKEN": _AWS_SESSION_TOKEN,
                },
            },
        ],
    },
    indent=1,
)


def test_secret_maps_redacted_wholesale():
    out = redact_credentials(SECRET_DUMP)
    for leaked in (
        "LS0tLS1CRUdJTi",
        "eyJhdXRocyI6",
        "hunter2hunter2",
        "correcthorsebattery",
        _ADMIN_TOKEN,
        _AWS_SESSION_TOKEN[:16],
    ):
        assert leaked not in out, leaked
    # metadata survives (names/namespaces are needed evidence)
    assert "router-tls" in out and "openshift-ingress" in out


def test_snake_case_keys_redacted_in_plain_text():
    text = (
        "bind_password: hunter2hunter2\n"
        "MY_PASSWORD: correcthorsebattery\n"
        "ldap_bind_password: swordfish12345\n"
        f"admin_token: {_ADMIN_TOKEN}\n"
    )
    out = redact_credentials(text)
    for leaked in (
        "hunter2hunter2",
        "correcthorsebattery",
        "swordfish12345",
        _ADMIN_TOKEN,
    ):
        assert leaked not in out, leaked


def test_b64_pem_redacted_outside_json():
    text = f"tls.key: {_PEM_B64}"
    assert "LS0tLS1CRUdJTi" not in redact_credentials(text)


def test_forge_tokens_redacted():
    text = "x ghp_abcdefghijklmnopqrstuv123456 glpat-aaaabbbbccccdddd"
    out = redact_credentials(text)
    assert "ghp_abcdefghijklmnopqrstuv123456" not in out
    assert "glpat-aaaabbbbccccdddd" not in out


def test_tls_recon_step_carries_no_key_projection():
    import novel

    src = Path(novel.__file__).read_text(encoding="utf-8")
    assert "type=kubernetes.io/tls -o json" not in src
    assert ".data.tls\\\\.crt" in src or ".data.tls" in src
    # the projection must never request the private key
    assert "data.tls\\\\.key" not in src and "{.data.tls\\.key}" not in src
