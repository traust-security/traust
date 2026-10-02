#!/usr/bin/env python3
"""
Scope binding & enforcement for the validate-findings harness.

Three binding modes (additive, precedence high→low):
  1. explicit   — targets.yaml rules-of-engagement file
  2. inline     — --context/--ns/--image/--pod/--container/--wasm flags
  3. inferred   — derived from report metadata + threat-model entry points

Every adapter call is gated by Scope.is_in_scope(action). Hard denies
(off_limits, control-plane namespaces not explicitly allowlisted, expired
engagement) win over everything including --auto --destructive.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

if __package__:
    from .http_scope import HttpDiscovery, HttpTarget
else:
    from http_scope import HttpDiscovery, HttpTarget

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Namespaces that are NEVER in scope unless explicitly listed in a mode-1
# targets.yaml clusters[].namespaces entry. Inferred/inline scope cannot
# unlock these.
CONTROL_PLANE_NS_PATTERNS = (
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "default",
    "openshift",
    # Prefix pattern (assessment 2026-07-31 F4): the literal list missed
    # openshift-config (pull secret, IdP binds), openshift-ingress
    # (wildcard router key), openshift-monitoring, service-ca, ovn/sdn,
    # marketplace, OLM, csi-drivers — the highest-value namespaces.
    # Mode-1 explicit_namespaces remain the only unlock, unchanged.
    "openshift-*",
    "openshift-etcd",
    "openshift-etcd-operator",
    "openshift-kube-apiserver*",
    "openshift-kube-controller-manager*",
    "openshift-kube-scheduler*",
    "openshift-apiserver*",
    "openshift-authentication*",
    "openshift-oauth-apiserver",
    "openshift-cluster-version",
    "openshift-machine-api",
    "openshift-machine-config-operator",
)

# Cluster-scoped resources with control-plane blast radius: non-read
# verbs on these are locked unless the mode-1 ROE grants "*"
# (assessment 2026-07-31 F2).
CONTROL_PLANE_CLUSTER_RESOURCES = frozenset(
    {
        "nodes",
        "node",
        "clusterroles",
        "clusterrole",
        "clusterrolebindings",
        "clusterrolebinding",
        "customresourcedefinitions",
        "customresourcedefinition",
        "crds",
        "crd",
        "machineconfigs",
        "machineconfig",
        "machineconfigpools",
        "machineconfigpool",
        "apiservices",
        "apiservice",
        "clusterversions",
        "clusterversion",
        "clusteroperators",
        "clusteroperator",
        "namespaces",
        "namespace",
        "ns",
        "priorityclasses",
        "priorityclass",
        "oauths",
        "oauth",
        "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations",
    }
)

READONLY_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "describe",
        "logs",
        "top",
        "explain",
        "raw-read",
        "rbac-can-i",
        "can-i",
    }
)


@dataclass(frozen=True)
class Action:
    """A single intended operation against a live target."""

    adapter: str  # k8s | container | wasm
    verb: str  # apply-manifest, exec, get, ...
    context: str | None = None  # kubeconfig context
    namespace: str | None = None
    resource: str | None = None  # k8s resource kind (pods, secrets, ...)
    name: str | None = None  # resource / container / pod name
    image: str | None = None
    selector: str | None = None  # pod label selector
    artifact: str | None = None  # wasm artifact path
    extra: tuple = ()  # adapter-specific freeform

    def describe(self) -> str:
        parts = [f"{self.adapter}/{self.verb}"]
        if self.context:
            parts.append(f"ctx={self.context}")
        if self.namespace:
            parts.append(f"ns={self.namespace}")
        if self.resource:
            parts.append(f"res={self.resource}")
        if self.name:
            parts.append(f"name={self.name}")
        if self.image:
            parts.append(f"image={self.image}")
        if self.artifact:
            parts.append(f"wasm={self.artifact}")
        return " ".join(parts)


@dataclass
class ClusterScope:
    context: str
    api: str | None = None
    namespaces: list[str] = field(default_factory=list)  # globs OK; [] => none
    verbs_denied: list[str] = field(default_factory=list)
    explicit_namespaces: set[str] = field(default_factory=set)  # mode-1 literal entries
    http_discovery: HttpDiscovery = field(default_factory=HttpDiscovery)

    def ns_allowed(self, ns: str | None) -> bool:
        if ns is None:
            # Cluster-scoped / -A: fail closed (assessment 2026-07-31
            # F2 defect 1 — "any pattern exists" allowed cluster-wide
            # actions under every namespaced ROE). Only an explicit
            # "*" grant authorizes cluster-scoped reach.
            return "*" in self.namespaces
        return any(fnmatch.fnmatch(ns, pat) for pat in self.namespaces)


@dataclass
class OffLimit:
    """A hard-deny rule. All non-None fields must match for the rule to fire."""

    context: str | None = None
    namespace: str | None = None
    resource: str | None = None
    verb: str | None = None
    name: str | None = None
    image: str | None = None

    def matches(self, a: Action) -> bool:
        # Fail closed on unknown fields (assessment 2026-07-31 F2
        # defect 3): a deny rule keyed on resource/name must FIRE when
        # the action's field is undeterminable — raw steps with
        # resource=None sailed past every resource-keyed off_limits
        # rule. A set rule + a None value now counts as a match.
        def m(rule, val):
            return rule is None or val is None or fnmatch.fnmatch(val, rule)

        return (
            m(self.context, a.context)
            and m(self.namespace, a.namespace)
            and m(self.resource, a.resource)
            and m(self.verb, a.verb)
            and m(self.name, a.name)
            and m(self.image, a.image)
        )


@dataclass
class Scope:
    engagement: str | None = None
    authorized_by: str | None = None
    expires: _dt.date | None = None
    environment: str | None = None
    clusters: dict[str, ClusterScope] = field(default_factory=dict)
    http_targets: tuple[HttpTarget, ...] = ()
    containers: list[str] = field(default_factory=list)  # name globs
    container_runtimes: list[str] = field(default_factory=list)
    wasm_artifacts: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    off_limits: list[OffLimit] = field(default_factory=list)
    modes: set[str] = field(default_factory=set)  # explicit/inline/inferred
    # credential-liveness probe classes (aws, github, ...). EXPLICIT-ONLY:
    # only a mode-1 targets.yaml `credential_probes.classes` entry populates
    # this — inline flags and inferred scope can never unlock a probe
    # against a third-party credential service.
    credential_probe_classes: set[str] = field(default_factory=set)
    # cloud-inventory read scope (compliance Phase 2b). EXPLICIT-ONLY,
    # same rationale: enumerating an AWS account or cluster is an
    # authorized-engagement action even when read-only.
    inventory_aws_profiles: set[str] = field(default_factory=set)
    inventory_cluster_contexts: set[str] = field(default_factory=set)

    # ----- mode loaders -------------------------------------------------

    @classmethod
    def from_targets_file(cls, path: str | Path) -> Scope:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load --targets files")
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        s = cls()
        s.modes.add("explicit")
        s.engagement = data.get("engagement")
        s.authorized_by = data.get("authorized_by")
        s.environment = data.get("environment")
        if exp := data.get("expires"):
            s.expires = exp if isinstance(exp, _dt.date) else _dt.date.fromisoformat(str(exp))
        for c in data.get("clusters", []):
            ns = [str(n) for n in c.get("namespaces", [])]
            cs = ClusterScope(
                context=c["context"],
                api=c.get("api"),
                namespaces=ns,
                verbs_denied=[str(v) for v in c.get("verbs_denied", [])],
                explicit_namespaces=set(ns),
                http_discovery=HttpDiscovery.model_validate(c.get("http_discovery", {})),
            )
            s.clusters[cs.context] = cs
        s.http_targets = tuple(
            HttpTarget.model_validate(target) for target in data.get("http_targets", [])
        )
        if any(target.context not in s.clusters for target in s.http_targets):
            raise ValueError("HTTP target context must be explicitly declared in clusters")
        for c in data.get("containers", []):
            s.container_runtimes.append(c.get("runtime", "podman"))
            s.containers.extend(c.get("name_patterns", []))
        for w in data.get("wasm", []):
            s.wasm_artifacts.append(w["artifact"])
        s.images.extend(data.get("images", []))
        for ol in data.get("off_limits", []):
            s.off_limits.append(OffLimit(**ol))
        for cls_name in (data.get("credential_probes") or {}).get("classes", []):
            s.credential_probe_classes.add(str(cls_name))
        inv = data.get("cloud_inventory") or {}
        for p in inv.get("aws_profiles", []):
            s.inventory_aws_profiles.add(str(p))
        for c in inv.get("cluster_contexts", []):
            s.inventory_cluster_contexts.add(str(c))
        return s

    def merge_inline(
        self,
        *,
        contexts: Iterable[str] = (),
        namespaces: Iterable[str] = (),
        images: Iterable[str] = (),
        pods: Iterable[str] = (),
        containers: Iterable[str] = (),
        wasm: Iterable[str] = (),
    ) -> Scope:
        contexts = list(contexts)
        namespaces = list(namespaces)
        if contexts or namespaces or images or pods or containers or wasm:
            self.modes.add("inline")
        for ctx in contexts or ([None] if namespaces else []):
            key = ctx or "__current__"
            cs = self.clusters.setdefault(key, ClusterScope(context=key))
            cs.namespaces.extend(namespaces)
        self.images.extend(images)
        self.containers.extend(containers)
        # pod selectors don't restrict scope directly; record for adapters
        self._pod_selectors = list(pods)
        self.wasm_artifacts.extend(wasm)
        return self

    def merge_inferred(self, inferred: dict) -> Scope:
        """Lowest precedence: only adds entries not already present."""
        self.modes.add("inferred")
        for ctx, ns_list in inferred.get("clusters", {}).items():
            cs = self.clusters.setdefault(ctx, ClusterScope(context=ctx))
            for ns in ns_list:
                if ns not in cs.namespaces:
                    cs.namespaces.append(ns)
        for img in inferred.get("images", []):
            if img not in self.images:
                self.images.append(img)
        for c in inferred.get("containers", []):
            if c not in self.containers:
                self.containers.append(c)
        for w in inferred.get("wasm", []):
            if w not in self.wasm_artifacts:
                self.wasm_artifacts.append(w)
        return self

    # ----- evaluation ---------------------------------------------------

    def curl_hosts(self) -> tuple[str, ...]:
        """Endpoints safe_exec may let curl reach, for its host allowlist.

        `clusters[].api` is per-engagement, so it cannot live in
        safe-exec-profiles.yaml; passing it at the call site is what makes a
        restricted profile usable. Entries are returned
        verbatim: safe_exec normalizes URL and host:port forms to a hostname
        itself, and refuses entries that do not, which a local pass would
        mask."""
        apis = {str(c.api).strip() for c in self.clusters.values() if c.api}
        return tuple(sorted(apis | {target.host for target in self.http_targets}))

    @property
    def binding_mode(self) -> str:
        if not self.modes:
            return "none"
        if len(self.modes) == 1:
            return next(iter(self.modes))
        return "mixed"

    def _control_plane_locked(self, a: Action) -> str | None:
        """Return reason if action targets a control-plane ns not explicitly unlocked."""
        if a.adapter != "k8s":
            return None
        if not a.namespace:
            # Cluster-scoped leg (assessment 2026-07-31 F2 defect 2:
            # the early return left nodes/clusterroles/CRDs/MCPs
            # outside the lock entirely). Reads stay allowed; anything
            # else on a control-plane cluster resource needs mode-1 "*".
            if a.resource in CONTROL_PLANE_CLUSTER_RESOURCES and a.verb not in READONLY_VERBS:
                cs = self.clusters.get(a.context) or self.clusters.get("__current__")
                if (
                    cs
                    and "explicit" in self.modes
                    and cs.http_discovery.nodes is not None
                    and a.resource == "nodes"
                    and a.verb == "port-forward+http"
                ):
                    return None
                if cs and "*" in cs.explicit_namespaces:
                    return None
                return (
                    f"cluster-scoped control-plane resource "
                    f"'{a.resource}' (verb '{a.verb}') not "
                    "explicitly authorized in targets.yaml"
                )
            return None
        if not any(fnmatch.fnmatch(a.namespace, p) for p in CONTROL_PLANE_NS_PATTERNS):
            return None
        # only mode-1 explicit_namespaces can unlock
        cs = self.clusters.get(a.context) or self.clusters.get("__current__")
        if cs and any(fnmatch.fnmatch(a.namespace, p) for p in cs.explicit_namespaces):
            return None
        return f"control-plane namespace '{a.namespace}' not explicitly authorized in targets.yaml"

    def is_in_scope(self, a: Action) -> tuple[bool, str]:
        # 0. expiry
        if self.expires and _dt.date.today() > self.expires:
            return False, f"engagement expired {self.expires.isoformat()}"

        # 1. off_limits — hard deny, wins over everything
        for ol in self.off_limits:
            if ol.matches(a):
                return False, f"off_limits: {ol}"

        # 2. control-plane lock
        if reason := self._control_plane_locked(a):
            return False, reason

        # 3. adapter-specific allow
        if a.adapter == "k8s":
            cs = self.clusters.get(a.context) or self.clusters.get("__current__")
            if cs is None:
                return False, f"context '{a.context}' not in scope"
            if a.verb in cs.verbs_denied:
                return False, f"verb '{a.verb}' denied for context '{cs.context}'"
            node_discovery = (
                "explicit" in self.modes
                and cs.http_discovery.nodes is not None
                and a.resource == "nodes"
                and a.verb in {"get", "list", "port-forward+http"}
                and a.namespace is None
                and (
                    not cs.http_discovery.nodes.names
                    or a.name in cs.http_discovery.nodes.names
                    or (a.verb == "port-forward+http" and a.name is None)
                )
            )
            if not node_discovery and not cs.ns_allowed(a.namespace):
                return False, f"namespace '{a.namespace}' not in scope for context '{cs.context}'"
            if (
                a.image
                and self.images
                and not any(fnmatch.fnmatch(a.image, p) for p in self.images)
            ):
                return False, f"image '{a.image}' not in scope"
            return True, "ok"

        if a.adapter == "container":
            if not self.containers:
                return False, "no containers in scope"
            if a.name and not any(fnmatch.fnmatch(a.name, p) for p in self.containers):
                return False, f"container '{a.name}' not in scope"
            if (
                a.image
                and self.images
                and not any(fnmatch.fnmatch(a.image, p) for p in self.images)
            ):
                return False, f"image '{a.image}' not in scope"
            return True, "ok"

        if a.adapter == "credential":
            # read-only liveness introspection of a committed credential.
            # Fail-closed: requires an explicit targets.yaml grant for the
            # exact class (a.resource) and the single read-only verb.
            if "explicit" not in self.modes:
                return False, (
                    "credential probes require a mode-1 "
                    "targets.yaml (explicit scope) — inline/"
                    "inferred scope cannot unlock them"
                )
            if a.verb != "introspect":
                return False, (
                    f"credential verb '{a.verb}' denied — probes are read-only introspection only"
                )
            if a.resource not in self.credential_probe_classes:
                return False, (
                    f"credential class '{a.resource}' not in targets.yaml credential_probes.classes"
                )
            return True, "ok"

        if a.adapter == "inventory":
            # read-only cloud/cluster enumeration for compliance
            # snapshots. Fail-closed and explicit-only like credential
            # probes; verb locked to the single read verb.
            if "explicit" not in self.modes:
                return False, ("cloud inventory requires a mode-1 targets.yaml (explicit scope)")
            if a.verb != "enumerate":
                return False, (f"inventory verb '{a.verb}' denied — read-only enumeration only")
            if a.resource == "aws_profile":
                if a.name not in self.inventory_aws_profiles:
                    return False, (
                        f"aws profile '{a.name}' not in targets.yaml cloud_inventory.aws_profiles"
                    )
                return True, "ok"
            if a.resource == "cluster_context":
                if a.name not in self.inventory_cluster_contexts:
                    return False, (
                        f"context '{a.name}' not in targets.yaml cloud_inventory.cluster_contexts"
                    )
                return True, "ok"
            return False, f"unknown inventory resource '{a.resource}'"

        if a.adapter == "wasm":
            if not self.wasm_artifacts:
                return False, "no wasm artifacts in scope"
            if a.artifact and not any(
                fnmatch.fnmatch(a.artifact, p) or Path(a.artifact).resolve() == Path(p).resolve()
                for p in self.wasm_artifacts
            ):
                return False, f"wasm artifact '{a.artifact}' not in scope"
            return True, "ok"

        return False, f"unknown adapter '{a.adapter}'"

    # ----- serialization ------------------------------------------------

    def target_environment(self) -> str | None:
        """What this run executes AGAINST, for the validation artifact.

        NOT `self.environment`, which is the SAFETY class of the
        engagement (`lab` is what gates --auto). This is the target
        identity: the bound kubeconfig context(s), e.g. `lab-spoke-1`.

        Two runs of the same finding set against different targets are
        not re-runs of each other, and storage supersedes on this value.
        Measured before it existed: a hub run and a spoke run of one
        subject covered the same findings and disagreed on a material
        share of the verdicts, some confirmed against one target and
        refuted against the other.

        None when nothing cluster-shaped was bound -- a container- or
        image-only run has no cluster target, and None is the honest
        answer. Sorted and joined so the same binding always yields the
        same string; a set's iteration order would make one run look
        like two.
        """
        contexts = sorted(self.clusters)
        if not contexts:
            return None
        return ",".join(contexts)

    def to_json(self) -> str:
        d = {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "expires": self.expires.isoformat() if self.expires else None,
            "environment": self.environment,
            "binding_mode": self.binding_mode,
            "clusters": {
                k: {
                    "api": v.api,
                    "namespaces": v.namespaces,
                    "verbs_denied": v.verbs_denied,
                    "http_discovery": v.http_discovery.model_dump(mode="json"),
                }
                for k, v in self.clusters.items()
            },
            "http_targets": [target.model_dump(mode="json") for target in self.http_targets],
            "containers": self.containers,
            "wasm_artifacts": self.wasm_artifacts,
            "images": self.images,
            "off_limits": [asdict(o) for o in self.off_limits],
            "credential_probe_classes": sorted(self.credential_probe_classes),
        }
        return json.dumps(d, indent=2)


# convenience for skill-prompt invocation
def build(
    targets_file: str | None = None,
    contexts: list[str] | None = None,
    namespaces: list[str] | None = None,
    images: list[str] | None = None,
    pods: list[str] | None = None,
    containers: list[str] | None = None,
    wasm: list[str] | None = None,
    inferred: dict | None = None,
) -> Scope:
    s = Scope.from_targets_file(targets_file) if targets_file else Scope()
    s.merge_inline(
        contexts=contexts or [],
        namespaces=namespaces or [],
        images=images or [],
        pods=pods or [],
        containers=containers or [],
        wasm=wasm or [],
    )
    if inferred:
        s.merge_inferred(inferred)
    return s


if __name__ == "__main__":  # pragma: no cover
    import argparse

    p = argparse.ArgumentParser(description="Compile and dump a validate-findings scope.")
    p.add_argument("--targets")
    p.add_argument("--context", action="append", default=[])
    p.add_argument("--ns", action="append", default=[])
    p.add_argument("--image", action="append", default=[])
    p.add_argument("--pod", action="append", default=[])
    p.add_argument("--container", action="append", default=[])
    p.add_argument("--wasm", action="append", default=[])
    a = p.parse_args()
    print(
        build(
            targets_file=a.targets,
            contexts=a.context,
            namespaces=a.ns,
            images=a.image,
            pods=a.pod,
            containers=a.container,
            wasm=a.wasm,
        ).to_json()
    )
