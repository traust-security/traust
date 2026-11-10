"""
Kubernetes / OpenShift adapter — covers cluster, operator, pod, and
cluster-component target types via kubectl/oc.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from pathlib import Path

from traust_core.v1.errors import ServiceError

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None

from .base import AdapterBase, BlockedCommand, Fingerprint, StepResult, step_get
from .credentials import redact_credentials


def _kbin() -> str:
    """Prefer oc when available (OpenShift), fall back to kubectl."""
    for b in ("oc", "kubectl"):
        if shutil.which(b):
            return b
    return "kubectl"


def _http_target_error(target: dict, probe) -> str | None:
    """A discovery request may narrow, never contradict, its declared target."""
    resource = {
        "route": "routes",
        "service": "services",
        "node": "nodes",
        "direct": "http_targets",
    }[probe.mode]
    if not target.get("context") or target.get("resource") != resource:
        return "HTTP mode and declared target resource must match"
    namespace = target.get("namespace")
    if probe.mode == "node":
        if namespace is not None or probe.namespaces:
            return "node HTTP targets cannot declare a namespace"
    elif probe.mode in {"route", "service"}:
        if not probe.namespaces:
            return "namespaced HTTP discovery requires declared namespaces"
        if len(probe.namespaces) == 1 and namespace != probe.namespaces[0]:
            return "HTTP probe namespace does not match the declared target"
        if len(probe.namespaces) > 1 and namespace is not None:
            return "multiple HTTP candidate namespaces require an unspecified target namespace"
    elif len(probe.namespaces) > 1 or namespace != (
        probe.namespaces[0] if probe.namespaces else None
    ):
        return "direct HTTP namespace does not match the declared target"
    if target.get("name") != probe.name:
        return "HTTP probe name does not match the declared target"
    for field in ("method", "path", "port"):
        if field in target and target[field] != getattr(probe, field):
            return f"HTTP probe {field} does not match the declared target"
    return None


class K8sAdapter(AdapterBase):
    name = "k8s"

    SAFE_VERBS = AdapterBase.SAFE_VERBS | {
        "get",
        "raw",
        "rbac-can-i",
        "port-forward+http",
        "describe",
    }
    MUTATING_VERBS = AdapterBase.MUTATING_VERBS | {
        "apply-manifest",
        "create-cr",
        "patch-cr",
        "exec",
    }
    DESTRUCTIVE_VERBS = AdapterBase.DESTRUCTIVE_VERBS | {"delete", "scale-zero", "drain"}

    # exec fallback: target-pod images frequently lack probe tooling
    # (openssl/jq/dig/nc/xxd).  When exec returns "command not found",
    # re-run via a one-shot pod using a tools image in the same namespace.
    _CMD_NOT_FOUND_RE = re.compile(
        r"(?:^|: )(?:sh|bash)?:?\s*\S*(?:openssl|jq|dig|nslookup|nc|ncat|xxd|"
        r"base64|wget|python3?|tar|sed|awk|grep)\S*: "
        r"(?:command )?not found|executable file not found in \$PATH",
        re.I | re.M,
    )
    _TOOLS_IMAGE = os.environ.get(
        "VF_TOOLS_IMAGE",
        "registry.redhat.io/rhel9/support-tools:latest",
    )

    def __init__(self):
        super().__init__()
        self._last_mutating: dict[str, float] = {}
        self._rate_lock = threading.Lock()

    def _ctx(self, target: dict) -> list[str]:
        ctx = target.get("context")
        return ["--context", ctx] if ctx and ctx != "__current__" else []

    def _ns(self, target: dict) -> list[str]:
        ns = target.get("namespace")
        return ["-n", ns] if ns else []

    # ----- preflight ---------------------------------------------------

    def preflight(self, scope) -> list[Fingerprint]:
        if __package__ and "." in __package__:
            from ..scope import Action
        else:
            from scope import Action

        kb = _kbin()
        out: list[Fingerprint] = []
        for ctx in scope.clusters:
            if scope.selected_contexts and ctx not in scope.selected_contexts:
                continue
            if scope.expired():
                break
            ctx_args = [] if ctx == "__current__" else ["--context", ctx]
            rc, ver, _ = self._run([kb, *ctx_args, "version", "-o", "json"])
            details = {}
            version = ""
            if rc == 0:
                try:
                    j = json.loads(ver)
                    sv = j.get("serverVersion", {})
                    version = sv.get("gitVersion", "")
                    details = {
                        "platform": sv.get("platform", ""),
                        "buildDate": sv.get("buildDate", ""),
                    }
                except json.JSONDecodeError:
                    pass
            allowed, _ = scope.is_in_scope(
                Action(adapter="k8s", context=ctx, resource="nodes", name=None, verb="list")
            )
            if allowed and not scope.expired():
                rc2, nodes, _ = self._run(
                    [kb, *ctx_args, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}"]
                )
                if rc2 == 0:
                    details["nodes"] = len(nodes.split())
            out.append(Fingerprint(adapter="k8s", identity=ctx, version=version, details=details))
        return out

    # ----- execution ---------------------------------------------------

    def execute(self, step, scope, audit, artifacts_dir: Path) -> StepResult:
        kb = _kbin()
        t0 = time.monotonic()
        target = step_get(step, "target", None) or {}
        verb = step.verb if hasattr(step, "verb") else step["verb"]
        sid = step.id if hasattr(step, "id") else step["id"]
        cls = (
            step.classification
            if hasattr(step, "classification")
            else step.get("classification", "safe")
        )
        ctx_args = self._ctx(target)
        ns_args = self._ns(target)

        def _unresolved(reason: str) -> StepResult:
            """Early-out for a step whose target was not resolved.
            v0.4.2 let ``None`` flow into argv → TypeError → 93
            adapter-error inconclusives with no attribution."""
            return StepResult(
                step_id=sid,
                adapter="k8s",
                verb=verb,
                target=target,
                classification=cls,
                verdict="inconclusive",
                expected=step_get(step, "expected", ""),
                observed=f"step target not resolved: {reason}",
                scope_reason=f"target-unresolved:{reason}",
                finding_ref=step_get(step, "finding_ref"),
                novel_ref=step_get(step, "novel_ref"),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        if cls in ("mutating", "destructive"):
            ctx = target.get("context", "__current__")
            with self._rate_lock:
                wait = 2.0 - (time.monotonic() - self._last_mutating.get(ctx, 0))
                if wait > 0:
                    time.sleep(wait)
                self._last_mutating[ctx] = time.monotonic()

        evidence: list[dict] = []
        observed = ""
        rc = 1
        http_status = None

        if verb == "apply-manifest":
            raw = getattr(step, "payload", None) or step.get("payload", "")
            payload = self._normalize_manifest(raw)
            if not payload:
                return _unresolved("no parseable Kubernetes object in payload")
            evidence.append(
                self._save_artifact(artifacts_dir, sid, "manifest", payload, ext="yaml")
            )
            rc, out, err = self._run([kb, *ctx_args, *ns_args, "apply", "-f", "-"], input_=payload)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))

        elif verb == "exec":
            pod = target.get("name") or target.get("pod")
            if not pod:
                return _unresolved("no pod/name in step.target")
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            argv = [kb, *ctx_args, *ns_args, "exec", pod, "--", "sh", "-c", cmd]
            rc, out, err = self._run(argv)
            observed = (out + err).strip()
            # Fallback: target pod's image lacks the probe tool (openssl/jq/…).
            # Re-run in a one-shot tools pod in the same namespace so service
            # DNS / NetworkPolicy scope match.  ROSA clusters carry the global
            # pull secret for registry.redhat.io, so support-tools is pullable.
            if (
                not isinstance(err, BlockedCommand)
                and self._CMD_NOT_FOUND_RE.search(observed)
                and ns_args
            ):
                audit.append(
                    event="exec-tools-fallback",
                    step=sid,
                    reason="cmd-not-found-in-pod",
                    image=self._TOOLS_IMAGE,
                )
                pod_name = f"traust-probe-{sid.lower().replace('_', '-')}"[:63]
                fb_argv = [
                    kb,
                    *ctx_args,
                    *ns_args,
                    "run",
                    pod_name,
                    "--rm",
                    "-i",
                    "--quiet",
                    "--restart=Never",
                    f"--image={self._TOOLS_IMAGE}",
                    "--",
                    "sh",
                    "-c",
                    cmd,
                ]
                rc, out, err = self._run(fb_argv, timeout=180)
                observed = (out + err).strip()
                # best-effort cleanup if --rm raced
                self._run(
                    [
                        kb,
                        *ctx_args,
                        *ns_args,
                        "delete",
                        "pod",
                        pod_name,
                        "--ignore-not-found",
                        "--wait=false",
                    ]
                )
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))

        elif verb == "rbac-can-i":
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            rc, out, err = self._run(cmd)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))

        elif verb == "port-forward+http":
            if (
                target.get("http") is None
                or step_get(step, "cmd")
                or step_get(step, "rollback")
                or step_get(step, "payload")
            ):
                return StepResult(
                    step_id=sid,
                    adapter="k8s",
                    verb=verb,
                    target=target,
                    classification=cls,
                    verdict="blocked_by_scope",
                    scope_reason=(
                        "HTTP execution requires a structured target without command, "
                        "payload or rollback"
                    ),
                    finding_ref=step_get(step, "finding_ref"),
                    novel_ref=step_get(step, "novel_ref"),
                )
            if __package__ and "." in __package__:
                from ..http_endpoints import HttpProbe
            else:
                from http_endpoints import HttpProbe
            from .http import HttpExecutor

            try:
                probe = HttpProbe.model_validate(target["http"])
            except ValueError:
                return _unresolved("invalid structured HTTP probe")
            if reason := _http_target_error(target, probe):
                return StepResult(
                    step_id=sid,
                    adapter="k8s",
                    verb=verb,
                    target=target,
                    classification=cls,
                    verdict="blocked_by_scope",
                    scope_reason=reason,
                    finding_ref=step_get(step, "finding_ref"),
                    novel_ref=step_get(step, "novel_ref"),
                )
            expected = step_get(step, "expected", "") or ""
            requires_identity = re.search(
                r"\bauthenticated\b|logged[- ]in|console user|low[- ]privilege user"
                r"|low[- ]priv|any user with",
                expected,
                re.IGNORECASE,
            )
            if requires_identity and not probe.authenticate:
                return _unresolved("authenticated caller precondition is not satisfied")
            if not probe.csrf and re.search(
                r"\bcsrf\b|cross[- ]site request forgery", expected, re.IGNORECASE
            ):
                return _unresolved("CSRF session precondition is not satisfied")
            try:
                result = HttpExecutor(self, scope, kb, audit).execute(target.get("context"), probe)
                rc, out, err, http_status = (
                    result.code,
                    result.output,
                    result.error,
                    result.status,
                )
                observed = (out + err).strip()
                # Verdicts classify the unredacted transcript (a reflected
                # marker is the proof); persisted fields stay redacted.
                raw_observed = (result.raw_output + result.raw_error).strip()
            except PermissionError as exc:
                return StepResult(
                    step_id=sid,
                    adapter="k8s",
                    verb=verb,
                    target=target,
                    classification=cls,
                    verdict="blocked_by_scope",
                    scope_reason=str(exc),
                    finding_ref=step_get(step, "finding_ref"),
                    novel_ref=step_get(step, "novel_ref"),
                )
            except (ValueError, RuntimeError, TimeoutError, OSError, ServiceError):
                return _unresolved("HTTP target resolution or request failed")
            evidence.append(self._save_artifact(artifacts_dir, sid, "http", observed))

        elif verb in ("raw", "get", "describe"):
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            rc, out, err = self._run(cmd)
            observed = (out + err).strip()
            # `raw` PoCs frequently embed `oc exec <pod> -- openssl ...`.
            # If the inner exec hits cmd-not-found, retry the inner command
            # via a tools-pod in the same namespace (V050-REGRESSION §3).
            if (
                verb == "raw"
                and not isinstance(err, BlockedCommand)
                and self._CMD_NOT_FOUND_RE.search(observed)
                and not self._POC_PLACEHOLDER_RE.search(observed)
            ):
                # v0.5.2 H3: also match `oc rsh` and `oc debug` wrappers.
                m = re.search(
                    r"\b(?:oc|kubectl)\s+(?:-n\s+(\S+)\s+)?"
                    r"(?:exec|rsh|debug)\s+"
                    r"(?:-[it]+\s+)*(?:-n\s+(\S+)\s+)?(\S+)\s+"
                    r"(?:-c\s+\S+\s+)?(?:--\s+)?(.+?)(?:\n|$)",
                    cmd,
                    re.S,
                )
                if m:
                    inner_ns = m.group(1) or m.group(2) or (ns_args[1] if ns_args else None)
                    inner_cmd = m.group(4)
                    if inner_ns:
                        audit.append(
                            event="exec-tools-fallback",
                            step=sid,
                            reason="raw-embedded-exec-cmd-not-found",
                            image=self._TOOLS_IMAGE,
                        )
                        pod_name = f"traust-probe-{sid.lower().replace('_', '-')}"[:63]
                        fb = [
                            kb,
                            *ctx_args,
                            "-n",
                            inner_ns,
                            "run",
                            pod_name,
                            "--rm",
                            "-i",
                            "--quiet",
                            "--restart=Never",
                            f"--image={self._TOOLS_IMAGE}",
                            "--",
                            "sh",
                            "-c",
                            inner_cmd,
                        ]
                        rc, out, err = self._run(fb, timeout=180)
                        observed = (out + err).strip()
                        self._run(
                            [
                                kb,
                                *ctx_args,
                                "-n",
                                inner_ns,
                                "delete",
                                "pod",
                                pod_name,
                                "--ignore-not-found",
                                "--wait=false",
                            ]
                        )
            # v0.5.2 H5: 200 KB → 1 MB. The step-004 recon snapshot
            # (`kubectl get networkpolicies,svc,endpoints -A -o json`)
            # truncated after ~openshift-operator-lifecycle-manager on
            # large clusters, leaving 14 S1 wrong-port unresolvable.
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed[:1_000_000]))

        elif verb in ("patch-cr", "create-cr"):
            payload = getattr(step, "payload", None) or step.get("payload", "")
            sub = "create" if verb == "create-cr" else "patch"
            argv = [kb, *ctx_args, *ns_args, sub, "-f", "-"]
            if sub == "patch":
                argv = [
                    kb,
                    *ctx_args,
                    *ns_args,
                    "patch",
                    target.get("resource", ""),
                    target.get("name", ""),
                    "--type=merge",
                    "-p",
                    payload,
                ]
                rc, out, err = self._run(argv)
            else:
                rc, out, err = self._run(argv, input_=payload)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))

        else:  # glue, noop, placeholder, unknown
            return StepResult(
                step_id=sid,
                adapter="k8s",
                verb=verb,
                target=target,
                classification=cls,
                verdict="not_attempted",
                expected=step_get(step, "expected", ""),
                observed="(non-exec verb)",
                finding_ref=step_get(step, "finding_ref"),
                novel_ref=step_get(step, "novel_ref"),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        expected = step_get(step, "expected", "")
        if isinstance(err, BlockedCommand):
            verdict = "blocked_by_scope"
        elif verb == "port-forward+http" and (rc or not http_status or http_status == "000"):
            verdict = "inconclusive"
        else:
            verdict = self._verdict(
                verb,
                rc,
                (raw_observed or observed) if verb == "port-forward+http" else observed,
                expected,
                http_status=http_status,
            )
        err_tag = ""
        if (
            verdict == "inconclusive"
            and verb in ("raw", "get", "exec", "port-forward+http")
            and self._PROBE_NOT_FOUND_RE.search(observed)
        ):
            err_tag = "probe-target-not-found"
        # Redact AFTER verdict (verdict logic may key on token shape) but
        # BEFORE anything that persists — StepResult.observed lands in
        # validation-audit.jsonl and validation.json, both committed.
        observed_out = redact_credentials(observed)[:4000]
        res = StepResult(
            step_id=sid,
            adapter="k8s",
            verb=verb,
            target=target,
            classification=cls,
            verdict=verdict,
            expected=expected,
            observed=observed_out,
            evidence=evidence,
            error=err_tag,
            scope_reason=err.reason if isinstance(err, BlockedCommand) else "",
            finding_ref=step_get(step, "finding_ref"),
            novel_ref=step_get(step, "novel_ref"),
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
        return res

    # ----- rollback ----------------------------------------------------

    def rollback(self, step, result: StepResult) -> tuple[bool, str]:
        verb = step.verb if hasattr(step, "verb") else step.get("verb")
        target = step.target if hasattr(step, "target") else step.get("target", {})
        kb = _kbin()
        if verb in ("apply-manifest", "create-cr"):
            payload = getattr(step, "payload", None) or step.get("payload", "")
            # If the apply was rejected (admission webhook / validation
            # error), the resource was never created, so deleting would
            # nuke a pre-existing object of the same name (e.g. the
            # operand CR we installed).  Skip rollback in that case.
            obs = (result.observed or "").lower()
            if any(
                m in obs
                for m in (
                    "denied the request",
                    "error when applying",
                    "is invalid",
                    "(forbidden)",
                    "validation failed",
                )
            ):
                return True, "skip-rollback: apply was rejected, nothing to delete"
            rc, out, err = self._run(
                [
                    kb,
                    *self._ctx(target),
                    *self._ns(target),
                    "delete",
                    "-f",
                    "-",
                    "--ignore-not-found",
                    "--wait=false",
                    "--timeout=30s",
                ],
                input_=payload,
                timeout=60,
            )
            return rc == 0, (out + err).strip()
        return super().rollback(step, result)

    # ----- payload / cmd normalizers -----------------------------------

    @staticmethod
    def _normalize_manifest(payload: str) -> str:
        """Round-trip the PoC body through a YAML parser, keeping only
        documents that look like Kubernetes objects.

        Replay PoCs are raw fenced code blocks from audit reports.
        ~60 of them carry a prose lead-in containing ``:`` (→ ``mapping
        values are not allowed in this context``), mixed indentation
        (→ ``did not find expected ':'``), or a bare spec fragment with
        no ``kind`` (→ ``Object 'Kind' is missing``).  Re-dumping via
        ``safe_dump_all`` re-quotes scalar values containing ``:`` and
        normalises indentation; non-object docs are dropped.

        Falls back to the original payload if PyYAML is unavailable or
        nothing parses (so we never regress a previously-working step).
        """
        if not payload:
            return payload
        if _yaml is None:
            return payload
        try:
            docs = list(_yaml.safe_load_all(payload))
        except _yaml.YAMLError:
            # The whole blob is unparseable — try stripping a leading
            # prose line (common: "# title" lost its ``#`` in transit,
            # or a sentence ending in ``:`` precedes the manifest).
            body = re.sub(r"\A[^\n]*:[^\n]*\n", "", payload, count=1)
            try:
                docs = list(_yaml.safe_load_all(body))
            except _yaml.YAMLError:
                return payload
        objs = [d for d in docs if isinstance(d, dict) and d.get("kind") and d.get("apiVersion")]
        if not objs:
            return payload
        return _yaml.safe_dump_all(objs, sort_keys=False, default_flow_style=False)

    # ----- verdict heuristic -------------------------------------------

    # Tokens in ``observed`` that indicate the cluster *blocked* the
    # action.  For findings that claim privilege escalation, missing
    # authz, admission bypass, or confused-deputy, a block == refuted.
    _BLOCKED_TOKENS = (
        "forbidden",
        "unauthorized",
        " 401 ",
        " 403 ",
        "permission denied",
        "admission webhook",
        "denied the request",
        "is not allowed",
        "cannot get",
        "cannot list",
        "cannot create",
        "cannot patch",
        "validation.* failed",
        "field is immutable",
        # v0.5.2 H1: OS-level access-control denials are refutations of
        # "X is allowed/exposed" claims (V052-INCONCLUSIVE-ANALYSIS).
        "operation not permitted",
        r"\beacces\b",
        r"\beperm\b",
        "read-only file system",
    )
    # v0.5.2 H3: PoC ``cmd`` contains a literal placeholder (``...``,
    # Unicode ellipsis, or a YAML key like ``containers:``) that the
    # static-audit author never filled in.  ~34 inconclusives showed
    # ``bash: ...: command not found``.  Unrunnable → not_attempted.
    _POC_PLACEHOLDER_RE = re.compile(
        r"(?:^|\n)(?:bash|sh): "
        r"(?:\.{3}|…|<[A-Za-z_ -]{2,40}>|[a-zA-Z][\w-]*:): "
        r"command not found",
        re.MULTILINE,
    )
    # Tokens that indicate the action *landed* (resource changed, secret
    # exposed, callback received, write succeeded).
    _LANDED_TOKENS = (
        "created",
        "configured",
        "patched",
        "applied",
        "traust-ssrf-probe",
        "vf-canary",  # harness listener markers
        " 200 ",
        " 201 ",
        " 204 ",
    )
    # Stop-words to drop from ``expected`` before token-matching.
    _STOP = frozenset(
        [
            "a",
            "an",
            "the",
            "in",
            "on",
            "of",
            "to",
            "for",
            "from",
            "with",
            "and",
            "or",
            "is",
            "are",
            "be",
            "will",
            "should",
            "expected",
            "outcome",
            "that",
            "this",
            "when",
            "then",
            "via",
            "using",
            "value",
            "field",
            "namespace",
            "resource",
            "cluster",
            "pod",
            "service",
        ]
    )
    # v0.4.4: claim-vocabulary words that also appear in *error text*
    # (``Error from server``, ``serviceaccount``, ``container X is not
    # valid``, …).  These alone never confirm — step 3 requires ≥1
    # non-stop strong token.  ``pod``/``service`` already in _STOP.
    _VERDICT_STOP = frozenset(
        ("error", "container", "pod", "service", "account", "request", "server", "client")
    )
    # v0.4.4: error text that means the probe *target* (pod, container,
    # path, host) wasn't there.  Environmental — not a security control
    # denying, and not evidence the claim holds — so the only honest
    # verdict is ``inconclusive`` with ``error=probe-target-not-found``.
    _PROBE_NOT_FOUND_RE = re.compile(
        r"\b(notfound|not found|no such file|no such container|"
        r"is not valid for pod|does not exist|could not resolve host)\b",
        re.IGNORECASE,
    )
    # Noise lines emitted by `oc port-forward` itself, not the HTTP probe.
    # Stripped from `observed` before classification so the actual curl body
    # is what _verdict() sees. (~12 findings had only chatter → ambiguous.)
    _PF_CHATTER_RE = re.compile(
        r"^(?:Forwarding from |Handling connection for ).*$\n?",
        re.MULTILINE,
    )
    # PodSecurity admission rejected the probe pod/manifest. The cluster's
    # baseline PSA policy blocked us — that's a scope/environment constraint,
    # not evidence either way on the finding. (~8 findings.)
    _PSA_BLOCKED_RE = re.compile(
        r"would violate PodSecurity|violates PodSecurity",
        re.IGNORECASE,
    )

    @classmethod
    def _expected_tokens(cls, expected: str) -> set[str]:
        """Significant tokens from the ``expected:`` outcome string."""
        toks = re.findall(r"[A-Za-z0-9_./:-]{3,}", expected.lower())
        return {t for t in toks if t not in cls._STOP}

    @classmethod
    def _verdict(
        cls, verb: str, rc: int, observed: str, expected: str, *, http_status: str | None = None
    ) -> str:
        """Decide confirmed / refuted / inconclusive for a single step.

        The decision is **verb-aware** and consults the plan step's
        ``expected:`` outcome (a one-line human description of what
        observable result confirms the finding — added to source
        reports by PoC synthesis).

        Precedence:
          1. Verb-specific hard rules (rbac-can-i yes/no, exec no-pod).
          2. Block signals → refuted (the cluster denied what the
             finding said it would allow).
          3. ``expected``-token match in observed → confirmed.
          4. Verb default.
        """
        if verb == "port-forward+http":
            if http_status is None:
                status_match = re.search(r"(?:vf-http-status:|\b)(\d{3})\s*$", observed.strip())
                http_status = status_match.group(1) if status_match else None
            if rc or http_status == "000":
                return "inconclusive"
        ok = rc == 0
        # Strip port-forward chatter so the curl body is what we classify.
        observed = cls._PF_CHATTER_RE.sub("", observed)
        obs = f" {observed.lower()} "
        exp_low = (expected or "").lower()

        # ---- 0. environment blocks (not evidence either way) ---------
        if cls._PSA_BLOCKED_RE.search(observed):
            # PSA admission denied the probe; treat like a scope block.
            return "blocked_by_scope"
        # v0.5.2 H3: PoC was a placeholder/template, never a real probe.
        if cls._POC_PLACEHOLDER_RE.search(observed):
            return "not_attempted"
        # v0.5.2 H4: probe produced no output at all (out+err both empty).
        # Surface the exit code so the report shows *something*; downstream
        # P1-style review can then add an rc-based assertion. Don't try to
        # infer confirmed/refuted from rc alone — too many false positives.
        if not observed.strip():
            observed = f"(no output; rc={rc})"
            obs = f" {observed.lower()} "

        # ---- 1. verb-specific hard rules -----------------------------
        if verb == "rbac-can-i":
            # `oc auth can-i` prints "yes" / "no" (rc mirrors it), or
            # "yes - <reason>" / "no - RBAC: ..." with an explanation.
            first = obs.strip().split("\n", 1)[0]
            if first == "yes" or first.startswith(("yes ", "yes\t", "yes -")):
                return "confirmed"
            if first == "no" or first.startswith(("no ", "no\t", "no -")):
                # H9: "no" because the claimed subject isn't deployed
                # here (management-plane / wrong-cluster) is NOT a
                # refute — the ClusterRole may well be over-broad
                # where it IS deployed.  Likewise "no" only because
                # every candidate SA was skipped as cluster-admin
                # leaves the specific grant untested.
                if "vf-rbac-subject-hint-miss:" in obs:
                    return "inconclusive"
                if "vf-rbac-skipped-cluster-admin:" in obs and re.search(
                    r"vf-rbac-tried:\s*$", obs, re.M
                ):
                    return "inconclusive"
                # V3: empty vf-rbac-tried with NO skip = no SAs in
                # the scoped namespace at all — component not
                # deployed on this platform/featureSet (e.g.
                # cluster-api without TechPreview).  Not a refute.
                if re.search(r"vf-rbac-tried:\s*$", obs, re.M):
                    return "inconclusive"
                return "refuted"
            # warning lines etc → fall through
        elif verb == "raw":
            # v0.6.4 V056 §A: ~17 PoCs use ``verb: raw`` but the cmd is
            # ``oc auth can-i ...`` which prints bare ``yes``/``no``.
            # Apply the rbac-can-i rule when the FULL stripped observed
            # is exactly ``yes``/``no`` (or that repeated line-for-line,
            # e.g. ``yes\nyes`` from two chained can-i checks).  Anything
            # else on the line — ``yesterday``, ``yes - reason``, a
            # trailing warning — falls through to the generic rules.
            bare = observed.strip()
            if re.fullmatch(r"yes(?:\nyes)*", bare):
                return "confirmed"
            if re.fullmatch(r"no(?:\nno)*", bare):
                return "refuted"

        if verb == "exec":
            # No target pod → can't test, not a refute.
            if any(
                s in obs
                for s in ("not found", "no pods found", "unable to find", "no resources found")
            ):
                return "inconclusive"
            # Privilege-escalation claims: shell ran as root.
            if ("uid=0" in obs or "(root)" in obs) and any(
                w in exp_low for w in ("root", "uid=0", "privileg", "escalat", "container escape")
            ):
                return "confirmed"
            if any(
                s in obs
                for s in ("permission denied", "operation not permitted", "read-only file system")
            ):
                return "refuted"

        # Manual-PoC sentinel — wins over everything (the PoC author has
        # already encoded the confirm/refute decision in the cmd output).
        if "vf-manual-confirmed" in obs:
            return "confirmed"
        if "vf-manual-refuted" in obs:
            return "refuted"

        # v0.6.5: manifest didn't apply at all (malformed apiVersion,
        # CRD not installed, dry-run validation error).  The probe
        # never reached the surface under test → no signal.  Without
        # this guard, step 3 expected-token match false-confirmed
        # azure-file-csi/f001 on AWS because the error text echoed
        # the ClusterRole name (``…-secret-role`` matched ``secret``).
        if verb == "apply-manifest" and any(
            s in obs
            for s in (
                "no matches for kind",
                "resource mapping not found",
                "error validating ",
                "unable to recognize",
                "ensure crds are installed",
            )
        ):
            return "inconclusive"

        if verb == "port-forward+http":
            if "traust-ssrf-probe" in obs:
                return "confirmed"  # harness listener received the SSRF
            if "vf-no-svc-in-scope" in obs:
                return "inconclusive"  # no Route/Service in any in-scope ns
            # v0.6.5: probe fell through to kube-apiserver when the
            # svc-hint didn't match any in-scope route/svc.  Detect this
            # by the kube-aggregator metric (kube-apiserver-only) AND
            # the etcd client metric (only kube-apiserver talks to
            # etcd) BOTH present.  Many controllers embed
            # ``apiserver_*`` metrics via genericapiserver lib, so a
            # single-name check over-corrects (regressed 14 real
            # confirms in storage/monitoring/network on first try).
            if (
                "aggregator_discovery_aggregation_count" in obs
                and "etcd_request_duration_seconds" in obs
            ) and not any(
                w in exp_low for w in ("kube-apiserver", "apiserver", "aggregator", "etcd")
            ):
                return "inconclusive"
            # kube-rbac-proxy SAR denial (``Authorization error
            # (user=…, verb=…, resource=…)``).  Auth IS enforced.
            # V1: for "unauthenticated/exposed" claims that's a REFUTE
            # — the shipped deployment fronts the port with rbac-proxy.
            # Otherwise (probe under-specified resource) → inconclusive.
            if re.search(r"authoriz\w*\s+error\s*\(user=", obs, re.I) or re.search(
                r"authoriz.*error.*resource=,", obs, re.I
            ):
                if any(
                    w in exp_low
                    for w in (
                        "unauthenticat",
                        "without auth",
                        "no auth",
                        "missing auth",
                        "exposed",
                        "anonymous",
                        "bypass",
                        "unprotected",
                    )
                ):
                    return "refuted"
                return "inconclusive"
            # Hit an apiserver root and got the discovery doc — endpoint
            # IS reachable; whether that confirms depends on the claim.
            if '"paths"' in obs and '"/apis"' in obs:
                if any(
                    w in exp_low
                    for w in ("unauthenticat", "without auth", "no auth", "exposed", "reachable")
                ):
                    return "confirmed"
                return "inconclusive"
            code = http_status
            if code == "000" or "could not resolve" in obs or "connection refused" in obs:
                return "inconclusive"  # endpoint unreachable — no signal
            if code in ("401", "403"):
                # Auth IS enforced.  If the finding claims it should be
                # denied → confirmed; if it claims unauth access → refuted.
                if any(w in exp_low for w in ("denied", "rejected", "401", "403", "blocked")):
                    return "confirmed"
                # If the finding's precondition is an *authenticated* caller
                # and the adapted probe couldn't satisfy that auth model
                # (e.g. openshift-console accepts only its own OAuth session
                # cookie, not bearer tokens), a 401 means "probe could not
                # authenticate", not "vulnerability absent".
                if code == "401" and any(
                    w in exp_low
                    for w in (
                        "authenticated",
                        "logged-in",
                        "console user",
                        "low-privilege user",
                        "low-priv",
                        "any user with",
                    )
                ):
                    return "inconclusive"
                return "refuted"
            # v0.6.3: claim taxonomy used by A2/A3/2xx below.
            # V2: add plaintext/no-TLS/cleartext — an anonymous 2xx over
            # plain HTTP IS the success criterion for those claims; the
            # body-token matcher was leaving them inconclusive.
            claims_unauth = any(
                w in exp_low
                for w in (
                    "unauthenticat",
                    "without auth",
                    "no auth",
                    "missing auth",
                    "unauth ",
                    "anonymous",
                    "plaintext",
                    "no tls",
                    "cleartext",
                    "without tls",
                    "unprotected",
                )
            )
            claims_exposed = claims_unauth or any(
                w in exp_low
                for w in (
                    "exposed",
                    "ssrf",
                    "reachable",
                    "responds",
                    "200",
                    "pprof",
                    "metrics endpoint",
                )
            )
            claims_infoleak = any(
                w in exp_low
                for w in (
                    "info leak",
                    "stack trace",
                    "stacktrace",
                    "debug",
                    "exception",
                    "traceback",
                    "discloses",
                    "reveals",
                    "leak",
                )
            )
            # ---- A2: body-aware verdict --------------------------------
            # JSON error envelope ⇒ the service *handled* the request and
            # rejected it at app layer.  For unauth-access claims that's a
            # refute (auth/validation IS enforced); otherwise no signal.
            if (
                (
                    re.search(r'"(?:error|err|message|detail|title)"\s*:\s*"[^"]{2,}', obs)
                    or ('"kind"' in obs and '"status"' in obs and '"failure"' in obs)
                )
                and claims_unauth
                and (code is None or code[0] != "2")
            ):
                return "refuted"
            # Echo of the requested path / a distinctive resource name from
            # the expected outcome inside a 2xx body ⇒ the endpoint served
            # the attacker-chosen target → confirm exposure.  Tokens here
            # are already ≥6 chars + contain path punctuation, so plain
            # substring is safe (word-boundary fails on ``/etc/passwd``).
            if code and code.startswith("2") and expected:
                etoks = {
                    t
                    for t in cls._expected_tokens(expected)
                    if len(t) >= 6
                    and t not in cls._VERDICT_STOP
                    and ("/" in t or "." in t or "-" in t or "_" in t)
                }
                if any(t in obs for t in etoks):
                    return "confirmed"
            if code and code.startswith("2"):
                if claims_exposed:
                    return "confirmed"
                if any(w in exp_low for w in ("denied", "401", "403", "rejected", "blocked")):
                    return "refuted"  # control was supposed to block
            # ---- A3: 3xx / 5xx classification --------------------------
            if code and code.startswith("3"):
                # Redirect to a login/OAuth/SSO flow ⇒ auth IS enforced.
                if re.search(
                    r"\blocation:\s*\S*(?:login|oauth|sso|auth/|signin"
                    r"|authorize|realms/)\b",
                    obs,
                ) or re.search(
                    r"\b(?:/login|/oauth|/sso|/signin"
                    r"|/auth/realms)\b",
                    obs,
                ):
                    if claims_unauth:
                        return "refuted"
                    return "inconclusive"
                return "inconclusive"
            if code and code.startswith("5"):
                # 5xx body that contains a stack trace / debug detail and
                # the claim IS info-leak / debug-exposure → confirmed.
                if claims_infoleak and re.search(
                    r"\b(?:traceback|stack ?trace|panic:"
                    r"|goroutine \d+|at [\w$.]+\([\w.]+:\d+\)"
                    r"|caused by:|exception)\b",
                    obs,
                ):
                    return "confirmed"
                return "inconclusive"
            # legacy fallback — padded substring match
            if (" 200 " in obs or " 201 " in obs) and any(
                t in exp_low for t in ("200", "reachable", "responds", "exposed")
            ):
                return "confirmed"

        if verb == "network-probe":
            if any(w in obs for w in ("succeeded", " open ", "connected to")):
                return "confirmed"
            if any(
                w in obs
                for w in ("refused", "timed out", "timeout", "no route to host", "filtered")
            ):
                return "refuted"

        # ---- 2. block signals → refuted ------------------------------
        # The finding claims the action SHOULD succeed (or bypass
        # something).  If the cluster blocked it, the claim is refuted.
        # Exception: if expected itself describes a denial (the finding
        # is "X is wrongly denied"), invert.
        expected_is_denial = any(
            w in exp_low for w in ("denied", "forbidden", "401", "403", "rejected", "blocked")
        )
        for pat in cls._BLOCKED_TOKENS:
            if re.search(pat, obs):
                return "confirmed" if expected_is_denial else "refuted"

        # ---- 2b. probe-target-not-found → inconclusive ---------------
        # v0.4.4: ``Error from server (NotFound)``, ``no such file``,
        # ``container X is not valid for pod`` etc. mean the probe
        # never reached the surface under test.  Without this guard,
        # step 3 below substring-matched claim vocabulary inside the
        # error text (``account`` ⊂ ``serviceaccount``, ``oauth`` ⊂
        # ``oauth-proxy``) and emitted 6 false-positive confirms.
        if verb in ("raw", "get", "exec", "port-forward+http") and cls._PROBE_NOT_FOUND_RE.search(
            obs
        ):
            return "inconclusive"

        # ---- 3. expected-token match → confirmed ---------------------
        if expected:
            etoks = cls._expected_tokens(expected)

            def _hit(tok: str) -> bool:
                # v0.4.4: word-boundary match for tokens ≥4 chars so
                # ``account`` no longer matches inside ``serviceaccount``,
                # ``error`` inside ``errored``, etc.
                if len(tok) >= 4:
                    return re.search(r"\b" + re.escape(tok) + r"\b", obs) is not None
                return tok in obs

            # require ≥1 distinctive non-stop token (≥5 chars) to match,
            # OR ≥2 short tokens, to avoid trivial matches.
            strong = [t for t in etoks if len(t) >= 5 and t not in cls._VERDICT_STOP and _hit(t)]
            weak = [t for t in etoks if 3 <= len(t) < 5 and t not in cls._VERDICT_STOP and _hit(t)]
            if strong or len(weak) >= 2:
                return "confirmed"

        # ---- 4. verb defaults ----------------------------------------
        if not ok:
            return "inconclusive"

        if verb in ("apply-manifest", "create-cr", "patch-cr"):
            landed = any(t in obs for t in cls._LANDED_TOKENS)
            # The finding said the API server / webhook SHOULD reject
            # this object, but it was admitted → control is absent.
            # (Check this before the bypass-keywords below, since
            # "admission webhook should reject X" otherwise matches
            # the ``"admission"`` keyword and flips to confirmed.)
            if expected_is_denial and landed:
                return "refuted"
            # Manifest accepted.  If the finding's claim IS "CR accepts
            # <bad value> without validation" (expected mentions
            # accepted/created/without validation/admission), that's a
            # confirm.  Otherwise we only know the CR was admitted, not
            # that the controller acted on it → inconclusive.
            if any(
                w in exp_low
                for w in (
                    "accept",
                    "created",
                    "applied",
                    "without validation",
                    "without rejection",
                    "admission",
                    "webhook does not",
                    "no validation",
                    "bypass",
                )
            ):
                return "confirmed"
            # RBAC-escalation PoCs: a ClusterRoleBinding/RoleBinding
            # that grants the attacker elevated rights was accepted.
            if (
                landed
                and re.search(r"\b(clusterrolebinding|rolebinding)\b.*\bcreated\b", obs)
                and any(
                    w in exp_low
                    for w in (
                        "cluster-admin",
                        "cluster admin",
                        "escalat",
                        "privileg",
                        "rbac",
                        "→ full",
                        "-> full",
                    )
                )
            ):
                return "confirmed"
            if landed and not expected:
                # Legacy PoCs with no expected: keep prior behaviour.
                return "confirmed"
            return "inconclusive"

        if verb in ("raw", "get", "describe"):
            # v0.6.4 V056 §A: harness secret-scan completed cleanly
            # with no hits — ``vf-secret-scan-done`` present,
            # ``vf-plaintext-cred-found`` absent.  For findings whose
            # ``expected`` claims plaintext/credential/secret exposure,
            # that is a positive refutation: the scan ran over every
            # Secret/ConfigMap in the in-scope namespace and matched
            # nothing.  Checked before the base64-blob and
            # readable/exposed heuristics below so a clean scan never
            # confirms on incidental output. (~54 findings.)
            if (
                verb == "raw"
                and "vf-secret-scan-done" in obs
                and "vf-plaintext-cred-found" not in obs
                and any(
                    w in exp_low
                    for w in (
                        "plaintext",
                        "credential",
                        "secret",
                        "token",
                        "password",
                        "key leak",
                        "cleartext",
                    )
                )
            ):
                return "refuted"
            # Empty result set → nothing to read → claim refuted.
            if (
                observed.strip() in ("", "{}", "[]")
                or "no resources found" in obs
                or re.search(r'"items"\s*:\s*\[\s*\]', obs)
            ):
                if any(
                    w in exp_low
                    for w in (
                        "read",
                        "leak",
                        "expos",
                        "exfiltrat",
                        "harvest",
                        "secret",
                        "credential",
                        "token",
                        "obtain",
                    )
                ):
                    return "refuted"
                return "inconclusive"
            # Sensitive-data exposure claims: if the finding expects a
            # secret/token/key and the output contains a base64-looking
            # blob, the data IS exposed.
            if any(
                w in exp_low
                for w in (
                    "secret",
                    "token",
                    "password",
                    "credential",
                    "private key",
                    " key ",
                    "kubeconfig",
                )
            ) and re.search(r"[A-Za-z0-9+/]{20,}={0,2}", observed):
                return "confirmed"
            # An RBAC object the PoC tried to create via raw kubectl
            # was accepted → same escalation rule as apply-manifest.
            if re.search(r"\b(clusterrolebinding|rolebinding)\b.*\bcreated\b", obs) and any(
                w in exp_low
                for w in ("cluster-admin", "cluster admin", "escalat", "privileg", "rbac")
            ):
                return "confirmed"
            # Read-only recon — success means the data was readable.
            # Only confirm if expected explicitly says "readable" /
            # "exposed" / "leaks" / a specific secret key.
            if any(
                w in exp_low
                for w in ("readable", "exposed", "leak", "visible", "returns", "appears in")
            ):
                return "confirmed"
            return "inconclusive"

        if verb == "exec":
            # Shell command ran.  Confirm only on landed-tokens or
            # expected-match (handled above).
            if any(t in obs for t in cls._LANDED_TOKENS):
                return "confirmed"
            return "inconclusive"

        return "inconclusive"
