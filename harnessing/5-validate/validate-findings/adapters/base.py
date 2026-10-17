"""
Adapter base class and shared types.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, ClassVar


@dataclass
class Fingerprint:
    adapter: str
    identity: str  # context name / container id / wasm path
    version: str = ""
    digest: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def step_get(step, key, default=None):
    """Read *key* from a plan step that may be a dataclass OR a dict.

    Plan steps are dataclasses while in-memory (plan.py) but become plain
    dicts once round-tripped through ``*-attack-plan.yaml``.  Adapters
    must handle both — using ``getattr()`` alone silently returns
    ``default`` for dict steps, which is what dropped ``finding_ref``
    on every executed step before v0.4.2.
    """
    if isinstance(step, dict):
        return step.get(key, default)
    return getattr(step, key, default)


@dataclass
class StepResult:
    step_id: str
    adapter: str
    verb: str
    target: dict
    classification: str
    # confirmed|refuted|inconclusive|blocked_by_scope|not_attempted
    verdict: str
    expected: str = ""
    observed: str = ""
    evidence: list[dict] = field(default_factory=list)  # {type,path,sha256,caption}
    rollback_performed: bool | None = None
    rollback_output: str = ""
    scope_reason: str = ""
    error: str = ""  # environmental failure (e.g. probe-target-not-found)
    # set when a refuted verdict was gated to inconclusive (soundness.py)
    soundness_flag: str = ""
    duration_ms: int = 0
    finding_ref: str | None = None
    novel_ref: str | None = None

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


class AdapterBase:
    """Base class — subclasses override the verb tables and preflight()."""

    name: str = "base"

    #: verbs that never change target state
    SAFE_VERBS: ClassVar[set[str]] = {
        "get",
        "raw-readonly",
        "inspect",
        "rbac-can-i",
        "capability-probe",
        "port-forward+http",
    }
    #: verbs that change state but are reversible
    MUTATING_VERBS: ClassVar[set[str]] = {
        "apply-manifest",
        "create-cr",
        "patch-cr",
        "exec",
        "invoke-export",
        "network-probe",
        "cp",
    }
    #: verbs that delete data, kill workloads, or cannot be undone
    DESTRUCTIVE_VERBS: ClassVar[set[str]] = {"delete", "scale-zero", "kill", "fuzz-import"}

    def __init__(self) -> None:
        #: extra curl hosts for safe_exec; see bind_scope()
        self._curl_hosts: tuple[str, ...] = ()
        self._safe_exec_profile_map: dict[str, Any] | None = None

    def bind_scope(self, scope: object) -> None:
        """Take the curl host allowlist from the engagement scope.

        Lets a deployment run validation-step with `posture: restricted`
        and still reach the cluster it was authorized against."""
        getter = getattr(scope, "curl_hosts", None)
        self._curl_hosts = tuple(getter()) if callable(getter) else ()

    def bind_profile_map(self, profile_map: dict[str, Any] | None) -> None:
        """Take the resolved safe_exec profile map for this deployment."""
        self._safe_exec_profile_map = profile_map

    # ----- classification ---------------------------------------------

    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {"safe": 0, "mutating": 1, "destructive": 2}

    def classify(self, verb: str, payload: str | None = None, cmd: str | None = None) -> str:
        """Classify a step. The verb table is a FLOOR, never a pass:
        the content heuristic runs unconditionally and the result is
        the more severe of the two — a `raw`-verb step carrying
        `oc delete …` classified `safe` was a confirmed bypass
        (prior assessment F1)."""
        v = verb.lower()
        if v in self.DESTRUCTIVE_VERBS:
            table = "destructive"
        elif v in self.MUTATING_VERBS:
            table = "mutating"
        elif v in self.SAFE_VERBS:
            table = "safe"
        else:
            table = None
        content = self._classify_content(payload, cmd)
        if table is None:
            return content
        return max(table, content, key=lambda c: self._SEVERITY_ORDER[c])

    @classmethod
    def _classify_content(cls, payload: str | None, cmd: str | None) -> str:
        """Heuristic over the step's actual text. Routes human review;
        the execution gate remains _vet_shell_string/safe_exec (a
        substring denylist here was bypassable — audit C2, P2.13)."""
        text = f"{payload or ''} {cmd or ''}"
        classes = ["safe"]
        # kube-aware pass: classify by the real subcommand
        try:
            from . import kubeargv
        except ImportError:  # pragma: no cover — direct module load
            import kubeargv  # type: ignore
        kube = kubeargv.classify_worst(text.strip())
        if kube:
            classes.append(kube)
        try:
            tokens = [t.lower() for t in shlex.split(text)]
        except ValueError:
            return "destructive"  # unparseable → most conservative class
        joined = " ".join(tokens)
        if (
            any(t in ("delete", "rm", "kill", "destroy", "drop") for t in tokens)
            or "--replicas=0" in joined
        ):
            classes.append("destructive")
        if any(t in ("apply", "create", "patch", "exec", "post", "put", "write") for t in tokens):
            classes.append("mutating")
        return max(classes, key=lambda c: cls._SEVERITY_ORDER[c])

    # ----- execution helpers ------------------------------------------

    # Step text originates in finding prose — hostile per the threat
    # model. Validation and execution of string-form (PoC-derived)
    # steps delegate to traust_engine._util.safe_exec under the
    # "validation-step" profile ($TRAUST_CONFIG_HOME/safe-exec-profiles.yaml):
    # substitution/operator denies, per-segment binary allowlist, and
    # native pipeline execution with a scrubbed environment — no shell
    # at any point (closes audit C2 / plan P2.13; sandbox-adoption
    # WS1). Adapter-authored argv (list) steps are trusted code and run
    # directly. ALLOWED_STEP_BINARIES remains as the profile mirror for
    # error messages and callers.
    _SAFE_EXEC_PROFILE = "validation-step"
    ALLOWED_STEP_BINARIES = frozenset(
        {
            "curl",
            "oc",
            "kubectl",
            "jq",
            "grep",
            "base64",
            "head",
            "tail",
            "tr",
            "wc",
            "cat",
            "sleep",
            "echo",
            "printf",
        }
    )

    _safe_exec_mod = None

    @classmethod
    def _safe_exec(cls):
        if cls._safe_exec_mod is None:
            import importlib

            cls._safe_exec_mod = importlib.import_module("traust_engine._util.safe_exec")
        return cls._safe_exec_mod

    def _vet_shell_string(self, cmd: str) -> tuple[list[str] | None, str]:
        """Vet a PoC-derived command string via safe_exec. Returns
        (argv, "") for a pipeless command, (None, "") for an approved
        pipeline, or (None, reason) when rejected."""
        se = self._safe_exec()
        v = se.vet_command_string(
            cmd,
            se.get_profile(self._SAFE_EXEC_PROFILE, profile_map=self._safe_exec_profile_map),
            allowed_hosts=self._curl_hosts,
        )
        if not v.ok:
            return None, v.reason
        if len(v.segments) == 1:
            return list(v.segments[0]), ""
        return None, ""  # approved pipeline

    def _run(
        self, cmd: str | list[str], *, timeout: int = 120, input_: str | None = None
    ) -> tuple[int, str, str]:
        if isinstance(cmd, str):
            se = self._safe_exec()
            profile = se.get_profile(
                self._SAFE_EXEC_PROFILE, profile_map=self._safe_exec_profile_map
            )
            v = se.vet_command_string(cmd, profile, allowed_hosts=self._curl_hosts)
            if not v.ok:
                return 126, "", f"[step blocked: {v.reason}]"
            # single command or approved pipeline — both execute
            # natively under safe_exec (scrubbed env, no shell)
            return se.run_segments(v.segments, profile, timeout=timeout, input_=input_)
        argv = cmd
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_,
            )
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            return 124, out, err + f"\n[timeout after {timeout}s]"
        return proc.returncode, proc.stdout, proc.stderr

    # ---- credential redaction ----------------------------------------
    # Artifacts and observed-text are committed to analysis-results.  On
    # shared-CI clusters probe output can
    # contain LIVE cloud credentials.  Scrub before anything hits disk.
    _REDACT_PATTERNS: ClassVar[list] = [
        # PEM private-key blocks (RSA/EC/OPENSSH/PKCS8)
        (
            re.compile(
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
                r"-----END [A-Z ]*PRIVATE KEY-----",
                re.S,
            ),
            "pem-privkey",
        ),
        # kubeconfig / SA JSON embedded keys
        (
            re.compile(
                r"(client-key-data|private_key)\"?\s*[:=]\s*\"?"
                r"([A-Za-z0-9+/\\n=_-]{40,})",
                re.I,
            ),
            "key-data",
        ),
        # AWS access key id + secret
        (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "aws-akid"),
        (
            re.compile(
                r"(aws_secret_access_key|secretAccessKey)\"?\s*[:=]\s*\"?"
                r"([A-Za-z0-9+/=]{30,})",
                re.I,
            ),
            "aws-secret",
        ),
        # Azure SP / GCP SA secrets
        (
            re.compile(
                r"(client[_-]?secret|clientSecret|client_secret_data)"
                r"\"?\s*[:=]\s*\"?([A-Za-z0-9~._+/=-]{20,})",
                re.I,
            ),
            "cloud-client-secret",
        ),
        # Bearer / OpenShift sha256~ tokens / JWTs
        (re.compile(r"\b(sha256~[A-Za-z0-9_-]{20,})\b"), "oc-token"),
        (re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{20,})", re.I), "bearer"),
        (
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                r"\.[A-Za-z0-9_-]{10,}\b"
            ),
            "jwt",
        ),
        # Pull-secret / dockerconfigjson auth blobs
        (re.compile(r"(\"auth\"\s*:\s*\")([A-Za-z0-9+/=]{40,})"), "registry-auth"),
        # base64-encoded PEM material ("LS0tLS1CRUdJTi" = b64("-----BEGIN"))
        # — k8s Secret data values dodge the plaintext-PEM rule entirely
        # (assessment 2026-07-31 F3, execution-confirmed miss)
        (re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{40,}"), "b64-pem"),
        # .dockerconfigjson data values (b64 of '{"auths"' = eyJhdXRo)
        (re.compile(r"\beyJhdXRo[A-Za-z0-9+/=]{20,}"), "b64-dockerconfig"),
        # forge / chat tokens
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "github-token"),
        (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github-pat"),
        (re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"), "gitlab-pat"),
        (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
        (
            re.compile(
                r"(aws_session_token)\"?\s*[:=]\s*\"?"
                r"([A-Za-z0-9+/=]{40,})",
                re.I,
            ),
            "aws-session",
        ),
        # Generic password=… / token=… — key prefix included: the old
        # \b anchor let bind_password / MY_PASSWORD / admin_token pass
        # untouched (assessment 2026-07-31 F3, execution-confirmed)
        (
            re.compile(
                r"([A-Za-z0-9_.\-]*(?:password|passwd|token|"
                r"api[_-]?key|secret))"
                r"\"?\s*[:=]\s*\"?([^\s\"',;]{12,})",
                re.I,
            ),
            "generic-secret",
        ),
    ]

    # Keys whose ENTIRE value maps are secret material when they appear
    # in kubectl/oc JSON output (structure-aware pass — keyword rules
    # cannot enumerate every key name a Secret might carry).
    _SECRET_MAP_KEYS = ("data", "stringData")

    @classmethod
    def _redact_credentials(cls, text: str) -> str:
        if not text:
            return text
        out = cls._redact_secret_maps(text)
        for pat, tag in cls._REDACT_PATTERNS:

            def _sub(m, _tag=tag):
                full = m.group(0)
                # If there's a key=value capture, keep the key, redact value.
                if m.lastindex and m.lastindex >= 2:
                    val = m.group(m.lastindex)
                    h = hashlib.sha256(val.encode()).hexdigest()[:12]
                    return full.replace(val, f"[REDACTED:{_tag}:{len(val)}b:sha256:{h}]")
                h = hashlib.sha256(full.encode()).hexdigest()[:12]
                return f"[REDACTED:{_tag}:{len(full)}b:sha256:{h}]"

            out = pat.sub(_sub, out)
        return out

    @classmethod
    def _redact_secret_maps(cls, text: str) -> str:
        """Structure-aware pass (assessment 2026-07-31 F3): when the
        output is kubectl/oc JSON carrying Secret objects, redact EVERY
        value under data/stringData wholesale — keyword patterns cannot
        enumerate arbitrary Secret key names, and the confirmed miss
        list (tls.key, .dockerconfigjson, bind_password, admin_token,
        AWS_SESSION_TOKEN) all lived in these maps."""
        if '"data"' not in text and '"stringData"' not in text:
            return text
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text

        def scrub(node):
            if isinstance(node, dict):
                is_secretish = (
                    str(node.get("kind", "")).lower() in ("secret", "secretlist") or "data" in node
                )
                for k, v in list(node.items()):
                    if k in cls._SECRET_MAP_KEYS and isinstance(v, dict) and is_secretish:
                        node[k] = {
                            dk: f"[REDACTED:secret-data:{len(str(dv))}b]" for dk, dv in v.items()
                        }
                    else:
                        scrub(v)
            elif isinstance(node, list):
                for item in node:
                    scrub(item)

        scrub(doc)
        return json.dumps(doc, indent=1)

    @classmethod
    def _save_artifact(
        cls, artifacts_dir: Path, step_id: str, kind: str, content: str, ext: str = "log"
    ) -> dict:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = artifacts_dir / f"{step_id}.{kind}.{ext}"
        # sha256 of the ORIGINAL content (so evidence integrity is provable)
        # but the REDACTED content is what hits disk.
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        redacted = cls._redact_credentials(content)
        path.write_text(redacted, encoding="utf-8")
        meta = {
            "type": kind,
            "path": str(path.relative_to(artifacts_dir.parent)),
            "sha256": sha,
            "caption": f"{kind} for {step_id}",
        }
        if redacted != content:
            meta["redacted"] = True
        return meta

    # ----- interface ---------------------------------------------------

    def preflight(self, scope) -> list[Fingerprint]:  # pragma: no cover
        raise NotImplementedError

    def execute(self, step, scope, audit, artifacts_dir: Path) -> StepResult:  # pragma: no cover
        raise NotImplementedError

    def rollback(self, step, result: StepResult) -> tuple[bool, str]:
        """Default: run the step's rollback command if present."""
        rb = (
            getattr(step, "rollback", None) or step.get("rollback")
            if isinstance(step, dict)
            else getattr(step, "rollback", None)
        )
        if not rb:
            return False, "no rollback defined"
        rc, out, err = self._run(rb)
        return rc == 0, (out + err).strip()
