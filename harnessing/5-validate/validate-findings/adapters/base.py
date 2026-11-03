"""
Adapter base class and shared types.
"""

from __future__ import annotations

import hashlib
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import ClassVar

from traust.context import load

from .credentials import redact_credentials


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
    controls: list[dict] = field(default_factory=list)
    differential: dict | None = None
    replay: dict | None = None

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

    def __init__(self):
        pass

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
    # steps delegate to traust-core's safe-exec under the
    # "validation-step" profile (the safe-exec-profiles.yaml traust-core ships):
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

    _safe_exec_policy = None

    @classmethod
    def _safe_exec(cls):
        if cls._safe_exec_policy is None:
            cls._safe_exec_policy = load().safe_exec
        return cls._safe_exec_policy

    @classmethod
    def _vet_shell_string(cls, cmd: str) -> tuple[list[str] | None, str]:
        """Vet a PoC-derived command string via safe_exec. Returns
        (argv, "") for a pipeless command, (None, "") for an approved
        pipeline, or (None, reason) when rejected."""
        se = cls._safe_exec()
        v = se.vet_command_string(cmd, se.profile(cls._SAFE_EXEC_PROFILE))
        if not v.ok:
            return None, v.reason
        if len(v.segments) == 1:
            return list(v.segments[0]), ""
        return None, ""  # approved pipeline

    @classmethod
    def _run(
        cls, cmd: str | list[str], *, timeout: int = 120, input_: str | None = None
    ) -> tuple[int, str, str]:
        if isinstance(cmd, str):
            se = cls._safe_exec()
            profile = se.profile(cls._SAFE_EXEC_PROFILE)
            v = se.vet_command_string(cmd, profile)
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

    # ----- artifact storage -------------------------------------------
    @classmethod
    def _save_artifact(
        cls, artifacts_dir: Path, step_id: str, kind: str, content: str, ext: str = "log"
    ) -> dict:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = artifacts_dir / f"{step_id}.{kind}.{ext}"
        # sha256 of the ORIGINAL content (so evidence integrity is provable)
        # but the REDACTED content is what hits disk.
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        redacted = redact_credentials(content)
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
