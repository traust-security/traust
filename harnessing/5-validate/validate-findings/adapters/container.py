"""
Running-container adapter — podman or docker.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from .base import AdapterBase, Fingerprint, StepResult
from .credentials import redact_credentials


def _rt(preferred: str | None = None) -> str:
    for b in ([preferred] if preferred else []) + ["podman", "docker"]:
        if b and shutil.which(b):
            return b
    return "podman"


class ContainerAdapter(AdapterBase):
    name = "container"

    SAFE_VERBS = AdapterBase.SAFE_VERBS | {"inspect", "logs"}
    MUTATING_VERBS = AdapterBase.MUTATING_VERBS | {"exec", "cp", "network-probe"}
    DESTRUCTIVE_VERBS = AdapterBase.DESTRUCTIVE_VERBS | {"kill", "rm", "restart"}

    def preflight(self, scope) -> list[Fingerprint]:
        rt = _rt(scope.container_runtimes[0] if scope.container_runtimes else None)
        out: list[Fingerprint] = []
        for pat in scope.containers:
            rc, txt, _ = self._run([rt, "inspect", pat])
            digest = ""
            details = {}
            if rc == 0:
                try:
                    j = json.loads(txt)[0]
                    digest = j.get("ImageDigest", j.get("Image", ""))
                    details = {
                        "running": j.get("State", {}).get("Running"),
                        "privileged": j.get("HostConfig", {}).get("Privileged"),
                    }
                except (json.JSONDecodeError, IndexError, AttributeError):
                    pass
            out.append(
                Fingerprint(adapter="container", identity=pat, digest=digest, details=details)
            )
        return out

    def execute(self, step, scope, audit, artifacts_dir: Path) -> StepResult:
        t0 = time.monotonic()
        target = step.target if hasattr(step, "target") else step.get("target", {})
        verb = step.verb if hasattr(step, "verb") else step["verb"]
        sid = step.id if hasattr(step, "id") else step["id"]
        cls = (
            step.classification
            if hasattr(step, "classification")
            else step.get("classification", "safe")
        )
        expected = getattr(step, "expected", "") or step.get("expected", "")
        name = target.get("name")
        rt = _rt(target.get("runtime"))
        evidence: list[dict] = []
        observed = ""
        rc = 1

        if verb == "inspect":
            rc, out, err = self._run([rt, "inspect", name])
            observed = (out + err).strip()
            evidence.append(
                self._save_artifact(artifacts_dir, sid, "stdout", observed[:200_000], ext="json")
            )
        elif verb == "exec":
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            # If cmd already starts with the runtime, run as-is; else wrap.
            if cmd.lstrip().startswith((rt, "podman", "docker")):
                rc, out, err = self._run(cmd)
            else:
                rc, out, err = self._run([rt, "exec", name, "sh", "-c", cmd])
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))
        elif verb == "network-probe":
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            rc, out, err = self._run(cmd)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "http", observed))
        elif verb == "cp":
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            rc, out, err = self._run(cmd)
            observed = (out + err).strip()
        else:
            return StepResult(
                step_id=sid,
                adapter="container",
                verb=verb,
                target=target,
                classification=cls,
                verdict="not_attempted",
                observed="(unsupported verb)",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        verdict = self._verdict(rc, observed, expected)
        return StepResult(
            step_id=sid,
            adapter="container",
            verb=verb,
            target=target,
            classification=cls,
            verdict=verdict,
            expected=expected,
            # container output carries env dumps / mounted-secret reads —
            # same redaction as the k8s adapter (assessment 2026-07-31 F16)
            observed=redact_credentials(observed)[:4000],
            evidence=evidence,
            finding_ref=(
                step.get("finding_ref")
                if isinstance(step, dict)
                else getattr(step, "finding_ref", None)
            ),
            novel_ref=(
                step.get("novel_ref")
                if isinstance(step, dict)
                else getattr(step, "novel_ref", None)
            ),
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    @staticmethod
    def _verdict(rc: int, observed: str, expected: str) -> str:
        low = observed.lower()
        # Denial signals → the finding (privilege/access claim) is refuted
        if any(
            w in low
            for w in (
                "permission denied",
                "not permitted",
                "forbidden",
                "unauthorized",
                "access denied",
                "operation not permitted",
            )
        ):
            return "refuted"
        if rc != 0:
            return "inconclusive"
        # Positive signals in output → exploit succeeded
        if any(
            w in low
            for w in (
                "vf-canary",
                "root",
                "cap_sys_admin",
                "docker.sock",
                "crio.sock",
                "containerd.sock",
                "200",
                "secret",
            )
        ):
            return "confirmed"
        # rc==0 with expected mentioning absence → check for negative-expected
        # probes (e.g. "no socket present") where clean exit means refuted
        exp_low = expected.lower()
        if any(
            w in exp_low
            for w in (
                "no socket",
                "no mount",
                "not present",
                "not accessible",
                "not found",
                "differs from host",
            )
        ):
            return "refuted"
        return "inconclusive"
