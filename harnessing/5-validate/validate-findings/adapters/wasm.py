"""
WASM adapter — wasmtime preferred, wasmedge fallback.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

from .base import AdapterBase, Fingerprint, StepResult
from .credentials import redact_credentials


def _wrt() -> str:
    for b in ("wasmtime", "wasmedge"):
        if shutil.which(b):
            return b
    return "wasmtime"


class WasmAdapter(AdapterBase):
    name = "wasm"

    SAFE_VERBS = AdapterBase.SAFE_VERBS | {"capability-probe", "instantiate"}
    MUTATING_VERBS = AdapterBase.MUTATING_VERBS | {"invoke-export"}
    DESTRUCTIVE_VERBS = AdapterBase.DESTRUCTIVE_VERBS | {"fuzz-import"}

    def preflight(self, scope) -> list[Fingerprint]:
        out: list[Fingerprint] = []
        for art in scope.wasm_artifacts:
            p = Path(art)
            digest = ""
            details = {}
            if p.is_file():
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                details["size"] = p.stat().st_size
                if shutil.which("wasm-tools"):
                    rc, _txt, _ = self._run(["wasm-tools", "validate", str(p)])
                    details["valid"] = rc == 0
            out.append(Fingerprint(adapter="wasm", identity=str(p), digest=digest, details=details))
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
        art = target.get("artifact")
        rt = _wrt()
        evidence: list[dict] = []
        observed = ""
        rc = 1

        if verb == "capability-probe":
            cmd = (
                getattr(step, "cmd", None)
                or step.get("cmd")
                or f"wasm-tools print {art} | grep -E '\\(import|\\(export'"
            )
            rc, out, err = self._run(cmd)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))
        elif verb in ("invoke-export", "instantiate"):
            cmd = getattr(step, "cmd", None) or step.get("cmd") or f"{rt} run {art}"
            rc, out, err = self._run(cmd, timeout=30)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "stdout", observed))
        elif verb == "fuzz-import":
            cmd = getattr(step, "cmd", None) or step.get("cmd", "")
            rc, out, err = self._run(cmd, timeout=60)
            observed = (out + err).strip()
            evidence.append(self._save_artifact(artifacts_dir, sid, "dump", observed))
        else:
            return StepResult(
                step_id=sid,
                adapter="wasm",
                verb=verb,
                target=target,
                classification=cls,
                verdict="not_attempted",
                observed="(unsupported verb)",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        expected = getattr(step, "expected", "") or step.get("expected", "")
        verdict = self._verdict(rc, observed, expected)
        return StepResult(
            step_id=sid,
            adapter="wasm",
            verb=verb,
            target=target,
            classification=cls,
            verdict=verdict,
            expected=expected,
            # module metadata can embed secrets from build env — same
            # redaction as the k8s adapter.
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
        exp_low = expected.lower()
        # For OOB/hostcall probes, a trap IS the positive signal
        if "trap" in low or "out of bounds" in low or "unreachable" in low:
            return "confirmed"
        # Capability/fuel enforcement working correctly → finding is refuted
        if any(
            w in low
            for w in ("fuel limit", "epoch deadline", "insufficient fuel", "resource exhausted")
        ):
            return "refuted"
        # Probe expected a security failure but the runtime enforced policy
        if rc != 0 and any(
            w in low
            for w in (
                "not allowed",
                "permission denied",
                "capability not",
                "access denied",
                "wasi error",
            )
        ):
            return "refuted"
        # Clean exit on probes that test for presence of a weakness: if
        # expected says "limited" / "enforces" / "rejected", clean = refuted
        if rc == 0 and any(
            w in exp_low for w in ("limited", "enforces", "rejected", "no ", "not ")
        ):
            return "refuted"
        # Clean exit with positive evidence
        if rc == 0 and any(w in low for w in ("vf-canary", "preopens", "import", "export")):
            return "confirmed"
        return "inconclusive"
