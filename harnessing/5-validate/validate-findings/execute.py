#!/usr/bin/env python3
"""
Staged executor for the validate-findings harness.

Reads an attack-plan.yaml, enforces scope on every step, dispatches to the
correct adapter, captures evidence to artifacts/, and appends one JSONL
line per step to validation-audit.jsonl.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, ClassVar

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

if __package__:
    from . import soundness
    from .adapters import (
        Fingerprint,
        StepResult,
        kubeargv,
        new_adapter,
    )
    from .novel import diff_surfaces, probe_steps
    from .scope import Action, Scope
else:
    sys.path.insert(0, str(Path(__file__).parent))
    import soundness
    from adapters import (
        Fingerprint,
        StepResult,
        kubeargv,
        new_adapter,
    )
    from novel import diff_surfaces, probe_steps
    from scope import Action, Scope


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # ensure file exists for sha256 later
        self.path.touch()

    def append(self, **fields):
        line = json.dumps({"ts": _dt.datetime.now(_dt.UTC).isoformat(), **fields}, default=str)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


def _load_plan(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if yaml and path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def _step_action(step: dict) -> Action:
    t = step.get("target", {}) or {}
    return Action(
        adapter=step.get("adapter", "k8s"),
        verb=step.get("verb", ""),
        context=t.get("context"),
        namespace=t.get("namespace"),
        resource=t.get("resource"),
        name=t.get("name"),
        image=t.get("image"),
        artifact=t.get("artifact"),
    )


def _step_actions(step: dict) -> tuple[list[Action], str | None]:
    """Every Action a step really performs, plus a hard-deny reason.

    The parsed target dict alone was the confirmed F2 bypass
    (assessment 2026-07-31): the command's REAL argv can carry
    credential/target overrides, `-A`, and any number of `-n` flags the
    dict never mentions. For k8s string-command steps, derive one
    Action per kube command from the argv — real subcommand as verb,
    every real namespace (None for cluster-scoped/-A) — and deny
    retargeting flags outright. ALL derived actions must pass scope.
    """
    base_action = _step_action(step)
    actions = [base_action]
    if base_action.adapter != "k8s":
        return actions, None
    if step.get("target", {}).get("http") is not None:
        if step.get("cmd") or step.get("rollback"):
            return actions, "structured HTTP steps cannot carry command or rollback text"
        return actions, None
    cmd = step.get("cmd") or ""
    if not cmd:
        return actions, None
    for k in kubeargv.analyze(cmd):
        if k.denied_flags:
            return actions, (
                "step text carries cluster/credential override flag(s) "
                f"{', '.join(k.denied_flags)} — PoC-derived commands run "
                "only against the engagement-pinned context "
                "(assessment 2026-07-31 F2)"
            )
        real_verb = k.subcommand or base_action.verb
        if k.all_namespaces:
            ns_list = [None]
        elif k.namespaces:
            ns_list = list(k.namespaces)
        else:
            ns_list = [base_action.namespace]
        for ns in ns_list:
            actions.append(
                Action(
                    adapter="k8s",
                    verb=real_verb,
                    context=base_action.context,
                    namespace=ns,
                    resource=k.resource or base_action.resource,
                    name=None if k.resource in {"node", "nodes"} else base_action.name,
                    image=base_action.image,
                )
            )
    return actions, None


def _parse_recon_inventory(results: list[StepResult], artifacts_dir: Path) -> dict:
    """
    Best-effort parse of recon outputs into the structure novel.diff_surfaces
    expects. Heavy lifting (CRD field introspection etc.) is left to the
    AI-driven layer in the skill prompt; here we extract the cheap signals.
    """
    inv = {"crds": [], "rbac": [], "pods": [], "components": [], "wasm": [], "containers": []}
    for r in results:
        if r.adapter != "k8s" or r.verb != "raw":
            continue
        if "crd" in (r.observed[:200].lower() if r.observed else ""):
            try:
                j = json.loads(_load_evidence(r, artifacts_dir))
                for item in j.get("items", []):
                    spec = item.get("spec", {})
                    inv["crds"].append(
                        {
                            "api": (
                                f"{spec.get('group', '')}/"
                                f"{spec.get('versions', [{}])[0].get('name', 'v1')}"
                            ),
                            "kind": spec.get("names", {}).get("kind", ""),
                            "ref_fields": [],
                            "url_fields": [],
                        }
                    )
            except Exception:
                pass
    return inv


def _load_evidence(r: StepResult, artifacts_dir: Path) -> str:
    for ev in r.evidence:
        p = artifacts_dir.parent / ev["path"]
        if p.is_file():
            return p.read_text(encoding="utf-8")
    return r.observed or ""


def _auto_profile_map() -> dict[str, Any] | None:
    from traust.context import load_engine

    try:
        return load_engine().adapters.safe_exec_profile_map()
    except Exception as exc:
        raise RuntimeError(f"Failed to load safe_exec configuration from estate: {exc}") from exc


def preflight(scope: Scope, *, profile_map: dict[str, Any] | None = None) -> list[Fingerprint]:
    """Capture target fingerprints for ``metadata.target_fingerprint``.

    run.py calls this as ``ex.preflight(scope)`` (it always has — the
    function just never existed, so fingerprints came back empty).
    Delegates to each bound adapter's own ``preflight()``.
    """
    profiles = profile_map if profile_map is not None else _auto_profile_map()
    fps: list[Fingerprint] = []
    seen = set()
    bound = []
    if getattr(scope, "clusters", None):
        bound.append("k8s")
    if getattr(scope, "containers", None):
        bound.append("container")
    if getattr(scope, "wasm_artifacts", None):
        bound.append("wasm")
    for name in bound:
        if name in seen:
            continue
        seen.add(name)
        with contextlib.suppress(Exception):
            adapter = new_adapter(name)
            adapter.bind_scope(scope)
            adapter.bind_profile_map(profiles)
            fps.extend(adapter.preflight(scope))
    return fps


def run(
    plan_path: Path,
    scope: Scope,
    out_dir: Path,
    *,
    permit_destructive: bool = False,
    second_pass_novel: bool = True,
    profile_map: dict[str, Any] | None = None,
) -> tuple[list[StepResult], AuditLog]:
    profiles = profile_map if profile_map is not None else _auto_profile_map()
    adapters = {}

    def get_adapter(name: str) -> Any:
        if name not in adapters:
            adapter = new_adapter(name)
            adapter.bind_scope(scope)
            adapter.bind_profile_map(profiles)
            adapters[name] = adapter
        return adapters[name]

    plan = _load_plan(plan_path)
    steps: list[dict] = list(plan.get("steps", []))
    artifacts_dir = out_dir / "artifacts"
    audit = AuditLog(out_dir / "validation-audit.jsonl")

    # Refutation-soundness gate (soundness.py): an install-failure.yaml
    # in the run directory means the operand never deployed — no step in
    # this run may verdict `refuted`.
    install_failed = soundness.run_install_failed(out_dir)

    results: list[StepResult] = []
    done: dict[str, StepResult] = {}

    def record(step: dict, res: StepResult):
        # Soundness gate: `refuted` is un-emittable on error-signature
        # transcripts, zero-subject RBAC probes, or target-not-deployed
        # runs — downgrade to `inconclusive` with a machine-readable flag.
        gated, flag = soundness.gate_verdict(
            res.verdict, res.verb, res.observed, install_failure=install_failed
        )
        if flag:
            res.verdict = gated
            res.soundness_flag = flag
        results.append(res)
        done[res.step_id] = res
        audit.append(
            step_id=res.step_id,
            adapter=res.adapter,
            verb=res.verb,
            target=res.target,
            classification=res.classification,
            verdict=res.verdict,
            scope_check="pass" if not res.scope_reason else f"fail: {res.scope_reason}",
            evidence=[e["path"] for e in res.evidence],
            rollback=step.get("rollback"),
            finding_ref=res.finding_ref,
            novel_ref=res.novel_ref,
            **({"soundness_flag": res.soundness_flag} if res.soundness_flag else {}),
        )

    i = 0
    while i < len(steps):
        step = steps[i]
        i += 1
        sid = step["id"]
        verb = step.get("verb", "")
        cls = step.get("classification", "safe")
        http = step.get("target", {}).get("http")
        if isinstance(http, dict):
            method = http.get("method", "GET")
            severity = (
                "destructive"
                if method == "DELETE"
                else "mutating"
                if method in {"POST", "PUT", "PATCH"}
                else "safe"
            )
            ranks = {"safe": 0, "mutating": 1, "destructive": 2}
            cls = max((cls, severity), key=lambda value: ranks.get(value, 2))
            step["classification"] = cls

        # pre-skipped in plan
        if step.get("skip") and verb != "placeholder":
            res = StepResult(
                step_id=sid,
                adapter=step.get("adapter", "k8s"),
                verb=verb,
                target=step.get("target", {}),
                classification=cls,
                verdict=(
                    "blocked_by_scope" if "blocked_by_scope" in step["skip"] else "not_attempted"
                ),
                scope_reason=step["skip"],
                finding_ref=step.get("finding_ref"),
                novel_ref=step.get("novel_ref"),
            )
            record(step, res)
            continue

        # second-pass novel materialization
        if verb == "placeholder" and step.get("technique") == "novel":
            if second_pass_novel:
                inv = _parse_recon_inventory(
                    [
                        r
                        for r in results
                        if r.adapter and r.verdict != "not_attempted" and r.classification == "safe"
                    ],
                    artifacts_dir,
                )

                # threat_model is not in the plan file; diff_surfaces handles
                # an empty model gracefully.
                class _TM:
                    entry_points: ClassVar[list] = []
                    threats: ClassVar[list] = []

                cands = diff_surfaces(inv, _TM())
                extra = probe_steps(cands, context=next(iter(scope.clusters), "__current__"))
                # scope-check + classify the new steps before inserting
                for ex in extra:
                    ad = get_adapter(ex["adapter"])
                    ex["classification"] = ad.classify(ex["verb"], ex.get("payload"), ex.get("cmd"))
                    if ex["classification"] == "destructive" and not permit_destructive:
                        ex["skip"] = "destructive-not-permitted"
                steps[i:i] = extra  # insert after current position
            continue

        # preconditions
        unmet = [
            p
            for p in step.get("preconditions", [])
            if done.get(p) is None or done[p].verdict != "confirmed"
        ]
        if unmet:
            res = StepResult(
                step_id=sid,
                adapter=step.get("adapter", "k8s"),
                verb=verb,
                target=step.get("target", {}),
                classification=cls,
                verdict="not_attempted",
                scope_reason=f"precondition-failed:{','.join(unmet)}",
                finding_ref=step.get("finding_ref"),
                novel_ref=step.get("novel_ref"),
            )
            record(step, res)
            continue

        # scope guard (re-checked at exec time — plan may have been
        # edited). Every argv-derived action must pass, not just the
        # declared target dict (assessment 2026-07-31 F2).
        actions, deny = _step_actions(step)
        ok, reason = (False, deny) if deny else (True, "ok")
        if ok:
            for act in actions:
                ok, reason = scope.is_in_scope(act)
                if not ok:
                    reason = f"{reason} [{act.describe()}]"
                    break
        if not ok:
            res = StepResult(
                step_id=sid,
                adapter=step.get("adapter", "k8s"),
                verb=verb,
                target=step.get("target", {}),
                classification=cls,
                verdict="blocked_by_scope",
                scope_reason=reason,
                finding_ref=step.get("finding_ref"),
                novel_ref=step.get("novel_ref"),
            )
            record(step, res)
            continue

        if cls == "destructive" and not permit_destructive:
            res = StepResult(
                step_id=sid,
                adapter=step.get("adapter", "k8s"),
                verb=verb,
                target=step.get("target", {}),
                classification=cls,
                verdict="not_attempted",
                scope_reason="destructive-not-permitted",
                finding_ref=step.get("finding_ref"),
                novel_ref=step.get("novel_ref"),
            )
            record(step, res)
            continue

        # dispatch
        adapter = get_adapter(step.get("adapter", "k8s"))
        try:
            res = adapter.execute(step, scope, audit, artifacts_dir)
        except Exception as e:
            res = StepResult(
                step_id=sid,
                adapter=step.get("adapter", "k8s"),
                verb=verb,
                target=step.get("target", {}),
                classification=cls,
                verdict="inconclusive",
                observed=f"adapter error: {e!r}",
                finding_ref=step.get("finding_ref"),
                novel_ref=step.get("novel_ref"),
            )

        # rollback mutating steps immediately after evidence capture
        if (
            cls == "mutating"
            and not http
            and res.verdict not in {"blocked_by_scope", "not_attempted"}
        ):
            try:
                ok_rb, rb_out = adapter.rollback(step, res)
            except Exception as e:
                ok_rb, rb_out = False, f"rollback error: {e!r}"
            res.rollback_performed = ok_rb
            res.rollback_output = rb_out

        record(step, res)

    return results, audit


if __name__ == "__main__":  # pragma: no cover
    import argparse

    from scope import build as build_scope

    p = argparse.ArgumentParser(description="Execute an attack-plan.yaml.")
    p.add_argument("plan", help="path to *-attack-plan.yaml")
    p.add_argument("--targets")
    p.add_argument("--context", action="append", default=[])
    p.add_argument("--ns", action="append", default=[])
    p.add_argument("--container", action="append", default=[])
    p.add_argument("--wasm", action="append", default=[])
    p.add_argument("--destructive", action="store_true")
    p.add_argument("--out")
    a = p.parse_args()

    plan_path = Path(a.plan)
    out_dir = Path(a.out) if a.out else plan_path.parent
    scope = build_scope(
        targets_file=a.targets,
        contexts=a.context,
        namespaces=a.ns,
        containers=a.container,
        wasm=a.wasm,
    )
    results, audit = run(plan_path, scope, out_dir, permit_destructive=a.destructive)
    by = {}
    for r in results:
        by[r.verdict] = by.get(r.verdict, 0) + 1
    print(
        json.dumps(
            {"results": by, "audit_log": str(audit.path), "audit_sha256": audit.sha256()}, indent=2
        )
    )
