#!/usr/bin/env python3
"""
Browser-based security validation runner.

Usage:
  run.py <validation-dir> [--plan FILE] [--targets FILE] [--destructive] [--out DIR]
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from adapter import BrowserAdapter, StepResult
from pydantic import ValidationError as PydanticValidationError
from traust_core.v1.errors import ValidationError as CoreValidationError
from traust_core.v1.models.validation import (
    BrowserTarget,
    ValidationAction,
    ValidationActionKind,
    ValidationScope,
    ValidationTarget,
)
from traust_core.v1.models.vocabulary import ScopeBindingMode

try:
    import yaml
except ImportError:
    yaml = None


# --- Models ---


@dataclass
class ValidationConfig:
    validation_dir: Path
    plan_path: Path
    targets_path: Path
    out_dir: Path
    source_audit: Path | None
    name: str
    destructive: bool

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> ValidationConfig:
        vdir = Path(args.validation_dir).resolve()
        out_dir = Path(args.out).resolve() if args.out else vdir
        out_dir.mkdir(parents=True, exist_ok=True)

        plan_path = _find_plan(vdir, args.plan)
        targets_path = _find_targets(vdir, args.targets)
        audits = list(vdir.glob("*-security-audit.json"))

        return cls(
            validation_dir=vdir,
            plan_path=plan_path,
            targets_path=targets_path,
            out_dir=out_dir,
            source_audit=audits[0] if audits else None,
            name=args.name or vdir.name,
            destructive=args.destructive,
        )


# --- Scope ---


@dataclass
class Targets:
    """The targets.yaml scope; credentials stay here, never in the core scope document."""

    scope: ValidationScope
    credentials: tuple[dict, ...]  # parallel to scope.browser, resolved by target index

    @classmethod
    def from_file(cls, path: Path) -> Targets:
        data = _load(path) or {}
        meta = data.get("metadata", data.get("meta", {}))
        expires = meta.get("expires") or data.get("expires")
        browser = data.get("browser", [])
        scope = ValidationScope(
            engagement=meta.get("engagement") or data.get("engagement"),
            authorized_by=meta.get("authorized_by") or data.get("authorized_by"),
            environment=meta.get("environment") or data.get("environment", "lab"),
            expires=dt.date.fromisoformat(expires) if isinstance(expires, str) else expires,
            modes=frozenset({ScopeBindingMode.EXPLICIT}),
            browser=tuple(
                BrowserTarget(
                    victim_origin=b["victim_origin"],
                    attacker_origins=tuple(b.get("attacker_origins", ())),
                    allowed_verbs=frozenset(b.get("allowed_verbs", ())),
                )
                for b in browser
            ),
        )
        return cls(scope, tuple(b.get("credentials", {}) for b in browser))

    def credentials_for(self, url: str) -> dict:
        # Same first-match walk the scope gate uses, so the credentials come
        # from the entry that authorised the verb even when origins repeat.
        for i, target in enumerate(self.scope.browser):
            if target.matches_url(url):
                return self.credentials[i]
        return {}


# --- Services ---


class AuditLog:
    """Append-only JSONL execution trace."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()

    def record(self, **fields) -> None:
        line = json.dumps({"ts": dt.datetime.now(dt.UTC).isoformat(), **fields}, default=str)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class PlanExecutor:
    """Executes attack plan steps through the browser adapter."""

    def __init__(self, adapter: BrowserAdapter, targets: Targets, audit: AuditLog):
        self._adapter = adapter
        self._targets = targets
        self._audit = audit
        self._done: dict[str, StepResult] = {}

    def run(
        self, steps: list[dict], artifacts_dir: Path, *, destructive: bool = False
    ) -> list[StepResult]:
        results: list[StepResult] = []
        for step in steps:
            result = self._execute_step(step, artifacts_dir, destructive=destructive)
            results.append(result)
            self._done[step["id"]] = result
            print(f"  {result.step_id}: {result.verb} → {result.verdict}")
        return results

    def _execute_step(self, step: dict, artifacts_dir: Path, *, destructive: bool) -> StepResult:
        sid = step["id"]
        verb = step.get("verb", "")
        cls = step.get("classification", "safe")
        target = step.get("target", {}) or {}
        url = target.get("url") or target.get("victim_origin") or ""

        # Gate: preconditions
        if reason := self._check_preconditions(step):
            self._audit.record(step_id=sid, verb=verb, verdict="not_attempted", reason=reason)
            return StepResult(
                step_id=sid,
                verb=verb,
                target=target,
                classification=cls,
                verdict="not_attempted",
                observed=reason,
            )

        # Gate: destructive
        if cls == "destructive" and not destructive:
            self._audit.record(
                step_id=sid,
                verb=verb,
                verdict="not_attempted",
                reason="destructive-blocked",
            )
            return StepResult(
                step_id=sid,
                verb=verb,
                target=target,
                classification=cls,
                verdict="not_attempted",
                observed="destructive not permitted",
            )

        # Gate: scope — resolve current page when step omits URL so origin
        # checks still bind to the page actually being acted on.
        if not url:
            url = getattr(self._adapter, "current_url", "") or ""
        try:
            decision = self._targets.scope.decide(
                ValidationAction(kind=ValidationActionKind.BROWSER, verb=verb),
                ValidationTarget(url=url),
                as_of=dt.date.today(),
            )
        except (PydanticValidationError, CoreValidationError) as e:
            # A malformed verb or URL is blocked and audited, never a crash:
            # the audit trail must survive every rejected step.
            reason = f"invalid action: {e}"
            self._audit.record(step_id=sid, verb=verb, verdict="blocked_by_scope", reason=reason)
            return StepResult(
                step_id=sid,
                verb=verb,
                target=target,
                classification=cls,
                verdict="blocked_by_scope",
                observed=reason,
            )
        if not decision.allowed:
            reason = decision.reason
            self._audit.record(step_id=sid, verb=verb, verdict="blocked_by_scope", reason=reason)
            return StepResult(
                step_id=sid,
                verb=verb,
                target=target,
                classification=cls,
                verdict="blocked_by_scope",
                observed=reason,
            )

        # Auto-inject credentials for authenticate verb
        if (
            verb == "authenticate"
            and not step.get("payload")
            and (creds := self._targets.credentials_for(url))
        ):
            step["payload"] = creds

        # Execute
        result = self._adapter.execute(step, artifacts_dir)
        self._audit.record(
            step_id=sid,
            verb=verb,
            verdict=result.verdict,
            observed=result.observed,
            duration_ms=result.duration_ms,
            evidence=[e.get("path", "") for e in result.evidence],
        )
        return result

    def _check_preconditions(self, step: dict) -> str | None:
        preconds = step.get("preconditions", [])
        # Fail closed: missing / not-yet-run / non-confirmed IDs all block.
        failed = [
            p for p in preconds if p not in self._done or self._done[p].verdict != "confirmed"
        ]
        return f"precondition failed: {','.join(failed)}" if failed else None


# NEED(contracts: validation-adapter enum — browser kind): the enum is k8s/container/wasm, so this
# report cannot be a core ValidationArtifact (recorded by `traust validation record`) yet.
class ReportBuilder:
    """Builds structured validation report JSON."""

    VERDICT_PRECEDENCE: ClassVar[list[str]] = [
        "confirmed",
        "refuted",
        "inconclusive",
        "blocked_by_scope",
        "not_attempted",
    ]

    def __init__(self, scope: ValidationScope, name: str):
        self._scope = scope
        self._name = name

    def build(
        self,
        results: list[StepResult],
        plan: dict,
        audit_path: Path,
        out_dir: Path,
        source_audit: Path | None,
    ) -> Path:
        by_verdict = {v: sum(1 for r in results if r.verdict == v) for v in self.VERDICT_PRECEDENCE}
        validated = self._group_findings(results)
        chains = [
            {
                "chain_id": c["chain_id"],
                "name": c["name"],
                "entry_point": c["entry_point"],
                "terminal_asset": c["terminal_asset"],
                "mitre_attack_refs": c.get("mitre_attack_refs", []),
            }
            for c in plan.get("chains", [])
        ]

        report = {
            "title": f"Browser Validation — {self._name}",
            "metadata": {
                "date": dt.date.today().isoformat(),
                "harness": "validate-browser-finding",
                "version": "0.1.0",
                "engagement": self._scope.engagement,
                "authorized_by": self._scope.authorized_by,
                "expires": self._scope.expires.isoformat() if self._scope.expires else None,
                "environment": self._scope.environment,
                "layer": "1-bare-app",
            },
            "source_reports": self._source_reports(source_audit),
            "summary": by_verdict,
            "validated_findings": validated,
            "attack_chains": chains,
            "execution_log_ref": "validation-audit.jsonl",
            "execution_log_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        }

        out = out_dir / f"{self._name}-validation.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return out

    def _group_findings(self, results: list[StepResult]) -> list[dict]:
        groups: dict[str, list[StepResult]] = {}
        for r in results:
            if ref := r.finding_ref:
                groups.setdefault(ref, []).append(r)

        validated = []
        for ref, steps in groups.items():
            verdicts = [s.verdict for s in steps]
            overall = next((v for v in self.VERDICT_PRECEDENCE if v in verdicts), "not_attempted")
            validated.append(
                {
                    "source_id": ref,
                    "verdict": overall,
                    "steps": [s.to_dict() for s in steps],
                    "evidence": [e for s in steps for e in s.evidence],
                }
            )
        return validated

    @staticmethod
    def _source_reports(path: Path | None) -> list[dict]:
        if not path or not path.exists():
            return []
        return [
            {
                "kind": "security-audit",
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        ]


# --- CLI ---


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if err := _check_deps():
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    config = ValidationConfig.from_args(args)
    targets = Targets.from_file(config.targets_path)
    scope = targets.scope

    if scope.expires and dt.date.today() > scope.expires:
        print("ERROR: engagement expired", file=sys.stderr)
        return 1

    plan = _load(config.plan_path)
    artifacts_dir = config.out_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(config.out_dir / "validation-audit.jsonl")

    print(f"Browser Validation: {config.name}")
    print(f"  Plan: {config.plan_path.name}")
    print(f"  Targets: {config.targets_path.name}")
    print(f"  Engagement: {scope.engagement}")
    print(f"  Expires: {scope.expires}")
    print()

    with BrowserAdapter() as adapter:
        executor = PlanExecutor(adapter, targets, audit)
        results = executor.run(plan.get("steps", []), artifacts_dir, destructive=config.destructive)

    report_path = ReportBuilder(scope, config.name).build(
        results,
        plan,
        audit.path,
        config.out_dir,
        config.source_audit,
    )

    confirmed = sum(1 for r in results if r.verdict == "confirmed")
    refuted = sum(1 for r in results if r.verdict == "refuted")
    inconclusive = sum(1 for r in results if r.verdict == "inconclusive")
    blocked = sum(1 for r in results if r.verdict == "blocked_by_scope")
    skipped = sum(1 for r in results if r.verdict == "not_attempted")

    print(
        f"\nResults: {confirmed} confirmed, {refuted} refuted, "
        f"{inconclusive} inconclusive, {blocked} blocked, {skipped} skipped"
    )
    print(f"Report: {report_path}")
    return 0


# --- Helpers ---


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("validation_dir", help="Directory with attack-plan, targets, compose")
    ap.add_argument("--plan", help="Attack plan YAML")
    ap.add_argument("--targets", help="Targets YAML")
    ap.add_argument("--destructive", action="store_true")
    ap.add_argument("--out", help="Output directory")
    ap.add_argument("--name", help="Slug for output files")
    return ap.parse_args(argv)


def _check_deps() -> str | None:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return "playwright not installed. Run: pip install playwright"
    try:
        import yaml  # noqa: F401
    except ImportError:
        return "pyyaml not installed. Run: pip install pyyaml"
    return None


def _find_plan(vdir: Path, override: str | None) -> Path:
    if override:
        return Path(override)
    plans = list(vdir.glob("*-attack-plan.yaml")) + list(vdir.glob("*-attack-plan.yml"))
    if not plans:
        print(f"ERROR: No *-attack-plan.yaml in {vdir}", file=sys.stderr)
        sys.exit(1)
    return plans[0]


def _find_targets(vdir: Path, override: str | None) -> Path:
    if override:
        return Path(override)
    p = vdir / "targets.yaml"
    if not p.exists():
        print(f"ERROR: No targets.yaml in {vdir}", file=sys.stderr)
        sys.exit(1)
    return p


def _load(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if yaml and path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


if __name__ == "__main__":
    sys.exit(main())
