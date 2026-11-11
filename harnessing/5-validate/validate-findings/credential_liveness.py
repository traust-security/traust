#!/usr/bin/env python3
"""Credential-liveness verifier — read-only probes for gitleaks candidates.

Takes the secret-free candidate artifact from `traust adapters gitleaks`,
re-reads each testable credential from the checkout (working tree or the
candidate's commit), and issues ONE read-only introspection call against
the credential's issuing service:

    class      probe                                  live / revoked signal
    github     GET  api.github.com/user               200 / 401
    gitlab     GET  <gitlab>/api/v4/user              200 / 401
    slack      POST slack.com/api/auth.test           ok:true / invalid_auth
    openshift  GET  <api>/apis/user.openshift.io/v1/users/~   200 / 401
    aws        `aws sts get-caller-identity` (needs the paired secret key
               in the same file; key id alone is UNTESTABLE)

Verdicts: CONFIRMED_LIVE / REVOKED / UNTESTABLE(reason). Every probe is
gated by the validate-findings scope guard (scope.py): the `credential`
adapter is EXPLICIT-ONLY — a mode-1 targets.yaml `credential_probes.classes`
entry is the only unlock; no targets file means every candidate is
UNTESTABLE. Probes are never destructive and never mutate the credential;
revocation is the finding owner's action, not ours.

Secret handling: values live only in process memory. The output artifact
and the audit trail carry a masked prefix (4 chars) at most, and a
serialization guard refuses to write any artifact containing a recovered
secret.

Usage:
    python3 credential_liveness.py --candidates <repo>-gitleaks.json \
        --repo <checkout> --targets targets.yaml [--out <file>] \
        [--endpoint openshift=https://api.cluster:6443] [--dry-run]

Exit 0 on a completed run (whatever the verdicts); 1 on input errors.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Harness root: the directory holding VERSION, found by walking up rather
# than counting parents, so nesting this skill under a stage directory
# (skill-usability plan 1.2) cannot silently repoint it.
HARNESS_ROOT = next(
    p
    for p in Path(__file__).resolve().parents
    if (p / "pyproject.toml").is_file()
    and 'name = "traust"' in (p / "pyproject.toml").read_text(encoding="utf-8")
)
_SCOPE_SPEC = importlib.util.spec_from_file_location(
    "vf_scope", Path(__file__).resolve().parent / "scope.py"
)
_scope_mod = importlib.util.module_from_spec(_SCOPE_SPEC)
sys.modules["vf_scope"] = _scope_mod
_SCOPE_SPEC.loader.exec_module(_scope_mod)
Scope, Action = _scope_mod.Scope, _scope_mod.Action

PROBE_TIMEOUT = 10  # seconds, single attempt, no retries

# per-class extraction regexes — mirror the gitleaks rules that route to
# each class (run_gitleaks.py LIVENESS_CLASSES).
# INTAKE RULE: adding a probe class means calling a new external service
# endpoint. The /check-harness-docs gate only detects subprocess binaries,
# not HTTP endpoints — every new class must add its endpoint to the
# web-APIs table in docs/external-dependencies.md by hand (and to
# run_gitleaks.py LIVENESS_CLASSES + targets.example.yaml).
# hosts a probe may carry recovered secrets to without being declared
# in the ROE targets file (plan P3): the services' own canonical
# Public endpoints. A deployment adds its own forge/lab domains through
# LIVENESS_PROBE_HOSTS / LIVENESS_PROBE_DOMAINS (comma-separated) rather
# than shipping them here — an internal hostname in a public default is a
# disclosure, and the probe set is site-specific anyway.
CANONICAL_PROBE_HOSTS = frozenset(
    {
        "api.github.com",
        "gitlab.com",
        "slack.com",
        "quay.io",
    }
    | {h.strip() for h in os.environ.get("LIVENESS_PROBE_HOSTS", "").split(",") if h.strip()}
)
CANONICAL_PROBE_DOMAINS = (
    "amazonaws.com",
    "openshiftapps.com",
    *tuple(d.strip() for d in os.environ.get("LIVENESS_PROBE_DOMAINS", "").split(",") if d.strip()),
)

SECRET_RXS = {
    "github": re.compile(
        r"(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36,255}"
        r"|github_pat_[A-Za-z0-9_]{22,255}"
    ),
    "gitlab": re.compile(
        r"glpat-[0-9a-zA-Z_=-]{20,22}"
        r"|glptt-[0-9a-f]{40}"
        r"|GR1348941[0-9a-zA-Z_-]{20,22}"
    ),
    "slack": re.compile(r"xox[bpsar]-[0-9a-zA-Z-]{10,250}"),
    "openshift": re.compile(r"sha256~[A-Za-z0-9_-]{43}"),
    "aws": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
}
AWS_PAIRED_SECRET_RX = re.compile(r"""(?i)aws.{0,40}?['"]([0-9a-zA-Z/+]{40})['"]""", re.S)


def mask(secret: str) -> str:
    return secret[:4] + "…" if secret else ""


def now_utc() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def recover_secret(repo: Path, cand: dict) -> str | None:
    """Re-read the credential from the checkout (never from the artifact)."""
    rx = SECRET_RXS.get(cand["liveness_class"])
    if rx is None:
        return None
    # commit comes from an artifact file — hex-gate blocks git-show
    # option injection via a leading-dash value (audit A4, plan P0.1)
    if cand.get("commit") and re.fullmatch(r"[0-9a-f]{7,40}", str(cand["commit"])):
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", f"{cand['commit']}:{cand['path']}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        text = proc.stdout if proc.returncode == 0 else ""
    else:
        try:
            text = (repo / cand["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    lines = text.splitlines()
    lo = max((cand.get("start_line") or 1) - 1, 0)
    hi = cand.get("end_line") or len(lines)
    window = "\n".join(lines[lo:hi]) or text
    m = rx.search(window) or rx.search(text)
    return m.group(0) if m else None


def _http(url: str, headers: dict, method: str = "GET"):
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return None, str(e)


def probe(cls: str, secret: str, endpoints: dict, file_text: str = "") -> dict:
    """One read-only introspection call. Returns verdict + evidence."""
    if cls == "github":
        status, body = _http(
            "https://api.github.com/user",
            {"Authorization": f"token {secret}", "User-Agent": "traust-credential-liveness"},
        )
        if status == 200:
            login = (json.loads(body or "{}") or {}).get("login")
            return {
                "verdict": "CONFIRMED_LIVE",
                "http_status": status,
                "identity": login,
                "endpoint": "https://api.github.com/user",
            }
        if status in (401, 403):
            return {
                "verdict": "REVOKED",
                "http_status": status,
                "endpoint": "https://api.github.com/user",
            }
        return {
            "verdict": "UNTESTABLE",
            "http_status": status,
            "reason": f"unexpected response: {status or body[:120]}",
        }

    if cls == "gitlab":
        base = endpoints.get("gitlab", "https://gitlab.com")
        url = f"{base.rstrip('/')}/api/v4/user"
        status, body = _http(url, {"PRIVATE-TOKEN": secret})
        if status == 200:
            login = (json.loads(body or "{}") or {}).get("username")
            return {
                "verdict": "CONFIRMED_LIVE",
                "http_status": status,
                "identity": login,
                "endpoint": url,
            }
        if status == 401:
            return {"verdict": "REVOKED", "http_status": status, "endpoint": url}
        return {
            "verdict": "UNTESTABLE",
            "http_status": status,
            "reason": f"unexpected response: {status or body[:120]}",
        }

    if cls == "slack":
        status, body = _http(
            "https://slack.com/api/auth.test", {"Authorization": f"Bearer {secret}"}, method="POST"
        )
        if status == 200:
            doc = json.loads(body or "{}") or {}
            if doc.get("ok"):
                return {
                    "verdict": "CONFIRMED_LIVE",
                    "http_status": status,
                    "identity": doc.get("user"),
                    "endpoint": "https://slack.com/api/auth.test",
                }
            if doc.get("error") in (
                "invalid_auth",
                "token_revoked",
                "account_inactive",
                "token_expired",
            ):
                return {
                    "verdict": "REVOKED",
                    "http_status": status,
                    "reason": doc.get("error"),
                    "endpoint": "https://slack.com/api/auth.test",
                }
        return {
            "verdict": "UNTESTABLE",
            "http_status": status,
            "reason": f"unexpected response: {status or body[:120]}",
        }

    if cls == "openshift":
        api = endpoints.get("openshift")
        if not api:
            return {
                "verdict": "UNTESTABLE",
                "reason": "no openshift API endpoint (targets.yaml "
                "clusters[].api or --endpoint openshift=…)",
            }
        url = f"{api.rstrip('/')}/apis/user.openshift.io/v1/users/~"
        status, body = _http(url, {"Authorization": f"Bearer {secret}"})
        if status == 200:
            name = ((json.loads(body or "{}") or {}).get("metadata") or {}).get("name")
            return {
                "verdict": "CONFIRMED_LIVE",
                "http_status": status,
                "identity": name,
                "endpoint": url,
            }
        if status == 401:
            return {"verdict": "REVOKED", "http_status": status, "endpoint": url}
        return {
            "verdict": "UNTESTABLE",
            "http_status": status,
            "reason": f"unexpected response: {status or body[:120]}",
        }

    if cls == "aws":
        m = AWS_PAIRED_SECRET_RX.search(file_text)
        if not m:
            return {
                "verdict": "UNTESTABLE",
                "reason": "access key id found but no paired secret "
                "key in the same file — cannot sign a "
                "request",
            }
        import shutil as _sh

        if not _sh.which("aws"):
            return {"verdict": "UNTESTABLE", "reason": "aws CLI not on PATH"}
        env = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": secret,
            "AWS_SECRET_ACCESS_KEY": m.group(1),
            "AWS_DEFAULT_REGION": "us-east-1",
        }
        env.pop("AWS_PROFILE", None)
        env.pop("AWS_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        if proc.returncode == 0:
            arn = (json.loads(proc.stdout or "{}") or {}).get("Arn")
            return {
                "verdict": "CONFIRMED_LIVE",
                "identity": arn,
                "endpoint": "sts:GetCallerIdentity",
            }
        err = proc.stderr
        if "InvalidClientTokenId" in err:
            return {
                "verdict": "REVOKED",
                "reason": "InvalidClientTokenId",
                "endpoint": "sts:GetCallerIdentity",
            }
        if "SignatureDoesNotMatch" in err:
            return {
                "verdict": "UNTESTABLE",
                "reason": "SignatureDoesNotMatch — key id may exist "
                "but the co-located secret is not its pair",
            }
        return {"verdict": "UNTESTABLE", "reason": f"sts error: {err.strip()[:160]}"}

    return {"verdict": "UNTESTABLE", "reason": f"no probe for class '{cls}'"}


def harness_version():
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return None
    try:
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (subprocess.SubprocessError, OSError):
        return v


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--candidates", required=True, type=Path, help="run_gitleaks.py output artifact"
    )
    ap.add_argument(
        "--repo", required=True, type=Path, help="the checkout the candidates were scanned from"
    )
    ap.add_argument(
        "--targets",
        type=Path,
        default=None,
        help="mode-1 rules-of-engagement file — the ONLY way "
        "to unlock probes (absent = every candidate "
        "UNTESTABLE)",
    )
    ap.add_argument(
        "--endpoint",
        action="append",
        default=[],
        metavar="CLASS=URL",
        help="override/provide a probe endpoint, e.g. openshift=https://api.cluster:6443",
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="plan probes (scope decisions included) without "
        "recovering secrets or calling anything",
    )
    args = ap.parse_args(argv)

    try:
        doc = json.loads(args.candidates.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read candidates: {e}", file=sys.stderr)
        return 1
    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"ERROR: {repo} is not a directory", file=sys.stderr)
        return 1

    scope = Scope.from_targets_file(args.targets) if args.targets else Scope()
    endpoints = {}
    for cs in scope.clusters.values():
        if cs.api:
            endpoints.setdefault("openshift", cs.api)
    for spec in args.endpoint:
        cls, _, url = spec.partition("=")
        # probes carry LIVE recovered secrets — an arbitrary --endpoint
        # would ship them to an attacker-chosen host (audit hardening
        # note, plan P3). https only; non-canonical hosts must be
        # declared in the ROE targets file, not on argv.
        if not url.startswith("https://"):
            print(f"ERROR: --endpoint {cls} must be https:// (got {url!r})", file=sys.stderr)
            return 1
        host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        canon = host in CANONICAL_PROBE_HOSTS or any(
            host.endswith("." + d) for d in CANONICAL_PROBE_DOMAINS
        )
        in_roe = any(host in (cs.api or "") for cs in scope.clusters.values())
        if not (canon or in_roe):
            print(
                f"ERROR: --endpoint host {host!r} is neither a "
                "canonical service endpoint nor declared in the ROE "
                "targets file — refusing to send recovered secrets "
                "there",
                file=sys.stderr,
            )
            return 1
        endpoints[cls] = url

    out = args.out or Path.cwd() / (
        args.candidates.stem.replace("-gitleaks", "") + "-credential-liveness.json"
    )
    audit_path = out.parent / "credential-liveness-audit.jsonl"

    verdicts, recovered = [], []
    counts = {"CONFIRMED_LIVE": 0, "REVOKED": 0, "UNTESTABLE": 0}
    for cand in doc.get("candidates") or []:
        cls = cand.get("liveness_class")
        entry = {
            "fingerprint": cand.get("fingerprint"),
            "rule_id": cand.get("rule_id"),
            "path": cand.get("path"),
            "commit": cand.get("commit"),
            "liveness_class": cls,
        }
        if cls is None:
            entry.update(verdict="UNTESTABLE", reason="no probe exists for this rule class")
            verdicts.append(entry)
            counts["UNTESTABLE"] += 1
            continue
        allowed, reason = scope.is_in_scope(
            Action(adapter="credential", verb="introspect", resource=cls)
        )
        audit = {
            "ts": now_utc(),
            "action": f"credential/introspect class={cls} path={cand.get('path')}",
            "fingerprint": cand.get("fingerprint"),
            "scope_allowed": allowed,
            "scope_reason": reason,
            "dry_run": args.dry_run,
        }
        if not allowed:
            entry.update(verdict="UNTESTABLE", reason=f"scope: {reason}")
            counts["UNTESTABLE"] += 1
        elif args.dry_run:
            entry.update(verdict="UNTESTABLE", reason="dry-run — probe planned, not executed")
            counts["UNTESTABLE"] += 1
        else:
            secret = recover_secret(repo, cand)
            if not secret:
                entry.update(
                    verdict="UNTESTABLE",
                    reason="could not re-extract the credential from the checkout",
                )
                counts["UNTESTABLE"] += 1
            else:
                recovered.append(secret)
                file_text = ""
                if cls == "aws":
                    with contextlib.suppress(OSError):
                        file_text = (repo / cand["path"]).read_text(
                            encoding="utf-8", errors="replace"
                        )
                    if cand.get("commit") and re.fullmatch(r"[0-9a-f]{7,40}", str(cand["commit"])):
                        proc = subprocess.run(
                            ["git", "-C", str(repo), "show", f"{cand['commit']}:{cand['path']}"],
                            capture_output=True,
                            text=True,
                            timeout=60,
                        )
                        if proc.returncode == 0:
                            file_text = proc.stdout
                res = probe(cls, secret, endpoints, file_text)
                entry["secret_prefix"] = mask(secret)
                entry.update(res)
                counts[res["verdict"]] += 1
                audit["verdict"] = res["verdict"]
                audit["http_status"] = res.get("http_status")
        verdicts.append(entry)
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(audit) + "\n")

    result = {
        "metadata": {
            "artifact": "credential-liveness-verdicts",
            "role": (
                "liveness verdicts for gitleaks candidates — "
                "CONFIRMED_LIVE is class-1 evidence (single "
                "read-only introspection); REVOKED refutes "
                "exposure-now but NOT historical exposure; "
                "revocation/rotation remains the finding owner's "
                "action."
            ),
            "harness_version": harness_version(),
            "candidates_artifact": str(args.candidates),
            "repository": str(repo),
            "engagement": scope.engagement,
            "authorized_by": scope.authorized_by,
            "scope_mode": scope.binding_mode,
            "probe_classes_authorized": sorted(scope.credential_probe_classes),
            "generated_at": now_utc(),
            "dry_run": args.dry_run,
        },
        "summary": counts,
        "verdicts": verdicts,
    }
    serialized = json.dumps(result, indent=2)
    for s in recovered:
        if len(s) > 8 and s in serialized:
            print(
                "FATAL: recovered secret would leak into the artifact — refusing to write",
                file=sys.stderr,
            )
            return 1
    out.write_text(serialized + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print("  " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
