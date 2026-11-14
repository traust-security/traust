#!/usr/bin/env python3
"""Sanitizer micro-probes (Phase B3 — the narrow, lab-free slice of D4).

Executes repo-local sanitizer/validator functions in an isolated
subprocess against curated bypass corpora, recording per-payload
transcripts. Sanitizer-bypass findings are execution-shaped: reading a
sanitizer alone may not reveal whether a dangerous token survives it.

Two steps, deliberately separated:

  discovery         `traust adapters sanitizers <repo>` (traust-core's
                    code facts): candidate sanitizers by name/signature
                    shape, with file:line. Executes nothing.
  --run (this tool) EXECUTES REPOSITORY CODE. Imports each candidate's
                    module and calls it on bypass payloads. Run this only
                    inside the audit sandbox against a cloned, authorized
                    target — module import runs top-level code from the
                    audited repository (adversarial input by doctrine).
                    Containment: one `python3 -I` subprocess per module
                    (isolated mode — no user site, no PYTHONSTARTUP),
                    cleared environment, CPU/address-space rlimits,
                    hard timeout, cwd in a scratch dir.

Verdict vocabulary (soundness-gate aligned — an error is never evidence):
  survived      the payload's dangerous token reached the output intact
                → judged bypass CANDIDATE, never an auto-finding
  neutralized   output no longer carries the dangerous token
  error         the function (or its import) raised — outcome
                INCONCLUSIVE by the Phase-1 soundness rule: an
                error-signature transcript proves nothing about safety
  skipped       module import impossible (missing deps) — inconclusive

This is a CANDIDATE GENERATOR (docs/deterministic-inferential-mix.md):
`survived` still gets judged — the "sanitizer" may be defense-in-depth
behind a real encoder, or the probe's call convention may not match
production use. Judging protocol: secure-code-audit SKILL.md (sanitizer
micro-probe section).

Python-only in v1; Go/JS probing needs a build step and is handled by
create-fuzzing.

Usage:
    python3 probe_sanitizers.py <repo-path> --run --candidates <file>
                                [--only NAME] [--out <file>]
                                [--timeout SECONDS]

--candidates is the `traust adapters sanitizers` output (or a hand-written
`{"candidates": [{function, path, line, arg, is_method}]}` naming a
judge-chosen function). Output defaults to
<repo-basename>-sanitizer-probes.json in the CWD.
Exit 0 on completed probing; 1 on bad input.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.paths import HARNESS_ROOT

# Bypass corpora: (class, payload, survival token). A probe "survives"
# when the survival token appears in the function's output unchanged.
# Kept deliberately small and curated — this is a spot probe, not a
# fuzzer; breadth belongs to /create-fuzzing.
CORPORA = [
    ("ssti-jinja", "{{7*7}}", "{{"),
    ("ssti-jinja", "{%raw%}x{%endraw%}", "{%"),
    ("ssti-jinja", "{{''.__class__.__mro__}}", "__class__"),
    ("ssti-jinja-unicode", "｛｛7*7｝｝", "｛｛"),
    ("path-traversal", "../../etc/passwd", ".."),
    ("path-traversal-enc", "..%2f..%2fetc%2fpasswd", "..%2f"),
    ("path-traversal-win", "..\\..\\windows\\system32", "..\\"),
    ("null-byte", "safe.txt\x00.py", "\x00"),
    ("xss", "<script>alert(1)</script>", "<script"),
    ("xss-attr", '" onmouseover=alert(1) x="', "onmouseover="),
    ("sql", "' OR '1'='1", "' OR '"),
    ("shell", "; cat /etc/passwd #", "; cat"),
    ("shell-subst", "$(id)", "$("),
    ("crlf", "value\r\nSet-Cookie: pwn=1", "\r\n"),
    ("bidi", "file‮ gpj.exe", "‮"),
]


PROBE_DRIVER = r"""
import importlib.util, json, sys
mod_path, fn_name, payloads_json = sys.argv[1], sys.argv[2], sys.argv[3]
payloads = json.loads(payloads_json)
results = []
try:
    spec = importlib.util.spec_from_file_location("probe_target", mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, fn_name)
except BaseException as e:  # import failure = every probe inconclusive
    print(json.dumps({"import_error": f"{type(e).__name__}: {e}"[:300]}))
    sys.exit(0)
for p in payloads:
    try:
        out = fn(p["payload"])
        results.append({"class": p["class"],
                        "output": "" if out is None else str(out)[:500]})
    except BaseException as e:
        results.append({"class": p["class"],
                        "exception": f"{type(e).__name__}: {e}"[:300]})
print(json.dumps({"results": results}))
"""


def _rlimit_preexec():  # pragma: no cover - child-process context
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))


def probe(repo: Path, candidates: list[dict], timeout: int) -> list[dict]:
    """Execute candidates against the corpora. EXECUTES REPO CODE —
    caller is responsible for invoking this only in the audit sandbox."""
    probes = []
    payloads = [{"class": c, "payload": p} for c, p, _ in CORPORA]
    tokens = {(c, p): tok for c, p, tok in CORPORA}
    with tempfile.TemporaryDirectory(prefix="sanitizer-probe-") as scratch:
        for cand in candidates:
            if cand.get("is_method"):
                probes.append(
                    {
                        **cand,
                        "outcome": "skipped",
                        "reason": "bound method — no stable construction convention",
                    }
                )
                continue
            mod_path = str(repo / cand["path"])
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        PROBE_DRIVER,
                        mod_path,
                        cand["function"],
                        json.dumps(payloads),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=scratch,
                    env={"PATH": "/usr/bin:/bin"},
                    preexec_fn=_rlimit_preexec if os.name == "posix" else None,
                )
            except subprocess.TimeoutExpired:
                probes.append({**cand, "outcome": "error", "reason": f"timeout after {timeout}s"})
                continue
            line = (proc.stdout or "").strip().splitlines()
            data = None
            if line:
                with contextlib.suppress(json.JSONDecodeError):
                    data = json.loads(line[-1])
            if not data:
                probes.append(
                    {**cand, "outcome": "error", "reason": (proc.stderr or "no output")[:300]}
                )
                continue
            if "import_error" in data:
                probes.append({**cand, "outcome": "skipped", "reason": data["import_error"]})
                continue
            transcript = []
            survived = 0
            for p, r in zip(payloads, data.get("results", []), strict=False):
                entry = {"class": p["class"], "payload": p["payload"]}
                if "exception" in r:
                    entry["outcome"] = "error"
                    entry["exception"] = r["exception"]
                else:
                    tok = tokens[(p["class"], p["payload"])]
                    if tok in r.get("output", ""):
                        entry["outcome"] = "survived"
                        survived += 1
                    else:
                        entry["outcome"] = "neutralized"
                    entry["output_excerpt"] = r.get("output", "")[:200]
                transcript.append(entry)
            errors = sum(1 for t in transcript if t["outcome"] == "error")
            probes.append(
                {
                    **cand,
                    # soundness rule: a function that errored on every payload
                    # proved NOTHING — inconclusive, never "safe"
                    "outcome": (
                        "survived"
                        if survived
                        else "inconclusive"
                        if errors == len(transcript)
                        else "neutralized"
                    ),
                    "survived": survived,
                    "errors": errors,
                    "transcript": transcript,
                }
            )
    return probes


def _harness_version() -> str:
    """Version from the harness pyproject.toml — the single version source."""
    try:
        text = (HARNESS_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
        return m.group(1) if m else "unknown"
    except OSError:
        return "unknown"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", type=Path)
    ap.add_argument(
        "--run",
        action="store_true",
        required=True,
        help="EXECUTE repo sanitizers against the bypass corpora (audit-sandbox only)",
    )
    ap.add_argument(
        "--candidates",
        type=Path,
        required=True,
        help="`traust adapters sanitizers` output: the functions to probe",
    )
    ap.add_argument("--only", help="probe a single candidate by function name")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=20, help="per-module probe timeout, seconds")
    args = ap.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 1
    try:
        candidates = json.loads(args.candidates.read_text(encoding="utf-8"))["candidates"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"unreadable candidates {args.candidates}: {e}", file=sys.stderr)
        return 1
    if args.only:
        candidates = [c for c in candidates if c.get("function") == args.only]

    print(
        "probe_sanitizers: EXECUTING repository code in isolated "
        "subprocesses — audit-sandbox use only",
        file=sys.stderr,
    )
    probes = probe(repo, candidates, args.timeout)
    result = {
        "artifact": "sanitizer-probes",
        "repo": repo.name,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": _harness_version(),
        "mode": "run",
        "candidates": candidates,
        "probes": probes,
        "stats": {
            "candidates": len(candidates),
            "survived": sum(1 for p in probes if p["outcome"] == "survived"),
            "neutralized": sum(1 for p in probes if p["outcome"] == "neutralized"),
            "inconclusive": sum(
                1 for p in probes if p["outcome"] in ("inconclusive", "skipped", "error")
            ),
        },
    }
    out = args.out or Path(f"{repo.name}-sanitizer-probes.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    s = result["stats"]
    print(
        f"{result['repo']}: {s['candidates']} candidate sanitizer(s), {s['survived']} survived"
        f" / {s['neutralized']} neutralized / {s['inconclusive']} inconclusive -> {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
