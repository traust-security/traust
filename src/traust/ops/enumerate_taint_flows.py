#!/usr/bin/env python3
"""Taint-flow enumerator (deep-fn Phase B4) — Joern source→sink flow
facts for the flow-based injection classes syntactic rules can't see.

Enumerate-then-judge, same contract as `traust adapters config-matrix` /
`traust adapters route-guards`: every emitted flow is a judged row
(`judgement_required: true`), never a finding; un-modeled frameworks
are named in `coverage_gaps`; caps produce an explicit `omitted`
ledger; the run records to deterministic_steps/scanner_correlation
like every other pre-scan. CALIBRATION-GATED: this enumerator ships
opt-in until the Phase B4 calibration pilot clears the precision bar
(progress-tracker/plans/deep-fn-technique-plan.md) — do not wire it
run-by-default before that.

Soundness notes carried on every artifact:
  - a flow is a CANDIDATE data path, not exploitability — the judge
    owns reachability of the source, effectiveness of anything in
    `passes_through` (sanitizer_hint marks suspicious-looking
    intermediaries), and context;
  - NO flow found is NEVER evidence of safety (unmodeled sources,
    reflection/DI, C function pointers);
  - line numbers are approximate (javasrc2cpg drift, measured) — the
    path element code snippets and enclosing methods are the anchors.

Usage:
    python3 -m traust.cli.enumerate_taint_flows --repo DIR --out FILE \
        [--language java|c] [--families cmd-exec,sql,path,xml] \
        [--max-flows-per-family 50] [--timeout 1800]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# v1 catalog — deliberately tight; every family/language pair must
# clear the calibration pilot before default use. Regexes are Joern
# methodFullName patterns.
CATALOG: dict[str, dict] = {
    "java": {
        "sources": (
            r".*Servlet[Rr]equest\.(getParameter|getParameterValues|"
            r"getParameterMap|getHeader|getHeaders|getQueryString|"
            r"getCookies|getInputStream|getReader|getPathInfo|"
            r"getRequestURI).*"
        ),
        "families": {
            "cmd-exec": r".*(java\.lang\.Runtime\.exec|"
            r"java\.lang\.ProcessBuilder\.<init>).*",
            "sql": r".*(java\.sql\..*\.(execute|executeQuery|"
            r"executeUpdate|addBatch)|prepareStatement).*",
            "path": r".*(java\.io\.File\.<init>|"
            r"java\.nio\.file\.Paths\.get|"
            r"java\.io\.FileInputStream\.<init>|"
            r"java\.io\.FileOutputStream\.<init>).*",
            "xml": r".*(DocumentBuilder\.parse|SAXParser\.parse|"
            r"XMLReader\.parse|XMLInputFactory\.create).*",
        },
        "coverage_gaps": [
            "Spring/JAX-RS parameter binding (annotation-driven sources) "
            "not modeled — servlet API sources only",
            "socket/gRPC/message-queue sources not modeled",
            "reflection and DI-injected flows invisible to static analysis",
            "store-then-fetch flows (request value stored in session/"
            "heap state and executed on a later fetch — the H2-console "
            "shape) are invisible to per-request reachableByFlows "
            "(calibration 2026-07-31)",
        ],
    },
    "c": {
        "sources": r"^(read|recv|recvfrom|fgets|fread|getenv|gets|scanf)$",
        "families": {
            "cmd-exec": r"^(system|popen|execl|execlp|execle|execv|"
            r"execvp|execve)$",
            "overflow-copy": r"^(strcpy|strcat|sprintf|vsprintf|memcpy)$",
            "path": r"^(open|fopen|openat|unlink|remove)$",
        },
        "coverage_gaps": [
            "argv/envp program arguments not modeled as sources in v1",
            "function-pointer dispatch invisible to static analysis",
            "macro-heavy code may hide both ends of a flow",
        ],
    },
}

SANITIZER_HINT = re.compile(
    r"saniti|escap|encod|valid|quot|clean|filter|normaliz|replaceAll|"
    r"whitelist|allowlist",
    re.I,
)
_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|testdata|it)(/|$)", re.I)

QUERY_SC = r"""
@main def exec(cpgFile: String, specFile: String, outFile: String,
               maxCallDepth: String) = {
  importCpg(cpgFile)
  // bound the dataflow engine: unbounded reachableByFlows OOMs on
  // sink-dense repos (calibration pilot: h2 path family at 14g)
  import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
  implicit val engineContext: EngineContext =
    EngineContext(config = EngineConfig(maxCallDepth = maxCallDepth.toInt))
  // spec lines: FAMILY\tSRC_RE\tSINK_RE\tCAP
  val specs = scala.io.Source.fromFile(specFile).getLines()
    .filter(_.nonEmpty).map(_.split("\t")).toList
  val w = new java.io.PrintWriter(outFile)
  for (s <- specs) {
    val family = s(0); val srcRe = s(1); val sinkRe = s(2); val cap = s(3).toInt
    def src = cpg.call.methodFullName(srcRe)
    // NON-RECEIVER arguments only: argument(0) is the instance receiver
    // in Joern, and taint on the receiver object (e.g. a Statement
    // selected via a tainted map key) is NOT taint in the executed
    // data — the h2 judge pass measured 16/16 false positives from
    // exactly this class (calibration 2026-07-31)
    def snk = cpg.call.methodFullName(sinkRe).argument
      .filter(_.argumentIndex > 0)
      // constant pruning: an argument expression containing no
      // identifier anywhere in its AST (pure literals/operators, e.g.
      // "SELECT..." + "...") cannot carry runtime data — the h2
      // re-judge traced every surviving FP to exactly these endpoints
      .filter(a => a.isIdentifier || a.ast.isIdentifier.nonEmpty)
    val flows = snk.reachableByFlows(src).l
    for (f <- flows.take(cap)) {
      val es = f.elements
      def methodOf(e: AstNode): String = e match {
        case c: CfgNode =>
          scala.util.Try(c.method.fullName.takeWhile(_ != ':')).getOrElse("")
        case _ => ""
      }
      val fmts = es.map { e =>
        List(e.location.filename,
             e.lineNumber.map(_.toString).getOrElse("-1"),
             methodOf(e),
             e.code.take(80).replaceAll("[\t\n]", " ")).mkString("|")
      }
      val mids = es.drop(1).dropRight(1)
        .map(methodOf).filter(_.nonEmpty).distinct
      val midCodes = es.drop(1).dropRight(1)
        .map(_.code.take(40).replaceAll("[\t\n]", " ")).distinct.take(8)
      w.write(List("FLOW", family, fmts.head, fmts.last,
                   es.size.toString, mids.mkString(","),
                   midCodes.mkString(";")).mkString("\t") + "\n")
    }
    w.write(List("COUNT", family, flows.size.toString,
                 cap.toString).mkString("\t") + "\n")
  }
  w.close()
}
"""


def parse_site(blob: str) -> dict:
    f, line, method, code = ([*blob.split("|"), "", "", "", ""])[:4]
    return {"file": f, "line": int(line or -1), "method": method, "code": code}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--language", choices=("java", "c"), default="java")
    ap.add_argument(
        "--families",
        default="",
        help="comma-separated subset (default: all calibratable families for the language)",
    )
    ap.add_argument("--max-flows-per-family", type=int, default=50)
    ap.add_argument(
        "--max-call-depth",
        type=int,
        default=4,
        help="dataflow engine call-depth bound (pilot: "
        "unbounded OOMs on sink-dense repos; 4 is the "
        "calibrated default)",
    )
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args(argv)

    cat = CATALOG[args.language]
    fams = {
        k: v
        for k, v in cat["families"].items()
        if not args.families or k in args.families.split(",")
    }
    base = {
        "tool": "joern-taint",
        "enumerator": "taint-flows",
        "language": args.language,
        "repo": str(args.repo),
        "families": sorted(fams),
        "coverage_gaps": cat["coverage_gaps"],
        "soundness": {
            "flow": "a CANDIDATE data path, never a finding — the "
            "judge owns source reachability, sanitizer "
            "effectiveness (passes_through / "
            "sanitizer_hint), and context",
            "no_flow": "NEVER evidence of safety — unmodeled "
            "sources, reflection/DI, function pointers",
            "line_numbers": "approximate; path code snippets and enclosing methods are the anchors",
        },
    }

    def emit(doc):
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        print(f"taint-flows: {doc['status']} → {args.out}")
        return 0

    joern, parse = shutil.which("joern"), shutil.which("joern-parse")
    if not (joern and parse):
        return emit({**base, "status": "skipped: joern not on PATH"})
    exts = ("*.java",) if args.language == "java" else ("*.c", "*.h", "*.cc", "*.cpp", "*.hpp")
    if not any(f for pat in exts for f in args.repo.rglob(pat)):
        return emit({**base, "status": f"skipped: no {args.language} sources"})

    with tempfile.TemporaryDirectory(prefix="taint-") as td:
        tdp = Path(td)
        cpg = tdp / "cpg.bin"
        env = {**os.environ, "JAVA_OPTS": os.environ.get("JOERN_JAVA_OPTS", "-Xmx14g")}
        built = subprocess.run(
            [parse, str(args.repo), "--output", str(cpg)],
            capture_output=True,
            text=True,
            timeout=args.timeout,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        if built.returncode != 0 or not cpg.is_file():
            return emit(
                {
                    **base,
                    "status": "error: joern-parse failed",
                    "detail": (built.stderr or built.stdout).strip()[-400:],
                }
            )
        script = tdp / "query.sc"
        script.write_text(QUERY_SC, encoding="utf-8")
        # one JVM session per family — the whole-catalog single session
        # OOM'd on sink-dense repos (calibration pilot envelope); a
        # family that fails is recorded, the rest still run
        raw_rows: list[str] = []
        family_errors: dict[str, str] = {}
        for fam, sink in sorted(fams.items()):
            spec = tdp / f"spec-{fam}.tsv"
            spec.write_text(
                f"{fam}\t{cat['sources']}\t{sink}\t{args.max_flows_per_family * 4}\n",
                encoding="utf-8",
            )
            tsv = tdp / f"flows-{fam}.tsv"
            q = subprocess.run(
                [
                    joern,
                    "--script",
                    str(script),
                    "--param",
                    f"cpgFile={cpg}",
                    "--param",
                    f"specFile={spec}",
                    "--param",
                    f"outFile={tsv}",
                    "--param",
                    f"maxCallDepth={args.max_call_depth}",
                ],
                capture_output=True,
                text=True,
                timeout=args.timeout,
                stdin=subprocess.DEVNULL,
                env=env,
            )
            if q.returncode != 0 or not tsv.is_file():
                family_errors[fam] = (q.stderr or q.stdout).strip()[-300:]
                continue
            raw_rows.extend(tsv.read_text(encoding="utf-8").splitlines())
        if family_errors and not raw_rows:
            return emit(
                {
                    **base,
                    "status": "error: joern query failed (all families)",
                    "family_errors": family_errors,
                }
            )

    flows: dict[tuple, dict] = {}
    totals: dict[str, dict] = {}
    for row in raw_rows:
        parts = row.split("\t")
        if parts[0] == "COUNT" and len(parts) == 4:
            totals[parts[1]] = {"raw_flows": int(parts[2]), "raw_cap": int(parts[3])}
        elif parts[0] == "FLOW" and len(parts) == 7:
            _, fam, src_b, snk_b, plen, mids, midcodes = parts
            src, snk = parse_site(src_b), parse_site(snk_b)
            key = (fam, src["file"], src["line"], snk["file"], snk["line"])
            # dedupe subset paths: keep the longest per (src, sink)
            if key in flows and flows[key]["path_length"] >= int(plen):
                continue
            through = [m for m in mids.split(",") if m]
            hint = bool(SANITIZER_HINT.search(mids + ";" + midcodes))
            flows[key] = {
                "family": fam,
                "source": src,
                "sink": snk,
                "path_length": int(plen),
                "passes_through": through,
                "path_excerpt": [c for c in midcodes.split(";") if c],
                "sanitizer_hint": hint,
                "test_path": bool(_TEST_PATH.search(src["file"]) or _TEST_PATH.search(snk["file"])),
                "judgement_required": True,
            }

    rows, omitted = [], []
    by_fam: dict[str, list] = {}
    for f in flows.values():
        by_fam.setdefault(f["family"], []).append(f)
    for fam in sorted(by_fam):
        fam_rows = sorted(
            by_fam[fam], key=lambda r: (r["test_path"], r["source"]["file"], r["source"]["line"])
        )
        kept = fam_rows[: args.max_flows_per_family]
        if len(fam_rows) > len(kept):
            omitted.append(
                f"{fam}: {len(fam_rows) - len(kept)} deduped flow(s) "
                f"beyond --max-flows-per-family={args.max_flows_per_family}"
                " not emitted (test-path rows dropped first)"
            )
        rows.extend(kept)
    for fam, t in totals.items():
        if t["raw_flows"] > t["raw_cap"]:
            omitted.append(
                f"{fam}: raw flow count {t['raw_flows']} "
                f"exceeded the query cap {t['raw_cap']} — "
                f"dedupe ran over a truncated set"
            )

    return emit(
        {
            **base,
            "status": "ran",
            "flows": rows,
            "max_call_depth": args.max_call_depth,
            "family_totals": totals,
            "omitted": omitted,
            **({"family_errors": family_errors} if family_errors else {}),
            "stats": {
                "flows_emitted": len(rows),
                "flows_deduped_from": sum(t["raw_flows"] for t in totals.values()),
            },
        }
    )


if __name__ == "__main__":
    raise SystemExit(main())
