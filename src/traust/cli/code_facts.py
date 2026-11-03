"""``traust adapters route-guards|grpc-guards|llm-app|config-matrix|sanitizers|fork-lag|
priv-profile``: the deterministic pre-scans on traust-core's code facts. Each reads a checkout
and records nothing; every result is a candidate worklist the audit judges, never a finding.

route-guards    the route x guard matrix (go-http, django-drf, flask, fastapi, aiohttp,
                express), asymmetry groups first
grpc-guards     the gRPC service x interceptor matrix (Go): servers, services, diagnostic services
llm-app         whether the checkout is an LLM, agent or MCP application, and the files that use it
config-matrix   effective deployed defaults as (key, default, sink) triples
sanitizers      sanitizer-shaped Python functions (discovery only; probing executes target code
                and is `probe_sanitizers.py --run`)
fork-lag        fork / vendored-upstream signals, then the advisories whose range holds each
                tracked upstream version (unless --offline)
priv-profile    an operator's privilege profile (tiers 1-2): the operator-priv-profile document
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.models.code_facts import CodeFactKind
from traust_core.v1.models.common import ToolRequest

from traust.cli._doors import parser, run
from traust.cli.impact import harness_version
from traust.context import load


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    ap = parser("adapters", op, about)
    ap.add_argument("checkout", type=Path, help="the checkout to read (read-only)")
    ap.add_argument("--out", type=Path, help="write the JSON here (default: stdout)")
    return ap


def _emit(doc: dict, out: Path | None) -> dict:
    if out is None:
        return doc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counts = {k: len(v) for k, v in doc.items() if isinstance(v, list)}
    return {"wrote": str(out), **counts}


def route_guards(argv: list[str] | None = None) -> int:
    ap = _parser("route-guards", "A checkout's route x guard matrix.")
    ap.add_argument(
        "--resolve-handlers",
        action="store_true",
        help="place each handler at its definition through the symbol index",
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        matrix = (
            load(args.config_home)
            .services()
            .code_facts.route_guards(
                ToolRequest(workspace=args.checkout), resolve_handlers=args.resolve_handlers
            )
        )
        return _emit(matrix.model_dump(mode="json"), args.out)

    return run(call)


def grpc_guards(argv: list[str] | None = None) -> int:
    args = _parser("grpc-guards", "A checkout's gRPC service x interceptor matrix.").parse_args(
        argv
    )

    def call() -> dict:
        matrix = (
            load(args.config_home)
            .services()
            .code_facts.grpc_guards(ToolRequest(workspace=args.checkout))
        )
        return _emit(matrix.model_dump(mode="json"), args.out)

    return run(call)


def llm_app(argv: list[str] | None = None) -> int:
    args = _parser("llm-app", "Whether a checkout is an LLM, agent or MCP application.").parse_args(
        argv
    )

    def call() -> dict:
        fact = (
            load(args.config_home)
            .services()
            .code_facts.llm_app(ToolRequest(workspace=args.checkout))
        )
        return _emit(fact.model_dump(mode="json"), args.out)

    return run(call)


def config_matrix(argv: list[str] | None = None) -> int:
    ap = _parser("config-matrix", "A checkout's effective deployed defaults.")
    ap.add_argument(
        "--max-triples", type=int, help="retain at most this many triples, judged first"
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        [matrix] = (
            load(args.config_home)
            .services()
            .code_facts.enumerate(
                CodeFactKind.CONFIG,
                ToolRequest(
                    workspace=args.checkout,
                    params={} if args.max_triples is None else {"max_triples": args.max_triples},
                ),
            )
        )
        return _emit(
            {
                "artifact": "config-matrix",
                "repo": args.checkout.resolve().name,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "harness_version": harness_version(),
                "yaml_parser": "available",
                **matrix.model_dump(mode="json", by_alias=True),
            },
            args.out,
        )

    return run(call)


def sanitizers(argv: list[str] | None = None) -> int:
    args = _parser("sanitizers", "A checkout's sanitizer-shaped functions.").parse_args(argv)

    def call() -> dict:
        found = (
            load(args.config_home)
            .services()
            .code_facts.enumerate(CodeFactKind.SANITIZER, ToolRequest(workspace=args.checkout))
        )
        return _emit({"candidates": [c.model_dump(mode="json") for c in found]}, args.out)

    return run(call)


def fork_lag(argv: list[str] | None = None) -> int:
    ap = _parser("fork-lag", "A checkout's fork signals and its upstreams' in-range advisories.")
    ap.add_argument("--offline", action="store_true", help="fork detection only, no advisory read")
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load(args.config_home)
        # advisories come from the registry's osv source. NEED(core: feeds registered lazily)
        core.register_feeds()
        fork = core.services().code_facts.fork_lag(
            ToolRequest(workspace=args.checkout), offline=args.offline
        )
        return _emit(fork.model_dump(mode="json"), args.out)

    return run(call)


def priv_profile(argv: list[str] | None = None) -> int:
    ap = _parser("priv-profile", "A checkout's operator privilege profile (tiers 1-2).")
    ap.add_argument("--name", required=True, help="the repository name the profile carries")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = (
            load(args.config_home)
            .services()
            .code_facts.priv_profile(ToolRequest(workspace=args.checkout), args.name)
        )
        return _emit(json.loads(doc.payload), args.out)

    return run(call)
