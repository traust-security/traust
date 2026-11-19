"""Check Core/contracts pin evidence for the local, single-interpreter ops rig.

Run with the rig's Python after installation. A source-only preflight can
reject incompatible candidates before provisioning, but cannot certify the
install. Strict checks fetch the engine and SDK commits into empty Git
repositories. Probe and doctor stay local; neither is release evidence.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.metadata import distribution
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

SHA = r"[0-9a-f]{40}"
UPSTREAM = "https://github.com/traust-security/"


def full_sha(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(SHA, value):
        raise ValueError(f"{field} needs a full Git commit")
    return value


def checkout_head(repo: Path | None, label: str) -> str:
    if repo is None or not (repo / ".git").exists():
        raise ValueError(f"provide the {label} Git checkout root")
    head = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD^{commit}"], text=True)
    return full_sha(head.strip(), f"{label} HEAD")


def sdk_revision(repo: Path | None) -> str:
    head = checkout_head(repo, "SDK")
    if os.environ.get("OPS_SDK_REV", head) != head:
        raise ValueError("SDK checkout no longer matches the requested acceptance revision")
    return head


def clean_checkout(repo: Path, label: str, *, smoke_output: str = "") -> None:
    paths = ["."]
    # cmd_smoke creates exactly one temporary output tree *after* preflight.
    if re.fullmatch(r"\.local-ops-smoke\.[A-Za-z0-9]{8}", smoke_output):
        paths.append(f":(top,exclude,literal){smoke_output}")
    changed = subprocess.check_output(
        ["git", "-C", repo, "status", "--porcelain", "-uall", "--", *paths],
        text=True,
    )
    if changed:
        raise ValueError(f"{label} differs from candidate commit:\n{changed.rstrip()}")


def fetch_commit(dest: Path, project: str, head: str) -> None:
    """No candidate object database, remote-tracking ref or operator credentials."""
    url = f"{UPSTREAM}{project}.git"
    full_sha(head, project)
    dest.mkdir()
    with TemporaryDirectory() as home:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": home,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
        }
        git = ["git", "-C", str(dest)]
        subprocess.run([*git, "init", "--quiet", "--template="], env=env, check=True)
        subprocess.run(
            [*git, "fetch", "--quiet", "--no-tags", "--depth=1", url, head],
            env=env,
            check=True,
            timeout=90,
        )
        subprocess.run([*git, "checkout", "--quiet", "--detach", "FETCH_HEAD"], env=env, check=True)
        fetched = subprocess.check_output([*git, "rev-parse", "HEAD"], env=env, text=True).strip()
        if fetched != head:
            raise ValueError(f"{url} returned {fetched}, expected {head}")
    print(f"independent fetch: {url}@{head}")


def committed(repo: Path, head: str, path: str) -> str:
    return subprocess.check_output(["git", "-C", repo, "show", f"{head}:{path}"], text=True)


def locked_commit(lock: str, name: str) -> str:
    matches = [p for p in tomllib.loads(lock)["package"] if p["name"] == name]
    source = matches[0]["source"] if len(matches) == 1 else None
    if not isinstance(source, dict) or not isinstance(source.get("git"), str):
        raise ValueError(f"{name}: need one Git source in uv.lock")
    url = urlsplit(source["git"])
    if not (
        source["git"].split("?", 1)[0].removesuffix(".git") == f"{UPSTREAM}{name}"
        and re.fullmatch(SHA, url.fragment)
        and url.query == f"rev={url.fragment}"
    ):
        raise ValueError(f"{name}: lock must request and resolve the same full upstream commit")
    return url.fragment


def locked_pair(lock: str) -> tuple[str, str]:
    return locked_commit(lock, "traust-core"), locked_commit(lock, "traust-contracts")


def sdk_pair(makefile: str) -> tuple[str, str]:
    def rev(name: str) -> str:
        # Don't pick one valid line and silently skip a second, overriding assignment.
        defs = re.findall(
            rf"^[ \t]*(?:(?:export|override|private)[ \t]+)*{name}_REF[ \t]*([:+?!]*=.*)$",
            makefile,
            re.MULTILINE,
        )
        if len(defs) != 1 or not defs[0].startswith(":="):
            raise ValueError(f"need one literal {name}_REF := commit in go/Makefile")
        return full_sha(defs[0][2:].strip(), f"{name}_REF")

    return rev("CORE"), rev("CONTRACTS")


class Evidence:
    def __init__(self) -> None:
        self.pins: dict[str, dict[str, list[str]]] = defaultdict(dict)
        self.errors: list[str] = []

    @contextmanager
    def source(self, label: str) -> Iterator[None]:
        # Keep collecting independent evidence: an unpinned local engine must
        # not hide a real engine-lock vs runtime disagreement in probe output.
        try:
            yield
        except (
            ValueError,
            KeyError,
            TypeError,
            OSError,
            ImportError,
            subprocess.SubprocessError,
        ) as exc:
            self.errors.append(f"{label}: {exc}")

    def record(self, label: str, **pins: str) -> None:
        for key, value in pins.items():
            self.pins[key].setdefault(full_sha(value, f"{label} {key}"), []).append(label)
        print(f"{label}: " + " ".join(f"{k}={v}" for k, v in pins.items()))


def manifests(report: Evidence, repo: Path, label: str, head: str) -> None:
    with report.source(f"{label} pyproject.toml"):
        doc = tomllib.loads(committed(repo, head, "pyproject.toml"))
        expected = "traust-engine" if label == "runner/engine" else "traust"
        if doc["project"]["name"] != expected:
            raise ValueError(f"not the {expected} project")
        sources = doc["tool"]["uv"]["sources"]
        for part in ("core", "contracts"):
            package = f"traust-{part}"
            if part == "contracts" and package not in sources:
                continue  # Today's projects inherit contracts through Core; verified in uv.lock.
            source = sources[package]
            if not (
                isinstance(source, dict)
                and set(source) == {"git", "rev"}
                and isinstance(source["git"], str)
                and source["git"].removesuffix(".git") == f"{UPSTREAM}{package}"
            ):
                raise ValueError(f"{package} must be a pinned Git source")
            report.record(f"{label} declared", **{part: source["rev"]})
    with report.source(f"{label} uv.lock"):
        core, contracts = locked_pair(committed(repo, head, "uv.lock"))
        report.record(f"{label} lock", core=core, contracts=contracts)


def candidates(report: Evidence, engine: Path | None, sdk: Path | None) -> dict[str, str]:
    revisions = {}
    with report.source("runner/engine checkout"):
        engine_head = checkout_head(engine, "engine")
        report.record("runner/engine checkout", engine=engine_head)
        assert engine is not None
        manifests(report, engine, "runner/engine", engine_head)
        revisions["traust-engine"] = engine_head
        clean_checkout(engine, "engine")
    with report.source("SDK checkout"):
        sdk_head = sdk_revision(sdk)
        print(f"SDK checkout: {sdk_head}")
        assert sdk is not None
        makefile = "go/Makefile"
        stamp = "go/v1/types/version.go"
        with report.source("SDK build inputs"):
            core, contracts = sdk_pair(committed(sdk, sdk_head, makefile))
            report.record("SDK build inputs", core=core, contracts=contracts)
        with report.source("SDK generated contracts stamp"):
            refs = re.findall(
                r'^const ContractsRef = "([^"]*)"$', committed(sdk, sdk_head, stamp), re.MULTILINE
            )
            if len(refs) != 1:
                raise ValueError(f"need one generated ContractsRef in {stamp}")
            report.record("SDK generated types", contracts=refs[0])
        revisions["traust-sdk"] = sdk_head
        clean_checkout(sdk, "SDK")
    return revisions


def installed_pin(
    name: str, *, doctor_local: Path | None = None, upstream: bool = False
) -> str | None:
    data = distribution(name).read_text("direct_url.json")
    if not data:
        raise ValueError(f"{name}: missing direct_url.json (no install provenance)")
    direct = json.loads(data)
    if not isinstance(direct, dict) or not isinstance(direct.get("url"), str) or not direct["url"]:
        raise ValueError(f"{name}: invalid direct_url.json")
    if doctor_local is not None:
        if "dir_info" not in direct or direct["url"] != doctor_local.resolve().as_uri():
            raise ValueError(f"{name}: not installed from the configured local source")
        print(f"{name}: local source {doctor_local} (not commit pinned; doctor only)")
        return None
    if "dir_info" in direct:
        raise ValueError(f"{name}: unpinned local path installation")
    if upstream and direct["url"].removesuffix(".git") != f"{UPSTREAM}{name}":
        raise ValueError(f"{name}: not installed from its independent HTTPS repository")
    vcs = direct.get("vcs_info")
    if "archive_info" in direct or not isinstance(vcs, dict) or vcs.get("vcs") != "git":
        raise ValueError(f"{name}: not an identified Git installation")
    commit = full_sha(vcs.get("commit_id"), f"{name} installed commit_id")
    if vcs.get("requested_revision") != commit:
        raise ValueError(f"{name}: requested revision is not the installed full commit {commit}")
    return commit


def check_import(module: str, expected: Path) -> None:
    spec = find_spec(module)
    origin = spec.origin if spec else None
    if not origin or not expected.is_file() or Path(origin).resolve() != expected.resolve():
        raise ValueError(f"{module} import resolves to {origin}, expected {expected}")
    print(f"rig import: {module} -> {origin}")


def runtime(report: Evidence, doctor_local: Path | None, *, strict: bool) -> None:
    print(f"rig interpreter: {sys.executable}")
    # These are console entry points provided by distributions in *this*
    # interpreter, not whichever `traust-server` happens to be first on PATH.
    for name, command in (
        ("traust", "traust"),
        ("traust-engine", "traust-engine"),
        ("traust-core", "traust-server"),
    ):
        with report.source(f"{command} entry point"):
            dist = distribution(name)
            entries = dist.entry_points.select(group="console_scripts", name=command)
            if len(entries) != 1:
                raise ValueError(f"{name} does not provide one {command} in the rig interpreter")
            (entry,) = entries
            if strict:
                package = name.replace("-", "_")
                if not entry.module.startswith(package + "."):
                    raise ValueError(f"entry point does not belong to {package}")
                root = Path.cwd() / "src" if name == "traust" else Path(dist.locate_file(""))
                check_import(package, root / package / "__init__.py")
                check_import(entry.module, root / Path(*entry.module.split(".")).with_suffix(".py"))
            if command == "traust-server":
                module = Path(*entry.module.split(".")).with_suffix(".py")
                installed = Path(dist.locate_file(module))
                if not entry.module.startswith("traust_core.") or not installed.is_file():
                    raise ValueError("server entry point is not an installed Core module")
            print(f"same-interpreter {command}: {name} -> {entry.value}")
    if strict:
        with report.source("installed CLI checkout"):
            direct = json.loads(distribution("traust").read_text("direct_url.json") or "{}")
            if direct != {"url": Path.cwd().as_uri(), "dir_info": {"editable": True}}:
                raise ValueError("rig CLI must be installed editable from this exact checkout")
        with report.source("contracts import"):
            check_import(
                "traust_contracts",
                Path(distribution("traust-contracts").locate_file("traust_contracts/__init__.py")),
            )
    for part in ("core", "contracts"):
        with report.source(f"installed traust-{part}"):
            commit = installed_pin(f"traust-{part}", upstream=strict)
            assert commit is not None
            report.record("CLI / runner / same-interpreter server runtime", **{part: commit})
    with report.source("installed runner/engine"):
        commit = installed_pin("traust-engine", doctor_local=doctor_local, upstream=strict)
        if commit is not None:
            report.record("installed runner/engine", engine=commit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine",
        type=Path,
        default=os.environ.get("OPS_ENGINE_CHECKOUT") or None,
        help="candidate engine Git checkout (or OPS_ENGINE_CHECKOUT)",
    )
    parser.add_argument(
        "--sdk",
        type=Path,
        default=os.environ.get("OPS_SDK_CHECKOUT") or None,
        help="candidate Go SDK Git checkout (or OPS_SDK_CHECKOUT)",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--preflight", action="store_true", help="candidate manifests only")
    modes.add_argument("--probe", action="store_true", help="report gaps/skew without gating")
    modes.add_argument("--doctor", action="store_true", help="local rig health, not SDK acceptance")
    args = parser.parse_args()
    report = Evidence()
    strict = not (args.doctor or args.probe)
    cli = Path.cwd()
    with report.source("CLI checkout"):
        cli_head = checkout_head(cli, "CLI")
        print(f"CLI checkout: {cli_head} (committed inputs)")
        manifests(report, cli, "CLI", cli_head)
        if not args.doctor:
            output = "" if args.preflight else os.environ.get("OPS_DIR", "")
            clean_checkout(cli, "CLI", smoke_output=output)
            if Path(__file__).resolve() != cli / "scripts/check_ops_pins.py":
                raise ValueError("run the checker from the candidate CLI, not another checkout")
            # An ignored file can still be opened as a fixture or imported as
            # a module. Make executes a fresh CLI checkout as a second boundary.
            extras = subprocess.check_output(
                [
                    "git",
                    "ls-files",
                    "--others",
                    "--exclude=__pycache__/",
                    "--",
                    "scripts",
                    "src/traust",
                    "packs",
                    "config",
                ],
                text=True,
            )
            if extras:
                raise ValueError(f"uncommitted CLI input(s):\n{extras.rstrip()}")
    engine_source = os.environ.get("OPS_ENGINE_SRC", "")
    doctor_local = None
    if engine_source or args.doctor:
        with report.source("configured OPS_ENGINE_SRC"):
            if engine_source.startswith("git+") and "@" in engine_source:
                repo, _, rev = engine_source[4:].rpartition("@")
                if repo.removesuffix(".git") != f"{UPSTREAM}traust-engine":
                    raise ValueError("engine source must be the independent HTTPS repository")
                report.record("requested engine source", engine=rev)
            elif args.doctor and engine_source and Path(engine_source).is_dir():
                doctor_local = Path(engine_source)
            else:
                raise ValueError("engine source is not git+URL@full-commit")
    revisions = {}
    if not args.doctor:
        engine = args.engine
        if args.probe and not engine and engine_source and Path(engine_source).is_dir():
            engine = Path(engine_source)
        revisions = candidates(report, engine, args.sdk)
    if not args.preflight:
        runtime(report, doctor_local, strict=strict)
    for key, values in report.pins.items():
        if len(values) > 1:
            detail = " != ".join(f"{v} ({', '.join(labels)})" for v, labels in values.items())
            report.errors.append(f"pin disagreement: {key}: {detail}")
    # No network for a known mismatch, local probes, or interactive rig health.
    if strict and not report.errors:
        with TemporaryDirectory() as scratch:
            for project, head in revisions.items():
                with report.source(f"fetchable {project}"):
                    fetch_commit(Path(scratch) / project, project, head)
    for error in report.errors:
        print(f"  {error}", file=sys.stderr)
    if args.probe:
        status = "DISAGREEMENT or incomplete evidence" if report.errors else "observed agreement"
        print(f"DIAGNOSTIC ONLY: {status}; not acceptance evidence")
        return 0
    if report.errors:
        print("FAIL: cannot establish pin agreement", file=sys.stderr)
        return 1
    if args.preflight:
        print("Source preflight only: installed runtime not yet checked")
    elif args.doctor:
        print("Local rig install checked (not cross-component acceptance)")
    else:
        print("Exact candidate and single-interpreter installed pins agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
