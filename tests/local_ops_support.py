"""Isolated execution of the real local rig script and configuration installer.

Only external provisioning is replaced: containers, dependency installation,
Postgres schema setup, and the bootstrap login. All other Python, including
configuration heredocs and the approval command, runs in the test interpreter.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

_UV = r"""import os
import sys
from pathlib import Path


def record(event):
    with Path(os.environ["LOCAL_OPS_EVENTS"]).open("a") as stream:
        stream.write(event + "\n")


args = sys.argv[1:]
if args and args[0] in ("sync", "pip"):
    record("dependencies")
    sys.exit(0)
if args[:2] != ["run", "--no-sync"]:
    sys.exit("unexpected uv invocation: " + repr(args))
args = args[2:]
if args == ["python", "-c", "import traust_engine"]:
    record("engine-dependency")
    sys.exit(0)
if args == ["python", "-"] and "OPS_DSN" in os.environ:
    record("database")
    sys.exit(0)
if args[:5] == ["python", "-m", "traust.cli", "auth", "local"]:
    record("auth")
    sys.exit(0)
if args and args[0] == "python":
    os.execv(sys.executable, [sys.executable, *args[1:]])
os.execvp(args[0], args)
"""

_CONTAINER = """#!/bin/bash
printf 'container:%s\\n' "$1" >> "$LOCAL_OPS_EVENTS"
case "$1" in
    ps) printf '%s\\n' "${OPS_CONTAINER:-traust-ops-local}" ;;
    volume) printf '%s\\n' "${OPS_FAKE_VOLUME_CREATED:-2026-11-04 00:00:00 +00:00 UTC}" ;;
esac
"""


class LocalOpsRig:
    """A minimal copied checkout with no path to the caller's live rig or tools."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "rig"
        self.root.mkdir()
        for relative in (
            "scripts/local_ops.sh",
            "scripts/install_traust",
            "Makefile",
            "config/traust.example.yaml",
            "config/model-registry.yaml",
            "packs/security/assets.yaml",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, target)

        self.config_home = self.root / ".local-ops" / "config"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.events = self.root / "events"
        self.events.touch()
        home = self.root / "home"
        home.mkdir()

        # A whitelist, not the workstation PATH: an installed cosign must never
        # accidentally sign a test rig or erase the deliberate no-cosign case.
        for name in (
            "bash",
            "basename",
            "cat",
            "cp",
            "cut",
            "dirname",
            "grep",
            "id",
            "make",
            "mkdir",
            "rm",
            "sed",
            "seq",
            "sleep",
        ):
            binary = shutil.which(name)
            if binary is None:
                raise RuntimeError(f"local rig tests require {name}")
            (self.bin_dir / name).symlink_to(binary)
        (self.bin_dir / "python3").symlink_to(sys.executable)
        self._executable("uv", f"#!{sys.executable}\n{_UV}")
        self._executable("podman", _CONTAINER)
        for name in ("syft", "gitleaks"):
            self._executable(name, "#!/bin/bash\nexit 0\n")

        self.env = dict(os.environ)
        for name in (
            "OPS_DSN",
            "TRAUST_OPERATOR_CONFIG_HOME",
            "COSIGN_PASSWORD",
            "GITHUB_TOKEN",
            "ANTHROPIC_API_KEY",
            "BASH_ENV",
            "ENV",
        ):
            self.env.pop(name, None)
        self.env.update(
            PATH=str(self.bin_dir),
            HOME=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            HARNESS_BIN_DIR=str(self.bin_dir),
            OPS_DIR=".local-ops",
            OPS_CONTAINER="traust-ops-local-test",
            OPS_VOLUME="traust-ops-local-test-data",
            TRAUST_CONFIG_HOME=str(self.config_home),
            LOCAL_OPS_EVENTS=str(self.events),
            PYTHONPATH=os.pathsep.join(
                filter(None, (str(REPO / "src"), os.environ.get("PYTHONPATH", "")))
            ),
        )

    def _executable(self, name: str, source: str) -> None:
        path = self.bin_dir / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def run(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(self.root / "scripts" / "local_ops.sh"), *args],
            cwd=self.root,
            env=self.env | (env or {}),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def make(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.bin_dir / "make"), *args],
            cwd=self.root,
            env=self.env | (env or {}),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
