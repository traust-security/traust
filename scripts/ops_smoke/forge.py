"""Run production traust.cli with only its urllib forge transport simulated.

Fresh observation reads metadata and the default branch. The manifest materializer
gets a tarball at that SHA; extraction, syft, persistence and reporting are real.
"""

import gzip
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import BaseHandler, OpenerDirector, Request, install_opener

SHA = "a" * 40
REQUIREMENTS = Path(__file__).resolve().parent / "repo" / "requirements.txt"


def archive(slug: str) -> bytes:
    if slug == "smoke-containers":
        path, data = "build/images/Dockerfile", b"FROM base:1.2.3\n"
    elif slug == "smoke-repo":
        path, data = "requirements.txt", REQUIREMENTS.read_bytes()
    else:
        raise ValueError(f"no fixture archive for {slug}")
    header = tarfile.TarInfo(f"{slug}-{SHA}/{path}")
    header.size = len(data)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(header, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


class FixtureForge(BaseHandler):
    def default_open(self, req: Request) -> io.BytesIO:
        if req.get_method() == "GET" and req.data is None:
            for slug in ("smoke-repo", "smoke-failure", "smoke-containers"):
                base = f"https://api.github.com/repos/example/{slug}"
                if req.full_url == base:
                    metadata = {
                        "html_url": f"https://github.com/example/{slug}",
                        "default_branch": "main",
                        "visibility": "public",
                        "archived": False,
                        "fork": False,
                        "pushed_at": "2025-01-01T00:00:00Z",
                    }
                    return io.BytesIO(json.dumps(metadata).encode())
                if req.full_url == f"{base}/branches/main":
                    return io.BytesIO(json.dumps({"commit": {"sha": SHA}}).encode())
                if req.full_url == f"{base}/tarball/{SHA}":
                    if slug == "smoke-failure":
                        raise HTTPError(req.full_url, 403, "fixture archive unavailable", {}, None)
                    return io.BytesIO(archive(slug))
        raise ValueError("unexpected urllib request outside the smoke forge fixture")


if __name__ == "__main__":
    if sys.argv[1:3] not in (
        ["portfolio", "onboard"], ["portfolio", "observe"], ["impact", "manifest-sbom"]
    ):
        raise SystemExit("expected fixture onboard, observe or manifest-sbom")
    # In particular, syft must not read a caller's per-user scanner configuration.
    os.environ["HOME"] = str(Path(os.environ["OPS_SMOKE_RUN"]) / "home")
    os.environ["XDG_CONFIG_HOME"] = str(Path(os.environ["HOME"]) / ".config")
    # Unlike build_opener(), an empty director has no proxy, file or network handlers.
    opener = OpenerDirector()
    opener.add_handler(FixtureForge())
    install_opener(opener)

    from traust.cli.__main__ import main

    raise SystemExit(main())
