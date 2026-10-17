from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

if __package__:
    from .http_scope import HttpPolicy, origin
else:
    from http_scope import HttpPolicy, origin


class ClusterConnection(BaseModel):
    server: str


class ClusterEntry(BaseModel):
    cluster: ClusterConnection


class KubeconfigView(BaseModel):
    clusters: list[ClusterEntry] = Field(min_length=1, max_length=1)


def expiry_date(value: str) -> str:
    try:
        parsed = datetime.date.fromisoformat(value)
    except ValueError:
        try:
            parsed = datetime.datetime.fromisoformat(value).date()
        except ValueError as exc:
            raise ValueError("engagement expiry must be an ISO date or datetime") from exc
    return parsed.isoformat()


def configure_http_targets(
    document: dict, context: str, api: str | None, policy_path: str | None
) -> None:
    policy = HttpPolicy.model_validate(
        yaml.safe_load(Path(policy_path).read_text()) if policy_path else {}
    )
    binary = shutil.which("oc") or shutil.which("kubectl")
    if not binary:
        raise RuntimeError("oc or kubectl is required to resolve the engagement context")
    try:
        result = subprocess.run(
            [binary, f"--context={context}", "config", "view", "--minify", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        actual = KubeconfigView.model_validate_json(result.stdout).clusters[0].cluster.server
    except (subprocess.SubprocessError, ValueError) as exc:
        raise RuntimeError("cannot resolve the selected kubeconfig context") from exc
    origin(actual)
    if api and origin(api) != origin(actual):
        raise ValueError("requested API does not match the selected kubeconfig context")
    policy.apply(document, context)
    cluster = next(cluster for cluster in document["clusters"] if cluster["context"] == context)
    cluster["api"] = actual
