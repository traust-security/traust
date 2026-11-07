from __future__ import annotations

import datetime
import shutil
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.validation import HttpPolicy, origin
from traust_core.v1.providers.process import ProcessRunner


class ClusterConnection(BaseModel):
    server: str
    proxy_url: str | None = Field(default=None, alias="proxy-url")
    insecure: bool = Field(default=False, alias="insecure-skip-tls-verify")


class ClusterEntry(BaseModel):
    cluster: ClusterConnection


class KubeconfigView(BaseModel):
    clusters: list[ClusterEntry] = Field(min_length=1, max_length=1)


def context_api(output: str) -> str:
    cluster = KubeconfigView.model_validate_json(output).clusters[0].cluster
    if cluster.proxy_url or cluster.insecure:
        raise PermissionError("kubeconfig proxy and insecure API TLS are not permitted")
    parsed = urlsplit(cluster.server)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("kubeconfig server must be an HTTP(S) origin")
    origin(cluster.server)
    return cluster.server


def parse_expiry(value: str) -> datetime.date | datetime.datetime:
    try:
        return datetime.date.fromisoformat(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("engagement expiry must be an ISO date or aware datetime") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("engagement expiry datetime must include an ISO timezone") from None
        return parsed


def expiry_date(value: str) -> str:
    """Validate a live lease and preserve an aware ISO instant, if supplied."""
    parsed = parse_expiry(value)
    expired = (
        datetime.datetime.now(datetime.UTC) >= parsed
        if isinstance(parsed, datetime.datetime)
        else datetime.date.today() > parsed
    )
    if expired:
        raise ValueError("engagement expiry is already in the past")
    return parsed.isoformat()


def configure_http_targets(
    document: dict, context: str, api: str | None, policy_path: str | None
) -> None:
    if not context or context == "__current__" or any(ord(c) <= 32 for c in context):
        raise ValueError("a named kubeconfig context is required")
    matches = [
        cluster for cluster in document.get("clusters", []) if cluster.get("context") == context
    ]
    if len(matches) != 1:
        raise ValueError("selected context must occur exactly once in clusters")
    cluster = matches[0]
    policy = HttpPolicy.model_validate(
        (yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}) if policy_path else {}
    )
    binary = shutil.which("oc") or shutil.which("kubectl")
    if not binary:
        raise RuntimeError("oc or kubectl is required to resolve the engagement context")
    keep_env = ("PATH", "HOME", "KUBECONFIG", "LANG", "LC_ALL", *policy.http_discovery.kube_env)
    runner = ProcessRunner({"oc", "kubectl"}, keep_env=keep_env, timeout_seconds=15)
    try:
        result = runner.run(
            [binary, f"--context={context}", "config", "view", "--minify", "-o", "json"],
            check=False,
            timeout_seconds=15,
            max_output_bytes=4 * 1024 * 1024,
        )
        if result.returncode:
            raise RuntimeError("cannot resolve the selected kubeconfig context")
        actual = context_api(result.stdout.decode("utf-8"))
    except (ServiceError, ValueError) as exc:
        raise RuntimeError("cannot resolve the selected kubeconfig context") from exc
    if api is not None and origin(api) != origin(actual):
        raise ValueError("requested API does not match the selected kubeconfig context")
    if cluster.get("api") and origin(cluster["api"]) != origin(actual):
        raise ValueError("engagement API does not match the selected kubeconfig context")
    policy.apply(document, context)
    cluster["api"] = actual
