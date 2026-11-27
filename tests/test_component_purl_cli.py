"""CLI door tests for component PURL monorepo audits in traust."""

from __future__ import annotations

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind

from traust.cli import assessment_record, assessments, check_citations, repo, session
from traust.context import load


def _git(repo: Path, *args: str) -> str:
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _make_monorepo(root: Path, files: dict[str, str], tag: str) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"fixture {tag}")
    sha = _git(root, "rev-parse", "HEAD")
    _git(root, "tag", tag)
    return sha


def _config_home(tmp_path: Path) -> Path:
    home = tmp_path / "cfg"
    home.mkdir(parents=True, exist_ok=True)
    (home / "traust.yaml").write_text(
        "process:\n  allowed_binaries:\n    - git\n",
        encoding="utf-8",
    )
    return home


def test_assessments_prepare_resolves_component_purl_and_refuses_unresolved(
    tmp_path: Path, capsys
) -> None:
    repo_url = "https://github.com/example-spring/spring-framework"
    checkout = tmp_path / "spring"
    sha = _make_monorepo(
        checkout,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>spring-beans</module><module>spring-context</module></modules>"
                "</project>\n"
            ),
            "spring-beans/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-beans</artifactId></project>\n"
            ),
            "spring-context/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-context</artifactId></project>\n"
            ),
        },
        tag="v7.1.0",
    )
    home = _config_home(tmp_path)
    core = load(home)
    core.services().portfolio.register_repository(
        HttpsRepoUrl.parse(repo_url, core.config.forge_hosts), public=True
    )

    out_path = tmp_path / "prepared.json"
    rc = assessments.prepare(
        [
            "--config-home",
            str(home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "--release-ref",
            "v7.1.0",
            "--checkout",
            str(checkout),
            "-o",
            str(out_path),
        ]
    )
    assert rc == 0
    prepared = json.loads(out_path.read_text(encoding="utf-8"))
    assert (
        prepared["component_target"]["purl"] == "pkg:maven/org.springframework/spring-beans@7.1.0"
    )
    assert prepared["component_target"]["commit"] == sha
    assert prepared["component_target"]["module_path"] == "spring-beans"
    assert "provenance" not in prepared["component_target"]["verification"]
    _assert_contract_valid_report_target(prepared["component_target"])
    capsys.readouterr()
    rc_bad = assessments.prepare(
        [
            "--config-home",
            str(home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            "pkg:maven/org.springframework/spring-beans@9.9.9",
            "--sha",
            sha,
            "--checkout",
            str(checkout),
        ]
    )
    assert rc_bad == assessments.REFUSED
    payload = json.loads(capsys.readouterr().out)
    assert payload["unresolved"] is True
    assert payload["reason"] == "version_mismatch"


def test_reporting_record_and_check_citations_on_three_location_component_report(
    tmp_path: Path, capsys
) -> None:
    repo_url = "https://github.com/example-acme/tenant-cache"
    checkout = tmp_path / "tenant-cache"
    sha = _make_monorepo(
        checkout,
        {
            "package.json": json.dumps(
                {
                    "name": "acme-root",
                    "private": True,
                    "version": "0.0.0",
                    "workspaces": ["packages/*", "apps/*"],
                }
            ),
            "packages/cache-lib/package.json": json.dumps(
                {"name": "@acme/cache-lib", "version": "1.2.0"}
            ),
            "packages/cache-lib/src/cache.ts": (
                "export class ItemCache {\n"
                "  private map = new Map<string, string>();\n"
                "  put(id: string, val: string) { this.map.set(id, val); }\n"
                "}\n"
            ),
            "packages/tenant-ids/package.json": json.dumps(
                {"name": "@acme/tenant-ids", "version": "1.2.0"}
            ),
            "packages/tenant-ids/src/id.ts": (
                'export function nextTenantItemId(tenant: string) {\n  return "item-1";\n}\n'
            ),
            "apps/api-server/package.json": json.dumps(
                {"name": "@acme/api-server", "private": True, "version": "1.2.0"}
            ),
            "apps/api-server/src/server.ts": (
                "const GLOBAL_CACHE = new ItemCache();\n"
                "export function handle(t: string) {\n"
                "  GLOBAL_CACHE.put(nextTenantItemId(t), t);\n"
                "}\n"
            ),
        },
        tag="v1.2.0",
    )
    purl = "pkg:npm/%40acme/cache-lib@1.2.0"
    report = {
        "title": "Cache Lib Component Security Audit",
        "metadata": {
            "date": "2026-11-22",
            "scope": "Component PURL audit of @acme/cache-lib@1.2.0 in pinned monorepo",
            "repository": repo_url,
            "commit": sha,
            "ref": "v1.2.0",
            "ref_kind": "tag",
            "audit_profile": "code",
            "target": {
                "purl": purl,
                "repository": repo_url,
                "commit": sha,
                "module_path": "packages/cache-lib",
                "release_ref": "v1.2.0",
                "verification": {
                    "strategy": "workspace_package",
                    "manifest_paths": ["package.json", "packages/cache-lib/package.json"],
                },
            },
        },
        "executive_summary": {
            "prose": "Cross-module cache isolation review of @acme/cache-lib@1.2.0 at pin.",
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": "critical", "definition": "Unauthenticated remote compromise."},
            {"level": "high", "definition": "Cross-tenant cache read/write collision."},
            {"level": "medium", "definition": "Scoped weakness with extra preconditions."},
            {"level": "low", "definition": "Minor defense-in-depth hardening gap."},
        ],
        "findings": [
            {
                "id": f"CACHE_LIB-{sha[:7]}-001",
                "title": "Shared `ItemCache` keyed by tenant-local `nextTenantItemId` in `GLOBAL_CACHE`",
                "severity": "high",
                "kind": "vulnerability",
                "cwes": ["CWE-200"],
                "locations": [
                    {
                        "path": "packages/cache-lib/src/cache.ts",
                        "lines": "3",
                        "description": "`ItemCache` keys entries only by bare `id`.",
                    },
                    {
                        "path": "packages/tenant-ids/src/id.ts",
                        "lines": "1-3",
                        "description": "`nextTenantItemId` produces tenant-local IDs.",
                    },
                    {
                        "path": "apps/api-server/src/server.ts",
                        "lines": "1-3",
                        "description": "`GLOBAL_CACHE` is shared across tenants.",
                    },
                ],
                "description": (
                    "`ItemCache` keys entries by bare ID while sibling `nextTenantItemId` emits "
                    "tenant-local IDs and `GLOBAL_CACHE` shares one cache across tenants."
                ),
                "remediation": "Include tenantId in ItemCache keys or isolate per-tenant caches.",
                "remediation_effort": "s",
            }
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": [f"CACHE_LIB-{sha[:7]}-001"]},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "p1",
                "addresses": [f"CACHE_LIB-{sha[:7]}-001"],
                "action": "Namespace ItemCache keys by tenantId across callers.",
                "effort": "s",
            }
        ],
    }
    report_file = tmp_path / "cache-lib-security-audit.json"
    report_file.write_text(json.dumps(report), encoding="utf-8")
    # 1. Citation gate verifies all 3 cross-module locations at the pinned checkout.
    gated = check_citations.gate(report["findings"], checkout, 15)
    assert gated["summary"]["ok"] == 1
    assert gated["results"][0]["tag"] == "ok"

    # 2. Recording refuses mismatched --purl.
    rc_mismatch = assessment_record.main(
        [
            str(report_file),
            "--kind",
            "secure_code",
            "--repo-url",
            repo_url,
            "--sha",
            sha,
            "--purl",
            "pkg:npm/%40acme/other-lib@1.2.0",
        ]
    )
    assert rc_mismatch != 0

    # 3. Recording succeeds with matching --purl and stamps target_purl on Assessment.
    capsys.readouterr()
    rc_ok = assessment_record.main(
        [
            str(report_file),
            "--kind",
            "secure_code",
            "--repo-url",
            repo_url,
            "--sha",
            sha,
            "--purl",
            purl,
        ]
    )
    assert rc_ok == 0
    recorded = json.loads(capsys.readouterr().out)
    assert recorded["target_purl"] == purl


def test_repo_checkout_shared_and_session_run_purl_resolution(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    checkout = tmp_path / "spring"
    sha = _make_monorepo(
        checkout,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>spring-beans</module><module>spring-context</module></modules>"
                "</project>\n"
            ),
            "spring-beans/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-beans</artifactId></project>\n"
            ),
            "spring-context/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-context</artifactId></project>\n"
            ),
        },
        tag="v7.1.0",
    )
    home = _config_home(tmp_path)
    repo_url = "https://github.com/example-spring/spring-framework"

    # 1. traust repo checkout --shared returns a shared read-only worktree path.
    capsys.readouterr()
    rc1 = repo.checkout(["--config-home", str(home), str(checkout), "--ref", sha, "--shared"])
    p1 = capsys.readouterr().out.strip()
    assert rc1 == 0 and Path(p1).is_dir()

    # 2. traust session run --purl without --sha refuses with unresolved-target before spawning.
    monkeypatch.setattr(session, "resolve_model", lambda _role: "test-model")
    capsys.readouterr()
    rc_nopin = session.run(
        [
            "--config-home",
            str(home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--purl",
            "pkg:maven/org.springframework/spring-beans@7.1.0",
        ]
    )
    assert rc_nopin != 0
    out_nopin = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out_nopin["outcome"] == "refused"
    assert out_nopin["reason"] == "unresolved-target"

    # 3. traust session run --purl --sha --checkout resolves target via Core and forwards verified args.
    seen_checkout: list[tuple[str, str | None, bool]] = []
    seen_commands: list[list[str]] = []

    @contextmanager
    def fake_checkout(url, config_home, ref=None, *, shared=False):
        seen_checkout.append((url, None if ref is None else str(ref), shared))
        yield SimpleNamespace(path=checkout)

    monkeypatch.setattr(session, "checkout", fake_checkout)
    monkeypatch.setattr(
        session,
        "session",
        lambda cmd, skill, env: (seen_commands.append(cmd) or SimpleNamespace(returncode=0), ()),
    )
    capsys.readouterr()
    rc_ok = session.run(
        [
            "--config-home",
            str(home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--checkout",
            "--purl",
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "--sha",
            sha,
        ]
    )
    assert rc_ok == 0
    assert seen_checkout == [(repo_url, sha, True)]
    prompt_arg = seen_commands[0][-1]
    assert "--purl pkg:maven/org.springframework/spring-beans@7.1.0" in prompt_arg
    assert f"--commit {sha}" in prompt_arg
    assert "--module-path spring-beans" in prompt_arg
    assert "--release-ref v7.1.0" in prompt_arg
    assert "--target-json " in prompt_arg

    # 4. Unresolvable PURL in session run refuses with unresolved-target without launching agent.
    seen_commands.clear()
    capsys.readouterr()
    rc_bad = session.run(
        [
            "--config-home",
            str(home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--checkout",
            "--purl",
            "pkg:maven/org.springframework/spring-beans@9.9.9",
            "--sha",
            sha,
        ]
    )
    assert rc_bad != 0
    assert seen_commands == []
    out_bad = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out_bad["outcome"] == "refused"
    assert out_bad["reason"] == "unresolved-target"

    # 5. Regression: --purl --sha WITHOUT --checkout still acquires shared pinned checkout
    #    and resolves the component target rather than degrading into a repo-scope run.
    seen_checkout.clear()
    seen_commands.clear()
    capsys.readouterr()
    rc_no_flag = session.run(
        [
            "--config-home",
            str(home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--purl",
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "--sha",
            sha,
        ]
    )
    assert rc_no_flag == 0
    assert seen_checkout == [(repo_url, sha, True)]
    prompt_no_flag = seen_commands[0][-1]
    assert "--purl pkg:maven/org.springframework/spring-beans@7.1.0" in prompt_no_flag
    assert f"--commit {sha}" in prompt_no_flag
    assert "--module-path spring-beans" in prompt_no_flag
    assert "--release-ref v7.1.0" in prompt_no_flag

    # 6. Regression: --purl --sha without --repo refuses before launching agent.
    seen_commands.clear()
    capsys.readouterr()
    rc_norepo = session.run(
        [
            "--config-home",
            str(home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--purl",
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "--sha",
            sha,
        ]
    )
    assert rc_norepo != 0
    assert seen_commands == []
    out_norepo = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out_norepo["outcome"] == "refused"
    assert out_norepo["reason"] == "unresolved-target"

    # 7. Regression: --sha without --checkout or --purl fails fast with argparse error.
    with pytest.raises(SystemExit) as exc_info:
        session.run(
            [
                "--config-home",
                str(home),
                "--skill",
                "secure-code-audit",
                "--role",
                "audit",
                "--repo",
                repo_url,
                "--sha",
                sha,
            ]
        )
    assert exc_info.value.code == 2


def test_qodo_regressions_prepare_record_release_and_session_target_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _config_home(tmp_path)
    checkout = tmp_path / "spring"
    sha = _make_monorepo(
        checkout,
        {
            "pom.xml": (
                "<project>\n"
                "  <groupId>org.springframework</groupId>\n"
                "  <artifactId>spring-framework</artifactId>\n"
                "  <version>7.1.0</version>\n"
                "</project>\n"
            ),
            "spring-beans/pom.xml": (
                "<project>\n"
                "  <parent>\n"
                "    <groupId>org.springframework</groupId>\n"
                "    <artifactId>spring-framework</artifactId>\n"
                "    <version>7.1.0</version>\n"
                "  </parent>\n"
                "  <artifactId>spring-beans</artifactId>\n"
                "</project>\n"
            ),
        },
        tag="v7.1.0",
    )
    repo_url = "https://github.com/spring-projects/spring-framework"
    other_sha = "b" * 40
    core = load(home)
    services = core.services()
    registered = services.portfolio.register_repository(
        HttpsRepoUrl.parse(repo_url, core.config.forge_hosts), True
    )
    ref = services.portfolio.register_ref(registered.id, GitSha.parse(sha), "v7.1.0", RefKind.TAG)
    # 1. Orphaned --release-ref / --module-path without --purl fail closed in assessments.prepare.
    for extra_flag in (["--release-ref", "v7.1.0"], ["--module-path", "spring-beans"]):
        rc = assessments.prepare(
            [
                "--config-home",
                str(home),
                "--repo-url",
                repo_url,
                "--sha",
                sha,
                "--kind",
                "secure-code",
                *extra_flag,
            ]
        )
        assert rc != 0

    # 2. assessment_record rejects component report without --purl, wrong --sha, or wrong --repo-url.
    report_doc = {
        "title": "Spring Beans Component Security Audit",
        "metadata": {
            "date": "2026-11-22",
            "scope": "Component PURL audit of spring-beans@7.1.0 in pinned monorepo",
            "repository": repo_url,
            "commit": sha,
            "ref": "v7.1.0",
            "ref_kind": "tag",
            "audit_profile": "code",
            "target": {
                "purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "repository": repo_url,
                "commit": sha,
                "module_path": "spring-beans",
                "release_ref": "v7.1.0",
                "verification": {
                    "strategy": "shared_release",
                    "manifest_paths": ["pom.xml", "spring-beans/pom.xml"],
                },
            },
        },
        "executive_summary": {
            "prose": (
                "Focused component PURL security audit of spring-beans at the pinned release "
                "commit with no findings."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": "critical", "definition": "Unauthenticated remote code execution."},
            {"level": "high", "definition": "Privilege escalation or cross-tenant data leak."},
            {"level": "medium", "definition": "Scoped security weakness under preconditions."},
            {"level": "low", "definition": "Defense-in-depth hardening gap."},
        ],
        "findings": [],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 0, "finding_ids": []},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "p3",
                "addresses": ["NONE"],
                "action": "No remediation required for this clean component audit fixture.",
                "effort": "xs",
            }
        ],
    }
    report_path = tmp_path / "beans-report.json"
    report_path.write_text(json.dumps(report_doc), encoding="utf-8")
    capsys.readouterr()
    assert (
        assessment_record.main(
            [
                "--config-home",
                str(home),
                str(report_path),
                "--kind",
                "secure_code",
                "--repo-url",
                repo_url,
                "--sha",
                sha,
            ]
        )
        != 0
    )
    assert "requires --purl" in capsys.readouterr().err
    assert (
        assessment_record.main(
            [
                "--config-home",
                str(home),
                str(report_path),
                "--kind",
                "secure_code",
                "--repo-url",
                repo_url,
                "--sha",
                other_sha,
                "--purl",
                "pkg:maven/org.springframework/spring-beans@7.1.0",
            ]
        )
        != 0
    )
    assert "does not match --sha" in capsys.readouterr().err
    assert (
        assessment_record.main(
            [
                "--config-home",
                str(home),
                str(report_path),
                "--kind",
                "secure_code",
                "--repo-url",
                "https://github.com/other/repo",
                "--sha",
                sha,
                "--purl",
                "pkg:maven/org.springframework/spring-beans@7.1.0",
            ]
        )
        != 0
    )
    assert "does not match --repo-url" in capsys.readouterr().err

    # 3. traust repo checkout + release over real providers preserves unrelated directories.
    unrelated = tmp_path / "do-not-delete"
    unrelated.mkdir()
    sentinel = unrelated / "keep.txt"
    sentinel.write_text("precious\n", encoding="utf-8")

    # Refuses unrelated path on both local repo and HTTPS mirror origins without deleting it.
    for origin in (str(checkout), repo_url):
        for extra_flags in (["--shared"], []):
            rc_forged = repo.release(
                [
                    "--config-home",
                    str(home),
                    origin,
                    "--ref",
                    sha,
                    "--path",
                    str(unrelated),
                    *extra_flags,
                ]
            )
            assert rc_forged != 0
            assert unrelated.is_dir()
            assert sentinel.read_text(encoding="utf-8") == "precious\n"

    # Real cross-process shared checkout -> release lifecycle across fresh subprocesses.
    import sys

    def _run_cli(*cli_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "traust.cli", *cli_args],
            capture_output=True,
            text=True,
            check=False,
        )

    c1 = _run_cli(
        "repo", "checkout", "--config-home", str(home), str(checkout), "--ref", sha, "--shared"
    )
    assert c1.returncode == 0, c1.stderr
    wt1 = Path(c1.stdout.strip().splitlines()[-1])
    c2 = _run_cli(
        "repo", "checkout", "--config-home", str(home), str(checkout), "--ref", sha, "--shared"
    )
    assert c2.returncode == 0, c2.stderr
    wt2 = Path(c2.stdout.strip().splitlines()[-1])
    assert wt1 == wt2 and wt1.is_dir()

    # Release holder 1 WITHOUT --shared from a fresh process: holder 2's worktree must survive.
    r1 = _run_cli(
        "repo",
        "release",
        "--config-home",
        str(home),
        str(checkout),
        "--ref",
        sha,
        "--path",
        str(wt1),
    )
    assert r1.returncode == 0, r1.stderr
    assert wt2.is_dir()

    # Release holder 2 WITH --shared from a fresh process: worktree is now cleanly removed.
    r2 = _run_cli(
        "repo",
        "release",
        "--config-home",
        str(home),
        str(checkout),
        "--ref",
        sha,
        "--path",
        str(wt2),
        "--shared",
    )
    assert r2.returncode == 0, r2.stderr
    assert not wt2.exists()
    assert sentinel.read_text(encoding="utf-8") == "precious\n"
    # 4. session._recorded requires matching target_purl + commit + repo in PURL mode.
    from types import SimpleNamespace as _NS
    from uuid import uuid4

    from traust_core.v1.models.assessment import AssessmentKind
    from traust_core.v1.models.component_target import (
        ComponentTarget,
        ComponentTargetVerification,
    )
    from traust_core.v1.models.vocabulary import ComponentTargetStrategy

    expected = ComponentTarget(
        purl="pkg:maven/org.springframework/spring-beans@7.1.0",
        repository=repo_url,
        commit=sha,
        module_path="spring-beans",
        release_ref="v7.1.0",
        verification=ComponentTargetVerification(
            strategy=ComponentTargetStrategy.SHARED_RELEASE,
            manifest_paths=("pom.xml", "spring-beans/pom.xml"),
        ),
    )
    wrong_whole = _NS(
        id=uuid4(),
        kind=AssessmentKind.SECURE_CODE_CANONICAL,
        target_purl=None,
        repository_ref_id=ref.id,
    )
    wrong_sibling = _NS(
        id=uuid4(),
        kind=AssessmentKind.SECURE_CODE_CANONICAL,
        target_purl="pkg:maven/org.springframework/spring-context@7.1.0",
        repository_ref_id=ref.id,
    )
    right_target = _NS(
        id=uuid4(),
        kind=AssessmentKind.SECURE_CODE_CANONICAL,
        target_purl="pkg:maven/org.springframework/spring-beans@7.1.0",
        repository_ref_id=ref.id,
    )
    ns = _NS(config_home=home)
    monkeypatch.setattr(session, "order_assessments", lambda _oid, _h: [wrong_whole, wrong_sibling])
    assert (
        session._recorded(
            uuid4(), AssessmentKind.SECURE_CODE_CANONICAL, ns, expected_target=expected
        )
        == set()
    )
    monkeypatch.setattr(
        session, "order_assessments", lambda _oid, _h: [wrong_whole, wrong_sibling, right_target]
    )
    assert session._recorded(
        uuid4(), AssessmentKind.SECURE_CODE_CANONICAL, ns, expected_target=expected
    ) == {str(right_target.id)}
    # Whole-repo mode excludes component-scoped assessments too.
    assert session._recorded(uuid4(), AssessmentKind.SECURE_CODE_CANONICAL, ns) == {
        str(wrong_whole.id)
    }


def _make_sha256_repo(root: Path, files: dict[str, str], tag: str) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main", "--object-format=sha256")
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"fixture {tag}")
    sha = _git(root, "rev-parse", "HEAD")
    _git(root, "tag", tag)
    return sha


def _signed_provenance(
    private_key,
    key_id: str,
    statement: dict[str, object],
) -> dict[str, object]:
    import base64

    from traust_core.v1.providers.provenance import dsse_pae

    payload_type = "application/vnd.in-toto+json"
    payload_bytes = json.dumps(statement, sort_keys=True).encode("utf-8")
    sig = private_key.sign(dsse_pae(payload_type, payload_bytes))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def test_provenance_json_root_module_and_sha256_cli_doors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    repo_url = "https://github.com/example-org/root-rebuild"
    checkout = tmp_path / "root-rebuild"
    sha64 = _make_sha256_repo(
        checkout,
        {"setup.cfg": "[metadata]\nname = root-pkg\nversion = 1.4.0\n"},
        tag="build/1.4.0-rebuild-1",
    )
    assert len(sha64) == 64

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )

    trust_file = tmp_path / "provenance-trust.json"
    trust_file.write_text(
        json.dumps(
            {
                "trusted_keys": [
                    {"key_id": "ci-signer-1", "public_key_pem": pub_pem, "issuer": "ci-builder"}
                ],
                "allowed_sources": ["https://slsa.dev/provenance/v1"],
                "allowed_issuers": ["ci-builder"],
            }
        ),
        encoding="utf-8",
    )

    trusted_home = tmp_path / "cfg-trusted"
    trusted_home.mkdir()
    (trusted_home / "traust.yaml").write_text(
        f"process:\n  allowed_binaries:\n    - git\nlocations:\n  provenance_trust: {trust_file}\n",
        encoding="utf-8",
    )
    unconfigured_home = _config_home(tmp_path / "unconfigured")

    for home in (trusted_home, unconfigured_home):
        core = load(home)
        core.services().portfolio.register_repository(
            HttpsRepoUrl.parse(repo_url, core.config.forge_hosts), public=True
        )

    purl = "pkg:pypi/root-pkg@1.4.0+rebuild1"
    valid_env = _signed_provenance(
        priv,
        "ci-signer-1",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": purl}],
            "predicate": {
                "purl": purl,
                "repository": repo_url,
                "commit": sha64,
                "ref": "build/1.4.0-rebuild-1",
                "manifest_version": "1.4.0",
            },
        },
    )
    valid_prov = tmp_path / "valid-prov.json"
    valid_prov.write_text(json.dumps(valid_env), encoding="utf-8")

    tampered_env = {**valid_env, "signatures": [{"keyid": "ci-signer-1", "sig": "AAAA"}]}
    tampered_prov = tmp_path / "tampered-prov.json"
    tampered_prov.write_text(json.dumps(tampered_env), encoding="utf-8")

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    non_obj_json = tmp_path / "list.json"
    non_obj_json.write_text("[1, 2]", encoding="utf-8")

    # 1. assessments prepare succeeds with valid signed provenance, root ".", and 64-hex SHA.
    out_path = tmp_path / "prepared-ext.json"
    rc_ok = assessments.prepare(
        [
            "--config-home",
            str(trusted_home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            purl,
            "--sha",
            sha64,
            "--release-ref",
            "build/1.4.0-rebuild-1",
            "--module-path",
            ".",
            "--provenance-json",
            str(valid_prov),
            "--checkout",
            str(checkout),
            "-o",
            str(out_path),
        ]
    )
    assert rc_ok == 0
    prepared = json.loads(out_path.read_text(encoding="utf-8"))
    target = prepared["component_target"]
    assert target["commit"] == sha64
    assert target["module_path"] == "."
    assert target["verification"]["strategy"] == "external_provenance"
    assert target["verification"]["provenance"]["source"] == "https://slsa.dev/provenance/v1"
    assert target["verification"]["provenance"]["ref"] == "build/1.4.0-rebuild-1"
    assert target["verification"]["provenance"]["digest"].startswith("sha256:")
    assert target["verification"]["provenance"]["manifest_version"] == "1.4.0"

    # 2. assessments prepare fails closed when no provenance verifier is configured.
    capsys.readouterr()
    rc_unconf = assessments.prepare(
        [
            "--config-home",
            str(unconfigured_home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            purl,
            "--sha",
            sha64,
            "--provenance-json",
            str(valid_prov),
            "--checkout",
            str(checkout),
        ]
    )
    assert rc_unconf == assessments.REFUSED
    assert json.loads(capsys.readouterr().out)["reason"] == "provenance_unverified"

    # 3. assessments prepare fails closed on tampered signature, missing --purl, and bad JSON.
    capsys.readouterr()
    rc_tampered = assessments.prepare(
        [
            "--config-home",
            str(trusted_home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            purl,
            "--sha",
            sha64,
            "--provenance-json",
            str(tampered_prov),
            "--checkout",
            str(checkout),
        ]
    )
    assert rc_tampered == assessments.REFUSED
    assert json.loads(capsys.readouterr().out)["reason"] == "provenance_unverified"

    assert (
        assessments.prepare(
            [
                "--config-home",
                str(trusted_home),
                "--repo-url",
                repo_url,
                "--sha",
                sha64,
                "--kind",
                "secure_code",
                "--provenance-json",
                str(valid_prov),
            ]
        )
        != 0
    )
    for bad_file in (bad_json, non_obj_json):
        assert (
            assessments.prepare(
                [
                    "--config-home",
                    str(trusted_home),
                    "--repo-url",
                    repo_url,
                    "--kind",
                    "secure_code",
                    "--purl",
                    purl,
                    "--sha",
                    sha64,
                    "--provenance-json",
                    str(bad_file),
                    "--checkout",
                    str(checkout),
                ]
            )
            != 0
        )

    # 4. session.run stages full external_provenance target in --target-json and rejects failures.
    monkeypatch.setattr(session, "resolve_model", lambda _role: "test-model")

    @contextmanager
    def fake_checkout(url, config_home, ref=None, *, shared=False):
        yield SimpleNamespace(path=checkout)

    monkeypatch.setattr(session, "checkout", fake_checkout)
    staged_targets: list[dict[str, object]] = []

    def fake_session(cmd, skill, env):
        tokens = cmd[-1].split()
        target_idx = tokens.index("--target-json") + 1
        staged_targets.append(json.loads(Path(tokens[target_idx]).read_text(encoding="utf-8")))
        return SimpleNamespace(returncode=0), ()

    monkeypatch.setattr(session, "session", fake_session)
    capsys.readouterr()
    rc_sess_ok = session.run(
        [
            "--config-home",
            str(trusted_home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--purl",
            purl,
            "--sha",
            sha64,
            "--module-path",
            ".",
            "--provenance-json",
            str(valid_prov),
        ]
    )
    assert rc_sess_ok == 0
    assert len(staged_targets) == 1
    assert staged_targets[0]["module_path"] == "."
    assert staged_targets[0]["commit"] == sha64
    assert staged_targets[0]["verification"]["strategy"] == "external_provenance"
    assert staged_targets[0]["verification"]["provenance"]["manifest_version"] == "1.4.0"
    assert "release_ref" not in staged_targets[0]
    _assert_contract_valid_report_target(staged_targets[0])

    # Unconfigured verifier and tampered provenance refuse before spawning agent.
    for cfg, prov_file in ((unconfigured_home, valid_prov), (trusted_home, tampered_prov)):
        staged_targets.clear()
        capsys.readouterr()
        rc_refused = session.run(
            [
                "--config-home",
                str(cfg),
                "--skill",
                "secure-code-audit",
                "--role",
                "audit",
                "--repo",
                repo_url,
                "--purl",
                purl,
                "--sha",
                sha64,
                "--provenance-json",
                str(prov_file),
            ]
        )
        assert rc_refused != 0
        assert staged_targets == []
        out_refused = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert out_refused["outcome"] == "refused"
        assert out_refused["reason"] == "unresolved-target"

    # Malformed provenance JSON fails with bad-request before spawning agent.
    staged_targets.clear()
    capsys.readouterr()
    rc_bad_json = session.run(
        [
            "--config-home",
            str(trusted_home),
            "--skill",
            "secure-code-audit",
            "--role",
            "audit",
            "--repo",
            repo_url,
            "--purl",
            purl,
            "--sha",
            sha64,
            "--provenance-json",
            str(bad_json),
        ]
    )
    assert rc_bad_json != 0
    assert staged_targets == []
    out_bad_json = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out_bad_json["outcome"] == "failed"
    assert out_bad_json["reason"] == "bad_request"

    # --provenance-json without --purl fails fast with argparse exit 2.
    with pytest.raises(SystemExit) as exc_info:
        session.run(
            [
                "--config-home",
                str(trusted_home),
                "--skill",
                "secure-code-audit",
                "--role",
                "audit",
                "--repo",
                repo_url,
                "--checkout",
                "--sha",
                sha64,
                "--provenance-json",
                str(valid_prov),
            ]
        )
    assert exc_info.value.code == 2

    # Mismatched provenance PURL fails closed with provenance_mismatch in assessments.prepare.
    capsys.readouterr()
    rc_mismatch = assessments.prepare(
        [
            "--config-home",
            str(trusted_home),
            "--repo-url",
            repo_url,
            "--kind",
            "secure_code",
            "--purl",
            "pkg:pypi/root-pkg@1.4.0+other",
            "--sha",
            sha64,
            "--provenance-json",
            str(valid_prov),
            "--checkout",
            str(checkout),
        ]
    )
    assert rc_mismatch == assessments.REFUSED
    assert json.loads(capsys.readouterr().out)["reason"] == "provenance_mismatch"

    # 5. Emitted target JSON from BOTH assessments.prepare and session.run validates verbatim
    #    against report.schema.json + traust-contracts Pydantic models when optional fields
    #    (release_ref, manifest_version, verification.provenance) are absent.
    ext_report_doc = _assert_contract_valid_report_target(target)
    ext_report_path = tmp_path / "ext-sha256-report.json"
    ext_report_path.write_text(json.dumps(ext_report_doc), encoding="utf-8")
    capsys.readouterr()
    assert (
        assessment_record.main(
            [
                "--config-home",
                str(trusted_home),
                str(ext_report_path),
                "--kind",
                "secure_code",
                "--repo-url",
                repo_url,
                "--sha",
                sha64,
                "--purl",
                purl,
                "--public",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["target_purl"] == target["purl"]

    same_ver_purl = "pkg:pypi/root-pkg@1.4.0"
    minimal_ext_env = _signed_provenance(
        priv,
        "ci-signer-1",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": same_ver_purl}],
            "predicate": {
                "purl": same_ver_purl,
                "repository": repo_url,
                "commit": sha64,
                "ref": "build/1.4.0-minimal",
            },
        },
    )
    minimal_prov = tmp_path / "minimal-prov.json"
    minimal_prov.write_text(json.dumps(minimal_ext_env), encoding="utf-8")

    minimal_out = tmp_path / "prepared-minimal-ext.json"
    assert (
        assessments.prepare(
            [
                "--config-home",
                str(trusted_home),
                "--repo-url",
                repo_url,
                "--kind",
                "secure_code",
                "--purl",
                same_ver_purl,
                "--sha",
                sha64,
                "--module-path",
                ".",
                "--provenance-json",
                str(minimal_prov),
                "--checkout",
                str(checkout),
                "-o",
                str(minimal_out),
            ]
        )
        == 0
    )
    minimal_prepared_target = json.loads(minimal_out.read_text(encoding="utf-8"))[
        "component_target"
    ]
    assert "release_ref" not in minimal_prepared_target
    assert "manifest_version" not in minimal_prepared_target["verification"]["provenance"]
    _assert_contract_valid_report_target(minimal_prepared_target)

    staged_targets.clear()
    assert (
        session.run(
            [
                "--config-home",
                str(trusted_home),
                "--skill",
                "secure-code-audit",
                "--role",
                "audit",
                "--repo",
                repo_url,
                "--purl",
                same_ver_purl,
                "--sha",
                sha64,
                "--module-path",
                ".",
                "--provenance-json",
                str(minimal_prov),
            ]
        )
        == 0
    )
    assert len(staged_targets) == 1
    assert "release_ref" not in staged_targets[0]
    assert "manifest_version" not in staged_targets[0]["verification"]["provenance"]
    _assert_contract_valid_report_target(staged_targets[0])

    # Ordinary repo-verified release staged by session.run omits verification.provenance.
    ordinary_checkout = tmp_path / "ordinary-root"
    ordinary_sha = _make_monorepo(
        ordinary_checkout,
        {"setup.cfg": "[metadata]\nname = root-pkg\nversion = 1.4.0\n"},
        tag="v1.4.0",
    )

    @contextmanager
    def fake_ordinary_checkout(url, config_home, ref=None, *, shared=False):
        yield SimpleNamespace(path=ordinary_checkout)

    monkeypatch.setattr(session, "checkout", fake_ordinary_checkout)
    staged_targets.clear()
    assert (
        session.run(
            [
                "--config-home",
                str(trusted_home),
                "--skill",
                "secure-code-audit",
                "--role",
                "audit",
                "--repo",
                repo_url,
                "--purl",
                same_ver_purl,
                "--sha",
                ordinary_sha,
                "--module-path",
                ".",
            ]
        )
        == 0
    )
    assert len(staged_targets) == 1
    assert staged_targets[0]["verification"]["strategy"] == "shared_release"
    assert "provenance" not in staged_targets[0]["verification"]
    _assert_contract_valid_report_target(staged_targets[0])


def _assert_contract_valid_report_target(target_doc: dict[str, object]) -> dict[str, object]:
    """Validate emitted target JSON verbatim against contracts Pydantic + report.schema.json."""
    from traust_contracts.v1.models.report import ComponentTarget as ContractComponentTarget
    from traust_core.v1.models.artifacts import SecurityAuditArtifact

    ContractComponentTarget.model_validate(target_doc)
    report = {
        "title": "Component Target Contract Security Audit",
        "metadata": {
            "date": "2026-11-24",
            "scope": "Contract validation of emitted component_target JSON",
            "repository": target_doc["repository"],
            "commit": target_doc["commit"],
            "audit_profile": "code",
            "target": target_doc,
        },
        "executive_summary": {
            "prose": "Contract validation smoke report carrying emitted component_target verbatim.",
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": "critical", "definition": "Unauthenticated remote compromise."},
            {"level": "high", "definition": "Privilege escalation or data leak."},
            {"level": "medium", "definition": "Scoped security weakness."},
            {"level": "low", "definition": "Defense-in-depth hardening gap."},
        ],
        "findings": [],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 0, "finding_ids": []},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "p3",
                "addresses": ["NONE"],
                "action": "No findings identified during contract validation smoke test.",
                "effort": "xs",
            }
        ],
    }
    SecurityAuditArtifact.parse(json.dumps(report).encode("utf-8"))
    return report
