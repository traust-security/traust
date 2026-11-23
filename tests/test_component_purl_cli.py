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

    # Unresolved target exits REFUSED (3) with structured JSON reason.
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
    def fake_checkout(url, config_home, *, sha=None, shared=False):
        seen_checkout.append((url, sha, shared))
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

    # Real checkout -> release lifecycle removes only the real worktree.
    capsys.readouterr()
    assert (
        repo.checkout(
            [
                "--config-home",
                str(home),
                str(checkout),
                "--ref",
                sha,
            ]
        )
        == 0
    )
    wt_path = Path(capsys.readouterr().out.strip().splitlines()[-1])
    assert wt_path.is_dir()
    assert (
        repo.release(
            [
                "--config-home",
                str(home),
                str(checkout),
                "--ref",
                sha,
                "--path",
                str(wt_path),
            ]
        )
        == 0
    )
    assert not wt_path.exists()
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
