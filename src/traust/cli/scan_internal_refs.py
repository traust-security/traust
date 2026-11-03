#!/usr/bin/env python3
"""Pre-publication scrub: organization-internal references in an export candidate.

Open-sourcing turns every tracked file into a public artifact. This is the
Phase-3 gate of the open-source upstream plan — a repeatable check rather
than a one-off grep, so it can run on the export tree before every upstream
release, not just once.

Universal rules (credential shapes, RFC1918, cloud identifiers) are compiled
in. The rules that name YOUR hosts, tools, trackers and products come from
your vocabulary file — see --vocabulary. That split is not a
convenience: a scanner shipping a list of an organization's internal tool
names has published that list.

IT ROUTES ATTENTION, NEVER CONCLUDES. A hit is a thing to look at, not a
verdict: a security-alias address is published on purpose, a documentation
endpoint is public, and a tracker key inside a CHANGELOG entry may be
perfectly fine to ship. Severity orders the review queue; a human decides
what leaves.

Tiers
  block    credentials and internal-only network identity. Nothing in this
           tier should ever reach a public repo.
  review   internal process/tooling vocabulary and person identifiers.
           Usually fine in an internal doc, usually wrong in a public one.
  note     public surface and product vocabulary. Recorded so a reviewer can
           confirm the export reads as a generic tool rather than one
           organization's campaign artifact.

Scans only files git tracks: untracked scratch, caches and build output
are not part of an export, and including them buries the real signal.

Usage:
    python3 -m traust.cli.scan_internal_refs [REPO ...]
        [--tier block|review|note] [--json OUT] [--max-per-rule N]
        [--fail-on block|review]
Exit 0 when nothing at or above --fail-on is found, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Files whose whole purpose is to document the internal posture. Their hits
# are expected and would otherwise dominate the report; a reviewer still
# reads them, but they are not the signal this gate exists to surface.
EXPECTED_INTERNAL = (
    "docs/external-dependencies.md",
    "docs/continuous-operations.md",
    "docs/setup.md",
    "docs/requirements.md",
    "CHANGELOG.md",
)

# (id, tier, pattern, why)
RULES: tuple[tuple[str, str, str, str], ...] = (
    # ---- block: credentials -------------------------------------------
    (
        "private-key",
        "block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "private key material",
    ),
    ("aws-key", "block", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    ("gh-token", "block", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    ("glab-token", "block", r"\bglpat-[A-Za-z0-9_-]{20,}\b", "GitLab PAT"),
    ("slack-token", "block", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    ("vault-token", "block", r"\bhv[sb]\.[A-Za-z0-9_-]{20,}\b", "Vault token"),
    (
        "jwt",
        "block",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JWT — may carry identity/claims",
    ),
    (
        "rfc1918",
        "block",
        r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
        "private-range IP",
    ),
    # ---- block: cloud tenancy identity ---------------------------------
    # Added 2026-09-01. The 27-skill scrub found an AWS account id, two GCP
    # project ids and an installer service account BY HAND, in files this
    # scanner had already passed — so a recurrence would have been invisible.
    #
    # Both are ANCHORED, never shape-based. A bare 12-digit rule matches
    # fuzz-crash output (velocity-engine logs are full of long digit runs),
    # which is the same mistake the gdrive-id comment above records.
    (
        "cloud-account-id",
        "block",
        r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}\b|"
        # No leading \b: the real-world spelling is EXPECT_ACCOUNT="2660…",
        # and "_" is a word char, so \b never matches between them.
        r"acc(?:oun)?t(?:_id)?\b[^0-9\n]{0,24}\b\d{12}\b",
        "cloud account id — deployment config, never a shipped default",
    ),
    (
        "cloud-service-account",
        "block",
        r"\b[a-z0-9][a-z0-9-]*@[a-z0-9-]+\.iam\.gserviceaccount\.com\b",
        "GCP service account",
    ),
    # ---- block: a person's data --------------------------------------
    # Consumer-mailbox domains: a corporate address is org vocabulary (the
    # deployment's internal-vocabulary.yaml names it), but an address at a
    # consumer provider is a PERSON's, whatever repo it sits in. Found the
    # hard way 2026-09-07: eight people's personal addresses shipped in a
    # skill's reference table for two months while every gate passed.
    (
        "personal-email",
        "block",
        r"\b[a-z0-9._%+-]+@(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|"
        r"msn|icloud|me|mac|proton|protonmail|pm|aol|gmx|fastmail|zoho|yandex|"
        r"mail|hey)\.(?:com|net|org|me|ch|de|co\.uk|ru)\b",
        "personal email address — a person's data, never a shipped default",
    ),
    # Atlassian accountIds identify a person in one organisation's Jira. Two
    # shapes: the modern `<5-6 digits>:<uuid>` and the legacy 24-hex id. The
    # legacy shape alone collides with other 24-hex tokens, so it is only
    # flagged when the line names it (accountId / account_id / assignee).
    (
        "jira-account-id",
        "block",
        r"\b\d{5,6}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|"
        r"(?:account[_ -]?id|assignee)\b[^0-9a-z\n]{0,24}\b[0-9a-f]{24}\b",
        "Atlassian accountId — identifies a person in one org's issue tracker",
    ),
    # review, not block: a literal --project value is usually deployment
    # config, but the flag also appears in generic docs. Excludes $VAR and
    # ${VAR} forms, which are the CORRECT shape and must not be flagged.
    # Two shapes, and the SECOND is the one that actually shipped: a literal
    # as the fallback of a parameter expansion: ${GCP_PROJECT:-<literal>}.
    # The placeholder is angle-bracketed so this comment does not match its
    # own rule — the rule keys on the SHAPE, so any realistic example would.
    # The first draft of this rule excluded anything starting "$" and so
    # missed every real occurrence — caught by the smoke test, not by review.
    (
        "cloud-project",
        "review",
        r"--project[=\s]+[\"']?(?![$\"'])[a-z][-a-z0-9]{4,28}[a-z0-9]\b|"
        r"\$\{[A-Z_]*(?:PROJECT|ACCOUNT)[A-Z_]*:-[a-z][-a-z0-9]{4,28}[a-z0-9]\}",
        "literal cloud project id — expected to be deployment config",
    ),
    # URL-anchored, not shape-based: a bare "28+ chars starting 0/1" rule
    # matched sha256 digests, UUIDs and slug ids — 53 hits, all noise.
    (
        "gdrive-id",
        "review",
        r"(?:docs|drive|sheets)\.google\.com/[A-Za-z0-9/_-]+|"
        r"\b(?:spreadsheet_id|folder_id|document_id|drive_id)\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}",
        "Google Drive/Sheets identifier",
    ),
    (
        "employee-uid",
        "review",
        r"\b(?:cc_list|default_cc|private_tracker_cc|assignee|owner)s?\s*[:=]\s*\[?[\"']?"
        r"(?!(?:str|int|bool|list|dict|none|null|unset|unknown|any|true|false|"
        r"team|owner|self|other|based|additions|removals|"
        r"next|make|new|get|find|lambda|await|yield|match)\b)[a-z]{2,10}[\"']?",
        "possible LDAP uid in an ownership field",
    ),
)


# --- organization vocabulary ------------------------------------------------
# RULES above are universal: credential shapes, RFC1918, cloud identifiers,
# uid-shaped ownership fields. They are the same for everyone.
#
# The rules that name an organization's hosts, tools, trackers and products are
# NOT universal, and the vocabulary is itself the disclosure it detects -- a
# scanner shipping a list of internal tool names has published that list. Those
# live with the deployment (the harness ships only the template,
# tools/public-export/internal-vocabulary.example.yaml) and are loaded here.
#
# Order: --vocabulary > HARNESS_INTERNAL_VOCABULARY
#
# Missing or malformed fails LOUDLY. A scanner that quietly runs with fewer
# rules than you think reports "clean" for the wrong reason, which is worse
# than not running.
from traust.context import internal_vocabulary  # noqa: E402

_VALID_TIERS = ("block", "review", "note")


class VocabularyError(RuntimeError):
    """The organization vocabulary could not be loaded."""


def vocabulary_path(explicit: str | None = None) -> Path | None:
    return Path(explicit) if explicit else internal_vocabulary()


def load_vocabulary(explicit: str | None = None) -> tuple[tuple[str, str, str, str], ...]:
    """Org-specific rules as (id, tier, pattern, why), or raise."""
    path = vocabulary_path(explicit)
    if path is None or not path.is_file():
        raise VocabularyError(
            f"vocabulary not found: {path}\n"
            "Pass --vocabulary or set HARNESS_INTERNAL_VOCABULARY. The shipped "
            "tools/public-export/internal-vocabulary.example.yaml is a generic "
            "template and matches nothing real."
        )
    try:
        import yaml
    except ImportError as e:  # pragma: no cover
        raise VocabularyError("PyYAML is required to read the vocabulary") from e
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise VocabularyError(f"{path}: unparseable ({type(e).__name__})") from e
    except (OSError, UnicodeError) as e:
        raise VocabularyError(f"{path}: cannot read vocabulary ({type(e).__name__})") from e
    if not isinstance(doc, dict):
        raise VocabularyError(f"{path}: vocabulary must be a mapping")
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        raise VocabularyError(f"{path}: no 'rules' list")
    out, seen = [], set()
    for r in rules:
        if not isinstance(r, dict):
            raise VocabularyError(f"{path}: rule entry is not a mapping: {r!r}")
        rid, tier, pat = r.get("id"), r.get("tier"), r.get("pattern")
        why = r.get("why") or rid
        if not all(isinstance(value, str) and value for value in (rid, tier, pat)):
            raise VocabularyError(
                f"{path}: rule {rid or r!r} needs nonempty string id, tier and pattern"
            )
        if not isinstance(why, str):
            raise VocabularyError(f"{path}: rule {rid} needs a string explanation")
        if tier not in _VALID_TIERS:
            raise VocabularyError(
                f"{path}: rule {rid} has tier {tier!r}, expected one of {', '.join(_VALID_TIERS)}"
            )
        if rid in seen:
            raise VocabularyError(f"{path}: duplicate rule id {rid!r}")
        # Compile now: a bad pattern must fail at load, naming the rule, not
        # halfway through a scan with a bare re.error.
        try:
            re.compile(pat)
        except re.error as e:
            raise VocabularyError(f"{path}: rule {rid} has an invalid pattern ({e})") from e
        if rid in {u[0] for u in RULES}:
            raise VocabularyError(f"{path}: rule {rid!r} collides with a built-in universal rule")
        seen.add(rid)
        out.append((rid, tier, pat, why))
    return tuple(out)


def all_rules(explicit: str | None = None) -> tuple[tuple[str, str, str, str], ...]:
    """Universal rules plus the organization vocabulary."""
    return RULES + load_vocabulary(explicit)


TIER_ORDER = {"block": 0, "review": 1, "note": 2}

# Paths where a rule's own match is the point, not a leak: a scanner rule pack
# that finds private keys necessarily quotes the PEM header. Narrow on purpose --
# rule id -> path substrings, not a general allowlist.
RULE_EXEMPT_PATHS: dict[str, tuple[str, ...]] = {
    # A detector pack quotes the header it detects; a redaction example quotes
    # what it redacts; a fixture generates a throwaway PEM to exercise shape
    # handling. All three must contain the string, none is key material.
    "private-key": (
        "/rules/",
        "/opengrep/",
        "/semgrep/",
        "generate-team-report/SKILL.md",
        "tests/test_redact.py",
    ),
    # AWS's own published documentation key. It exists to be written down.
    "aws-key": ("tests/test_redact.py",),
    # docs/external-dependencies.md is the licence-intake record. Naming where
    # a dependency comes from IS the evidence; blanking the URLs would make the
    # provenance less true, not less internal (Michele, 2026-09-01). Exempting
    # RFC1918 space is non-routable by definition, so a 10.x literal in a test
    # fixture -- a CIDR selector, a connection-refused message -- is the correct
    # thing to write, not a disclosure. Scoped to tests/ so a real internal
    # address in shipped code or docs still blocks.
    "rfc1918": ("tests/",),
    # The scanner's own tests carry synthetic personal addresses and accountIds
    # as the positive cases for these two rules; nowhere else may.
    "personal-email": ("tests/test_scan_internal_refs.py",),
    "jira-account-id": ("tests/test_scan_internal_refs.py",),
}


def _exempt(rule_id: str, rel: str) -> bool:
    return any(frag in f"/{rel}" for frag in RULE_EXEMPT_PATHS.get(rule_id, ()))


# A vocabulary file is the SOURCE of the deployment rules: a literal pattern
# matches its own text, so scanning it with the rules it defines is circular
# (the shipped template and the test fixture both tripped `campaign` and
# `internal-tooling` on their own placeholders in the 2026-09-08 export
# dry-run). Universal rules (keys, personal data) still apply to it.
VOCABULARY_FILE_RX = re.compile(r"(^|/)internal-vocabulary[^/]*\.ya?ml$")
_UNIVERSAL_IDS = frozenset(r[0] for r in RULES)


def _is_vocabulary_file(rel: str) -> bool:
    return bool(VOCABULARY_FILE_RX.search(rel))


def tracked_files(repo: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files"], capture_output=True, text=True, timeout=120
        )
    except (subprocess.SubprocessError, OSError):
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def _is_binary(data: bytes) -> bool:
    return b"\0" in data[:4096]


def scan_repo(
    repo: Path, max_per_rule: int, rules: tuple[tuple[str, str, str, str], ...] | None = None
) -> list[dict]:
    # Default to universal + organization vocabulary. Passing `rules` is for
    # tests; production always goes through all_rules() so a missing
    # vocabulary raises instead of silently scanning with 13 rules.
    compiled = [
        (rid, tier, re.compile(pat, re.IGNORECASE), why)
        for rid, tier, pat, why in (rules if rules is not None else all_rules())
    ]
    counts: dict[str, int] = defaultdict(int)
    findings: list[dict] = []
    for rel in tracked_files(repo):
        p = repo / rel
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if _is_binary(raw):
            continue
        text = raw.decode("utf-8", "replace")
        expected = any(rel == e or rel.startswith(e) for e in EXPECTED_INTERNAL)
        vocab_file = _is_vocabulary_file(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:  # minified/data lines: not review surface
                continue
            for rid, tier, rx, why in compiled:
                if vocab_file and rid not in _UNIVERSAL_IDS:
                    continue
                m = rx.search(line)
                if not m or _exempt(rid, rel):
                    continue
                key = f"{rel}:{rid}"
                counts[key] += 1
                if counts[key] > max_per_rule:
                    continue
                findings.append(
                    {
                        "repo": repo.name,
                        "file": rel,
                        "line": lineno,
                        "rule": rid,
                        "tier": tier,
                        "why": why,
                        "match": m.group(0)[:80],
                        "expected_internal_doc": expected,
                    }
                )
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repos", nargs="*", type=Path, default=[Path()])
    ap.add_argument("--tier", choices=("block", "review", "note"))
    ap.add_argument("--json", type=Path)
    ap.add_argument(
        "--max-per-rule",
        type=int,
        default=3,
        help="per file+rule cap so one noisy file cannot bury the rest",
    )
    ap.add_argument("--fail-on", choices=("block", "review"))
    ap.add_argument(
        "--vocabulary",
        metavar="PATH",
        help="organization vocabulary YAML (default: $HARNESS_INTERNAL_VOCABULARY; "
        "template: tools/public-export/internal-vocabulary.example.yaml)",
    )
    args = ap.parse_args(argv)

    # Resolve the vocabulary BEFORE scanning: a bad path should fail in the
    # first second naming the file, not after a full tree walk.
    try:
        rules = all_rules(args.vocabulary)
    except VocabularyError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    all_f: list[dict] = []
    for repo in args.repos:
        if not (repo / ".git").exists():
            print(f"[!] {repo}: not a git repo — skipped", file=sys.stderr)
            continue
        all_f.extend(scan_repo(repo, args.max_per_rule, rules))

    shown = [f for f in all_f if not args.tier or f["tier"] == args.tier]
    shown.sort(key=lambda f: (TIER_ORDER[f["tier"]], f["repo"], f["file"]))

    by_tier: dict[str, int] = defaultdict(int)
    for f in all_f:
        by_tier[f["tier"]] += 1

    print(
        f"scan_internal_refs — {len(args.repos)} repo(s), "
        f"{len(all_f)} hit(s) [capped at {args.max_per_rule}/file/rule]"
    )
    for tier in ("block", "review", "note"):
        print(f"  {tier:8s} {by_tier[tier]}")
    print()

    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for f in shown:
        grouped[(f["tier"], f["rule"], f["repo"])].append(f)
    for (tier, rule, repo), items in sorted(
        grouped.items(), key=lambda kv: (TIER_ORDER[kv[0][0]], kv[0][1])
    ):
        files = sorted({i["file"] for i in items})
        exp = sum(1 for i in items if i["expected_internal_doc"])
        note = f"  ({exp} in expected-internal docs)" if exp else ""
        print(f"[{tier}] {rule} — {repo}: {len(items)} hit(s) in {len(files)} file(s){note}")
        print(f"        {items[0]['why']}")
        for i in items[:3]:
            print(f"        {i['file']}:{i['line']}  {i['match']}")
        if len(files) > 3:
            print(f"        … +{len(files) - 3} more file(s)")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps({"summary": dict(by_tier), "findings": all_f}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")

    if args.fail_on:
        bad = sum(v for k, v in by_tier.items() if TIER_ORDER[k] <= TIER_ORDER[args.fail_on])
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["admin", "scan-internal-refs", *sys.argv[1:]]))
