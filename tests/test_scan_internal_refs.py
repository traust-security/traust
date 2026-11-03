"""Tests for scan_internal_refs — universal rules vs organization vocabulary."""

import pytest

from traust.cli import scan_internal_refs as S

# --- organization vocabulary ------------------------------------------------
# The rules naming an org's hosts, tools and trackers used to be compiled into
# the scanner, which meant publishing the scanner published that list -- the
# vocabulary was itself the disclosure it detects. It now loads from config.


def test_universal_rules_carry_no_org_vocabulary():
    """Nothing in the built-in table may name what the deployment vocabulary
    names. The vocabulary is the list; this test does not carry a second one."""
    try:
        vocab = S.load_vocabulary()
    except S.VocabularyError:
        pytest.skip("no deployment vocabulary configured (HARNESS_INTERNAL_VOCABULARY)")
    blob = " ".join(f"{r[0]} {r[2]} {r[3]}" for r in S.RULES).lower()
    import re as _re

    generic = {
        "com",
        "net",
        "org",
        "http",
        "https",
        "www",
        "pages",
        "data",
        "prod",
        "dev",
        "int",
        "eng",
        "corp",
        "devel",
        "internal",
        "redhat",
        "project",
        "docs",
    }
    checked = 0
    for rid, tier, pat, _why in vocab:
        if tier == "note":
            continue  # note-tier rules name PUBLIC things (docs hosts, product names)
        # the org's names are the plain-word alternatives inside (?:a|b|c) groups
        for group in _re.findall(r"\(\?:([^()]+)\)", pat):
            for alt in group.split("|"):
                tok = alt.strip("\\b ").replace("\\s+", " ").replace("\\.", ".")
                if not _re.fullmatch(r"[A-Za-z][A-Za-z.-]{3,}", tok) or tok.lower() in generic:
                    continue
                checked += 1
                assert tok.lower() not in blob, (
                    f"{rid}: {tok!r} is compiled into the universal rules"
                )
    assert checked >= 5, "vocabulary yielded too few org names to check — pattern shape changed?"


def test_shipped_example_matches_nothing_in_this_repo():
    """.invalid is reserved, so the example cannot collide with real values
    or with this repo's own example.com fixtures. Loads the shipped TEMPLATE
    explicitly: the default now resolves the deployment vocabulary."""
    from pathlib import Path

    example = (
        Path(S.__file__).resolve().parents[3]
        / "tools"
        / "public-export"
        / "internal-vocabulary.example.yaml"
    )
    vocab = S.load_vocabulary(str(example))
    assert len(vocab) == 10
    for rid, tier, pat, _why in vocab:
        assert tier in ("block", "review", "note")
        assert "redhat" not in pat.lower(), rid


def test_missing_vocabulary_fails_loudly(tmp_path):
    with pytest.raises(S.VocabularyError) as e:
        S.load_vocabulary(str(tmp_path / "absent.yaml"))
    assert "not found" in str(e.value)


def test_malformed_vocabulary_names_the_rule(tmp_path):
    bad = tmp_path / "v.yaml"
    bad.write_text("rules:\n  - {id: x, tier: nope, pattern: 'a'}\n", encoding="utf-8")
    with pytest.raises(S.VocabularyError) as e:
        S.load_vocabulary(str(bad))
    assert "tier" in str(e.value) and "x" in str(e.value)


def test_invalid_regex_fails_at_load_not_mid_scan(tmp_path):
    bad = tmp_path / "v.yaml"
    bad.write_text("rules:\n  - {id: x, tier: block, pattern: '([unclosed'}\n", encoding="utf-8")
    with pytest.raises(S.VocabularyError) as e:
        S.load_vocabulary(str(bad))
    assert "invalid pattern" in str(e.value)


def test_a_config_rule_may_not_shadow_a_universal_one(tmp_path):
    bad = tmp_path / "v.yaml"
    bad.write_text("rules:\n  - {id: private-key, tier: block, pattern: 'x'}\n", encoding="utf-8")
    with pytest.raises(S.VocabularyError) as e:
        S.load_vocabulary(str(bad))
    assert "collides" in str(e.value)


@pytest.mark.parametrize(
    "content",
    [
        b"[]",
        b"false",
        b"\xff",
        b"rules:\n  - {id: [], tier: block, pattern: fixture}\n",
        b"rules:\n  - {id: fixture, tier: block, pattern: 42}\n",
        b"rules:\n  - {id: fixture, tier: block, pattern: fixture, why: [invalid]}\n",
    ],
)
def test_malformed_vocabulary_raises_contextual_load_error(tmp_path, content):
    vocabulary = tmp_path / "vocabulary.yaml"
    vocabulary.write_bytes(content)
    with pytest.raises(S.VocabularyError) as error:
        S.load_vocabulary(str(vocabulary))
    assert str(vocabulary) in str(error.value)


def test_all_rules_is_universal_plus_vocabulary():
    from pathlib import Path

    example = (
        Path(S.__file__).resolve().parents[3]
        / "tools"
        / "public-export"
        / "internal-vocabulary.example.yaml"
    )
    vocab = S.load_vocabulary(str(example))
    assert len(S.all_rules(str(example))) == len(S.RULES) + len(vocab)


# --- a person's data ---------------------------------------------------------


def _rule(rid):
    import re

    return next(re.compile(pat, re.IGNORECASE) for r, _t, pat, _w in S.RULES if r == rid)


@pytest.mark.parametrize(
    "text",
    [
        "someone.example@gmail.com",
        "Contact: A.PERSON@Yahoo.co.uk",
        "| user@redhat.example, user.name@protonmail.com | x |",
    ],
)
def test_personal_email_blocks(text):
    assert _rule("personal-email").search(text), text


@pytest.mark.parametrize(
    "text",
    [
        "user@example.com",
        "svc@redhat.example",
        "bot@users.noreply.github.com",
        "mailto:security@example.org",
        "gmail.com is a provider",
    ],
)
def test_personal_email_ignores_non_personal(text):
    assert not _rule("personal-email").search(text), text


def test_personal_email_is_block_tier():
    assert next(r for r in S.RULES if r[0] == "personal-email")[1] == "block"


@pytest.mark.parametrize(
    "text",
    [
        "jira_account_id: 712020:0f0e0d0c-0b0a-4c09-8807-060504030201",
        "| Name | 70121:11223344-5566-4788-99aa-bbccddeeff00 |",
        "accountId: 5f3e2d1c0b0a09080706abcd",
        'assignee = "60a1b2c3d4e5f60718293a4b"',
    ],
)
def test_jira_account_id_blocks(text):
    assert _rule("jira-account-id").search(text), text


@pytest.mark.parametrize(
    "text",
    [
        "commit 5f3e2d1c0b0a09080706abcd",  # 24-hex with no tracker context
        "sha256:2d13857d235251318c65c289b48d2096ef3e3f06",  # a real digest prefix
        "id: 1abac1d3-82c8-40ca-aab3-734a2d055556",  # bare uuid, no numeric prefix
        "port 12345: open",
    ],
)
def test_jira_account_id_ignores_lookalikes(text):
    assert not _rule("jira-account-id").search(text), text


def test_the_2026_09_07_leak_would_have_blocked():
    """The exact row shape that shipped for two months."""
    row = (
        "| someone@redhat.example, someone@gmail.com | login | A Person | "
        "712020:0f0e0d0c-0b0a-4c09-8807-060504030201 |"
    )
    assert _rule("personal-email").search(row)
    assert _rule("jira-account-id").search(row)
