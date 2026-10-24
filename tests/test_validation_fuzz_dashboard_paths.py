"""Output-path derivation for the validation-fuzz dashboard.

The HTML path is resolved against the configured dashboards directory, but the
Markdown companion used to be derived with ``Path(out_path).stem + ".md"``.
``.stem`` drops the parent directory as well as the suffix, so the Markdown
landed in the process's CWD while the HTML went to the dashboards directory —
leaving the two halves of one run in different places (and, on 2026-09-14, a
stray report in a repo working tree).
"""

import importlib.util
import sys
from pathlib import Path

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "build_validation_fuzz_dashboard",
    skill_dir("validation-fuzz-dashboard") / "scripts" / "build_validation_fuzz_dashboard.py",
)
vfd = importlib.util.module_from_spec(_SPEC)
sys.modules["build_validation_fuzz_dashboard"] = vfd
_SPEC.loader.exec_module(vfd)

HTML = "Live-validation-fuzz-dashboard.html"


def test_markdown_lands_beside_the_html():
    out = Path("/tmp/pt/metrics/dashboards") / HTML
    assert vfd.markdown_path(out).parent == out.parent


def test_markdown_keeps_the_html_name_with_an_md_suffix():
    out = Path("/tmp/pt/metrics/dashboards") / HTML
    assert vfd.markdown_path(out).name == "Live-validation-fuzz-dashboard.md"


def test_derived_markdown_path_is_absolute_when_the_html_path_is():
    """The regression itself: a relative result means it resolves against CWD."""
    out = Path("/tmp/pt/metrics/dashboards") / HTML
    assert vfd.markdown_path(out).is_absolute()


def test_string_html_path_is_accepted():
    """build() receives --out as a str, not a Path."""
    out = "/tmp/pt/metrics/dashboards/" + HTML
    assert vfd.markdown_path(out) == Path(
        "/tmp/pt/metrics/dashboards/Live-validation-fuzz-dashboard.md"
    )


def test_explicit_out_md_wins():
    out = Path("/tmp/pt/metrics/dashboards") / HTML
    assert vfd.markdown_path(out, "/tmp/elsewhere/custom.md") == Path("/tmp/elsewhere/custom.md")


def test_relative_html_path_stays_relative_to_its_own_directory():
    """A relative --out keeps its directory rather than collapsing to the name."""
    assert vfd.markdown_path(Path("metrics/dashboards") / HTML) == Path(
        "metrics/dashboards/Live-validation-fuzz-dashboard.md"
    )
