from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust.cli.loc_explore import main


def export() -> dict[str, Any]:
    def repo(url: str, code: int, language: str) -> dict[str, Any]:
        return {
            "repository_id": str(uuid4()),
            "repository_url": url,
            "code": code,
            "total": code,
            "primary": language,
            "unmeasured": None,
            "languages": [{"name": language, "code": code}],
            "code_delta": 10,
            "corpus_trees": ["findings"] if language == "Python" else ["oss-findings"],
        }

    return {
        "code": 1200,
        "total": 1200,
        "languages": [],
        "repositories": [
            repo("https://github.com/example/small", 200, "Python"),
            repo("https://github.com/example/large", 1000, "Go"),
            {
                **repo('<img src=x onerror="window.injected=1">', 0, "Go"),
                "unmeasured": "No recorded scan",
                "languages": [],
                "code_delta": None,
                "corpus_trees": [],
                "code": None,
                "total": None,
            },
        ],
        "corpus_buckets": [
            {"tree": "findings", "repositories": 1, "code": 200},
            {"tree": "oss-findings", "repositories": 1, "code": 1000},
            {"tree": None, "repositories": 1, "code": 0},
        ],
    }


@pytest.fixture
def page(tmp_path: Path) -> Any:
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("Install Chromium with python -m playwright install chromium")
        browser = playwright.chromium.launch()
        tab = browser.new_page()
        target = tmp_path / "explorer.html"
        assert main(["--config-home", str(tmp_path / "no-deployment"), "--out", str(target)]) == 0
        tab.goto(target.as_uri())
        yield tab
        browser.close()


def open_export(page: Any, data: dict[str, Any]) -> None:
    page.locator("#file").set_input_files(
        {
            "name": "lines-of-code.json",
            "mimeType": "application/json",
            "buffer": json.dumps(data).encode(),
        }
    )
    page.locator("#content").wait_for(state="visible")


def test_filter_sort_bucket_language_mix_and_untrusted_text_in_the_rendered_surface(
    page: Any,
) -> None:
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    open_export(page, export())
    assert page.locator("#rows tr").count() == 3
    assert page.locator("#rows tr").first.locator("td").first.inner_text().endswith("large")
    assert page.locator(".mix[role=img]").count() == 3
    assert page.locator("#rows img").count() == 0
    assert page.evaluate("window.injected") is None
    page.get_by_role("button", name="Code lines", exact=True).click()
    assert "small" in page.locator("#rows tr").first.inner_text()
    page.locator("#language").select_option("Python")
    assert page.locator("#rows tr").count() == 1
    assert "small" in page.locator("#rows").inner_text()
    page.get_by_role("button", name="Clear filters").click()
    page.locator("#tree").select_option('"findings"')
    assert page.locator("#rows tr").count() == 1
    assert "small" in page.locator("#rows").inner_text()
    page.get_by_role("button", name="Clear filters").click()
    page.get_by_role("button", name="1k–10k · 1", exact=True).click()
    assert page.locator("#rows tr").count() == 1
    assert "large" in page.locator("#rows").inner_text()
    page.locator("#search").fill("does-not-exist")
    assert page.locator("#empty").is_visible()
    assert requests == []
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_a_malformed_export_clears_previously_loaded_data_and_reports_the_problem(
    page: Any,
) -> None:
    open_export(page, export())
    page.locator("#file").set_input_files(
        {
            "name": "wrong.json",
            "mimeType": "application/json",
            "buffer": b'{"code": 9}',
        }
    )
    page.wait_for_function("document.getElementById('content').hidden")
    assert page.locator("#controls").is_disabled()
    assert page.locator("#status").inner_text().startswith("Could not open export:")
