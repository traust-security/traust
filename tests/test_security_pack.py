from __future__ import annotations

import re
from pathlib import Path

import yaml
from traust_core.v1.contracts import validate_config

from traust.paths import SECURITY_PACK_DIR

PACK = SECURITY_PACK_DIR / "assets.yaml"


def _assets() -> dict:
    """The pack's assets, after contracts' `pack` schema accepts the document."""
    raw = yaml.safe_load(PACK.read_text())
    validate_config("pack", raw)
    return raw["assets"]


def _asset_for_lane(assets: dict, lane: str) -> str:
    return next(n for n, a in assets.items() if lane in a.get("trigger", {}).get("lanes", ()))


def test_the_security_pack_loads_and_every_source_asset_has_a_cadence() -> None:
    assets = _assets()
    sources = [name for name, asset in assets.items() if not asset.get("deps")]
    assert {"feeds_cache", "inventory_discovery"} <= set(sources)
    assert all(assets[name]["trigger"].get("every") is not None for name in sources)


RELEASE_PLANNED = {"release_container_audit", "release_rpm_audit"}
DIRECT_PLANNED = {
    "external_report_audit": ["repo_state"],
    "external_report_validation": ["external_report_audit"],
    "methodology_audit": ["repo_state"],
    "cve_impact": ["feeds_cache"],
    "release_container_audit": ["release_discovery"],
    "release_rpm_audit": ["release_discovery"],
}


def test_below_range_review_waits_for_the_verification_packets() -> None:
    assert _assets()["below_range_review"]["deps"] == ["below_range_packets"]


def test_every_asset_has_a_trigger_freshness_and_runner_labels() -> None:
    raw = yaml.safe_load(PACK.read_text())["assets"]
    for name, asset in raw.items():
        if name in DIRECT_PLANNED:
            assert asset.get("deps") == DIRECT_PLANNED[name]
            assert not asset.get("trigger"), name
        else:
            assert asset.get("trigger") or asset.get("deps"), name
            assert asset.get("freshness") or asset.get("trigger", {}).get("lanes"), name
        assert asset.get("runner", {}).get("labels"), name


REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
# What traust-engine's claim-once runner fills in: the order's id, its repository's URL, a
# skill session's model role, a routed order's rule, and the claiming worker.
RUNNER_PARAMS = {"run_id", "repo_url", "role", "rule", "worker"}


def test_every_skill_session_names_a_registry_role() -> None:
    roles = set(yaml.safe_load(REGISTRY.read_text())["roles"])
    sessions = {n: a["model"]["role"] for n, a in _assets().items() if a.get("model")}
    assert sessions and set(sessions.values()) <= roles, sessions


def test_every_command_param_is_one_the_runner_fills() -> None:
    raw = yaml.safe_load(PACK.read_text())["assets"]
    for name, asset in raw.items():
        named = {m[1] for t in asset.get("run", []) if (m := re.fullmatch(r"\{(\w+)\}", t))}
        assert named <= RUNNER_PARAMS, (name, named)
        assert "repo_url" not in named or asset.get("partitions") == "dynamic:repo", name
        assert "rule" not in named or "lanes" in asset["trigger"], name


def test_every_runnable_skill_session_starts_through_traust_session_with_its_role() -> None:
    from traust.paths import skill_dir

    for name, asset in yaml.safe_load(PACK.read_text())["assets"].items():
        if "model" not in asset or "run" not in asset:
            continue
        run = asset["run"]
        if name in RELEASE_PLANNED:
            assert run[3:5] == ["portfolio", "release-audit"] and "{role}" in run, name
            kind = run[run.index("--kind") + 1]
            assert kind in {"container", "rpm"}
            skill_dir(f"secure-{kind}-audit")
        elif name == "external_report_validation":
            assert run[3:5] == ["portfolio", "event-validate"] and "{role}" in run
            skill_dir("validate-findings")
        else:
            assert run[3:5] == ["session", "run"] and "{role}" in run, name
            skill_dir(run[run.index("--skill") + 1])


def test_scheduled_check_up_applies_ratings() -> None:
    """The quarterly and release-review lanes write OWASP ratings and leave everything else
    report-only (decided 2026-10-01)."""
    assets = _assets()
    rating = {"threat-model-quarterly", "threat-model-review"}
    for lane in rating:
        run = assets[_asset_for_lane(assets, lane)]["run"]
        skill = run[run.index("--skill") + 1], run[run.index("--mode") + 1]
        assert skill == ("threat-model", "review"), lane
        assert run[run.index("--") + 1 :] == ["--auto", "--apply-ratings"], lane
    others = {n for n, a in assets.items() if "--apply-ratings" in a.get("run", ())}
    assert others == {_asset_for_lane(assets, lane) for lane in rating}
