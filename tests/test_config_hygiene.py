"""`check docs-consistency`'s config/ gate: config/ holds the shipped set and nothing else."""

from __future__ import annotations

from pathlib import Path

from traust.cli import check_docs_consistency as C


def test_a_template_beside_the_shipped_set_fails(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    for name in C.CONFIG_SHIPPED:
        (config / name).write_text("{}\n")
    (config / "sla-policy.example.yaml").write_text("{}\n")
    (config / ".env").write_text("x\n")
    failures = C.config_hygiene_failures(tmp_path)
    assert [f.split(":")[0] for f in failures] == ["config/.env", "config/sla-policy.example.yaml"]
    assert "a template lives beside its reader" in failures[1]
