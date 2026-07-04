"""CLI tests: exit codes and clear errors, with the LLM port stubbed."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import skillguard.cli as cli
from conftest import StubJudge
from skillguard.models import Tier

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def test_benign_skill_prints_clean_and_exits_zero(monkeypatch) -> None:
    monkeypatch.setattr(cli, "AnthropicJudge", lambda: StubJudge(tier=Tier.CLEAN))
    result = runner.invoke(cli.app, ["scan", str(FIXTURES / "benign")])
    assert result.exit_code == 0
    assert "Clean" in result.stdout


def test_non_skill_path_errors_without_traceback(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("not a skill\n")
    result = runner.invoke(cli.app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "not a Skill" in result.output
    assert "Traceback" not in result.output
