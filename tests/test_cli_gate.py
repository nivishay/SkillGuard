"""CLI tests for the Endpoint Gate commands: install-hook and the hook dispatcher."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import skillguard.cli as cli
from skillguard.install import SESSION_START_COMMAND

runner = CliRunner()


def test_install_hook_writes_session_start_entry(tmp_path: Path, monkeypatch) -> None:
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(cli, "claude_settings_path", lambda: settings)

    result = runner.invoke(cli.app, ["install-hook"])

    assert result.exit_code == 0
    data = json.loads(settings.read_text(encoding="utf-8"))
    commands = [
        h["command"] for group in data["hooks"]["SessionStart"] for h in group["hooks"]
    ]
    assert SESSION_START_COMMAND in commands


def test_hook_session_start_emits_valid_json(tmp_path: Path, monkeypatch) -> None:
    # No skills dir present -> the hook runs, quarantines nothing, and prints a payload.
    monkeypatch.setattr(cli.session_start, "default_skills_dirs", lambda: [tmp_path / "none"])
    monkeypatch.setattr(cli.session_start, "store_root", lambda: tmp_path / "sg")
    monkeypatch.setattr(cli.session_start, "quarantine_root", lambda: tmp_path / "sg" / "q")

    result = runner.invoke(cli.app, ["hook", "session-start"], input="{}")

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["hookSpecificOutput"]["hookEventName"] == "SessionStart"
