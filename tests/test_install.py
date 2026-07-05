"""install-hook tests: wire the gate into Claude Code settings, idempotently and safely.

``skillguard install-hook`` writes a ``SessionStart`` hook entry into the Claude Code
settings JSON so the barrier runs automatically — without a manual edit, and without
stomping on settings the developer already has.
"""

from __future__ import annotations

import json
from pathlib import Path

from skillguard.install import HOOK_ENTRIES, SESSION_START_COMMAND, install_hooks


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_writes_session_start_hook_into_empty_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"

    install_hooks(settings, entries=HOOK_ENTRIES)

    data = _read(settings)
    commands = [
        h["command"]
        for group in data["hooks"]["SessionStart"]
        for h in group["hooks"]
    ]
    assert SESSION_START_COMMAND in commands


def test_is_idempotent(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    install_hooks(settings, entries=HOOK_ENTRIES)
    install_hooks(settings, entries=HOOK_ENTRIES)

    data = _read(settings)
    session_groups = data["hooks"]["SessionStart"]
    matching = [
        h
        for group in session_groups
        for h in group["hooks"]
        if h["command"] == SESSION_START_COMMAND
    ]
    assert len(matching) == 1  # not duplicated on a second install


def test_preserves_existing_unrelated_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "model": "claude-sonnet-5",
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "echo hi"}]}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    install_hooks(settings, entries=HOOK_ENTRIES)

    data = _read(settings)
    assert data["model"] == "claude-sonnet-5"  # untouched
    commands = [
        h["command"]
        for group in data["hooks"]["SessionStart"]
        for h in group["hooks"]
    ]
    assert "echo hi" in commands  # pre-existing hook preserved
    assert SESSION_START_COMMAND in commands  # ours added alongside
