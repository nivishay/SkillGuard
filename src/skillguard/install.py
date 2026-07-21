"""Write SkillGuard's hooks into Claude Code settings so wiring isn't a manual chore.

``install-hook`` merges our hook entries into the Claude Code settings JSON
(``~/.claude/settings.json``): it adds each entry if missing, leaves it alone if already
present (idempotent), and never disturbs the developer's other settings or hooks. The
PreToolUse backstop registers itself here too by extending :data:`HOOK_ENTRIES`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SESSION_START_COMMAND = "skillguard hook session-start"
PRE_TOOL_USE_COMMAND = "skillguard hook pre-tool-use"


@dataclass(frozen=True)
class HookEntry:
    """One hook to register: the Claude Code event, the command, and an optional tool matcher.

    ``matcher`` is ``None`` for whole-session events like ``SessionStart`` and a tool pattern
    (e.g. ``"Skill|Bash"``) for tool events like ``PreToolUse``.
    """

    event: str
    command: str
    matcher: str | None = None


# The hooks SkillGuard installs: the SessionStart pre-load barrier and the PreToolUse
# mid-session backstop (matched on the Skill and Bash tools).
HOOK_ENTRIES: tuple[HookEntry, ...] = (
    HookEntry(event="SessionStart", command=SESSION_START_COMMAND),
    HookEntry(event="PreToolUse", command=PRE_TOOL_USE_COMMAND, matcher="Skill|Bash"),
)


def _load_settings(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    data: dict[str, Any] = json.loads(text) if text else {}
    return data


def _already_registered(event_list: list[Any], command: str) -> bool:
    return any(
        h.get("command") == command
        for group in event_list
        for h in group.get("hooks", [])
    )


def _apply_entry(settings: dict[str, Any], entry: HookEntry) -> None:
    hooks: dict[str, Any] = settings.setdefault("hooks", {})
    event_list: list[Any] = hooks.setdefault(entry.event, [])
    if _already_registered(event_list, entry.command):
        return
    group: dict[str, Any] = {"hooks": [{"type": "command", "command": entry.command}]}
    if entry.matcher is not None:
        group["matcher"] = entry.matcher
    event_list.append(group)


def install_hooks(
    settings_path: Path | str, *, entries: tuple[HookEntry, ...] = HOOK_ENTRIES
) -> None:
    """Merge ``entries`` into the settings JSON at ``settings_path``, creating it if absent."""
    path = Path(settings_path)
    settings = _load_settings(path)
    for entry in entries:
        _apply_entry(settings, entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
