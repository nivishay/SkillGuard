"""Where SkillGuard keeps its state and where it looks for Skills.

All of it hangs off ``~/.claude`` (Claude Code's home), overridable via ``SKILLGUARD_HOME``
so tests and power users can redirect it. These are the production defaults; the gate core
itself takes explicit paths and never reaches for these, which is what keeps it testable.
"""

from __future__ import annotations

import os
from pathlib import Path


def claude_home() -> Path:
    return Path.home() / ".claude"


def skillguard_home() -> Path:
    """The SkillGuard state root: the cache, the Allowlist, the quarantine holding area."""
    override = os.environ.get("SKILLGUARD_HOME")
    return Path(override) if override else claude_home() / "skillguard"


def store_root() -> Path:
    return skillguard_home()


def quarantine_root() -> Path:
    return skillguard_home() / "quarantine"


def default_skills_dirs(cwd: Path | str | None = None) -> list[Path]:
    """The skills directories the gate scans: the user-level one and the project-level one.

    Claude Code loads Skills from ``~/.claude/skills`` and from a project's ``.claude/skills``
    — both are enforcement surfaces.
    """
    cwd = Path(cwd) if cwd is not None else Path.cwd()
    dirs = [claude_home() / "skills", cwd / ".claude" / "skills"]
    seen: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.append(d)
    return seen
