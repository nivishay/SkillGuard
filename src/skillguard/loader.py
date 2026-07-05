"""Skill Loader — read a folder into a normalized in-memory :class:`Skill`.

The normalization here is load-bearing: it is the same rule that will define the
Canonical Bundle Hash (see ADR 0001). Line endings are normalized to LF and VCS/OS/editor
junk is excluded, so the *same* Skill on Windows, macOS, and Linux yields the same
in-memory representation.
"""

from __future__ import annotations

from pathlib import Path

from skillguard.models import Skill, SkillFile

# Directories never considered part of a Skill.
_EXCLUDED_DIRS = frozenset(
    {".git", ".svn", ".hg", "__pycache__", ".idea", ".vscode", ".DS_Store"}
)

# Exact filenames that are OS/editor junk.
_EXCLUDED_FILES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})

# Filename suffixes that are editor junk.
_EXCLUDED_SUFFIXES = ("~", ".swp", ".swo")


class SkillLoadError(Exception):
    """Raised when a path cannot be loaded as a Skill (missing, not a directory, or not
    a Skill at all). The CLI turns this into a clear message, not a traceback."""


def _is_excluded(rel_parts: tuple[str, ...], name: str) -> bool:
    if any(part in _EXCLUDED_DIRS for part in rel_parts):
        return True
    if name in _EXCLUDED_FILES:
        return True
    return name.endswith(_EXCLUDED_SUFFIXES)


def _normalize_bytes(raw: bytes) -> bytes:
    """Normalize line endings to LF (CRLF and lone CR both become LF)."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def load_skill(folder: Path | str) -> Skill:
    """Load ``folder`` into a normalized :class:`Skill`.

    A Skill must be a directory containing a ``SKILL.md`` at its root. Files are returned
    sorted by relative POSIX path with LF-normalized bytes and junk excluded.
    """
    root = Path(folder)
    if not root.exists():
        raise SkillLoadError(f"path does not exist: {root}")
    if not root.is_dir():
        raise SkillLoadError(f"not a folder: {root}")
    if not (root / "SKILL.md").is_file():
        raise SkillLoadError(
            f"not a Skill: no SKILL.md found in {root} "
            "(a Skill is a folder containing a SKILL.md)"
        )

    files: list[SkillFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if _is_excluded(rel.parts[:-1], rel.name):
            continue
        content = _normalize_bytes(path.read_bytes())
        files.append(SkillFile(path=rel.as_posix(), content=content))

    return Skill(root=str(root), files=tuple(sorted(files, key=lambda f: f.path)))
