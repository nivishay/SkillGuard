"""Skill Loader tests: normalization and clear errors on non-Skills."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.loader import SkillLoadError, load_skill

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _write(root: Path, rel: str, data: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_loads_benign_fixture() -> None:
    skill = load_skill(FIXTURES / "benign")
    paths = [f.path for f in skill.files]
    assert paths == ["SKILL.md"]


def test_normalizes_crlf_to_lf(tmp_path: Path) -> None:
    _write(tmp_path, "SKILL.md", b"# Title\r\nline two\r\n")
    skill = load_skill(tmp_path)
    assert skill.files[0].content == b"# Title\nline two\n"


def test_excludes_git_and_os_junk(tmp_path: Path) -> None:
    _write(tmp_path, "SKILL.md", b"# ok\n")
    _write(tmp_path, ".git/config", b"[core]\n")
    _write(tmp_path, ".DS_Store", b"junk")
    _write(tmp_path, "notes.md~", b"backup")
    skill = load_skill(tmp_path)
    assert [f.path for f in skill.files] == ["SKILL.md"]


def test_files_are_sorted(tmp_path: Path) -> None:
    _write(tmp_path, "SKILL.md", b"# ok\n")
    _write(tmp_path, "scripts/b.sh", b"echo b\n")
    _write(tmp_path, "scripts/a.sh", b"echo a\n")
    skill = load_skill(tmp_path)
    assert [f.path for f in skill.files] == ["SKILL.md", "scripts/a.sh", "scripts/b.sh"]


def test_missing_path_raises_clear_error(tmp_path: Path) -> None:
    with pytest.raises(SkillLoadError, match="does not exist"):
        load_skill(tmp_path / "nope")


def test_folder_without_skill_md_is_not_a_skill(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", b"# not a skill\n")
    with pytest.raises(SkillLoadError, match="not a Skill"):
        load_skill(tmp_path)
