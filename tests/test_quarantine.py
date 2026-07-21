"""Quarantine tests: move a Malicious Skill off disk, reversibly, never deleting.

Quarantine is the default enforcement action on Malicious (CONTEXT.md): the Skill's folder
is *moved* out of the scanned directory into a holding area so the agent never loads it,
and it is always restorable — moved, never deleted. These tests work on a temp filesystem.
"""

from __future__ import annotations

from pathlib import Path

from conftest import write_skill
from skillguard.quarantine import Quarantine, QuarantineError


def test_quarantine_moves_folder_out_of_skills_dir(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "evil", {"SKILL.md": "# evil\n", "run.sh": "rm -rf /\n"})
    q = Quarantine(tmp_path / "quarantine")

    entry = q.quarantine(skill_dir, bundle_hash="abc123")

    assert not skill_dir.exists()  # gone from the scanned directory
    assert entry.quarantined_path.exists()
    assert (entry.quarantined_path / "SKILL.md").read_text() == "# evil\n"
    assert (entry.quarantined_path / "run.sh").read_text() == "rm -rf /\n"


def test_quarantine_preserves_content_exactly(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "evil", {"SKILL.md": "# evil\npayload\n"})
    original_bytes = (skill_dir / "SKILL.md").read_bytes()  # verbatim on-disk bytes
    q = Quarantine(tmp_path / "quarantine")

    entry = q.quarantine(skill_dir, bundle_hash="abc123")

    # Quarantine is a move, not a normalization: bytes survive untouched.
    assert (entry.quarantined_path / "SKILL.md").read_bytes() == original_bytes


def test_restore_moves_folder_back_to_original_location(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "evil", {"SKILL.md": "# evil\n"})
    q = Quarantine(tmp_path / "quarantine")
    q.quarantine(skill_dir, bundle_hash="abc123")

    restored = q.restore("evil")

    assert restored == skill_dir
    assert skill_dir.exists()
    assert (skill_dir / "SKILL.md").read_text() == "# evil\n"


def test_restore_recreates_missing_parent(tmp_path: Path) -> None:
    # The original skills directory may have been removed; restore should not fail.
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "evil", {"SKILL.md": "# evil\n"})
    q = Quarantine(tmp_path / "quarantine")
    q.quarantine(skill_dir, bundle_hash="abc123")

    import shutil

    shutil.rmtree(skills)
    restored = q.restore("evil")
    assert restored.exists()


def test_list_reports_quarantined_entries_with_hash(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    q = Quarantine(tmp_path / "quarantine")
    q.quarantine(write_skill(skills / "a", {"SKILL.md": "# a\n"}), bundle_hash="hash-a")
    q.quarantine(write_skill(skills / "b", {"SKILL.md": "# b\n"}), bundle_hash="hash-b")

    entries = {e.name: e for e in q.list()}

    assert set(entries) == {"a", "b"}
    assert entries["a"].bundle_hash == "hash-a"
    assert Path(entries["a"].original_path).name == "a"


def test_restore_unknown_name_raises(tmp_path: Path) -> None:
    q = Quarantine(tmp_path / "quarantine")
    try:
        q.restore("nope")
    except QuarantineError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected QuarantineError for an unknown quarantine name")


def test_quarantine_survives_a_fresh_instance(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "evil", {"SKILL.md": "# evil\n"})
    Quarantine(tmp_path / "quarantine").quarantine(skill_dir, bundle_hash="abc123")

    # A new Quarantine over the same root can still restore (manifest persisted).
    restored = Quarantine(tmp_path / "quarantine").restore("evil")
    assert restored == skill_dir
