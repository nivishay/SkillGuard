"""Canonical Bundle Hash tests: a pure, order-stable identity over a Skill's files.

The hash is the cache key and the identity behind Allowlist evaporation (ADR 0001), so
its contract is: same normalized content -> same hash, any content change -> different
hash. The CRLF/LF and junk-exclusion properties come from the Loader's normalization, so
those are exercised through ``load_skill`` here.
"""

from __future__ import annotations

from pathlib import Path

from conftest import make_skill
from skillguard.hash import canonical_bundle_hash
from skillguard.loader import load_skill


def test_same_content_yields_same_hash() -> None:
    a = make_skill({"SKILL.md": "# hi\n", "run.sh": "echo hi\n"})
    b = make_skill({"SKILL.md": "# hi\n", "run.sh": "echo hi\n"})
    assert canonical_bundle_hash(a) == canonical_bundle_hash(b)


def test_hash_is_order_independent() -> None:
    # make_skill sorts, so build Skills whose file tuples differ only in order.
    from skillguard.models import Skill, SkillFile

    f1 = SkillFile(path="SKILL.md", content=b"# hi\n")
    f2 = SkillFile(path="a/run.sh", content=b"echo hi\n")
    forward = Skill(root="s", files=(f1, f2))
    reverse = Skill(root="s", files=(f2, f1))
    assert canonical_bundle_hash(forward) == canonical_bundle_hash(reverse)


def test_changed_content_yields_different_hash() -> None:
    original = make_skill({"SKILL.md": "# hi\n"})
    tampered = make_skill({"SKILL.md": "# hi\nrm -rf /\n"})
    assert canonical_bundle_hash(original) != canonical_bundle_hash(tampered)


def test_moving_content_between_files_changes_hash() -> None:
    # Same bytes, different layout must not collide (path is part of the identity).
    a = make_skill({"SKILL.md": "x\n", "b.txt": "y\n"})
    b = make_skill({"SKILL.md": "y\n", "b.txt": "x\n"})
    assert canonical_bundle_hash(a) != canonical_bundle_hash(b)


def test_crlf_and_git_junk_do_not_change_hash(tmp_path: Path) -> None:
    lf = tmp_path / "lf"
    crlf = tmp_path / "crlf"
    (lf / ".git").mkdir(parents=True)
    crlf.mkdir()

    (lf / "SKILL.md").write_bytes(b"# hi\nline two\n")
    (lf / ".git" / "config").write_bytes(b"junk\n")
    (crlf / "SKILL.md").write_bytes(b"# hi\r\nline two\r\n")

    assert canonical_bundle_hash(load_skill(lf)) == canonical_bundle_hash(load_skill(crlf))
