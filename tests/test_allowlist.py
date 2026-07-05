"""Allowlist tests: persisted developer approvals keyed by Canonical Bundle Hash.

An approval is by hash, so it applies to that exact content only — if the Skill's content
changes, its hash changes and the approval no longer matches (CONTEXT.md: Allowlist). These
tests work on a temp filesystem.
"""

from __future__ import annotations

from pathlib import Path

from skillguard.allowlist import Allowlist


def test_allowed_hash_is_contained(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "sg")

    allowlist.allow("hash-abc")

    assert allowlist.contains("hash-abc")


def test_unknown_hash_is_not_contained(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "sg")
    assert not allowlist.contains("never-added")


def test_approval_survives_a_fresh_instance(tmp_path: Path) -> None:
    Allowlist(tmp_path / "sg").allow("hash-abc")

    # A new Allowlist over the same root still sees the approval (persisted to disk).
    assert Allowlist(tmp_path / "sg").contains("hash-abc")
