"""The Allowlist — persisted developer approvals keyed by Canonical Bundle Hash.

An approval lets an otherwise-gated Skill through, and it is keyed by the Skill's
**Canonical Bundle Hash** so it applies to that exact content only: if the Skill's content
later changes, its hash changes, the approval no longer matches, and the Skill is
re-evaluated (CONTEXT.md: Allowlist). This is the local memory of "the developer already
blessed this Skill-version" — the seed of what the Control Plane holds centrally as Policy.

Stored as a JSON set of hashes under the SkillGuard state root, alongside the Verdict Store
and the quarantine holding area but owning only the approvals.
"""

from __future__ import annotations

import json
from pathlib import Path

_ALLOWLIST_FILE = "allowlist.json"


class Allowlist:
    """A JSON-backed set of approved Canonical Bundle Hashes under ``root``."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._path = self._root / _ALLOWLIST_FILE

    def _load(self) -> list[str]:
        if not self._path.is_file():
            return []
        data: list[str] = json.loads(self._path.read_text(encoding="utf-8"))
        return data

    def _save(self, hashes: list[str]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(sorted(hashes), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def allow(self, bundle_hash: str) -> None:
        """Record ``bundle_hash`` as approved (idempotent)."""
        hashes = self._load()
        if bundle_hash not in hashes:
            hashes.append(bundle_hash)
            self._save(hashes)

    def contains(self, bundle_hash: str) -> bool:
        """Return whether ``bundle_hash`` has been approved."""
        return bundle_hash in self._load()

    def list(self) -> list[str]:
        """Return every approved hash (for ``skillguard status``)."""
        return sorted(self._load())
