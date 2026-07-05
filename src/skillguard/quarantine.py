"""Quarantine — the reversible move that keeps a Malicious Skill out of the agent's reach.

On a Malicious Verdict the Endpoint Gate *moves* the Skill's folder from the scanned skills
directory into a holding area under ``~/.claude/skillguard/quarantine/`` (CONTEXT.md:
Quarantine). It is never a delete: a manifest records where each folder came from and its
Canonical Bundle Hash, so ``restore`` can put it back exactly and ``skillguard status`` can
join it to its Findings. Modeled on antivirus/EDR quarantine — always reversible, always
surfaced with its reason.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_MANIFEST_FILE = "manifest.json"


class QuarantineError(Exception):
    """Raised when a quarantine/restore cannot be carried out (e.g. unknown name)."""


@dataclass(frozen=True)
class QuarantineEntry:
    """One quarantined Skill: its name, where it now lives, where it came from, its hash."""

    name: str
    quarantined_path: Path
    original_path: Path
    bundle_hash: str
    quarantined_at: str


class Quarantine:
    """The holding area under ``root`` (``~/.claude/skillguard/quarantine/``)."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._manifest_path = self._root / _MANIFEST_FILE

    def _load(self) -> dict[str, dict[str, str]]:
        if not self._manifest_path.is_file():
            return {}
        data: dict[str, dict[str, str]] = json.loads(
            self._manifest_path.read_text(encoding="utf-8")
        )
        return data

    def _save(self, data: dict[str, dict[str, str]]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        self._manifest_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _unique_name(self, base: str, manifest: dict[str, dict[str, str]]) -> str:
        if base not in manifest and not (self._root / base).exists():
            return base
        i = 2
        while f"{base}-{i}" in manifest or (self._root / f"{base}-{i}").exists():
            i += 1
        return f"{base}-{i}"

    def _entry_from_raw(self, name: str, raw: dict[str, str]) -> QuarantineEntry:
        return QuarantineEntry(
            name=name,
            quarantined_path=self._root / name,
            original_path=Path(raw["original_path"]),
            bundle_hash=raw["bundle_hash"],
            quarantined_at=raw["quarantined_at"],
        )

    def quarantine(self, skill_dir: Path | str, *, bundle_hash: str) -> QuarantineEntry:
        """Move ``skill_dir`` into the holding area and record how to restore it."""
        skill_dir = Path(skill_dir)
        manifest = self._load()
        # Never collide: a same-named Skill from another directory (or a re-added copy of one
        # already held) gets a suffixed holding name, so a Malicious Skill is *always* moved
        # off disk rather than left in place on a clash.
        name = self._unique_name(skill_dir.name, manifest)

        self._root.mkdir(parents=True, exist_ok=True)
        dest = self._root / name
        shutil.move(str(skill_dir), str(dest))

        entry = QuarantineEntry(
            name=name,
            quarantined_path=dest,
            original_path=skill_dir,
            bundle_hash=bundle_hash,
            quarantined_at=datetime.now(UTC).isoformat(),
        )
        manifest[name] = {
            "original_path": str(entry.original_path),
            "bundle_hash": entry.bundle_hash,
            "quarantined_at": entry.quarantined_at,
        }
        self._save(manifest)
        return entry

    def restore(self, name: str) -> Path:
        """Move a quarantined Skill back to its original location and return that path."""
        manifest = self._load()
        raw = manifest.get(name)
        if raw is None:
            raise QuarantineError(f"nothing named {name!r} is quarantined")

        entry = self._entry_from_raw(name, raw)
        original = entry.original_path
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(entry.quarantined_path), str(original))

        del manifest[name]
        self._save(manifest)
        return original

    def list(self) -> list[QuarantineEntry]:
        """Return every currently-quarantined Skill (for ``skillguard status``)."""
        manifest = self._load()
        return [self._entry_from_raw(name, raw) for name, raw in sorted(manifest.items())]
