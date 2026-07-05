"""Local Verdict Store — a cache of Verdicts keyed by Canonical Bundle Hash.

Lives under ``~/.claude/skillguard/`` and holds one record per unique Skill content:
``{tier, findings, engine_version, scanned_at}``. It is treated as a *cache of a
would-be-shared verdict DB, never the source of truth* (ADR 0001): every record carries the
``engine_version`` that produced it, so a smarter future engine can recognise and re-scan
stale entries. JSON to start; SQLite when it earns it.

The Allowlist (persisted developer approvals keyed by the same hash) layers onto this store
in a later slice; this module owns the Verdict cache only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillguard.models import Finding, Location, ThreatVector, Tier, Verdict

_VERDICTS_FILE = "verdicts.json"


@dataclass(frozen=True)
class VerdictRecord:
    """A cached Verdict plus the provenance a cache needs: which engine judged it, when."""

    tier: Tier
    findings: tuple[Finding, ...]
    engine_version: str
    scanned_at: str


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "vector": finding.vector.value,
        "explanation": finding.explanation,
        "file": finding.location.file,
        "line": finding.location.line,
    }


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    return Finding(
        vector=ThreatVector(data["vector"]),
        explanation=str(data["explanation"]),
        location=Location(file=str(data["file"]), line=data["line"]),
    )


class VerdictStore:
    """A JSON-backed Verdict cache under ``root`` (``~/.claude/skillguard/`` in production)."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._path = self._root / _VERDICTS_FILE

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        data: dict[str, Any] = json.loads(self._path.read_text(encoding="utf-8"))
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def get(self, bundle_hash: str) -> VerdictRecord | None:
        """Return the cached record for ``bundle_hash``, or ``None`` on a miss."""
        raw = self._load().get(bundle_hash)
        if raw is None:
            return None
        findings = tuple(_finding_from_dict(f) for f in raw.get("findings", []))
        return VerdictRecord(
            tier=Tier(raw["tier"]),
            findings=findings,
            engine_version=str(raw["engine_version"]),
            scanned_at=str(raw["scanned_at"]),
        )

    def put(
        self, bundle_hash: str, verdict: Verdict, *, engine_version: str
    ) -> VerdictRecord:
        """Cache ``verdict`` for ``bundle_hash`` and return the stored record."""
        record = VerdictRecord(
            tier=verdict.tier,
            findings=verdict.findings,
            engine_version=engine_version,
            scanned_at=datetime.now(UTC).isoformat(),
        )
        data = self._load()
        data[bundle_hash] = {
            "tier": int(record.tier),
            "findings": [_finding_to_dict(f) for f in record.findings],
            "engine_version": record.engine_version,
            "scanned_at": record.scanned_at,
        }
        self._save(data)
        return record
