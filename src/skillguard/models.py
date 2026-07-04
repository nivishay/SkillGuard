"""Domain model for SkillGuard.

These types are the shared vocabulary every layer speaks. They are deliberately
dependency-free (stdlib only) so the Static Pass can stay a pure function and the
model can be constructed cheaply in tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Tier(IntEnum):
    """A Verdict tier. Ordered (Clean < Suspicious < Malicious) so severities can be
    combined with ``max``. It is a tier, not a numeric score — the integer values exist
    only to express that ordering and are never shown to the user."""

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2

    def __str__(self) -> str:
        return self.name.capitalize()


class ThreatVector(StrEnum):
    """A named category of harmful behavior. The v1 vectors."""

    PROMPT_INJECTION = "Prompt Injection"
    MALICIOUS_BUNDLED_CODE = "Malicious Bundled Code"
    SECOND_STAGE_OBFUSCATION = "Second-Stage / Obfuscation"


@dataclass(frozen=True)
class Location:
    """Where in the Skill a finding was triggered."""

    file: str
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}" if self.line is not None else self.file


@dataclass(frozen=True)
class Finding:
    """A single piece of evidence: which Threat Vector, why, and where."""

    vector: ThreatVector
    explanation: str
    location: Location


@dataclass(frozen=True)
class SkillFile:
    """A single declared file in a Skill: relative POSIX path + normalized bytes."""

    path: str
    content: bytes

    @property
    def text(self) -> str:
        """Best-effort decoded text for pattern matching and display."""
        return self.content.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Skill:
    """A normalized, in-memory Skill ready for analysis."""

    root: str
    files: tuple[SkillFile, ...]


@dataclass(frozen=True)
class Verdict:
    """The result of analyzing a Skill: a tier plus supporting findings."""

    tier: Tier
    findings: tuple[Finding, ...] = ()
