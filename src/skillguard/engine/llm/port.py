"""The injectable LLM port.

The Detection Engine reaches the model only through :class:`LLMJudge`. This lets the
deterministic test suite inject a stub (no network, fully controlled output) while the
CLI wires in the real Claude-backed implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from skillguard.models import Finding, Skill, Tier


@dataclass(frozen=True)
class LLMJudgment:
    """What the LLM Judgment layer returns for a Skill.

    ``tier`` is the severity the model concluded; ``findings`` are any threat findings it
    identified (each naming a Threat Vector and a location); ``explanation`` is the
    human-readable summary shown to the developer.
    """

    tier: Tier
    findings: tuple[Finding, ...] = ()
    explanation: str = ""


class LLMJudge(Protocol):
    """Port for the semantic analysis layer.

    Implementations receive the Skill and the Static Pass findings and return an
    :class:`LLMJudgment`. Skill content must be treated as untrusted *data*, never
    instructions (see ADR 0002).
    """

    def judge(self, skill: Skill, static_findings: tuple[Finding, ...]) -> LLMJudgment: ...
