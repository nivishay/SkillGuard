"""Detection Engine — ``analyze(skill) -> Verdict``.

Runs two layers and combines them:

- the **Static Pass** (a pure function) for deterministic known-dangerous signals, and
- the **LLM Judgment** layer (behind an injectable port) for novel/disguised intent and
  the human-readable evidence.

The combine step enforces the ADR 0002 **static floor**: the LLM may raise a Verdict's
severity but may never, on its own, downgrade a Static-Pass-flagged Skill to Clean. Such a
Skill surfaces as at least Suspicious for a human. The analyzer-injection slice hardens
this further.
"""

from __future__ import annotations

from skillguard.engine.llm.port import LLMJudge
from skillguard.engine.static_pass import static_pass
from skillguard.models import Finding, Skill, Tier, Verdict


class DetectionEngine:
    """Combines the Static Pass and the injected LLM Judgment into a Verdict."""

    def __init__(self, judge: LLMJudge) -> None:
        self._judge = judge

    def analyze(self, skill: Skill) -> Verdict:
        static_findings = static_pass(skill)
        judgment = self._judge.judge(skill, static_findings)

        # Combine findings: static evidence first, then anything the LLM added.
        findings: tuple[Finding, ...] = static_findings + judgment.findings

        # Static floor: if the Static Pass flagged anything, the Verdict can never be
        # Clean, no matter what the (possibly manipulated) LLM concluded.
        floor = Tier.SUSPICIOUS if static_findings else Tier.CLEAN
        tier = max(judgment.tier, floor)

        return Verdict(tier=tier, findings=findings)
