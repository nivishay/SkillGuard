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

from skillguard.engine.llm.port import LLMJudge, LLMJudgment
from skillguard.engine.static_pass import static_pass
from skillguard.models import Finding, Skill, Tier, Verdict


def combine_verdict(
    static_findings: tuple[Finding, ...], judgment: LLMJudgment
) -> Verdict:
    """Combine the Static Pass findings and the LLM Judgment into the final Verdict.

    This is the single source of truth for how the two layers are reconciled — used by
    :meth:`DetectionEngine.analyze` and by any tool (e.g. the flow tester) that wants to
    drive the layers itself while getting exactly the same result.

    Static floor (ADR 0002). The Static Pass reads the raw Skill and cannot be talked out
    of a match; the LLM reads that same possibly-hostile Skill and *can* be. So we let the
    LLM RAISE severity but never single-handedly LOWER a static-flagged Skill to Clean.
    Combining with ``max`` against a per-Skill floor gives:

    * no static findings  -> floor Clean  -> the LLM's tier stands (Clean/Susp/Mal), so a
      purely LLM-surfaced concern still reaches Suspicious or Malicious.
    * static findings + LLM Malicious -> Malicious (the LLM raised it).
    * static findings + LLM Clean     -> Suspicious (the floor holds; a static
      false-positive, or a Skill that tried to steer the LLM to "Clean", surfaces for a
      human review instead of being silently cleared).
    """
    # Deterministic static evidence first, then anything the LLM added.
    findings: tuple[Finding, ...] = static_findings + judgment.findings
    floor = Tier.SUSPICIOUS if static_findings else Tier.CLEAN
    tier = max(judgment.tier, floor)
    return Verdict(tier=tier, findings=findings)


class DetectionEngine:
    """Combines the Static Pass and the injected LLM Judgment into a Verdict."""

    def __init__(self, judge: LLMJudge) -> None:
        self._judge = judge

    def analyze(self, skill: Skill) -> Verdict:
        static_findings = static_pass(skill)
        judgment = self._judge.judge(skill, static_findings)
        return combine_verdict(static_findings, judgment)
