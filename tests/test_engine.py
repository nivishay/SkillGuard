"""Detection Engine tests, exercised through the ``analyze`` seam with a stubbed port."""

from __future__ import annotations

from conftest import StubJudge, make_skill
from skillguard.engine import DetectionEngine
from skillguard.models import Finding, Location, ThreatVector, Tier, Verdict


def test_benign_skill_is_clean() -> None:
    engine = DetectionEngine(judge=StubJudge(tier=Tier.CLEAN))
    verdict = engine.analyze(make_skill({"SKILL.md": "# Formatter\n"}))
    assert verdict == Verdict(tier=Tier.CLEAN, findings=())


def test_llm_findings_flow_into_the_verdict() -> None:
    finding = Finding(
        vector=ThreatVector.PROMPT_INJECTION,
        explanation="asks the agent to read ~/.ssh",
        location=Location(file="SKILL.md", line=3),
    )
    engine = DetectionEngine(judge=StubJudge(tier=Tier.MALICIOUS, findings=(finding,)))
    verdict = engine.analyze(make_skill({"SKILL.md": "# x\n"}))
    assert verdict.tier is Tier.MALICIOUS
    assert finding in verdict.findings


def test_the_port_receives_the_skill() -> None:
    judge = StubJudge()
    skill = make_skill({"SKILL.md": "# x\n"})
    DetectionEngine(judge=judge).analyze(skill)
    assert judge.calls and judge.calls[0][0] is skill
