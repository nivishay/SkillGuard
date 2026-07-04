"""Shared test helpers: a stub LLM port and a Skill builder.

The stub keeps the deterministic suite free of network calls — the whole engine is
exercised through ``analyze`` with the LLM port injected.
"""

from __future__ import annotations

from skillguard.engine.llm.port import LLMJudgment
from skillguard.models import Finding, Skill, SkillFile, Tier


class StubJudge:
    """A canned :class:`~skillguard.engine.llm.port.LLMJudge` for tests."""

    def __init__(
        self,
        tier: Tier = Tier.CLEAN,
        findings: tuple[Finding, ...] = (),
        explanation: str = "",
    ) -> None:
        self.tier = tier
        self.findings = findings
        self.explanation = explanation
        self.calls: list[tuple[Skill, tuple[Finding, ...]]] = []

    def judge(self, skill: Skill, static_findings: tuple[Finding, ...]) -> LLMJudgment:
        self.calls.append((skill, static_findings))
        return LLMJudgment(tier=self.tier, findings=self.findings, explanation=self.explanation)


def make_skill(files: dict[str, str] | None = None, *, root: str = "skill") -> Skill:
    """Build a :class:`Skill` from a ``{relative_path: text}`` mapping.

    Defaults to a single benign ``SKILL.md`` so tests that only care about one file can
    pass just that one.
    """
    files = files if files is not None else {"SKILL.md": "# skill\n"}
    skill_files = tuple(
        SkillFile(path=path, content=text.encode("utf-8"))
        for path, text in sorted(files.items())
    )
    return Skill(root=root, files=skill_files)
