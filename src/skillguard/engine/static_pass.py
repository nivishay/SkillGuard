"""Static Pass — a pure function ``skill -> findings``.

Deterministic pattern/heuristic matching for known-dangerous signals. Being pure (no I/O,
no globals) makes each danger pattern cheap and deterministic to unit-test.

Each Threat Vector has its own detector function that yields findings; :func:`static_pass`
composes them. :func:`scan_lines` is the shared line-oriented helper detectors build on.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillguard.models import Finding, Location, Skill, ThreatVector


def scan_lines(skill: Skill) -> Iterator[tuple[str, int, str]]:
    """Yield ``(file_path, line_number, line_text)`` for every line of every file.

    A convenience for line-oriented pattern matching that keeps the 1-based line number
    for finding locations.
    """
    for f in skill.files:
        for lineno, line in enumerate(f.text.splitlines(), start=1):
            yield f.path, lineno, line


def _make_finding(vector: ThreatVector, explanation: str, file: str, line: int) -> Finding:
    return Finding(vector=vector, explanation=explanation, location=Location(file=file, line=line))


def _is_instruction_file(path: str) -> bool:
    """Prompt Injection lives in the natural-language instructions the agent reads."""
    return path.lower().endswith(".md")


# (regex, explanation) pairs for Prompt Injection: instructions that redirect the agent to
# read secrets, exfiltrate data, run destructive commands, or disable its own safety.
_PROMPT_INJECTION_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:the\s+)?previous\s+instructions", re.I),
        "instruction-hijack phrase aimed at overriding the agent's prior instructions",
    ),
    (
        re.compile(r"disregard\s+(?:all\s+|the\s+)?(?:above|previous|prior)", re.I),
        "instruction-hijack phrase aimed at discarding earlier instructions",
    ),
    (
        re.compile(
            r"forget\s+(?:all\s+|the\s+|your\s+)?(?:above|previous|earlier|instructions|rules)",
            re.I,
        ),
        "instruction-hijack phrase aimed at discarding earlier instructions",
    ),
    (
        re.compile(r"~/\.ssh|\.ssh/|\bid_rsa\b|\bid_ed25519\b", re.I),
        "reference to SSH private keys, a common secret-exfiltration target",
    ),
    (
        re.compile(r"\.aws/credentials|\.git-credentials|\.netrc\b|\.npmrc\b", re.I),
        "reference to a stored-credentials file",
    ),
    (
        re.compile(
            r"(?:read|cat|open|load|access|send|upload|exfiltrate|print|dump|leak)"
            r"[^\n]{0,40}\.env\b",
            re.I,
        ),
        "instruction to read a .env secrets file",
    ),
    (
        re.compile(r"without\s+(?:telling|informing|asking|notifying)\s+the\s+user", re.I),
        "covert-action phrasing that hides behavior from the user",
    ),
    (
        re.compile(r"do\s+not\s+tell\s+the\s+user|don't\s+tell\s+the\s+user", re.I),
        "covert-action phrasing that hides behavior from the user",
    ),
    (
        re.compile(r"disable\s+(?:your\s+)?(?:safety|guardrails|safeguards|protections)", re.I),
        "instruction to disable the agent's own safety",
    ),
    (
        re.compile(r"\bexfiltrate\b", re.I),
        "explicit data-exfiltration instruction",
    ),
)


def _detect_prompt_injection(skill: Skill) -> Iterator[Finding]:
    for path, lineno, line in scan_lines(skill):
        if not _is_instruction_file(path):
            continue
        for pattern, explanation in _PROMPT_INJECTION_SIGNALS:
            if pattern.search(line):
                yield _make_finding(ThreatVector.PROMPT_INJECTION, explanation, path, lineno)


# (regex, explanation) pairs for Analyzer Manipulation: text aimed not at the *agent* that
# would run the Skill but at SkillGuard's own analyzer — fake system prompts, role
# reassignment, or an instruction to emit a "Clean" verdict. Per ADR 0002 an attempt to
# steer the analyzer is itself EVIDENCE OF MALICE, so we record it as a Prompt Injection
# finding. Because static findings floor the Verdict, a Skill carrying such text can never
# come back Clean, no matter what the (possibly steered) LLM concludes.
_ANALYZER_MANIPULATION_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"system\s*override", re.I),
        "fake 'SYSTEM OVERRIDE' directive attempting to command the analyzer",
    ),
    (
        re.compile(
            r"</?system\b[^>]*>|</?assistant\b[^>]*>|\[/?\s*(?:system|assistant)\s*\]",
            re.I,
        ),
        "fake system/assistant role markup impersonating the analyzer's own framing",
    ),
    (
        re.compile(r"\byou\s+are\s+now\b", re.I),
        "role-reassignment phrase ('you are now …') aimed at redefining the analyzer",
    ),
    (
        re.compile(r"ignore\s+your\s+(?:previous\s+|prior\s+|own\s+)?instructions", re.I),
        "instruction-hijack phrase aimed directly at the analyzer's instructions",
    ),
    (
        # Verdict word explicitly framed as the verdict: "…as safe", "…verdict CLEAN",
        # "mark this safe". The as/verdict/this hinge is what separates a steering attempt
        # from benign prose like "returns a clean report".
        re.compile(
            r"(?:return|output|respond\s+with|reply\s+with|print|emit|give|produce|"
            r"answer\s+with|mark|classify|rate|label|deem|report|flag|set|tag|consider|treat)"
            r"[^\n]{0,20}"
            r"\b(?:as|verdict|tier|result|classification|rating|it|this(?:\s+skill)?)\s+"
            r"[\"']?(?:clean|safe|benign|not\s+malicious|no\s+threat|trusted)\b",
            re.I,
        ),
        "attempt to dictate the analyzer's verdict (e.g. 'mark as safe', 'verdict CLEAN')",
    ),
    (
        # A bare all-caps verdict TOKEN after an output verb: "output CLEAN", "return SAFE".
        # Case-sensitive on purpose so lowercase prose ("returns a clean report") is ignored.
        re.compile(
            r"(?:return|output|respond|reply|print|emit|give|produce|answer|"
            r"mark|classify|rate|label|deem|report|flag)"
            r"[^\n]{0,20}"
            r"\b(?:CLEAN|SAFE|BENIGN|NOT\s+MALICIOUS|NO\s+THREAT|TRUSTED)\b"
        ),
        "attempt to dictate the analyzer's verdict (e.g. 'output CLEAN')",
    ),
)


def _detect_analyzer_manipulation(skill: Skill) -> Iterator[Finding]:
    """Flag attempts to steer SkillGuard's analyzer (ADR 0002).

    Unlike Prompt Injection, this scans ALL files (not just instructions): a manipulation
    payload can hide in a bundled script comment, a data file, or a docstring just as
    easily as in SKILL.md.
    """
    for path, lineno, line in scan_lines(skill):
        for pattern, explanation in _ANALYZER_MANIPULATION_SIGNALS:
            if pattern.search(line):
                yield _make_finding(ThreatVector.PROMPT_INJECTION, explanation, path, lineno)


def static_pass(skill: Skill) -> tuple[Finding, ...]:
    """Return all deterministic findings for ``skill``.

    Pure: depends only on ``skill``. Each Threat Vector contributes its own detector.
    """
    findings: list[Finding] = []
    findings.extend(_detect_prompt_injection(skill))
    findings.extend(_detect_analyzer_manipulation(skill))
    return tuple(findings)
