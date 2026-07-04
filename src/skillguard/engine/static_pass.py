"""Static Pass — a pure function ``skill -> findings``.

Deterministic pattern/heuristic matching for known-dangerous signals. Being pure (no I/O,
no globals) makes each danger pattern cheap and deterministic to unit-test.

The pattern tables are intentionally empty in the walking skeleton; the per-Threat-Vector
slices fill them in. :func:`static_pass` and the :func:`scan_lines` helper are the stable
surface those slices build on.
"""

from __future__ import annotations

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


def static_pass(skill: Skill) -> tuple[Finding, ...]:
    """Return all deterministic findings for ``skill``.

    Pure: depends only on ``skill``. The per-vector slices extend this by appending to
    ``findings`` from their own detector functions.
    """
    findings: list[Finding] = []
    # Per-vector detectors are added by later slices, e.g.:
    #   findings.extend(_detect_prompt_injection(skill))
    return tuple(findings)
