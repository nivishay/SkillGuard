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


# Suffixes of files the agent may run as executable code (as opposed to reading as prose).
_SCRIPT_SUFFIXES = (
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".cjs",
    ".mjs",
    ".rb",
    ".pl",
    ".ps1",
)


def _is_script_file(path: str) -> bool:
    """Malicious Bundled Code lives in the executable scripts an agent runs, not in the
    natural-language instructions (Prompt Injection owns those)."""
    return path.lower().endswith(_SCRIPT_SUFFIXES)


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


# (regex, explanation) pairs for Malicious Bundled Code: dangerous constructs in scripts an
# agent runs — pipe-to-shell installers, reverse shells, and destructive/disk-wipe commands.
_MALICIOUS_BUNDLED_CODE_SIGNALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh)\b",
            re.I,
        ),
        "pipe-to-shell installer that executes downloaded code without review",
    ),
    (
        re.compile(r"/dev/tcp/", re.I),
        "reverse shell via a /dev/tcp/ network redirection",
    ),
    (
        re.compile(r"\bn(?:c|cat)\b[^\n]*\s-e\b", re.I),
        "reverse shell spawned by netcat's -e execute flag",
    ),
    (
        re.compile(r"os\.dup2\s*\(|\bsocket\s*,\s*subprocess\s*,\s*os\b", re.I),
        "python reverse-shell one-liner wiring a socket to a shell",
    ),
    (
        re.compile(r"\bSocket\b[^\n]*\bexec\s*\(\s*[\"']/bin/(?:ba)?sh", re.I),
        "perl reverse-shell one-liner wiring a socket to a shell",
    ),
    (
        re.compile(
            r"\brm\s+(?:-\w+\s+)*-\w*(?:rf|fr)\w*\s+(?:/(?:\s|$|\*)|~|\$HOME)",
            re.I,
        ),
        "destructive recursive delete targeting the filesystem root or home",
    ),
    (
        re.compile(r"\bmkfs(?:\.\w+)?\b[^\n]*\s/dev/", re.I),
        "disk-wipe that reformats a block device",
    ),
    (
        re.compile(r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|vd|disk)", re.I),
        "disk-wipe writing raw bytes over a block device",
    ),
    (
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:"),
        "fork bomb that exhausts process resources",
    ),
)


def _detect_malicious_bundled_code(skill: Skill) -> Iterator[Finding]:
    for path, lineno, line in scan_lines(skill):
        if not _is_script_file(path):
            continue
        for pattern, explanation in _MALICIOUS_BUNDLED_CODE_SIGNALS:
            if pattern.search(line):
                yield _make_finding(
                    ThreatVector.MALICIOUS_BUNDLED_CODE, explanation, path, lineno
                )


def static_pass(skill: Skill) -> tuple[Finding, ...]:
    """Return all deterministic findings for ``skill``.

    Pure: depends only on ``skill``. Each Threat Vector contributes its own detector.
    """
    findings: list[Finding] = []
    findings.extend(_detect_prompt_injection(skill))
    findings.extend(_detect_malicious_bundled_code(skill))
    return tuple(findings)
