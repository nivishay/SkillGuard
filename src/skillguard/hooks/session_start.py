"""The ``SessionStart`` hook — SkillGuard's primary, pre-load barrier (ADR 0003).

``SessionStart`` fires *before* Claude loads skill/agent context, so this hook is the one
place a Prompt-Injection payload carried in a Skill's *description* can be stopped: it scans
the skills directories, quarantines any Malicious Skill's folder off disk, and returns
``reloadSkills: true`` so Claude re-reads the now-clean directory. The ``additionalContext``
tells the developer exactly what was moved and why — the Findings — so the action is never a
silent black box.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge
from skillguard.gate.core import EnginePort, Posture
from skillguard.gate.enforce import Enforcement, scan_and_quarantine
from skillguard.paths import default_skills_dirs, quarantine_root, store_root
from skillguard.quarantine import Quarantine
from skillguard.store import VerdictStore


@dataclass(frozen=True)
class SessionStartResult:
    """What :func:`run` produced: the enforcement outcome plus the hook JSON to emit."""

    enforcement: Enforcement
    hook_output: dict[str, Any]


def _context_lines(enforcement: Enforcement) -> str:
    lines = ["SkillGuard scanned your Skills at session start."]
    if not enforcement.quarantined:
        return lines[0] + " No Malicious Skills found."

    lines.append(
        f"Quarantined {len(enforcement.quarantined)} Malicious Skill(s) before load:"
    )
    for entry, decision in enforcement.quarantined:
        lines.append(f"- {entry.name} (moved to {entry.quarantined_path})")
        for finding in decision.findings:
            lines.append(f"    [{finding.vector}] {finding.location}: {finding.explanation}")
    return "\n".join(lines)


def _build_output(enforcement: Enforcement) -> dict[str, Any]:
    hook_specific: dict[str, Any] = {
        "hookEventName": "SessionStart",
        "additionalContext": _context_lines(enforcement),
    }
    # Only force a reload when we actually changed the skills directory.
    if enforcement.quarantined:
        hook_specific["reloadSkills"] = True
    return {"hookSpecificOutput": hook_specific}


def run(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    posture: Posture | None = None,
) -> SessionStartResult:
    """Scan ``skills_dirs``, quarantine Malicious Skills, and build the hook payload."""
    enforcement = scan_and_quarantine(
        skills_dirs, engine=engine, store=store, quarantine=quarantine, posture=posture
    )
    return SessionStartResult(enforcement=enforcement, hook_output=_build_output(enforcement))


def main() -> None:
    """CLI/hook entry point: wire real paths + engine, read stdin, emit the payload."""
    # The hook receives JSON on stdin; the walking skeleton doesn't need any of its fields
    # yet, but we drain it so the pipe closes cleanly.
    with contextlib.suppress(json.JSONDecodeError, ValueError):
        json.load(sys.stdin)

    engine = DetectionEngine(judge=AnthropicJudge())
    result = run(
        default_skills_dirs(),
        engine=engine,
        store=VerdictStore(store_root()),
        quarantine=Quarantine(quarantine_root()),
    )
    json.dump(result.hook_output, sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
