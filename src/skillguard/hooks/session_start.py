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

from skillguard.allowlist import Allowlist
from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge
from skillguard.gate.core import AllowlistStore, EnginePort, GateDecision, Posture
from skillguard.gate.enforce import Confirm, Enforcement, scan_and_quarantine
from skillguard.paths import default_skills_dirs, quarantine_root, store_root
from skillguard.quarantine import Quarantine
from skillguard.store import VerdictStore


@dataclass(frozen=True)
class SessionStartResult:
    """What :func:`run` produced: the enforcement outcome plus the hook JSON to emit."""

    enforcement: Enforcement
    hook_output: dict[str, Any]


def _finding_lines(decision: GateDecision, lines: list[str]) -> None:
    for finding in decision.findings:
        lines.append(f"    [{finding.vector}] {finding.location}: {finding.explanation}")


def _context_lines(enforcement: Enforcement) -> str:
    intro = "SkillGuard scanned your Skills at session start."
    if not enforcement.quarantined and not enforcement.held:
        return intro + " No Malicious or unresolved Suspicious Skills found."

    lines = [intro]
    if enforcement.quarantined:
        lines.append(
            f"Quarantined {len(enforcement.quarantined)} Malicious Skill(s) before load:"
        )
        for entry, decision in enforcement.quarantined:
            lines.append(f"- {entry.name} (moved to {entry.quarantined_path})")
            _finding_lines(decision, lines)
    if enforcement.held:
        lines.append(
            f"Held {len(enforcement.held)} Suspicious Skill(s) pending your review "
            "(approve with 'skillguard allow', then 'skillguard restore'):"
        )
        for entry, decision in enforcement.held:
            lines.append(f"- {entry.name} (held at {entry.quarantined_path})")
            _finding_lines(decision, lines)
    return "\n".join(lines)


def _build_output(enforcement: Enforcement) -> dict[str, Any]:
    hook_specific: dict[str, Any] = {
        "hookEventName": "SessionStart",
        "additionalContext": _context_lines(enforcement),
    }
    # Force a reload only when we actually changed the skills directory (moved something out).
    if enforcement.quarantined or enforcement.held:
        hook_specific["reloadSkills"] = True
    return {"hookSpecificOutput": hook_specific}


def run(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    posture: Posture | None = None,
    allowlist: AllowlistStore | None = None,
    interactive: bool = False,
    confirm: Confirm | None = None,
) -> SessionStartResult:
    """Scan ``skills_dirs``, quarantine Malicious, resolve Suspicious, and build the payload.

    ``interactive``/``confirm`` are injected so the same hook code covers both branches of the
    Suspicious posture: with a human present a warn-and-confirm allow lets a Skill load (and
    persists its hash to the Allowlist); with no human present a Suspicious Skill is held off
    disk (deny-and-hold), never silently allowed and never blocking on a prompt.
    """
    enforcement = scan_and_quarantine(
        skills_dirs,
        engine=engine,
        store=store,
        quarantine=quarantine,
        posture=posture,
        allowlist=allowlist,
        interactive=interactive,
        confirm=confirm if confirm is not None else (lambda _decision: False),
    )
    return SessionStartResult(enforcement=enforcement, hook_output=_build_output(enforcement))


def _prompt_confirm(decision: GateDecision) -> bool:  # pragma: no cover - interactive I/O
    """Warn-and-confirm for one Suspicious Skill: show its Findings, read a yes/no.

    The one place a prompt is allowed — testable code injects a stub ``Confirm`` instead.
    """
    sys.stderr.write(f"SkillGuard: Suspicious Skill at {decision.skill_path}\n")
    for finding in decision.findings:
        sys.stderr.write(f"  [{finding.vector}] {finding.location}: {finding.explanation}\n")
    sys.stderr.write("Allow this Skill to load? [y/N] ")
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


def main() -> None:
    """CLI/hook entry point: wire real paths + engine, read stdin, emit the payload."""
    # The hook receives JSON on stdin; the walking skeleton doesn't need any of its fields
    # yet, but we drain it so the pipe closes cleanly.
    with contextlib.suppress(json.JSONDecodeError, ValueError):
        json.load(sys.stdin)

    # A hook subprocess is fed its input on a pipe (not a tty): treat that as "no human" so
    # Suspicious degrades to deny-and-hold rather than hanging. A developer running it in a
    # terminal gets the interactive warn-and-confirm.
    interactive = sys.stdin.isatty()

    engine = DetectionEngine(judge=AnthropicJudge())
    result = run(
        default_skills_dirs(),
        engine=engine,
        store=VerdictStore(store_root()),
        quarantine=Quarantine(quarantine_root()),
        allowlist=Allowlist(store_root()),
        interactive=interactive,
        confirm=_prompt_confirm,
    )
    json.dump(result.hook_output, sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
