"""The ``PreToolUse`` hook — SkillGuard's mid-session backstop (ADR 0003).

The ``SessionStart`` barrier only catches Skills present at boot. A Skill that arrives
*during* a live session — one the agent downloads or generates for itself — would otherwise
be a blind spot. ``PreToolUse`` fires just before a Skill/Bash tool call runs, so this hook
runs the *same* gate core (hash -> store lookup -> scan-on-miss -> decide) at that second
choke point. Unlike the barrier it moves no files: on a Skill that is *not cleared* it emits
a hard ``deny`` and hands Claude the Findings as the reason it sees.

This catches body-based Prompt Injection (a Skill body loads only on invocation) and
Malicious Bundled Code (which runs via Bash). It adds no new enforcement decision beyond
wiring the gate to a second hook point; the "hold on unknown, never a false Clean" rule is
inherited straight from the gate core.
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
from skillguard.gate import Action, GateDecision, evaluate
from skillguard.gate.core import AllowlistPort, EnginePort, Posture
from skillguard.models import Tier
from skillguard.paths import default_skills_dirs, store_root
from skillguard.store import VerdictStore

# The PreToolUse posture: this hook *denies* rather than quarantining, and it runs
# non-interactively, so anything short of a clear Clean is refused (ADR 0003: Suspicious
# degrades to deny-and-hold when no human is present). CLEAN allows; everything the gate
# does not clear (Malicious, Suspicious, and — via HOLD — unknown) blocks the call.
PRE_TOOL_USE_POSTURE: Posture = {
    Tier.CLEAN: Action.ALLOW,
    Tier.SUSPICIOUS: Action.DENY,
    Tier.MALICIOUS: Action.DENY,
}


@dataclass(frozen=True)
class PreToolUseResult:
    """What :func:`run` produced: every decision, whether the call is blocked, and the JSON."""

    decisions: list[GateDecision]
    blocked: bool
    hook_output: dict[str, Any]


def _is_blocked(decision: GateDecision) -> bool:
    # Fail toward blocking: only an explicit ALLOW lets the tool call proceed. A HOLD
    # (unknown Verdict) is not a clear, so it blocks too.
    return decision.action is not Action.ALLOW


def _deny_reason(decisions: Sequence[GateDecision]) -> str:
    lines = ["SkillGuard blocked this tool call — a Skill in your session is not cleared."]
    for decision in decisions:
        name = Path(decision.skill_path).name
        if decision.findings:
            for finding in decision.findings:
                lines.append(
                    f"- {name}: [{finding.vector}] {finding.location}: {finding.explanation}"
                )
        else:
            lines.append(f"- {name}: Verdict unknown — held, not cleared.")
    return "\n".join(lines)


def _build_output(blocked: Sequence[GateDecision]) -> dict[str, Any]:
    # Nothing blocked: stay out of the way (no permissionDecision) so other hooks and the
    # developer's own settings still decide. Only actively speak up to deny.
    if not blocked:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": _deny_reason(blocked),
        }
    }


def run(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    posture: Posture | None = None,
    allowlist: AllowlistPort | None = None,
) -> PreToolUseResult:
    """Evaluate every Skill under ``skills_dirs`` and hard-deny the call if any is not cleared."""
    posture = posture if posture is not None else PRE_TOOL_USE_POSTURE
    decisions: list[GateDecision] = []
    for skills_dir in skills_dirs:
        decisions.extend(
            evaluate(
                skills_dir, engine=engine, store=store, posture=posture, allowlist=allowlist
            )
        )
    blocked = [decision for decision in decisions if _is_blocked(decision)]
    return PreToolUseResult(
        decisions=decisions, blocked=bool(blocked), hook_output=_build_output(blocked)
    )


def main() -> None:
    """CLI/hook entry point: wire real paths + engine, read stdin, emit the payload."""
    # The hook receives JSON on stdin; we don't need its fields yet, but drain it so the
    # pipe closes cleanly.
    with contextlib.suppress(json.JSONDecodeError, ValueError):
        json.load(sys.stdin)

    engine = DetectionEngine(judge=AnthropicJudge())
    result = run(
        default_skills_dirs(),
        engine=engine,
        store=VerdictStore(store_root()),
        allowlist=Allowlist(store_root()),
    )
    json.dump(result.hook_output, sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
