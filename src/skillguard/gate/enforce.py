"""Scan-and-quarantine — the shared "decide then act on Malicious" step.

The gate core (:func:`skillguard.gate.evaluate`) only *decides*; this is where a
:data:`Action.QUARANTINE` decision is carried out by moving the folder off disk. Both the
SessionStart hook (pre-load barrier) and the daemon (ahead-of-time scanning) call this, so
they enforce identically. The PreToolUse backstop does *not* — it hard-denies a tool call
instead of moving files — so its wiring lives elsewhere.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from skillguard.gate.core import Action, EnginePort, GateDecision, Posture, evaluate
from skillguard.quarantine import Quarantine, QuarantineEntry
from skillguard.store import VerdictStore


@dataclass(frozen=True)
class Enforcement:
    """The outcome of a scan-and-quarantine pass over one or more skills directories."""

    decisions: list[GateDecision] = field(default_factory=list)
    quarantined: list[tuple[QuarantineEntry, GateDecision]] = field(default_factory=list)


def scan_and_quarantine(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    posture: Posture | None = None,
) -> Enforcement:
    """Evaluate every Skill under each of ``skills_dirs`` and quarantine the Malicious ones."""
    decisions: list[GateDecision] = []
    quarantined: list[tuple[QuarantineEntry, GateDecision]] = []

    for skills_dir in skills_dirs:
        for decision in evaluate(skills_dir, engine=engine, store=store, posture=posture):
            decisions.append(decision)
            if decision.action is Action.QUARANTINE:
                entry = quarantine.quarantine(
                    decision.skill_path, bundle_hash=decision.bundle_hash
                )
                quarantined.append((entry, decision))

    return Enforcement(decisions=decisions, quarantined=quarantined)
