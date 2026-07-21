"""Decide-then-act — the shared enforcement step both hooks and the daemon call.

The gate core (:func:`skillguard.gate.evaluate`) only *decides* a tier -> :class:`Action`;
this layer carries those decisions out where interactivity and the confirm mechanism are
known (ADR 0003):

* :func:`resolve_warnings` resolves a Suspicious :data:`Action.WARN` into a concrete outcome.
  With a human present it warns with the Findings and asks for an explicit allow (which
  persists the Canonical Bundle Hash to the Allowlist so it is a one-time decision per
  Skill-version); with no human present it degrades to **deny-and-hold** — never a silent
  allow, never a blocking prompt. The pure core stays a tier->Action map; the interactivity
  decision lives *here*.
* :func:`scan_and_quarantine` runs the gate, resolves warnings, and moves the Skills that
  must not load — Malicious ones, and Suspicious ones that resolve to hold/decline — into the
  reversible holding area. The PreToolUse backstop does *not* (it hard-denies a tool call),
  so its wiring lives elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from skillguard.gate.core import (
    Action,
    AllowlistStore,
    ApprovalPort,
    EnginePort,
    GateDecision,
    Posture,
    evaluate,
)
from skillguard.models import Tier
from skillguard.quarantine import Quarantine, QuarantineEntry
from skillguard.store import VerdictStore

Confirm = Callable[[GateDecision], bool]
"""A human-in-the-loop prompt: shown one Suspicious decision (which carries its Findings),
returns whether to allow that Skill to load. Injected so the confirm mechanism is stubbable
and no *testable* code calls ``input()`` directly — only the CLI entry point does."""


def _decline(_decision: GateDecision) -> bool:
    """The safe default confirm: approve nothing. Never invoked on the non-interactive path."""
    return False


def resolve_warnings(
    decisions: Iterable[GateDecision],
    *,
    interactive: bool,
    confirm: Confirm = _decline,
    allowlist: ApprovalPort | None = None,
) -> list[GateDecision]:
    """Resolve every Suspicious :data:`Action.WARN` into a terminal Action; pass the rest through.

    For a WARN decision:

    * **Interactive** (a human is present, e.g. session start): ask ``confirm`` — which is
      handed the decision *with* its Findings — for an explicit allow. On allow, persist the
      Skill's Canonical Bundle Hash to ``allowlist`` (so the developer is not re-nagged next
      session, and the approval evaporates when the content — and thus the hash — changes) and
      return :data:`Action.ALLOW`. On decline, return :data:`Action.DENY` (it does not load).
    * **Non-interactive** (no human, e.g. an autonomous/background run): **deny-and-hold** —
      return :data:`Action.HOLD` *without ever calling* ``confirm``, so the run neither
      silently allows a false Clean nor blocks waiting on a prompt.
    """
    resolved: list[GateDecision] = []
    for decision in decisions:
        if decision.action is not Action.WARN:
            resolved.append(decision)
            continue
        if not interactive:
            resolved.append(replace(decision, action=Action.HOLD))
            continue
        if confirm(decision):
            if allowlist is not None:
                allowlist.allow(decision.bundle_hash)
            resolved.append(replace(decision, action=Action.ALLOW))
        else:
            resolved.append(replace(decision, action=Action.DENY))
    return resolved


@dataclass(frozen=True)
class Enforcement:
    """The outcome of a decide-then-act pass over one or more skills directories.

    ``quarantined`` are the Malicious Skills moved off disk; ``held`` are Suspicious Skills
    that resolved to deny-and-hold (or an interactive decline) and were moved into the same
    reversible holding area so they cannot load. Both travel with their :class:`GateDecision`
    so the surface layer can show *why*.
    """

    decisions: list[GateDecision] = field(default_factory=list)
    quarantined: list[tuple[QuarantineEntry, GateDecision]] = field(default_factory=list)
    held: list[tuple[QuarantineEntry, GateDecision]] = field(default_factory=list)


def scan_and_quarantine(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    posture: Posture | None = None,
    allowlist: AllowlistStore | None = None,
    interactive: bool = False,
    confirm: Confirm = _decline,
) -> Enforcement:
    """Evaluate every Skill, resolve Suspicious warnings, and move the ones that must not load.

    Malicious Skills are quarantined. A Suspicious Skill that resolves to deny-and-hold
    (non-interactive) or a decline (interactive) is moved into the same reversible holding
    area — the physical side of "does not load" at the session-start surface. An approved (or
    Clean) Skill is left in place. ``interactive``/``confirm`` are injected so the daemon and
    a live session pick different branches while enforcing through the same code.
    """
    decisions: list[GateDecision] = []
    quarantined: list[tuple[QuarantineEntry, GateDecision]] = []
    held: list[tuple[QuarantineEntry, GateDecision]] = []

    for skills_dir in skills_dirs:
        raw = evaluate(
            skills_dir, engine=engine, store=store, posture=posture, allowlist=allowlist
        )
        for decision in resolve_warnings(
            raw, interactive=interactive, confirm=confirm, allowlist=allowlist
        ):
            decisions.append(decision)
            if decision.action is Action.QUARANTINE:
                entry = quarantine.quarantine(
                    decision.skill_path, bundle_hash=decision.bundle_hash
                )
                quarantined.append((entry, decision))
            elif decision.tier is Tier.SUSPICIOUS and decision.action in (
                Action.HOLD,
                Action.DENY,
            ):
                entry = quarantine.quarantine(
                    decision.skill_path, bundle_hash=decision.bundle_hash
                )
                held.append((entry, decision))

    return Enforcement(decisions=decisions, quarantined=quarantined, held=held)
