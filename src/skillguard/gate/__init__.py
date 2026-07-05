"""Gate core — hook-agnostic enforcement, the seam both hooks and the daemon call.

The gate answers one question for a skills directory: *what should happen to each Skill?*
It enumerates Skills, resolves each Canonical Bundle Hash, looks up its Verdict in the
local Store (scanning on a miss via the injected engine, then caching the result), and maps
the Verdict tier to an :class:`Action` per the Enforcement Posture. It decides; it does not
itself move files — the calling hook applies a :data:`Action.QUARANTINE`.

Two invariants from ADR 0003 live here:

* **Hold on unknown / fail toward blocking.** A Skill that cannot be scanned (engine error,
  scan in flight) is returned as :data:`Action.HOLD`, never a bare allow — an unknown
  Verdict is *not cleared*.
* **The Posture is a dial, not hard-coded.** The tier→action mapping is a parameter; the
  shipped default quarantines Malicious, warns on Suspicious, and silently allows Clean.
"""

from __future__ import annotations

from skillguard.gate.core import (
    DEFAULT_POSTURE,
    Action,
    GateDecision,
    Posture,
    enumerate_skill_dirs,
    evaluate,
)

__all__ = [
    "Action",
    "DEFAULT_POSTURE",
    "GateDecision",
    "Posture",
    "enumerate_skill_dirs",
    "evaluate",
]
