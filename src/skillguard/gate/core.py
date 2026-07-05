"""The gate core decision function and its Action/Posture vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from skillguard import __version__
from skillguard.hash import canonical_bundle_hash
from skillguard.loader import SkillLoadError, load_skill
from skillguard.models import Finding, Skill, Tier, Verdict
from skillguard.store import VerdictStore


class Action(StrEnum):
    """What the gate decides should happen to a Skill.

    ``ALLOW``/``QUARANTINE`` are terminal; ``WARN`` (Suspicious, later slice) asks a human;
    ``DENY`` is the PreToolUse hard block; ``HOLD`` is the fail-toward-blocking state for a
    Skill whose Verdict is not yet known (unscannable or in flight) — *not cleared*.
    """

    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"
    DENY = "deny"
    HOLD = "hold"


# The Enforcement Posture: the configurable tier -> Action mapping (a dial, not hard-coded).
Posture = dict[Tier, Action]

DEFAULT_POSTURE: Posture = {
    Tier.CLEAN: Action.ALLOW,
    Tier.SUSPICIOUS: Action.WARN,
    Tier.MALICIOUS: Action.QUARANTINE,
}


@dataclass(frozen=True)
class GateDecision:
    """One Skill's evaluation: where it is, its identity, and what to do about it.

    ``tier`` is ``None`` exactly when ``action`` is :data:`Action.HOLD` (Verdict unknown).
    ``scanned`` is ``True`` when this evaluation paid for a fresh scan (a cache miss),
    ``False`` on a cache hit — the property user story 5 (fast repeat sessions) rides on.
    ``findings`` travel with the decision so the surface layer can show *why*.
    """

    skill_path: str
    bundle_hash: str
    tier: Tier | None
    action: Action
    findings: tuple[Finding, ...]
    scanned: bool


class EnginePort(Protocol):
    """The slice of the Detection Engine the gate needs: ``analyze(skill) -> Verdict``."""

    def analyze(self, skill: Skill) -> Verdict: ...


class AllowlistPort(Protocol):
    """The slice of the Allowlist the gate needs: is this exact content approved?"""

    def contains(self, bundle_hash: str) -> bool: ...


def enumerate_skill_dirs(skills_dir: Path | str) -> list[Path]:
    """Return every Skill root under ``skills_dir`` (each folder holding a ``SKILL.md``).

    Searches recursively so it handles both flat (``skills/<name>/SKILL.md``) and nested
    plugin layouts, and is empty (not an error) when the directory is absent.
    """
    root = Path(skills_dir)
    if not root.is_dir():
        return []
    return sorted({md.parent for md in root.rglob("SKILL.md")})


def evaluate(
    skills_dir: Path | str,
    *,
    engine: EnginePort,
    store: VerdictStore,
    posture: Posture | None = None,
    allowlist: AllowlistPort | None = None,
    engine_version: str = __version__,
) -> list[GateDecision]:
    """Decide an :class:`Action` for every Skill under ``skills_dir``.

    For each Skill: hash it, look the hash up in ``store``, scan on a miss (caching the
    result), then map its tier through ``posture``. A Skill that cannot be scanned is held,
    never allowed (fail toward blocking).

    A Skill whose Canonical Bundle Hash is on ``allowlist`` is allowed outright without a
    scan — a persisted developer approval. Because the approval is keyed by hash, it applies
    to that exact content only: change the content and the approval no longer matches.
    """
    posture = posture if posture is not None else DEFAULT_POSTURE
    decisions: list[GateDecision] = []

    for skill_dir in enumerate_skill_dirs(skills_dir):
        try:
            skill = load_skill(skill_dir)
        except SkillLoadError:
            continue
        bundle_hash = canonical_bundle_hash(skill)

        if allowlist is not None and allowlist.contains(bundle_hash):
            cached = store.get(bundle_hash)
            decisions.append(
                GateDecision(
                    skill_path=str(skill_dir),
                    bundle_hash=bundle_hash,
                    tier=cached.tier if cached is not None else None,
                    action=Action.ALLOW,
                    findings=cached.findings if cached is not None else (),
                    scanned=False,
                )
            )
            continue

        record = store.get(bundle_hash)
        scanned = False
        if record is None:
            try:
                verdict = engine.analyze(skill)
            except Exception:  # noqa: BLE001 - any scan failure means "not cleared"
                decisions.append(
                    GateDecision(
                        skill_path=str(skill_dir),
                        bundle_hash=bundle_hash,
                        tier=None,
                        action=Action.HOLD,
                        findings=(),
                        scanned=False,
                    )
                )
                continue
            record = store.put(bundle_hash, verdict, engine_version=engine_version)
            scanned = True

        decisions.append(
            GateDecision(
                skill_path=str(skill_dir),
                bundle_hash=bundle_hash,
                tier=record.tier,
                action=posture[record.tier],
                findings=record.findings,
                scanned=scanned,
            )
        )

    return decisions
