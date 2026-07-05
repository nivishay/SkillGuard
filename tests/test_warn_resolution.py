"""Suspicious warn-resolution tests — the posture branch that needs a human (ADR 0003).

The gate core maps a Suspicious tier to :data:`Action.WARN`; ``resolve_warnings`` turns that
WARN into a concrete outcome depending on whether a human is present. It is exercised through
the public seam — a real :class:`Allowlist`, a real Verdict Store, a stubbed engine, and a
stubbed confirm callback — so both the interactive and the non-interactive branch are
deterministic and neither calls ``input()``.

Interactive-allow persists the Canonical Bundle Hash and lets the Skill load; interactive-
decline blocks it; non-interactive is deny-and-hold (never a silent allow, never a blocking
prompt); an approved hash is not re-prompted next pass; changed content re-triggers the flow.
"""

from __future__ import annotations

from pathlib import Path

from conftest import StubEngine, write_skill
from skillguard.allowlist import Allowlist
from skillguard.gate import Action, evaluate
from skillguard.gate.core import GateDecision
from skillguard.gate.enforce import resolve_warnings
from skillguard.hash import canonical_bundle_hash
from skillguard.loader import load_skill
from skillguard.models import Finding, Location, ThreatVector, Tier, Verdict
from skillguard.store import VerdictStore

_SUSPICIOUS = {"SKILL.md": "# helper\nReads a project config and phones a URL from it.\n"}


def _suspicious_verdict() -> Verdict:
    return Verdict(
        tier=Tier.SUSPICIOUS,
        findings=(
            Finding(
                vector=ThreatVector.PROMPT_INJECTION,
                explanation="ambiguous instruction to contact an external URL",
                location=Location(file="SKILL.md", line=2),
            ),
        ),
    )


class _RecordingConfirm:
    """A stub confirm callback: records the decisions it was shown, returns a canned answer."""

    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.seen: list[GateDecision] = []

    def __call__(self, decision: GateDecision) -> bool:
        self.seen.append(decision)
        return self.answer


def _warn_decisions(tmp_path: Path, allowlist: Allowlist) -> tuple[list[GateDecision], str]:
    """Materialize a Suspicious Skill and return its (unresolved) WARN decisions + its hash."""
    skills = tmp_path / "skills"
    skill_dir = write_skill(skills / "maybe", _SUSPICIOUS)
    store = VerdictStore(tmp_path / "store")
    engine = StubEngine(verdict=_suspicious_verdict())
    decisions = evaluate(skills, engine=engine, store=store, allowlist=allowlist)
    assert decisions[0].action is Action.WARN  # the core hands us a bare WARN to resolve
    return decisions, canonical_bundle_hash(load_skill(skill_dir))


def test_interactive_allow_persists_hash_and_permits_load(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "store")
    decisions, bundle_hash = _warn_decisions(tmp_path, allowlist)
    confirm = _RecordingConfirm(answer=True)

    resolved = resolve_warnings(
        decisions, interactive=True, confirm=confirm, allowlist=allowlist
    )

    assert resolved[0].action is Action.ALLOW  # explicit allow lets it load
    assert confirm.seen[0].findings  # Findings surfaced at the confirm moment
    assert allowlist.contains(bundle_hash)  # approval persisted, keyed by hash


def test_interactive_decline_blocks_and_does_not_persist(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "store")
    decisions, bundle_hash = _warn_decisions(tmp_path, allowlist)
    confirm = _RecordingConfirm(answer=False)

    resolved = resolve_warnings(
        decisions, interactive=True, confirm=confirm, allowlist=allowlist
    )

    assert resolved[0].action is Action.DENY  # a decline does not load
    assert not allowlist.contains(bundle_hash)  # nothing persisted


def test_non_interactive_is_deny_and_hold_without_prompting(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "store")
    decisions, bundle_hash = _warn_decisions(tmp_path, allowlist)
    confirm = _RecordingConfirm(answer=True)  # would allow if ever asked

    resolved = resolve_warnings(
        decisions, interactive=False, confirm=confirm, allowlist=allowlist
    )

    assert resolved[0].action is Action.HOLD  # held until a human resolves it
    assert confirm.seen == []  # never blocks on a prompt
    assert not allowlist.contains(bundle_hash)  # never silently allowed


def test_approved_hash_is_not_re_prompted_next_pass(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "store")
    store = VerdictStore(tmp_path / "store")
    decisions, _ = _warn_decisions(tmp_path, allowlist)
    resolve_warnings(
        decisions, interactive=True, confirm=_RecordingConfirm(answer=True), allowlist=allowlist
    )

    # Next pass: evaluate now short-circuits on the persisted approval, so there is no WARN
    # to resolve and the confirm callback is never invoked again.
    again = evaluate(
        tmp_path / "skills",
        engine=StubEngine(verdict=_suspicious_verdict()),
        store=store,
        allowlist=allowlist,
    )
    assert again[0].action is Action.ALLOW  # allowlist hit, not a fresh WARN
    confirm = _RecordingConfirm(answer=True)
    resolved = resolve_warnings(again, interactive=True, confirm=confirm, allowlist=allowlist)
    assert resolved[0].action is Action.ALLOW
    assert confirm.seen == []  # developer is not re-nagged


def test_changed_content_re_triggers_the_flow(tmp_path: Path) -> None:
    allowlist = Allowlist(tmp_path / "store")
    store = VerdictStore(tmp_path / "store")
    decisions, _ = _warn_decisions(tmp_path, allowlist)
    resolve_warnings(
        decisions, interactive=True, confirm=_RecordingConfirm(answer=True), allowlist=allowlist
    )

    # The approved Skill's content changes -> new Canonical Bundle Hash -> the old approval no
    # longer matches -> the Suspicious flow re-triggers as a fresh WARN.
    write_skill(tmp_path / "skills" / "maybe", {"SKILL.md": "# helper\nNow does something new.\n"})
    reevaluated = evaluate(
        tmp_path / "skills",
        engine=StubEngine(verdict=_suspicious_verdict()),
        store=store,
        allowlist=allowlist,
    )
    assert reevaluated[0].action is Action.WARN  # approval evaporated

    confirm = _RecordingConfirm(answer=True)
    resolve_warnings(reevaluated, interactive=True, confirm=confirm, allowlist=allowlist)
    assert len(confirm.seen) == 1  # re-prompted for the changed content


def test_non_warn_decisions_pass_through_untouched(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    write_skill(skills / "good", {"SKILL.md": "# good\nFormat markdown tables.\n"})
    store = VerdictStore(tmp_path / "store")
    decisions = evaluate(skills, engine=StubEngine(verdict=Verdict(tier=Tier.CLEAN)), store=store)
    confirm = _RecordingConfirm(answer=False)

    resolved = resolve_warnings(decisions, interactive=True, confirm=confirm, allowlist=None)

    assert resolved[0].action is Action.ALLOW  # a Clean allow is not a WARN, left alone
    assert confirm.seen == []  # only Suspicious WARNs reach the human
