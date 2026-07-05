"""The resident daemon — ahead-of-time scanning so the load-time barrier stays fast (ADR 0003).

The `SessionStart` hook is the *correctness floor*: it cannot silently fail. But on a
never-before-seen Skill it pays a synchronous scan at boot, and a Malicious Skill dropped
between sessions is only caught at the next start. The daemon closes both gaps: it scans
Skills *as they appear* and writes their Verdicts into the Store, so a later `SessionStart`
on an already-scanned Skill is a cache hit (no synchronous re-scan) and a Malicious Skill
that arrived between sessions is already quarantined before the next boot.

Two layers, per ADR 0003:

* **In-session** is covered by Claude Code's native ``watchPaths`` / ``FileChanged`` — the
  agent already re-fires ``SessionStart``-style enforcement when the skills directory
  changes during a live session, so SkillGuard does not re-implement it here.
* **Between sessions** is the gap this daemon fills with an OS-level watcher over the skills
  directories (Windows-first, per the PRD platform note).

The heart of the daemon is :func:`scan_pass` — a single, pure-ish pass that reuses the same
:func:`~skillguard.gate.enforce.scan_and_quarantine` step the hook calls, so the daemon
enforces *identically* (Malicious quarantined off disk, every Verdict cached). Everything
platform-specific is confined to the thin :func:`_run_forever` watch loop, which is guarded
behind :func:`main` so it never blocks the test suite; the gate core stays OS-agnostic.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path

from skillguard.allowlist import Allowlist
from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge
from skillguard.gate.core import AllowlistPort, EnginePort, Posture
from skillguard.gate.enforce import Enforcement, scan_and_quarantine
from skillguard.paths import default_skills_dirs, quarantine_root, store_root
from skillguard.quarantine import Quarantine
from skillguard.store import VerdictStore

# How long the polling watcher sleeps between passes. A rescan is cheap: the Verdict Store
# turns every already-seen Skill into a cache hit (the engine is not re-invoked), so polling
# stays dependency-light without a third-party file-watcher — see README "Daemon".
DEFAULT_POLL_INTERVAL_SECONDS = 2.0


def scan_pass(
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    posture: Posture | None = None,
    allowlist: AllowlistPort | None = None,
) -> Enforcement:
    """Run one ahead-of-time scan pass over ``skills_dirs`` — the unit the watcher fires.

    This is the single testable seam of the daemon. It delegates straight to
    :func:`~skillguard.gate.enforce.scan_and_quarantine` (no duplicated enforcement), so a
    Malicious Skill is quarantined off disk and every Skill's Verdict is written to the
    Store. Because scanning is Store-cached, calling this repeatedly is cheap: an unchanged
    Skill is a cache hit and the engine is not re-invoked.
    """
    return scan_and_quarantine(
        skills_dirs,
        engine=engine,
        store=store,
        quarantine=quarantine,
        posture=posture,
        allowlist=allowlist,
    )


def _run_forever(  # pragma: no cover - the OS watch loop; never entered by the test suite
    skills_dirs: Sequence[Path | str],
    *,
    engine: EnginePort,
    store: VerdictStore,
    quarantine: Quarantine,
    allowlist: AllowlistPort | None,
    interval: float,
) -> None:
    """Poll the skills directories forever, running :func:`scan_pass` on each tick.

    A deliberately thin shell: the only platform-specific part of the daemon. It is guarded
    behind :func:`main` and marked no-cover so tests exercise :func:`scan_pass` directly and
    never block on this ``while True`` loop. Stop it with Ctrl+C (see README "Daemon").
    """
    while True:
        scan_pass(
            skills_dirs,
            engine=engine,
            store=store,
            quarantine=quarantine,
            allowlist=allowlist,
        )
        time.sleep(interval)


def main(
    *, once: bool = False, interval: float = DEFAULT_POLL_INTERVAL_SECONDS
) -> Enforcement | None:
    """Wire real paths + engine, then run one pass (``once``) or the resident watch loop.

    Mirrors :func:`skillguard.hooks.session_start.main`'s wiring so the daemon enforces with
    exactly the same Store, Quarantine, and Allowlist as the load-time barrier. Returns the
    :class:`Enforcement` for a single pass (used by ``skillguard daemon --once`` / cron); the
    resident loop never returns.
    """
    engine = DetectionEngine(judge=AnthropicJudge())
    skills_dirs = default_skills_dirs()
    store = VerdictStore(store_root())
    quarantine = Quarantine(quarantine_root())
    allowlist = Allowlist(store_root())

    if once:
        return scan_pass(
            skills_dirs,
            engine=engine,
            store=store,
            quarantine=quarantine,
            allowlist=allowlist,
        )

    _run_forever(
        skills_dirs,
        engine=engine,
        store=store,
        quarantine=quarantine,
        allowlist=allowlist,
        interval=interval,
    )
    return None


if __name__ == "__main__":  # pragma: no cover
    main()
