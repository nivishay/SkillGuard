"""Quarantine demo — run the REAL Endpoint Gate enforcement pass over a sandbox.

Same wiring as `skillguard daemon --once` (daemon.main), but pointed at an isolated
sandbox skills dir instead of your real ~/.claude/skills, so nothing real is touched.
"""
from __future__ import annotations

import sys
from pathlib import Path

from skillguard.daemon import scan_pass
from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge
from skillguard.paths import quarantine_root, store_root
from skillguard.quarantine import Quarantine
from skillguard.store import VerdictStore
from skillguard.allowlist import Allowlist

skills_dir = Path(sys.argv[1])

def show(label: str) -> None:
    print(f"\n{label}")
    print(f"  skills/     -> {sorted(p.name for p in skills_dir.iterdir())}")
    qdir = quarantine_root()
    held = sorted(p.name for p in qdir.iterdir()) if qdir.is_dir() else []
    print(f"  quarantine/ -> {held}")

show("BEFORE the gate runs:")

engine = DetectionEngine(judge=AnthropicJudge())
enforcement = scan_pass(
    [skills_dir],
    engine=engine,
    store=VerdictStore(store_root()),
    quarantine=Quarantine(quarantine_root()),
    allowlist=Allowlist(store_root()),
)

print("\n--- Enforcement decisions ---")
for d in enforcement.decisions:
    print(f"  {Path(d.skill_path).name:28} tier={str(d.tier):16} action={d.action}")
for entry, d in enforcement.quarantined:
    reason = d.findings[0].explanation if d.findings else "(no finding)"
    print(f"\n  QUARANTINED {Path(d.skill_path).name}: {reason}")

show("AFTER the gate runs:")
