"""Unit tests for status rendering — exercised without the CLI (typer writes to stdout).

``render_status`` is the display half of ``skillguard status``: it turns the gate's three
state collections (cached Verdicts, quarantined Skills joined to their Findings, the
Allowlist) into terminal output. A Tier is never shown without its evidence, so a
quarantined entry surfaces its joined Findings (CONTEXT.md: Finding).
"""

from __future__ import annotations

from pathlib import Path

from skillguard.models import Finding, Location, ThreatVector, Tier
from skillguard.quarantine import QuarantineEntry
from skillguard.rendering import render_status
from skillguard.store import VerdictRecord


def _record(tier: Tier, findings: tuple[Finding, ...] = ()) -> VerdictRecord:
    return VerdictRecord(
        tier=tier, findings=findings, engine_version="0.1.0", scanned_at="2026-07-05T00:00:00+00:00"
    )


def _entry(name: str, bundle_hash: str) -> QuarantineEntry:
    return QuarantineEntry(
        name=name,
        quarantined_path=Path("q") / name,
        original_path=Path("skills") / name,
        bundle_hash=bundle_hash,
        quarantined_at="2026-07-05T00:00:00+00:00",
    )


def test_render_empty_state_names_all_three_sections(capsys) -> None:
    render_status(cached=[], quarantined=[], allowlisted=[])
    out = capsys.readouterr().out
    assert "Cached Skills" in out
    assert "Quarantined Skills" in out
    assert "Allowlisted" in out
    assert "(none)" in out


def test_render_cached_shows_tier_and_short_hash(capsys) -> None:
    render_status(
        cached=[("0123456789abcdef0000", _record(Tier.CLEAN))],
        quarantined=[],
        allowlisted=[],
    )
    out = capsys.readouterr().out
    assert "Clean" in out
    assert "0123456789ab" in out  # first 12 chars only
    assert "0123456789abcdef0000" not in out  # full hash is not shown


def test_render_quarantined_surfaces_joined_findings(capsys) -> None:
    finding = Finding(
        vector=ThreatVector.PROMPT_INJECTION,
        explanation="reads ~/.ssh/id_rsa",
        location=Location(file="SKILL.md", line=4),
    )
    render_status(
        cached=[],
        quarantined=[(_entry("evil", "deadbeef0000"), _record(Tier.MALICIOUS, (finding,)))],
        allowlisted=[],
    )
    out = capsys.readouterr().out
    assert "evil" in out
    assert "Prompt Injection" in out
    assert "reads ~/.ssh/id_rsa" in out
    assert "SKILL.md:4" in out


def test_render_quarantined_without_record_still_shown(capsys) -> None:
    render_status(
        cached=[],
        quarantined=[(_entry("orphan", "norecord0000"), None)],
        allowlisted=[],
    )
    out = capsys.readouterr().out
    assert "orphan" in out
    assert "norecord0000"[:12] in out


def test_render_allowlist_shows_short_hash(capsys) -> None:
    render_status(cached=[], quarantined=[], allowlisted=["abcdef0123456789"])
    out = capsys.readouterr().out
    assert "abcdef012345" in out
