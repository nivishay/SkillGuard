"""CLI tests for ``skillguard status`` — the read-only view of the gate's state.

``status`` displays existing state only (PRD 0002 user story 3): it reads the Verdict Store,
the quarantine holding area, and the Allowlist and renders them. No detection or enforcement.
It joins each quarantined Skill back to its Verdict Store record by Canonical Bundle Hash so a
quarantined Tier is shown with its Findings.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import skillguard.cli as cli
from conftest import write_skill
from skillguard.allowlist import Allowlist
from skillguard.models import Finding, Location, ThreatVector, Tier, Verdict
from skillguard.quarantine import Quarantine
from skillguard.store import VerdictStore

runner = CliRunner()


def _point_state_at(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "store_root", lambda: tmp_path / "sg")
    monkeypatch.setattr(cli, "quarantine_root", lambda: tmp_path / "sg" / "quarantine")


def test_status_empty_state_renders_cleanly_and_exits_zero(tmp_path: Path, monkeypatch) -> None:
    _point_state_at(tmp_path, monkeypatch)

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "Traceback" not in result.output
    assert "(none)" in result.stdout


def test_status_lists_cached_skill_with_tier_and_short_hash(tmp_path: Path, monkeypatch) -> None:
    _point_state_at(tmp_path, monkeypatch)
    VerdictStore(tmp_path / "sg").put(
        "0123456789abcdef", Verdict(tier=Tier.CLEAN), engine_version="0.1.0"
    )

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "Clean" in result.stdout
    assert "0123456789ab" in result.stdout


def test_status_lists_quarantined_skill_with_its_findings(tmp_path: Path, monkeypatch) -> None:
    _point_state_at(tmp_path, monkeypatch)
    malicious = Verdict(
        tier=Tier.MALICIOUS,
        findings=(
            Finding(
                vector=ThreatVector.PROMPT_INJECTION,
                explanation="reads ~/.ssh/id_rsa",
                location=Location(file="SKILL.md", line=4),
            ),
        ),
    )
    VerdictStore(tmp_path / "sg").put("evilhash0000", malicious, engine_version="0.1.0")
    skill_dir = write_skill(tmp_path / "skills" / "evil", {"SKILL.md": "# evil\n"})
    Quarantine(tmp_path / "sg" / "quarantine").quarantine(skill_dir, bundle_hash="evilhash0000")

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "evil" in result.stdout
    assert "Prompt Injection" in result.stdout
    assert "reads ~/.ssh/id_rsa" in result.stdout


def test_status_quarantined_without_a_record_is_shown_gracefully(
    tmp_path: Path, monkeypatch
) -> None:
    _point_state_at(tmp_path, monkeypatch)
    # Quarantined, but the Verdict Store has no record for this hash (e.g. cache cleared).
    skill_dir = write_skill(tmp_path / "skills" / "orphan", {"SKILL.md": "# orphan\n"})
    Quarantine(tmp_path / "sg" / "quarantine").quarantine(skill_dir, bundle_hash="norecord0000")

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "orphan" in result.stdout


def test_status_shows_allowlisted_hash(tmp_path: Path, monkeypatch) -> None:
    _point_state_at(tmp_path, monkeypatch)
    Allowlist(tmp_path / "sg").allow("abcdef0123456789")

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "abcdef012345" in result.stdout
