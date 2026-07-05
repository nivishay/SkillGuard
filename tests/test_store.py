"""Local Verdict Store tests: a JSON cache keyed by Canonical Bundle Hash.

The store is a *cache of a would-be-shared verdict DB* (ADR 0001): it persists
``{tier, findings, engine_version, scanned_at}`` per hash and survives a fresh process, so
a repeat session is a lookup, not a re-scan. Records carry ``engine_version`` so a future
engine can tell a stale entry from a current one.
"""

from __future__ import annotations

from pathlib import Path

from skillguard.models import Finding, Location, ThreatVector, Tier, Verdict
from skillguard.store import VerdictStore


def _malicious_verdict() -> Verdict:
    return Verdict(
        tier=Tier.MALICIOUS,
        findings=(
            Finding(
                vector=ThreatVector.PROMPT_INJECTION,
                explanation="reads ~/.ssh/id_rsa",
                location=Location(file="SKILL.md", line=4),
            ),
        ),
    )


def test_get_missing_hash_returns_none(tmp_path: Path) -> None:
    store = VerdictStore(tmp_path)
    assert store.get("deadbeef") is None


def test_put_then_get_roundtrips_tier_and_findings(tmp_path: Path) -> None:
    store = VerdictStore(tmp_path)
    store.put("abc123", _malicious_verdict(), engine_version="0.1.0")

    record = store.get("abc123")
    assert record is not None
    assert record.tier is Tier.MALICIOUS
    assert record.engine_version == "0.1.0"
    assert len(record.findings) == 1
    finding = record.findings[0]
    assert finding.vector is ThreatVector.PROMPT_INJECTION
    assert finding.location.file == "SKILL.md"
    assert finding.location.line == 4


def test_record_persists_across_store_instances(tmp_path: Path) -> None:
    VerdictStore(tmp_path).put("abc123", _malicious_verdict(), engine_version="0.1.0")
    # A brand-new store over the same root reads the persisted cache.
    record = VerdictStore(tmp_path).get("abc123")
    assert record is not None
    assert record.tier is Tier.MALICIOUS


def test_put_records_a_scanned_at_timestamp(tmp_path: Path) -> None:
    store = VerdictStore(tmp_path)
    store.put("abc123", _malicious_verdict(), engine_version="0.1.0")
    record = store.get("abc123")
    assert record is not None
    assert record.scanned_at  # ISO-8601 string, non-empty


def test_clean_verdict_with_no_findings_roundtrips(tmp_path: Path) -> None:
    store = VerdictStore(tmp_path)
    store.put("clean1", Verdict(tier=Tier.CLEAN), engine_version="0.1.0")
    record = store.get("clean1")
    assert record is not None
    assert record.tier is Tier.CLEAN
    assert record.findings == ()
