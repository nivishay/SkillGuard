"""Render a Verdict for the terminal and map it to a process exit code."""

from __future__ import annotations

import typer

from skillguard.hash import short_hash
from skillguard.models import Finding, Tier, Verdict
from skillguard.quarantine import QuarantineEntry
from skillguard.store import VerdictRecord

_TIER_COLOR = {
    Tier.CLEAN: typer.colors.GREEN,
    Tier.SUSPICIOUS: typer.colors.YELLOW,
    Tier.MALICIOUS: typer.colors.RED,
}


def exit_code_for(verdict: Verdict) -> int:
    """0 for Clean, 1 for a non-Clean Verdict, so the scan is scriptable/CI-friendly."""
    return 0 if verdict.tier is Tier.CLEAN else 1


def render_verdict(verdict: Verdict) -> None:
    """Print the Verdict tier and its findings to stdout."""
    color = _TIER_COLOR[verdict.tier]
    typer.secho(f"Verdict: {verdict.tier}", fg=color, bold=True)

    if not verdict.findings:
        if verdict.tier is Tier.CLEAN:
            typer.echo("No threat vectors found.")
        return

    typer.echo("")
    for finding in verdict.findings:
        _render_finding(finding, color)


def _render_finding(finding: Finding, color: str) -> None:
    typer.secho(f"  [{finding.vector}] {finding.location}", fg=color)
    typer.echo(f"    {finding.explanation}")


def render_status(
    *,
    cached: list[tuple[str, VerdictRecord]],
    quarantined: list[tuple[QuarantineEntry, VerdictRecord | None]],
    allowlisted: list[str],
) -> None:
    """Print the gate's current state: cached Verdicts, quarantined Skills, the Allowlist.

    Display only — the caller has already read the three collections from the Verdict Store,
    the quarantine holding area, and the Allowlist. Each quarantined Skill is passed with its
    joined ``VerdictRecord`` (or ``None`` if the cache no longer holds one) so its Findings —
    a Tier's evidence — are surfaced, never a bare Tier.
    """
    typer.secho("Cached Skills", bold=True)
    if not cached:
        typer.echo("  (none)")
    for bundle_hash, record in cached:
        color = _TIER_COLOR[record.tier]
        typer.secho(f"  {str(record.tier):<10} {short_hash(bundle_hash)}", fg=color)

    typer.echo("")
    typer.secho("Quarantined Skills", bold=True)
    if not quarantined:
        typer.echo("  (none)")
    for entry, joined in quarantined:
        typer.secho(f"  {entry.name} ({short_hash(entry.bundle_hash)})", fg=typer.colors.RED, bold=True)
        if joined is None:
            typer.echo("    (no cached Verdict — re-scan to recover Findings)")
            continue
        for finding in joined.findings:
            _render_finding(finding, typer.colors.RED)

    typer.echo("")
    typer.secho("Allowlisted", bold=True)
    if not allowlisted:
        typer.echo("  (none)")
    for bundle_hash in allowlisted:
        typer.echo(f"  {short_hash(bundle_hash)}")
