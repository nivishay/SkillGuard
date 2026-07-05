"""Render a Verdict for the terminal and map it to a process exit code."""

from __future__ import annotations

import typer

from skillguard.models import Tier, Verdict

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
        typer.secho(f"  [{finding.vector}] {finding.location}", fg=color)
        typer.echo(f"    {finding.explanation}")
