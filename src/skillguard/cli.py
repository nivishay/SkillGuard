"""SkillGuard CLI — ``skillguard scan <folder>``.

Thin entry point: parse arguments, invoke the Skill Loader then the Detection Engine,
render the Verdict, and set the process exit code. No detection logic lives here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from skillguard.allowlist import Allowlist
from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge, LLMJudgeError
from skillguard.hash import canonical_bundle_hash
from skillguard.hooks import pre_tool_use, session_start
from skillguard.install import install_hooks
from skillguard.loader import SkillLoadError, load_skill
from skillguard.paths import claude_home, quarantine_root, store_root
from skillguard.quarantine import Quarantine, QuarantineError
from skillguard.rendering import exit_code_for, render_status, render_verdict
from skillguard.store import VerdictStore

app = typer.Typer(
    name="skillguard",
    help="Detect malicious AI agent Skills before your agent trusts them.",
    add_completion=False,
    no_args_is_help=True,
)

_USAGE_ERROR = 2


@app.callback()
def main() -> None:
    """SkillGuard — keep ``scan`` as a named subcommand even though it is the only one."""


@app.command()
def scan(
    folder: Annotated[
        Path,
        typer.Argument(help="Path to the Skill folder to scan."),
    ],
) -> None:
    """Scan a Skill folder and report a Verdict (Clean / Suspicious / Malicious)."""
    try:
        skill = load_skill(folder)
    except SkillLoadError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=_USAGE_ERROR) from exc

    engine = DetectionEngine(judge=AnthropicJudge())
    try:
        verdict = engine.analyze(skill)
    except LLMJudgeError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=_USAGE_ERROR) from exc

    render_verdict(verdict)
    raise typer.Exit(code=exit_code_for(verdict))


def claude_settings_path() -> Path:
    """The Claude Code settings file the Endpoint Gate hooks are written into."""
    return claude_home() / "settings.json"


@app.command("install-hook")
def install_hook() -> None:
    """Wire the Endpoint Gate into Claude Code (writes the SessionStart hook into settings)."""
    settings_path = claude_settings_path()
    install_hooks(settings_path)
    typer.secho(f"Installed SkillGuard hooks into {settings_path}", fg=typer.colors.GREEN)


@app.command()
def restore(
    name: Annotated[
        str,
        typer.Argument(help="Name of the quarantined Skill to move back (see 'status')."),
    ],
) -> None:
    """Move a quarantined Skill back to its original location (the false-positive escape hatch)."""
    quarantine = Quarantine(quarantine_root())
    try:
        original = quarantine.restore(name)
    except QuarantineError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=_USAGE_ERROR) from exc
    typer.secho(f"Restored {name} to {original}", fg=typer.colors.GREEN)


@app.command()
def allow(
    folder: Annotated[
        Path,
        typer.Argument(help="Path to the Skill folder to approve."),
    ],
) -> None:
    """Approve a Skill by its Canonical Bundle Hash so the gate passes this exact content."""
    try:
        skill = load_skill(folder)
    except SkillLoadError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=_USAGE_ERROR) from exc

    bundle_hash = canonical_bundle_hash(skill)
    Allowlist(store_root()).allow(bundle_hash)
    typer.secho(f"Allowed {folder} ({bundle_hash[:12]})", fg=typer.colors.GREEN)


@app.command()
def status() -> None:
    """Show the gate's state: cached Verdicts, quarantined Skills with Findings, the Allowlist."""
    store = VerdictStore(store_root())
    quarantine = Quarantine(quarantine_root())
    allowlist = Allowlist(store_root())
    # Join each quarantined entry back to its Verdict Store record by Canonical Bundle Hash so
    # its Findings are recovered (the manifest holds no Findings): a Tier without its evidence
    # is not acceptable. A missing record surfaces as None, still shown gracefully.
    quarantined = [(entry, store.get(entry.bundle_hash)) for entry in quarantine.list()]
    render_status(
        cached=store.items(),
        quarantined=quarantined,
        allowlisted=allowlist.list(),
    )


@app.command("hook", hidden=True)
def hook(
    event: Annotated[str, typer.Argument(help="Hook event, e.g. 'session-start'.")],
) -> None:
    """Internal dispatcher Claude Code invokes for a hook event. Not for direct use."""
    if event == "session-start":
        session_start.main()
        return
    if event == "pre-tool-use":
        pre_tool_use.main()
        return
    typer.secho(f"error: unknown hook event: {event}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=_USAGE_ERROR)
