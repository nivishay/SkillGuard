"""SkillGuard CLI — ``skillguard scan <folder>``.

Thin entry point: parse arguments, invoke the Skill Loader then the Detection Engine,
render the Verdict, and set the process exit code. No detection logic lives here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from skillguard import daemon as daemon_mod
from skillguard.allowlist import Allowlist
from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge, LLMJudgeError
from skillguard.hash import canonical_bundle_hash
from skillguard.hooks import session_start
from skillguard.install import install_hooks
from skillguard.loader import SkillLoadError, load_skill
from skillguard.paths import claude_home, quarantine_root, store_root
from skillguard.quarantine import Quarantine, QuarantineError
from skillguard.rendering import exit_code_for, render_verdict

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
def daemon(
    once: Annotated[
        bool,
        typer.Option(
            "--once", help="Run a single ahead-of-time scan pass and exit (cron/testing)."
        ),
    ] = False,
) -> None:
    """Run the resident watcher that scans Skills ahead of time so SessionStart stays fast.

    Without ``--once`` this runs in the foreground and polls the skills directories until you
    stop it (Ctrl+C, or close the terminal / Stop-Process on Windows). ``--once`` performs a
    single pass — quarantining any Malicious Skill and caching every Verdict — then exits.
    """
    if once:
        enforcement = daemon_mod.main(once=True)
        moved = len(enforcement.quarantined) if enforcement is not None else 0
        typer.secho(
            f"Scan pass complete: quarantined {moved} Malicious Skill(s).",
            fg=typer.colors.GREEN,
        )
        return

    typer.secho(
        "SkillGuard daemon watching your Skills. Press Ctrl+C to stop.",
        fg=typer.colors.GREEN,
    )
    try:
        daemon_mod.main(once=False)
    except KeyboardInterrupt:  # pragma: no cover - interactive stop
        typer.secho("Daemon stopped.", fg=typer.colors.YELLOW)


@app.command("hook", hidden=True)
def hook(
    event: Annotated[str, typer.Argument(help="Hook event, e.g. 'session-start'.")],
) -> None:
    """Internal dispatcher Claude Code invokes for a hook event. Not for direct use."""
    if event == "session-start":
        session_start.main()
        return
    typer.secho(f"error: unknown hook event: {event}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=_USAGE_ERROR)
