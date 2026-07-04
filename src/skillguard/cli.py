"""SkillGuard CLI — ``skillguard scan <folder>``.

Thin entry point: parse arguments, invoke the Skill Loader then the Detection Engine,
render the Verdict, and set the process exit code. No detection logic lives here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from skillguard.engine import DetectionEngine
from skillguard.engine.llm.anthropic_judge import AnthropicJudge, LLMJudgeError
from skillguard.loader import SkillLoadError, load_skill
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
