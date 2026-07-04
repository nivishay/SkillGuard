# SkillGuard

Detect malicious AI agent **Skills** before your coding agent trusts and runs them.

A Skill is a bundle of natural-language instructions (SKILL.md style) plus optionally
bundled scripts and resources that an AI coding agent loads and acts on. Because a Skill
is *instructions the agent will follow* and *code the agent may run*, a malicious one can
quietly redirect the agent to read secrets, exfiltrate data, or run destructive commands.

`skillguard scan <folder>` analyzes a Skill on disk and returns a **Verdict** —
**Clean**, **Suspicious**, or **Malicious** — with human-readable evidence explaining *why*.

This release is the **Detection Engine only**: it reports a Verdict; it does not gate installs.

## Install (development)

Requires Python 3.11+. Using [uv](https://docs.astral.sh/uv/):

```bash
uv venv
uv pip install -e ".[dev]"
```

## Usage

```bash
skillguard scan path/to/skill
```

Exit code is `0` for a Clean Verdict, `1` for Suspicious/Malicious, and `2` for a usage
error (e.g. the path is not a Skill), so the scan can be wired into scripts and CI.

The LLM Judgment layer calls a Claude model and requires `ANTHROPIC_API_KEY` in the
environment. The model is configurable via `SKILLGUARD_MODEL` (defaults to a current
Claude model).

## Architecture

- **CLI** (`skillguard.cli`) — thin entry point; parses args, invokes the Loader then the
  Engine, renders the Verdict, sets the exit code. No detection logic.
- **Skill Loader** (`skillguard.loader`) — reads a folder into a normalized in-memory
  `Skill` (LF line endings, `.git`/OS/editor junk excluded).
- **Detection Engine** (`skillguard.engine`) — `analyze(skill) -> Verdict`, combining:
  - **Static Pass** (`skillguard.engine.static_pass`) — pure function, deterministic
    pattern matching for known-dangerous signals.
  - **LLM Judgment** (`skillguard.engine.llm`) — semantic analysis behind an injectable
    port, catching novel/disguised intent and authoring the evidence.

## Development

```bash
pytest          # deterministic suite (LLM port stubbed, no network)
ruff check .
mypy
```

The eval harness (`evals/`) measures detection accuracy against the real model and is run
separately from the deterministic suite.
