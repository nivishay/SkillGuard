# PRD: Endpoint Gate — scan-on-load quarantine for Claude Code Skills

## Problem Statement

The Detection Engine works (`skillguard scan <folder>` returns a Verdict), but nothing *uses* it at the right moment. A developer only gets protection if they remember to run the scan by hand — which the careless developer, the one most likely to install a malicious Skill, never does. Skills arrive by `git clone`, manual copy, plugin marketplaces, or riding inside a cloned project repo, and Claude Code loads whatever it finds in the skills directories with no checkpoint. We need an **involuntary** gate that runs the engine automatically at the moment a Skill would be trusted, and enforces the Verdict — the **Endpoint Gate** (see ADR 0003).

## Solution

A gate wired into Claude Code's hooks that scans Skills as they appear and enforces their Verdict at load time. This PRD covers the **solo-developer, Claude-Code, inline-barrier** slice — the correctness floor. The daemon and the org Control Plane are explicitly later, additive layers (ADR 0003).

The **walking skeleton** (thinnest end-to-end, build first): a `SessionStart` hook that, before Claude loads any Skill, enumerates the skills directories, resolves each Skill's **Canonical Bundle Hash**, looks up its Verdict in a local cache (scanning on a miss via the existing engine), and **quarantines any Malicious Skill's folder off disk** before its content — including its description — enters context. Everything else layers onto this.

## User Stories

1. As a developer, I want SkillGuard to scan my Skills automatically when I start Claude Code, so that I am protected without remembering to run anything.
2. As a developer, when a Malicious Skill is present, I want it moved out of the way *before* Claude loads it, so that a Prompt-Injection payload in its description never reaches my agent.
3. As a developer, I want to be told exactly what was quarantined and why (the Findings), so that the action isn't a silent black box.
4. As a developer, I want a one-command way to restore a quarantined Skill (and to allow one I trust), so that a false positive isn't a dead end.
5. As a developer, I want repeat sessions to be fast, so that the gate doesn't re-run the LLM on Skills it already judged — it looks up the cached Verdict by hash.
6. As a developer, when a Skill has never been scanned, I want the gate to hold and scan it rather than let it load unchecked, so that an unknown Skill is never a false Clean.
7. As a developer who downloads or generates a Skill *mid-session*, I want the gate to still catch it before Claude acts on it, so that the live session isn't a blind spot. *(PreToolUse layer.)*
8. As a developer, when a Skill is Suspicious, I want to see why and decide myself when I'm present — and I want that decision remembered for that exact Skill, so that I'm not re-nagged. *(Suspicious layer.)*
9. As a developer running Claude unattended, I want a Suspicious Skill blocked rather than silently allowed or hung on a prompt, so that autonomy never means a false Clean. *(Suspicious layer.)*
10. As a developer, I want to install the gate with one command, so that wiring the hook into Claude Code isn't a manual chore.

## Implementation Decisions

**Reuses (already built):** the Detection Engine (`analyze(skill) -> Verdict`), the Skill Loader's canonical normalization, the Verdict/Finding models, terminal rendering.

**New — build now, in staged order:**

- **Canonical Bundle Hash** (`hash.py`) — pure function `skill -> hash` over the Loader's already-normalized files (relative path + LF-normalized bytes, `.git`/OS-junk excluded), sorted and combined. Pulled forward from deferred into this slice: it is the cache key *and* the identity that makes an Allowlist approval evaporate when content changes (ADR 0001).
- **Local Verdict Store** (`store.py`) — a cache under `~/.claude/skillguard/` (JSON to start, SQLite when it earns it) keyed by Canonical Bundle Hash, holding `{tier, findings, engine_version, scanned_at}` plus the local **Allowlist/denylist**. Treated as a *cache of a would-be-shared verdict DB, never the source of truth* (ADR 0001) — records carry `engine_version` so a smarter future engine soft-invalidates stale entries.
- **Quarantine** (`quarantine.py`) — move a Skill folder to `~/.claude/skillguard/quarantine/` (reversible, never delete); `restore`/`allow` commands.
- **Gate core** (`gate/`) — the enforcement logic, independent of which hook calls it: `enumerate skills -> for each: hash -> store lookup -> scan-on-miss -> decide action per Enforcement Posture`. Holds on unknown. This is the seam both hooks call, and later the daemon.
- **`SessionStart` hook** — the pre-load barrier: runs the gate core synchronously, quarantines Malicious before load, returns `additionalContext` (what was quarantined + Findings) and `reloadSkills: true`. **Primary choke point.**
- **CLI additions** — `skillguard install-hook` (writes the hook config into Claude Code settings), `skillguard restore <skill>`, `skillguard allow <skill>`, `skillguard status` (what's cached/quarantined).

**Later layers (same PRD, after the skeleton):**
- **`PreToolUse` hook** (Skill + Bash) — mid-session backstop; hard-`deny` with Findings as the reason.
- **Suspicious posture** — interactive warn-and-confirm when a human is present; deny-and-hold when not; persist approval keyed by hash.
- **Daemon** — ahead-of-time scanning via `watchPaths`/`FileChanged` (in-session) + an OS watcher (between sessions).

**Enforcement Posture default:** Quarantine on Malicious, warn-and-confirm on Suspicious, silent allow on Clean (ADR 0003). Configurable.

**Platform:** Windows-first (developer's environment); the gate core is OS-agnostic, only the hook install and OS watcher are platform-specific.

## Testing Decisions

- **Gate core is the primary seam** — `gate.evaluate(skills_dir) -> [actions]`, tested with a stubbed engine port and a temp skills dir: a Malicious fixture yields a quarantine action; a cached hash yields no re-scan; an unknown hash triggers a scan; an allowlisted hash passes. Deterministic, no live model.
- **Canonical Bundle Hash is a pure function** — same content across CRLF/LF and with/without `.git` junk yields the same hash; changed content yields a different hash (which must drop any Allowlist approval).
- **Quarantine/restore is filesystem-level** — a Malicious Skill folder is moved out and restorable, on a temp dir; nothing is ever deleted.
- **Hook wiring** — a thin integration test that the `SessionStart` hook emits well-formed output (quarantine + `reloadSkills`) given a Malicious skills dir. The engine's own accuracy stays measured by the existing eval harness, not here.

## Out of Scope

- The **Control Plane** — shared verdict DB, org Policy push, dashboard, audit log, fleet visibility, seat management. (The local store's shape anticipates it; the sync layer is not built here.)
- **Non-Claude-Code agents** (Cursor, Codex, etc.) — the Agent Skills open standard makes them a later additive enforcement target.
- **Distribution of the tool itself** beyond `install-hook` (pipx/uv-tool/published package, org push) — parked to a later thread.
- **Sandboxed execution** of bundled scripts (deeper Second-Stage detection) — unchanged from PRD 0001.
- The **Data-Collection / Privacy** Threat Vector (v2).

## Further Notes

- Ordering rationale (inline barrier first, daemon second, Control Plane last) and the verified Claude-Code hook facts live in **ADR 0003**. Cache/identity rationale in **ADR 0001** (now extended with the local-store-is-a-cache decision). Glossary terms — Endpoint Gate, Control Plane, Quarantine, Enforcement Posture, Finding, Allowlist — in `CONTEXT.md`.
- **Re-verify on major Claude Code upgrades:** that `SessionStart` still fires before skill descriptions load (the pre-load barrier depends on it) and that `PreToolUse` still supports hard `deny`.
