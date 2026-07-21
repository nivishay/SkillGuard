# The Endpoint Gate enforces via hooks + quarantine, not a wrapper or a marketplace

**Status:** accepted

SkillGuard's integration surface is an **Endpoint Gate**: an involuntary checkpoint on the developer's machine that runs the Detection Engine at the moment a Skill would be trusted, and enforces the Verdict. We chose this over a voluntary `skillguard add` wrapper (which only protects developers who *choose* to route through it — missing the careless developer who `git clone`s a Skill or clones a repo that already contains one) and over a **marketplace/curated catalog** (which only governs Skills installed *from* it, and is blind to everything pulled from anywhere else). The product is therefore shaped like **EDR for Skills** (a resident gate + a central Control Plane), not an app store. See `CONTEXT.md`: **Endpoint Gate**, **Control Plane**, **Quarantine**, **Enforcement Posture**.

## Decision

**Analyze on arrival, enforce on load.** The expensive analysis (Static Pass + LLM Judgment) runs *once per unique Skill content*, keyed by **Canonical Bundle Hash**, and its Verdict is cached. Enforcement at load time is a fast cache lookup, never a re-scan. This is why the hash/cache (ADR 0001), deferred in the engine-only slice, is a prerequisite for the gate.

**Two enforce points against the real Claude Code hook API** (verified against the hooks reference):

1. **`SessionStart` hook — the primary, pre-load barrier.** `SessionStart` fires *before* skill/agent context is loaded, so the hook enumerates the skills directories, hashes each Skill, looks up its Verdict (scanning synchronously on a cache miss), and — for a **Malicious** Verdict — **quarantines the Skill's folder off disk before Claude reads it**, then returns `reloadSkills: true`. This is the only way to defeat **Prompt Injection carried in a Skill's *description*** (which loads into context at session start, before any tool call). The hook holds boot until it returns, which realises the "hold on unknown" rule.

2. **`PreToolUse` hook (Skill + Bash) — the mid-session backstop.** For a Skill that arrives *during* a live session (including one the agent downloads itself), `PreToolUse` can hard-`deny` the tool call with the **Findings** as the reason Claude sees. This catches body-based injection (Skill body loads only on invocation) and Malicious Bundled Code (runs via Bash).

**Fail toward blocking, never a false Clean.** An **unknown** Verdict (never scanned, or scan still in flight) is treated as *not cleared*: block/hold until the Verdict lands, rather than allow. This extends the existing engine constraint to the gate.

**Enforcement Posture is a dial, not hard-coded.** Shipped default: **Quarantine** on Malicious, **warn-and-confirm** on Suspicious (interactive only — see below), silent allow on Clean. Turning auto-quarantine on by default is *earned* by the eval harness's measured false-positive rate on Malicious.

**Suspicious requires a human, and degrades safely when there isn't one.** When a human is present (session start / interactive), the gate warns with the Findings and asks for an explicit allow. When no human is present (autonomous/background run), it must not silently allow (false Clean) and must not hang waiting — so Suspicious degrades to **deny-and-hold** until a human resolves it. An approval **persists keyed by Canonical Bundle Hash** (the seed of the **Allowlist**), so it is a one-time decision per Skill-version; if the content changes, the approval evaporates.

**Inline barrier first, daemon second.** The inline hook barrier is built first because it is the correctness floor: it *cannot* silently fail (either it runs at the choke point or the session doesn't start), and it is the thinnest end-to-end proof of the gate. A resident **daemon** (ahead-of-time scanning to keep boot fast and to shrink the arrival→quarantine race, plus catching mid-session arrivals) is the immediate next layer — not omitted, just second. The daemon can partly reuse Claude Code's native `watchPaths`/`FileChanged` for the in-session case, needing an OS-level watcher only for the between-sessions gap.

## Consequences

- **The gate physically moves files** (quarantine). This is more invasive than a warning and is justified only because it is Malicious-only, reversible (moved to a holding area, never deleted; restorable and overridable), always surfaced with its Findings, and gated on the eval false-positive rate. Modeled on antivirus/EDR quarantine.
- **First-encounter latency.** A never-before-seen Skill pays a synchronous scan at the enforce point (slow boot after adding many new Skills). The cache makes this one-time; the daemon layer removes it from the common path.
- **The `SessionStart`-before-load guarantee is load-bearing.** If a future Claude Code change loaded skill descriptions before `SessionStart`, the pre-load barrier would regress to next-session-only, and the daemon (quarantine between sessions) would become the primary defense for the description surface. Re-verify on major Claude Code upgrades.
- **Enforcement is Claude-Code-shaped for now** but the analysis core is agent-agnostic; Skills follow the Agent Skills open standard, so other agents' skill directories are a later, additive enforcement target.
