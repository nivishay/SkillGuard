# SkillGuard

A security service for developers that detects and blocks malicious AI agent skills before they are trusted and run in a developer's environment.

## Language

**Skill**:
An AI agent skill — a bundle of natural-language instructions (SKILL.md style) plus optionally bundled scripts and resources that an AI coding agent (e.g. Claude Code) will load and act on. This is the artifact SkillGuard scans.
_Avoid_: Plugin, extension, package

**Malicious Skill**:
A Skill that exhibits one or more known Threat Vectors. The verdict SkillGuard is ultimately trying to reach about a Skill.
_Avoid_: Bad skill, virus

**Provenance**:
Where a Skill came from — repo URL, author, stars, age, download source. Recorded as metadata for display and audit, but in v1 it does **not** influence the Verdict (Skill identity and danger are content-based, not source-based).
_Avoid_: Source, origin (when precision matters, use Provenance)

**Detection Engine**:
The component that examines an uploaded Skill and produces a Verdict with supporting evidence. Works in two layers: a **Static Pass** (deterministic pattern/heuristic matching for known-dangerous signals) and an **LLM Judgment** layer (semantic analysis of intent that catches novel or disguised Threat Vectors and writes the human-readable explanation).
_Avoid_: Scanner, algorithm, AI

**Canonical Bundle Hash**:
A Skill's identity for caching. Computed by hashing every declared file (relative path + normalized bytes — LF line endings, VCS/OS junk like `.git`/`.DS_Store` excluded), sorted and combined. Designed so the same Skill downloaded on different machines yields the same hash, enabling one shared Verdict per Skill.
_Avoid_: Checksum, fingerprint, skill ID

**Verdict**:
The result SkillGuard returns for a Skill. One of three tiers:
- **Clean** — no Threat Vectors found; the gate installs silently.
- **Suspicious** — signals present but not conclusive; the gate warns, shows why, and requires explicit confirmation.
- **Malicious** — one or more Threat Vectors confirmed; the gate blocks by default, and the developer may force an override.
_Avoid_: Score, rating (a Verdict is a tier, not a number)

**Threat Vector**:
A named category of harmful behavior SkillGuard looks for. v1 vectors:
- **Prompt Injection** — SKILL.md instructions that redirect the agent to harmful acts (read secrets/keys, exfiltrate data, run destructive commands, disable its own safety, escalate permissions).
- **Malicious Bundled Code** — shipped scripts (.sh/.py/.js/…) that do harm when the agent runs them.
- **Second-Stage / Obfuscation** — looks clean but fetches a payload at runtime or hides intent behind obfuscated/encoded code.
v2 vector (out of scope for now): **Data-Collection / Privacy** — quiet telemetry or over-reading context; grey-area unwanted behavior rather than clear malice.
