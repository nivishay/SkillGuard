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

**Endpoint Gate**:
The involuntary checkpoint that runs on an individual developer's machine and invokes the Detection Engine at the moment a Skill would otherwise be trusted or run (e.g. via an agent hook or a watch on the skills directory). Unlike a voluntary wrapper command, it catches Skills no matter how they arrived — `git clone`, manual copy, or riding inside a cloned project repo — and enforces the Verdict (block/warn/allow) locally. It is the same artifact in both the solo-developer product and the organization product.
_Avoid_: Scanner, wrapper, plugin

**Control Plane**:
The central organization-facing service that sits above many Endpoint Gates. It distributes/ensures the gate is present on every developer's machine, enforces org **Policy** (which Verdict tiers and which specific Skills are allowed), aggregates each Skill's Verdict once and shares it across the fleet, records an audit trail, and shows which Skills are in use across the organization. It governs; it does not itself distribute a curated catalog (SkillGuard is EDR for Skills, not a marketplace).
_Avoid_: Dashboard, marketplace, registry, server

**Quarantine**:
The default enforcement action the Endpoint Gate takes on a **Malicious** Verdict: it moves the offending Skill's folder out of the scanned skills directory into a holding area so the agent never loads it (crucially, so a Prompt-Injection payload in the Skill's description never enters the agent's context). Quarantine is reserved for the Malicious tier only, is always reversible (moved, never deleted; restorable and overridable), and is always surfaced to the developer with the reason — never silent. Modeled on antivirus/EDR quarantine.
_Avoid_: Delete, remove, block (block is vaguer — quarantine is the specific reversible move)

**Enforcement Posture**:
The configurable mapping from each Verdict tier to the action the Endpoint Gate takes (e.g. quarantine / warn-and-confirm / deny-tool-call / allow). It is a dial, not hard-coded: the shipped default is quarantine-on-Malicious, warn-and-confirm-on-Suspicious, silent-allow-on-Clean; a nervous developer may pick a non-destructive posture (weaker, since only removing a Skill from the scanned directory can stop injection-via-description); an organization sets a stricter posture centrally via **Policy** in the Control Plane. Turning on auto-quarantine by default is earned by the eval harness's measured false-positive rate on Malicious.
_Avoid_: Mode, setting, rule

**Finding**:
A single piece of evidence inside a Verdict: which **Threat Vector** was detected, a short human-readable explanation, and a location (which file and where in it). Findings are *why* a Verdict is what it is. The Endpoint Gate must surface a Skill's Findings to the developer at the warn/confirm and quarantine moments — a tier without its evidence is not acceptable.
_Avoid_: Alert, hit, match

**Sighting**:
A single machine's encounter with a Skill at a moment in time: which machine, which Skill (by **Canonical Bundle Hash** and name), the **Verdict** tier applied, the enforcement **Action** taken, when, and the **Source** of the Verdict. Distinct from a Verdict, which is deduped per Skill *content* across the whole fleet and carries no machine — a Verdict is *what is known about a Skill*; a Sighting is *what happened on one machine*. Sightings are the **Control Plane**'s fleet activity feed: the per-machine, per-encounter rows that let the dashboard show "quarantined on 3 of 5 machines." A Verdict is upserted once per hash; a Sighting is appended once per encounter.
_Avoid_: Event, log entry, scan (a scan is one Source of a Sighting, not the Sighting itself)

**Source**:
How a machine came to know a Skill's Verdict at a given **Sighting** — one of: **scanned** (this machine ran its own Detection Engine, a local cache miss with no Control Plane hit), **adopted** (the machine took the Verdict from the **Control Plane** without scanning — herd immunity in action), or **cache** (a hit in the machine's own local Verdict Store from an earlier encounter). Source is what makes herd immunity *visible*: an **adopted** Sighting is a machine enforcing a Verdict it never computed itself.
_Avoid_: Origin, method (reserve Provenance for where a *Skill* came from; Source is how a *Verdict* reached a machine)

**Allowlist**:
The set of persisted developer/organization approvals that let an otherwise-gated Skill through. Each approval is keyed by the Skill's **Canonical Bundle Hash**, so it applies to that exact content only — if the Skill's content changes, the approval evaporates and the Skill is re-evaluated (an approved name cannot be used to smuggle in swapped-out malicious content). Locally it is the memory of "the developer already confirmed this Suspicious Skill"; at organization scale it is held centrally as part of **Policy** in the Control Plane. Its opposite, an explicit block regardless of Verdict, is a denylist.
_Avoid_: Whitelist, exceptions, ignore list

**Threat Vector**:
A named category of harmful behavior SkillGuard looks for. v1 vectors:
- **Prompt Injection** — SKILL.md instructions that redirect the agent to harmful acts (read secrets/keys, exfiltrate data, run destructive commands, disable its own safety, escalate permissions).
- **Malicious Bundled Code** — shipped scripts (.sh/.py/.js/…) that do harm when the agent runs them.
- **Second-Stage / Obfuscation** — looks clean but fetches a payload at runtime or hides intent behind obfuscated/encoded code.
v2 vector (out of scope for now): **Data-Collection / Privacy** — quiet telemetry or over-reading context; grey-area unwanted behavior rather than clear malice.
