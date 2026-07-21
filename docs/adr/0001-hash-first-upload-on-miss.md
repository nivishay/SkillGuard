# Hash-first, upload-on-miss with a shared verdict cache

**Status:** accepted — but the *upload-on-miss* flow is **superseded by ADR 0004** (see amendment below)

> **Amendment (ADR 0004).** This ADR assumed a *thin client + server-side engine*: on a miss the
> client uploads content and the server scans. The project instead ships a **fat gate with a
> local Detection Engine** — each gate scans on its own machine and pushes only Verdict
> *metadata* (`hash, tier, findings, engine_version, scanned_at`) to the Control Plane; the
> Skill's **content never leaves the machine**, on hit *or* miss. The hash-first lookup, the
> shared verdict cache, the network effect, and version-stamping below all still stand — only
> "upload content on miss → server scans" is replaced by "scan locally → push metadata." Central
> content upload survives only as an *optional* future thin-client / self-hosted central-scan
> tier. The trade-off this creates (the Control Plane can no longer independently verify a pushed
> verdict) is recorded in ADR 0004.

To scan an AI agent skill for malicious behavior, the client first computes a **Canonical Bundle Hash** of the skill and asks the API whether a Verdict already exists for that hash. On a cache **hit**, the Verdict is returned instantly and the skill's content never leaves the developer's machine. Only on a cache **miss** does the client upload the skill's content for full analysis, after which the Verdict is stored keyed by hash for everyone. *(Superseded — see amendment above: the gate now scans locally on a miss and uploads no content.)*

We chose this over "always upload" (simpler, but every skill's content leaves the machine even when already known) and "fully local" (max privacy, but no shared cache and much weaker detection since the heavy LLM/static analysis lives server-side).

## Consequences

- **Network effect / moat:** the more skills scanned, the higher the cache hit-rate; a skill scanned once benefits every later developer who pulls the same one.
- **Canonicalization is load-bearing:** the shared cache only works if "same skill on different machines" reliably yields the same hash. The hash therefore normalizes line endings to LF and excludes VCS/OS junk (`.git`, `.DS_Store`, editor files). Without this, cross-platform byte differences (notably Windows CRLF) collapse the hit-rate to near zero. See the **Canonical Bundle Hash** term in `CONTEXT.md`.
- **Privacy caveat to revisit:** on a cache miss, full content is uploaded. Proprietary/internal skills will always miss the shared cache (they're unique), so their content is always sent. A future private/self-hosted tier may be needed for such users.
- **Verdicts are version-stamped.** Each cached Verdict records the Detection Engine version that produced it. A cache hit from an outdated engine is treated as a soft miss and re-scanned (background where possible), so engine improvements propagate without discarding the cache. Forced revocation of a specific verdict is deferred past v1.
- **The Endpoint Gate's local store is a *cache* of this shared verdict DB — never the source of truth — from day one.** Even in solo mode (no server yet), the gate persists Verdict records (keyed by Canonical Bundle Hash, version-stamped) plus the local Allowlist/denylist as "cached results of a scan I ran," not as canonical facts. This keeps the solo→org path a straight line: when the Control Plane appears, the lookup becomes local-cache → Control Plane → scan-and-upload (exactly the hash-first/upload-on-miss flow above), and org **Policy** (allowlist/denylist/Enforcement Posture) is pulled down and overrides local — with no rewrite of the local store's shape. Chosen over a solo-only local store that would need a schema/semantics refactor once org arrives. See ADR 0003 and `CONTEXT.md`.
