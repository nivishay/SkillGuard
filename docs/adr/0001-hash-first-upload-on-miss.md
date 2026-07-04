# Hash-first, upload-on-miss with a shared verdict cache

**Status:** accepted

To scan an AI agent skill for malicious behavior, the client first computes a **Canonical Bundle Hash** of the skill and asks the API whether a Verdict already exists for that hash. On a cache **hit**, the Verdict is returned instantly and the skill's content never leaves the developer's machine. Only on a cache **miss** does the client upload the skill's content for full analysis, after which the Verdict is stored keyed by hash for everyone.

We chose this over "always upload" (simpler, but every skill's content leaves the machine even when already known) and "fully local" (max privacy, but no shared cache and much weaker detection since the heavy LLM/static analysis lives server-side).

## Consequences

- **Network effect / moat:** the more skills scanned, the higher the cache hit-rate; a skill scanned once benefits every later developer who pulls the same one.
- **Canonicalization is load-bearing:** the shared cache only works if "same skill on different machines" reliably yields the same hash. The hash therefore normalizes line endings to LF and excludes VCS/OS junk (`.git`, `.DS_Store`, editor files). Without this, cross-platform byte differences (notably Windows CRLF) collapse the hit-rate to near zero. See the **Canonical Bundle Hash** term in `CONTEXT.md`.
- **Privacy caveat to revisit:** on a cache miss, full content is uploaded. Proprietary/internal skills will always miss the shared cache (they're unique), so their content is always sent. A future private/self-hosted tier may be needed for such users.
- **Verdicts are version-stamped.** Each cached Verdict records the Detection Engine version that produced it. A cache hit from an outdated engine is treated as a soft miss and re-scanned (background where possible), so engine improvements propagate without discarding the cache. Forced revocation of a specific verdict is deferred past v1.
