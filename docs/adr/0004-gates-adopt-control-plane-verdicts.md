# Gates adopt Control Plane Verdicts, hash-bound and engine-version-gated

**Status:** accepted — supersedes the *upload-on-miss* flow of ADR 0001

**The gate scans locally; only Verdict metadata is shared.** Each gate runs the full Detection
Engine on its own machine. On a Control Plane miss it scans locally and pushes up only
`{Canonical Bundle Hash, tier, findings, engine_version, scanned_at, machine_id}` — **never the
Skill's file contents**, on hit or miss. This replaces ADR 0001's "upload content on miss →
server scans" (thin-client) with a fat-gate model: privacy (source never leaves the machine) and
a lightweight Control Plane (a Verdict DB + dashboard, no server-side LLM) are bought at the cost
that the Control Plane cannot independently re-scan to verify a pushed verdict — see the residual
"compromised authorized writer" threat under Consequences. Central content upload survives only
as an optional future thin-client / self-hosted central-scan tier.

The **Control Plane** holds the authoritative shared **Verdict** store — the real thing the
local Store has always been "a cache of" (ADR 0001). On a **local** cache miss, a gate queries
the Control Plane *before* running its own engine, and **adopts** the Control Plane's Verdict —
of **any tier, Clean included** — writing it into the local Store and enforcing it without a
local scan. This is what makes the fleet immune once *one* machine has scanned a given Skill:
each unique Skill is scanned once *per fleet*, not once *per machine*. We adopt Clean too
(not just Malicious/Suspicious) because Clean is the common case and therefore where nearly all
the redundant compute lives — caching only the threat tiers would throw away the main benefit.

## What makes adopting a remote Verdict safe

Adoption is trusted only under two guards, both of which the existing model already provides:

1. **Content-hash binding.** A Verdict is adopted only for the *exact bytes* that were scanned,
   because it is keyed by **Canonical Bundle Hash**. Any change to the Skill's content yields a
   different hash → no hit → re-scan. This is the same mechanism that makes an **Allowlist**
   approval evaporate when content changes; a Clean Verdict can never be reused to smuggle in
   swapped-out content.
2. **Engine-version gating.** A Verdict is adopted only if it was produced by an engine
   `engine_version >= ` the gate's own. A Clean from an older, weaker engine is *not* trusted and
   is re-scanned locally (the "soft-invalidation" the Store records were built for, ADR 0001).
   Wall-clock age is at most a secondary TTL safety net, not the primary signal — a *fresh* wrong
   Verdict is still wrong; a *newer engine* is the principled reason to redo one.

## Considered Options

- **Asymmetric trust** (adopt Malicious/Suspicious, always re-scan on Clean). Safe against a
  poisoned-Clean, but re-scans every Clean Skill on every machine — it caches the rare case and
  discards the common one, defeating the compute win. Rejected.
- **Report-only** (gates only push, never adopt; the dashboard shows propagation but each machine
  still scans). Safest, but there is no herd immunity — machine B still pays the full scan.
  Rejected as the *mechanism*, though the dashboard it implies is kept as the visible surface.
- **Full unconditional trust** (adopt whatever the Control Plane says, no guards). Simplest, but a
  stale or wrong Verdict propagates unchecked. Rejected in favor of the two guards above.

## Consequences

- **The residual threat is a compromised *authorized* writer**, not the adoption rule: a gate that
  is enrolled and authenticated but malicious could push a fake Clean for a genuinely malicious
  Skill. Refusing to adopt Clean does not fix this (an attacker who owns a gate has better
  options). It is a **Control Plane write-authentication / integrity** problem — only enrolled,
  authenticated gates may write, and the Control Plane is trusted org infrastructure, not
  peer-to-peer. That auth/integrity layer is future work, explicitly out of the first slice.
- **The Control Plane is an accelerator and aggregator, never a dependency.** If it is unreachable,
  the gate falls back to a local scan — it must never fail *open* (never skip scanning because it
  could not ask). The correctness floor stays local; the Control Plane only removes redundant work
  and shares knowledge.
- **The local Store's shape was already right.** Records keyed by Canonical Bundle Hash carrying
  `{tier, findings, engine_version, scanned_at}` are exactly what the Control Plane exchanges — the
  query-on-miss and push-on-scan paths move these same records up and down. See `CONTEXT.md`:
  **Control Plane**, **Verdict**, **Canonical Bundle Hash**, **Allowlist**.
