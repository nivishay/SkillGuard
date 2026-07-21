# PRD: Control Plane — herd-immunity vertical slice + fleet dashboard

## Problem Statement

The Endpoint Gate protects one machine at a time, and each machine re-scans every Skill it
encounters — even a Skill the machine *next to it* already judged a minute ago. There is no shared
memory across a developer's fleet: the same Malicious Skill is re-discovered from scratch on every
laptop, and no one has a single place to see *"which Skills are running across all my machines, and
what got quarantined where."* ADR 0003 always named the **Control Plane** as the layer above many
Endpoint Gates; the local Verdict Store was built from day one as "a cache of a would-be-shared
verdict DB" (ADR 0001). This slice makes that shared DB real — so **one machine learns and the whole
fleet is immune** — and gives it a face.

## Solution

A central **Control Plane** service that holds the authoritative shared **Verdict** DB and a fleet
activity feed, plus the gate-side wiring to consult and feed it. Each gate keeps its **local
Detection Engine** (the fat-gate model, ADR 0004): it scans on its own machine and shares only
Verdict *metadata* — the Skill's content never leaves the machine.

The **herd-immunity loop** (the thesis): on a **local** Verdict Store miss, the gate asks the
Control Plane *before* scanning. If the Control Plane already knows this exact Skill (by **Canonical
Bundle Hash**, produced by an engine `engine_version >=` the gate's own), the gate **adopts** that
Verdict and enforces it **without running its own engine**. Only if the Control Plane is also unaware
does the gate scan locally and **publish** the result upward — so the *next* machine's lookup hits.
If the Control Plane is unreachable, the gate falls back to a local scan and never fails open (ADR
0004). The **dashboard** is how you watch a Verdict propagate: a machine enforcing an **adopted**
Verdict it never computed is herd immunity made visible.

The **walking skeleton** (thinnest end-to-end, build first): a `GET /verdicts/{hash}` +
`POST /report` server backed by Postgres, a nullable `ControlPlanePort` injected into the existing
gate `evaluate()`, and a one-page React dashboard reading `GET /fleet`. Demo: two gate instances on
`localhost` against one local Control Plane — instance A scans a Malicious Skill and publishes;
instance B **adopts** and quarantines without scanning; the dashboard shows it quarantined on both,
one **scanned**, one **adopted**.

## User Stories

1. As a developer with several machines, I want a Skill scanned on one machine to be known to the
   others, so that the same Skill is scanned **once per fleet, not once per machine**.
2. As a developer, when a machine meets a Skill the fleet already judged Malicious, I want it
   quarantined **without a local re-scan**, so that immunity is instant and free.
3. As a developer, I want my Skills' **content to never leave my machine** — only a hash and a
   Verdict summary — so that proprietary Skill source stays private.
4. As a developer, when the Control Plane is unreachable, I want the gate to scan locally and still
   protect me, so that the central service is an accelerator, never a single point of failure.
5. As a security-minded lead, I want one dashboard showing every Skill across the fleet, its Verdict,
   and *"quarantined on 3 of 5 machines,"* so that fleet posture is one pane of glass.
6. As that lead, I want to see **how** each machine knew a Verdict — **scanned**, **adopted**, or
   **cache** — so that I can watch immunity spread, not just see a static list.
7. As an operator, I want the Control Plane to keep only the higher-`engine_version` Verdict per
   Skill, so that a smarter engine's judgment supersedes an older one across the fleet.

## Implementation Decisions

**Architecture: fat gate, local engine, metadata-only (ADR 0004, supersedes ADR 0001's upload flow).**
The engine runs on the endpoint; the Control Plane is a lightweight Verdict DB + dashboard with **no
server-side LLM**. Gates share `{Canonical Bundle Hash, tier, findings, engine_version, scanned_at}`
plus per-machine Sighting fields — never Skill file contents.

**Trust: adopt all tiers, hash-bound and engine-version-gated (ADR 0004).** A gate adopts a Control
Plane Verdict — **Clean included** (Clean is the common case and where the compute savings live) —
only for the exact hash and only when `remote.engine_version >= local`. The residual "compromised
authorized writer" threat is a Control-Plane **write-authentication** problem, deferred as future
work.

**Reuses (already built):** the Detection Engine (`analyze`), the Skill Loader + **Canonical Bundle
Hash**, the `Verdict`/`Finding` models (they *are* the wire contract — serialized to/from JSON), the
gate `evaluate()` core, the local Verdict Store.

**New — gate side:**
- **`ControlPlanePort`** (`gate/core.py`) — mirrors the existing `EnginePort`/`AllowlistPort`
  Protocols: `lookup(bundle_hash) -> VerdictRecord | None` and `publish(...)`. Injected into
  `evaluate()`, **nullable with default `None`** — `cp=None` means standalone-local (the ADR-0004
  fail-safe; the existing deterministic test suite keeps passing untouched).
- **CP query slotted into `evaluate()`** — between the local Store miss and the local scan
  (`core.py:143–161`): local miss → `cp.lookup` → adopt if engine-version-gated → else scan → 
  `cp.publish`.
- **`store.put_record(record)`** (`store.py`) — persist an **adopted** record *preserving* the
  Control Plane's original `engine_version` and `scanned_at` (the current `put` stamps `now`, which
  would destroy the provenance the engine-version gate depends on).
- **`Source` on the decision** — `scanned | adopted | cache`, so the Sighting can report how the
  machine knew the Verdict.
- **`cp_client.py`** (`skillguard/`) — the concrete HTTP adapter implementing `ControlPlanePort`.
- **Enrollment (minimal)** — a stable random `machine_id` persisted under `~/.claude/skillguard/`,
  a human `machine_label` (hostname or `SKILLGUARD_MACHINE_NAME`), and a `control_plane_url` config
  value. Single implicit org, no auth.

**New — Control Plane service (its own deployable):**
- **`control_plane/` top-level package** — a **FastAPI + Uvicorn** app importing `skillguard.models`
  for the wire contract. Endpoints:
  - `GET /verdicts/{hash}` → `VerdictRecord` or 404 (herd-immunity read).
  - `POST /report` → 202; one call per gate evaluation, carrying **Verdict + Sighting** together.
    Server **upserts** the `verdicts` row by hash (keeping the higher `engine_version`) and
    **appends** a `sightings` row.
  - `GET /fleet` → aggregated per-Skill + per-machine view for the dashboard.
  - `GET /` → the built React bundle (static).
- **Postgres** (SQLAlchemy + Alembic, via **docker-compose**):
  - `verdicts (bundle_hash PK, tier, findings jsonb, engine_version, scanned_at, first_seen)`
  - `sightings (id PK, machine_id, machine_label, bundle_hash FK, skill_name, tier, action, source,
    seen_at)` — append-only.
- **Dashboard** — **React + TypeScript (Vite)**, built and served as static assets *by FastAPI*
  (one origin, no CORS, one process for the demo; Vite hot-reload against the API during dev).

**Two stores, on purpose:** the Control Plane uses **Postgres** (a cloud server); the **endpoint gate
store stays embedded** (JSON/SQLite) — an EDR endpoint agent must not require a Postgres install.

## Testing Decisions

- **The CP query in `evaluate()` is the primary seam** — with a **stubbed `ControlPlanePort`** and a
  stubbed engine, on a temp skills dir: a CP `lookup` hit yields an **adopted** decision with **no
  engine call** (`scanned=False`, `source=adopted`); a CP miss triggers a local scan followed by a
  `publish`; a lower-`engine_version` remote is **not** adopted (re-scan); `cp=None` behaves exactly
  as today. Deterministic, no server, no live model.
- **Engine-version gate is a pure predicate** — adopt iff `remote.engine_version >= local`; tested
  across equal/newer/older.
- **`store.put_record` preserves provenance** — an adopted record round-trips the original
  `engine_version`/`scanned_at`, not `now`.
- **Control Plane endpoints** — against a test Postgres (or a SQLite/transactional test harness):
  `POST /report` upserts one `verdicts` row per hash (higher `engine_version` wins) and appends one
  `sightings` row; `GET /verdicts/{hash}` round-trips; `GET /fleet` aggregates "N of M machines."
- **Herd-immunity integration test** — two gate instances share one Control Plane: A scans + publishes
  a Malicious fixture, B adopts and quarantines with **no engine call**; the fleet view reflects both
  Sightings with the right `source`.
- Detection *accuracy* stays measured by the existing eval harness, not here.

## Out of Scope

- **Write-authentication / enrollment security** — tokens, device certs, SSO device-flow, and the
  rogue-writer defense (ADR 0004). The slice has **no auth**.
- **Multi-tenancy** — org boundaries, per-org isolation, seat management. Single implicit org.
- **Org Policy push** — central allowlist/denylist/Enforcement-Posture pushed down and overriding
  local. (The local store already anticipates it; the sync isn't built here.)
- **Optional central content upload** — the thin-client / self-hosted central-scan tier that ADR
  0001's original flow becomes; not built.
- **Sighting dedup** — append-only for now; real dedup (machine+hash+session) is future.
- **Live push to the dashboard** (websockets) — the dashboard polls `GET /fleet`.
- **Hosting/deploy of the real cloud Control Plane** and **packaging/distribution** of the gate —
  parked (packaging is the deferred "show-off polish").

## Further Notes

- Trust and content-privacy rationale live in **ADR 0004** (which supersedes ADR 0001's upload-on-miss
  flow; ADR 0001 carries the amendment). Enforcement ordering (gate → daemon → Control Plane) in **ADR
  0003**. New glossary terms — **Sighting**, **Source** — plus **Control Plane**, **Verdict**,
  **Canonical Bundle Hash**, **Allowlist** — in `CONTEXT.md`.
- **The demo collapses the real topology onto one laptop:** production is *one* cloud Postgres +
  Control Plane serving *many* light gate machines; the demo runs Postgres + the Control Plane + several
  gate instances locally to stand in for the cloud and the fleet. State that when presenting.
- **Re-verify on major changes:** that the `Verdict`/`Finding` model shape stays the shared wire
  contract (gate and Control Plane must not drift), and that the engine-version comparison uses proper
  version ordering (`packaging.version`), not string compare.
