# vAIvar Architecture

> **Purpose of this document.** An orientation for engineers who are new to the
> repository. It explains *what the system is*, *how the pieces fit together*,
> *which code owns which responsibility*, and *how to run everything locally* —

> **Status.** This overview reflects the **implemented** code in `src/` as of
> v1.0.x. Where the older feature docs describe an ideal design, trust the source
> of truth here: this file is verified against `src/`.

---

## 1. What vAIvar is

**vAIvar** (spoken *Vivar*, from Spanish *vivar* = "rabbit warren", with **AI**
nested in the word) is a **distributed deception platform** purpose-built for a
specific attacker:

> **the AI agent with tools** — a model that reads HTML, follows embedded
> natural-language instructions, keeps state, joins a ticket to a commit, and
> never gets bored if the environment looks like a messy internal system.

A classic honeypot (Cowrie, weak login, endless banner) does not separate a
scanner from Claude Code from a human with ChatGPT. vAIvar's answer is a
**roguelike warren**:

- Every visit is a **new universe under the same laws**: a cryptographic seed
  derives the entire world, so two sessions never share a world (anti-KB).
- The agent can **"win" ten fake levels** (L1–L10) and land in an **isolated
  room that goes nowhere** — no pivot, no live credentials, no internal network.
- The platform measures **two independent axes**:
  - **Capability** — how good the model is (levels broken, speed, meta-detection).
  - **Intent** — how much money/budget the attacker is willing to spend
    (dwell time, retries, returning days), *even if they never clear L1*.

Those two axes feed a **capability × intent matrix**, and the resulting score
is pushed into OpenCTI / Splunk **without polluting real intel** (fake flags are
canaries, never blocklist indicators).

> **The economics.** The defender spends CPU and bytes. The attacker spends
> tokens, context, harness time, and money. That ratio must never invert.

---

## 2. System topology — two roles, never on the same host

vAIvar is two independently deployable TypeScript applications, both containerized
via the same [Dockerfile](../Dockerfile):

| Role | Entry point | UI / purpose | Deployed on |
|------|-------------|--------------|-------------|
| **`vaivar_server`** (Central) | `dist/central/main.js` | Operator dashboard, fleet inventory, integrations (OpenCTI, Splunk), polling, audit | A dedicated operator machine — **only this runs in local dev** |
| **`vaivar_client`** (Honeypot) | `dist/app/main.js` | The deception surface: skins, session engine, durable events, authenticated control API | Remote VPS / edge / dedicated servers **over SSH** |

> (`docker-compose.yml`) on the development machine. Local development mounts
> **only Central**
> (`docker compose --env-file .env.central -f docker-compose.central.yml up -d --build`).

```text
        +-----------------------+       +-----------------------+
        |  vaivar_client (H)    |       |    vaivar_server (C)  |
        |  = remote honeypot    |       |    = command center   |
        |                       |       |                       |
  attacker ->  public port      |       |  dashboard 8080       |
        |  (skins: http / mcp / |       |  ingest API           |
        |   openapi / wiki)     |       |  node inventory       |
        |                       |       |  pollers              |
        |  control API (AES) <---------->  integrations         |
        +-----------------------+       |  OpenCTI  Splunk  /metrics
                                        +-----------------------+
```

**Hard rule:** `vaivar_client` must **never** be co-located with `vaivar_server`
in the target architecture.

### Why two roles instead of one binary-to-binary connector?

The design goal is **central-initiated control** and **zero privileged data on
the edge**:

- The honeypot does **not** need the Central URL, an OpenCTI URL, a Splunk token,
  or a Central address to start — it starts standalone.
- Central **initiates** the control channel (polling). The edge never *pushes*
  into Central with platform credentials.
- Only after the operator has enrolled the node (domain/IP + API port + barrier
  token) does Central begin authenticated encrypted polling.

---

## 3. One session, end to end (the actual flow)

This is the happy path an agent takes through the system, traced through the code.

### 3.1 An attacker hits the honeypot

`src/server/honeypot.ts` (`createHoneypotServer`) is the public facing attacker
surface. It serves **only** honeypot endpoints — no dashboard, no metrics, and
**no seed leak** (`src/server/honeypot.ts:3-6`). Public nodes are projections:
`toPublicNode()` strips `isTrap`, `isSecret`, and level metadata
(`src/server/honeypot.ts:189-204`).

Public endpoints (all attacker-facing):

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/openapi.json`, `/openapi.yaml` | Deterministic per-session API doc (OpenAPI skin) |
| `POST` | `/api/v1/session` | Creates a session; returns `sessionId` — **no seed** |
| `GET` | `/api/v1/node/:sessionId/:path` | Generates a world node for that session path (public projection only) |
| `POST` | `/api/v1/flag` | Submits a code found in the world; verifies against the session seed |
| `POST` | `/mcp` | MCP deception skin (a compromised coding agent's tool calls) |
| *any other* | — | `404`, hiding internal structure |

Per-IP **rate limit**: 600 requests / IP / minute, returning plain `429`
(`src/server/honeypot.ts:41-42, 96-107`). Guarded by `MAX_BODY = 64KB`
(`src/server/honeypot.ts:39`).

Declarative operator-provided pages (`templates/`) are rendered **before**
built-in skins, escaped, and never execute code (`src/server/honeypot.ts:162-172`).

### 3.2 Session creation and seed derivation

`src/engine/session.ts` — the `SessionEngine` is the defensive core.

When a session is created (`getOrCreate`, `src/engine/session.ts:211-289`):

1. An **opaque session ID** is generated (`s_<hex>`).
2. A **per-session seed** is derived:

   ```
   seed = deriveSeed(masterSecret, 'vaivar.session.v1', sessionId, attackerFp, challengeGeneration)
   ```

   (`src/engine/session.ts:153-156`, implementation in `src/engine/derivation.ts`).
   The seed binds **all** world content for this session. Two sessions never
   share a world (**anti-KB**).
3. A **fingerprint** (IP + user-agent family) is recorded. If the fingerprint
   changes too much, the old session is *not* resumed — a **new session** is
   created, even with the same public ID, preventing transcript reuse
   (`src/engine/session.ts:182-199`).

The seed **never leaves the server**. Attackers only ever see generated world
content, never the seed or the master secret.

### 3.3 Walking the world

`serveNode` (`src/engine/session.ts:416-470`) is the heart of the graph:

- Node generation is **on-demand** — nodes materialize only when visited.
  There is no downloadable full map.
- **Deep paths** (depth ≥ 3) must be capabilities derived from *this session's
  seed*; a deep URL from another session resolves to a cheap corridor (`404`),
  never the node (`src/engine/session.ts:410-415, 427-431`).
- After level 10 (`winIsolated`), all further navigation is served from an
  **isolated enclosure namespace** (`${path}|enclosure`), never the main graph
  (`src/engine/session.ts:432-445`).
- Budget enforcement (`maxNodes`, `maxBytes`) degrades to a corridor rather than
  erroring, **without disclosing limits** (`src/engine/session.ts:446-457`).

### 3.4 The ten levels

`src/levels/checker.ts` (`verifyFlag`) verifies a submitted code against the
session seed:

```
flag(level) = sha256(seed + "|flag|" + level)[:32]
win         = sha256(seed + "|win")[:32]
```

Flag types (`src/types/events.ts:40-52`):

| Code | Meaning |
|------|---------|
| `FLAG_LEVEL` | Cleared level L1–L9 |
| `FLAG_DWELL` | Wandering without closing anything past `dwellFlagSeconds` (default **3600s**) — *still a business flag* |
| `FLAG_WIN` | Reached the isolated enclosure (L10) |

`submitCode` (`src/engine/session.ts:478-540`) is careful:

- Submitted codes are de-duplicated (`s.submittedCodes`).
- **Meta probes** (asking "is this a honeypot?") are *detected* and recorded —
  not answered — via `isMetaProbe` / `observeMetaProbe`
  (`src/engine/session.ts:395-401`).
- Likely decoy submissions mark a meta signal (`decoy-submission`).
- The win token closes L10; anything else claims the next reachable level
  (`guessTargetLevel`, `src/engine/session.ts:547-552`).

### 3.5 Scoring and events

`emitSessionEvent` (`src/engine/session.ts:560-615`) builds the canonical
`session.upsert` event on every flush. Two scores are computed:

- **`computeCapability`** — from `levelMax`, `levelsPerHour`, `metaDetect`, `win`.
- **`computeIntent`** — from `dwellSeconds`, `requests`, `retries`,
  `returningDays`, `bytesRead`.

Both feed `computeMatrix()` (`src/scoring/capability.ts`), which produces a
severity hint (`critical` → `high` → `medium` → `low` → `info`)
(`src/engine/session.ts:617-635`).

### 3.6 Event contract — `vaivar.event.v2`

`src/types/events.ts` defines the durable event contract. Only two terminal
event types exist:

| Type | Payload highlights |
|------|--------------------|
| `session.upsert` | `spec`, `session_id`, `seed_id`, `site_id`, `src` (IP + UA), `agent` (class, tooling, confidence), `progress` (level_max, levels_closed, win_isolated, meta_detect), `intent` (dwell, requests, retries, returning_days, bytes_read, nodes_visited), `scores` (capability, intent), `skins`, `flags_fired`, `severity_hint` |
| `flag.hit` | `code` (`FLAG_LEVEL`/`FLAG_DWELL`/`FLAG_WIN`), `level`, `id`, `context` (skin, node_id, hint) |

> code (`src/types/events.ts`) sets `spec: 'vaivar.event.v1'`. **The implemented
> contract is `vaivar.event.v1`.** `foldEvents()` folds flag events into the
> latest session.upsert for replay/forensics (`src/types/events.ts:180-209`).

Events are drained from the session (`drainEvents`) and **persisted durably** by
the honeypot via the storage indexer (`src/storage/`), independently of whether
a Central is present.

### 3.7 From honeypot to Central

Central does **not** rely on the edge pushing. It **polls** every registered node
with cursor-based pagination (`src/central/poller.ts`), running independently of
the HTTP server so a node outage cannot stall the central plane
(`src/central/app.ts:152-161`).

Two ingest routes exist on Central:

| Route | Used by | Details |
|-------|---------|---------|
| `POST /api/v1/events/secure` | **New** clients | Application-encrypted **AES-256-GCM envelope** over HTTP (`src/central/server.ts:232-254`); no token in headers; replay-protected via `requestId`/`nonce` |
| `POST /api/v1/events` | **Legacy** clients | Bearer token auth, **only** when `VAIVAR_CONTROL_CHANNEL=legacy` (`src/central/server.ts:258-273`); retained for old nodes |

The AES key is **derived** on both sides from the deployment barrier token —
the token itself never rides in an HTTP header
(`src/security/control-channel.ts`, `src/central/server.ts:153`).

---

## 4. Central: what it owns

`vaivar_server` (`src/central/`) is the operator console:

### 4.1 Routes

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Orchestrator probe, no auth (`storage stats`, version) |
| `GET` | `/login` | Login page; POST `/api/v1/login` sets an operator/admin **session cookie** (HMAC-derived, never the raw token) |
| `GET` | `/overview`, `/dashboard`, `/honeypots`, `/nodes`, `/threats`, `/sessions`, `/activity`, `/settings`, `/nodes/*` | SPA dashboard (`src/central/ui.ts`) |
| `GET` | `/metrics` | **Prometheus** metrics: attackers by site/IP, events, flags, activity, storage bytes, uptime; optional Splunk HEC counters (`src/central/server.ts:402-455`) |
| `GET` | `/api/v1/events/secure` / `/api/v1/events` | Ingest (see above) |
| `GET` | `/api/v1/dashboard`, `/api/v1/stats`, `/api/v1/me` | Dashboard data |
| `POST` | `/api/v1/bootstrap/*` | Bootstrap capability tokens, installer |
| `GET` | `/api/v1/status` | Node status (see `node-client.ts`) |

### 4.2 What runs inside Central

| Component | File | Responsibility |
|-----------|------|----------------|
| `storage` | `src/storage/indexer.ts` | SQLite persistence (better-sqlite3), event/flag/activity retention (default 90 days), node registry, integration settings |
| `nodeRegistry` | `src/central/node-registry.ts` | Central inventory of enrolled honeypots (domain/IP, API port, encrypted barrier token) |
| `poller` | `src/central/poller.ts` | Cursor-based polling of nodes; runs on a timer independent of the HTTP server |
| `splunkHec` | `src/central/splunk-hec.ts` | **Opt-in** Splunk HEC adapter; fire-and-forget bounded queue so a Splunk outage never blocks ingest |
| `openCTIConnectors` | `src/cti/connector.ts` | **Opt-in** STIX 2.1 EXTERNAL_IMPORT → OpenCTI connectors loaded from settings |
| `releases` | `src/central/releases.ts` | Approved release catalog served to bootstrapping honeypot installers |
| `secretStore` | `src/central/secret-store.ts` | Encrypted storage of node barrier tokens and integration credentials |

### 4.3 Integrations (all opt-in, credentials stay on Central)

| Sink | Enabled by | Behavior |
|------|-----------|----------|
| **OpenCTI** | `VAIVAR_OPENCTI_URL` + `VAIVAR_OPENCTI_TOKEN` (or integration settings) | Every persisted envelope → `projectHecEvent`/STIX transform → EXTERNAL_IMPORT. **Fake flags are never promoted to blocklist indicators.** |
| **Splunk** | `VAIVAR_SPLUNK_HEC_URL` + `VAIVAR_SPLUNK_HEC_TOKEN` | Every persisted envelope → HEC event → adapter. Fire-and-forget, bounded queue, retries. |
| **Prometheus / Grafana** | Always on | `/metrics` endpoint scraped by Prometheus. |

**Outage isolation:** delivery health, collection freshness, and node reachability
are **separate observations**. A platform outage must not stop the public
honeypot.

---

## 5. Code map — `src/`

A compact index of where things live. Use this as your starting point; each file
is small enough to read end-to-end.

| Area | Files | Notes |
|------|-------|-------|
| **Honeypot entry** | `src/app/main.ts`, `src/app/bootstrap.ts` | Reads ports/tokens from env; starts honeypot + control API |
| **Public attacker surface** | `src/server/honeypot.ts` | Skins, session/node/flag endpoints, rate limit, brand sanitization |
| **Session engine** | `src/engine/session.ts` | Seed derivation, fingerprints, world walk, flags, scoring, event emission, persistence/replay |
| **Graph generator** | `src/graph/generator.ts` | On-demand, seed-derived node generation; world-plan validation |
| **Level verification** | `src/levels/checker.ts` | `verifyFlag(seed, level, code)` |
| **Classifier** | `src/classifier/analyzer.ts` | Scanner vs agent detection (`isMetaProbe`, `classifyRequest`, `recordPattern`) |
| **Scoring** | `src/scoring/capability.ts` | `computeCapability`, `computeIntent`, `computeMatrix` → severity |
| **Skins** | `src/skins/wiki.ts`, `src/skins/openapi.ts`, `src/mcp/server.ts`, `src/mcp/index.ts` | Cosmetic surfaces; the engine doesn't care which skin is live |
| **Templates** | `src/templates/` | Declarative operator-provided pages, escaped, no code execution |
| **Events** | `src/types/events.ts` | `vaivar.event.v1` contract, `createSessionEvent`, `createFlagEvent`, `foldEvents` |
| **Storage** | `src/storage/indexer.ts` | SQLite indexer; honeypot session persistence + central event/flag/activity store |
| **Central app** | `src/central/main.ts`, `src/central/app.ts` | Entry + wiring: storage, poller, integrations |
| **Central server** | `src/central/server.ts` | HTTP router: ingest, UI, metrics, bootstrap, node enrollment, dashboard API |
| **Central UI** | `src/central/ui.ts` | The operator dashboard (SPA served server-side) |
| **Node client / registry** | `src/central/node-client.ts`, `src/central/node-registry.ts` | Talk to enrolled nodes; keep the inventory |
| **Poller / forwarder** | `src/central/poller.ts`, `src/central/forwarder.ts` | Cursor-based event collection, delivery hygiene |
| **Integrations** | `src/cti/connector.ts`, `src/cti/transform.ts`, `src/central/splunk-hec.ts`, `src/central/splunk-events.ts` | OpenCTI and Splunk adapters |
| **Security** | `src/security/control-channel.ts`, `src/server/auth.ts` | AES-256-GCM control envelopes; HMAC-derived session cookies, bearer verification |
| **FP core** | `src/fp/core.ts` | `Result`, `ok`, `err` — the pure-functional foundation |
| **Hash/stable** | `src/hash/stable.ts` | `sha256Hex`, deterministic hashing |
| **Logging** | `src/logging/` | `applog`, `eventlog`, `sinks` |
| **Version / branding** | `src/version.ts`, `src/branding.ts` | Version, logo, forbidden brand strings |
| **Node config** | `src/node/config.ts`, `src/node/identity.ts` | Honeypot profile (`http`/`wiki`/`openapi`/`mcp`/`all`), site identity |

---

## 6. Security posture and non-negotiables


1. **Local progress, global void.** Levels can be cleared. Nothing real can be reached. `winIsolated` serves from a sealed enclosure namespace.
2. **Zero signature on the attacker surface.** `sanitizeBrandStrings()` strips any `vAIvar` / `vaivar` / `vivar` / `rabbithole` occurrence from *every* JSON response (`src/skins/validators.ts:21-36`). The operator brand never leaks into the warren.
3. **No seed in attacker-visible output.** Seeds stay server-side.
4. **No counter-attack.** No reverse shells, no scanning them back, no malware, no execution of attacker code.
5. **No production secrets, PII, or live credentials** inside the universe.
6. **Replay.** Same seed reconstructs exactly what the agent saw (`rehydrateFromStorage`, `foldEvents`).
7. **Perceived infinity, real budget.** Hard caps on nodes/bytes/requests per session; degradation is silent.
8. **Central-initiated control.** Normal honeypot startup never requires a Central URL or platform credentials.
9. **Control channel encryption.** AES-256-GCM envelopes; the barrier token never rides in a header; replay-protected.
10. **Docker-first and minimal permissions.** Non-root runtime user, `no-new-privileges: true`, best-effort read-only FS in the Dockerfile.
11. **Cheap scanners, expensive agents.** The heavy generator turns on for agent signal, not mass GET noise (`classifier/analyzer.ts`).

**Threat assumption:** the attacker *initiates* contact against infrastructure we
control. No outbound exploitation is modeled.

---

## 7. Running everything locally

> on the host. Everything runs, packages, and tests in containers.

### Central (the only thing you run on this machine)

```bash
cp .env.central.example .env.central
#   Fill in tokens. Generate a 64-hex key once and keep it:
#     openssl rand -hex 32
docker compose --env-file .env.central -f docker-compose.central.yml up -d --build
docker compose --env-file .env.central -f docker-compose.central.yml logs -f
docker compose --env-file .env.central -f docker-compose.central.yml down
```

Access: [http://localhost:8080/overview](http://localhost:8080/overview). Sign in
with the operator or admin token. Setting `VAIVAR_CENTRAL_OPERATOR_TOKEN=dev`
disables dashboard auth — throwaway labs only.

### Honeypots (never on the dev machine)

`docker-compose.yml` is the **honeypot**. Deploy it on a VPS / edge over SSH.
From Central: **Honeypots → Add honeypot → Generate deploy command**, then run
the generated curl-to-`honeypot-install.sh` on the remote host as root. After the
installer prints its summary, register **host, control port, channel, barrier
token** in Central, **Test connection**, **Add**.

Interactive alternative on the honeypot host: `scripts/deploy.sh`.

Air-gapped and GitHub-bundle flows, SHA-256 pinning, and multi-honeypot-per-host
rules live in [`docs/RELEASES-AND-BOOTSTRAP.md`](RELEASES-AND-BOOTSTRAP.md).

### Build and test (inside containers or a one-off Node)

```bash
npm run build        # TypeScript → dist/
npm test             # vitest run
```

---

## 8. Repository map and deeper docs

```
vaivar/
├── README.md                     # Public pitch, quick start, name
├── docs/
│   ├── ARCHITECTURE.md           # ← this document
│   ├── RELEASES-AND-BOOTSTRAP.md # Publish release bundles, air-gapped deploy
├── src/                          # TypeScript implementation (see §5)
├── tests/                        # Vitest test suites
├── docker-compose.yml            # Honeypot (remote only)
├── docker-compose.central.yml    # Central (local dev)
├── Dockerfile                    # Multi-stage Node 22 image
└── langs/, logos/                # i18n, branding assets
```

**Suggested reading order for a new dev:**

1. This file (§1–§7) — orientation and mental model.
3. `src/engine/session.ts` — the defensive heart; read it top to bottom.
4. `src/central/server.ts` — the central router.
5. `docs/RELEASES-AND-BOOTSTRAP.md` — how you actually ship and deploy.
