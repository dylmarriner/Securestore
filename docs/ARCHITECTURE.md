# SecureStore Architecture

SecureStore is a self-hostable, shared credential-storage and policy platform:
one persistent store, one policy engine, reachable concurrently by every kind
of AI agent and automation system over MCP and REST. This document explains
the design, walks through the required workflows against the actual code,
and is explicit about what's fully implemented versus what's designed as a
clean extension point for a larger production rollout.

## 1. Goals and non-goals

**Goals**: a single shared, durable credential store and policy engine that
many concurrently-connected agents can read/write safely; automatic capture
and enrichment of credentials agents encounter; strong encryption and
deduplication; auditable, policy-gated access with both direct and brokered
modes; horizontal scalability with no single-agent or single-server
ownership assumption.

**Non-goals for this implementation**: a full enterprise IdP (SSO/SCIM),
a general-purpose workflow/approval UI, a bundled HSM, or a Rego-compatible
policy DSL. Each has a clearly marked extension seam (§11) rather than a
half-built version of the real thing.

## 2. High-level architecture

```
                      ┌─────────────────────────────────────────┐
                      │              PostgreSQL                  │
                      │  credentials · credential_versions        │
                      │  credential_secrets · credential_fingerprints
                      │  policies · agents · agent_sessions        │
                      │  audit_log · events (outbox)               │
                      └───────────────▲─────────────▲─────────────┘
                                       │             │
                     shared metadata + secret store, │ LISTEN/NOTIFY
                     policy state, audit trail        │ (event fan-out)
                                       │             │
        ┌──────────────────────────────┴─────────────┴──────────────────────────────┐
        │                     SecureStore process (stateless, N replicas)             │
        │  ┌───────────────┐ ┌────────────────┐ ┌───────────────┐ ┌────────────────┐ │
        │  │ MCP stdio      │ │ MCP HTTP        │ │ REST API       │ │ Event bus       │ │
        │  │ (1 proc/agent) │ │ (streamable,    │ │ (1:1 mirror    │ │ (outbox +       │ │
        │  │                │ │  multi-session) │ │  of MCP tools) │ │  LISTEN/NOTIFY) │ │
        │  └───────┬────────┘ └────────┬────────┘ └───────┬────────┘ └────────┬───────┘ │
        │          └───────────────────┴──────────────────┴───────────────────┘         │
        │                                    │                                          │
        │                     ┌──────────────┴──────────────┐                           │
        │                     │   Tool handlers (transport-   │                          │
        │                     │   agnostic; toolHandlers.ts)  │                          │
        │                     └──────────────┬───────────────┘                          │
        │      ┌──────────────┬──────────────┼───────────────┬───────────────┐          │
        │      │              │              │               │               │          │
        │ ┌────▼───┐   ┌──────▼─────┐  ┌─────▼──────┐  ┌─────▼──────┐  ┌─────▼──────┐   │
        │ │ Policy  │   │ Credential │  │ Ingestion   │  │ Provider    │  │ Agent /     │   │
        │ │ engine  │   │ service    │  │ pipeline    │  │ adapters    │  │ audit svc   │   │
        │ │ (ABAC)  │   │ (CRUD, dedup,│ │ (detect ->  │  │ (validate,  │  │             │   │
        │ │         │   │  versioning) │ │  enrich)    │  │  execute)   │  │             │   │
        │ └─────────┘   └──────┬─────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
        │                       │                                                            │
        │               ┌───────▼────────┐                                                   │
        │               │ Envelope crypto │  DEK per secret, wrapped by pluggable KeyProvider │
        │               │ (AES-256-GCM)   │  (local key today; AWS/GCP KMS / Vault = seam)    │
        │               └────────────────┘                                                   │
        └───────────────────────────────────────────────────────────────────────────────────┘
              ▲                    ▲                     ▲                      ▲
              │                    │                     │                      │
        local CLI/IDE agent   Claude web / ChatGPT   CI/CD, scripts,      Unix socket / named
        (stdio, 1 proc =      connectors / browser   custom apps (REST)  pipe clients (same
        1 agent identity)     agents (HTTPS MCP)                          Fastify app, no port)
```

Every client — regardless of transport — ends up calling the same
transport-agnostic handler functions in `src/mcp/toolHandlers.ts`, which is
what guarantees identical policy evaluation, auditing, and event publication
no matter how a client connected. There is exactly one logical namespace:
one Postgres database is both the metadata store and (physically separated,
§4) the secret store, shared by every replica.

## 3. Data model

See `db/migrations/0001_init.sql` for the authoritative schema. Key design
choices:

- **`credentials` (current pointer) + `credential_versions` (append-only
  history) + `credential_secrets` (ciphertext, 1:1 with a version)** are
  three separate tables. Metadata queries never touch ciphertext; the
  secret table could be moved to a separate database/trust boundary without
  a schema change to the other two.
- **`credential_fingerprints.fingerprint` is the dedup mechanism**: a
  `UNIQUE PRIMARY KEY` on a keyed HMAC fingerprint (§4), enforced by
  Postgres itself, not application logic — this is what actually prevents
  two concurrent writers from creating duplicate secret rows.
- **`credentials.metadata` is a JSONB map of `{field: {value, confidence,
  source, verified, updatedAt, introducedByAgentId}}`** — every metadata
  field carries its own provenance, which is what makes the
  merge-without-clobbering-verified-data rule (§8) possible.
- **`events` is a transactional outbox**: every mutation inserts its event
  row in the same DB transaction, so an event can never be observed for a
  write that rolled back, or dropped for one that committed.
- **`audit_log`** captures every field the spec calls for (user, agent,
  client type, session, device, workspace, project, credential + version,
  provider, operation, access mode, creation source, introducing agent,
  metadata source, policy decision, approval decision, source network, MCP
  transport, result) and is written in the same transaction as the
  operation it describes.

## 4. Cryptography and deduplication

**Envelope encryption** (`src/crypto/envelope.ts`, `src/crypto/kms.ts`):
every secret gets a fresh random 256-bit DEK; the plaintext is AES-256-GCM
encrypted with the DEK; the DEK is wrapped by a KEK supplied by a
`KeyProvider` and then discarded. `LocalKeyProvider` derives the KEK from an
operator-supplied `SECURESTORE_MASTER_KEY` env var — production
deployments should implement `KeyProvider` against AWS KMS / GCP Cloud KMS /
HashiCorp Vault Transit / a PKCS#11 HSM instead (the interface is designed
for that swap with zero call-site changes).

**Deduplication** (`src/crypto/fingerprint.ts`): a keyed fingerprint —
`HMAC-SHA256(serverPepper, provider:credentialType:normalizedSecret)` — is
computed for every incoming secret. Because the key is a server-side pepper
that never leaves the trusted boundary, database access alone doesn't let
an attacker test candidate plaintexts against stored fingerprints the way a
bare hash would. Plaintext secrets are never compared or logged anywhere
outside `src/crypto/envelope.ts`'s decrypt call sites.

## 5. Concurrency and consistency

- **Atomicity**: every multi-statement mutation runs inside a single
  Postgres transaction (`withTransaction` in `src/db/pool.ts`).
- **Idempotency**: `secret_store` accepts an `idempotencyKey`, unique per
  workspace (`credentials_idempotency_idx`); calling it twice returns the
  same credential. Independently, the fingerprint unique index makes
  `secret_store_detected` idempotent even without an explicit key, because
  the same secret value always fingerprints to the same row.
- **Conflict detection / CAS**: `storeCredential` selects `FOR UPDATE`
  before mutating an existing row, and the fingerprint table's unique
  constraint is the real compare-and-swap: if two agents race to store the
  same never-seen-before secret, one INSERT wins and the other gets a
  Postgres `23505` unique-violation, which `createCredential` turns into a
  `DuplicateCredentialError` — the caller's retry path re-reads and merges
  into the winner's row instead of creating a second one.
- **Provenance-aware metadata merge** (`mergeMetadata` in
  `credentialService.ts`, unit-tested in `test/mergeMetadata.test.ts`): a
  field already marked `verified` is never silently overwritten by a
  lower-confidence, unverified incoming value; equal-or-higher confidence or
  an explicit `verified` flag is required to win.
- **Versioning**: `credential_versions` is append-only with a
  `(credential_id, version_number)` unique constraint; rotation inserts a
  new version, marks the prior one `superseded`, and flips
  `credentials.current_version_id` atomically.
- **Event ordering / dedup**: events are a monotonically increasing
  `bigserial`; subscribers dedupe by id and resume from
  `nextSinceEventId` (`credential_event_subscribe`), so a redelivered or
  out-of-order NOTIFY can't cause double-processing.

## 6. Multi-tenant isolation

Every credential, audit entry, and event carries an `org_id`; every
credential additionally carries a `workspace_id` (nullable only for
explicitly org-wide-shared credentials). Isolation is enforced at three
points, not just one, because a single missed call site is enough to leak
across tenants:

1. **Session open** (`openSession` in `src/services/agentService.ts`): a
   caller cannot select a workspace it isn't a member of via the
   `X-SecureStore-Workspace-Id` header/session param — membership is
   checked against `agent_workspace_memberships` before a session (and
   therefore `ctx.workspaceId`) is issued. This is what makes
   `ctx.workspaceId` trustworthy everywhere downstream.
2. **Per-credential visibility** (`src/services/visibilityService.ts`,
   `assertCredentialVisible`/`loadVisibleCredential`): every tool handler
   that operates on a specific `credentialId` resolves it through this gate
   before any policy decision is made. It checks `credential.orgId ===
   agent.orgId` and then the credential's `sharing_policy.visibility`
   (`workspace` [default, requires membership] | `organization` [any agent
   in the org] | `agents` [explicit allow-list] | `private` [owner only]).
   A cross-tenant or out-of-scope request fails as `not_found`, never
   `denied` — so it can't be used to confirm a credential's existence.
3. **Listing/query scoping** (`visibilityWhereClause` in
   `visibilityService.ts`, reused by `findCredentials`, `queryAudit`, and
   the event bus's `subscribe`/`listEventsSince`): rather than fetching
   broadly and filtering in application code, the SQL `WHERE` clause itself
   is scoped to `org_id = <agent's org>` AND (workspace membership OR
   org-wide-shared OR agent-owned OR explicitly agent-shared). Audit and
   event queries additionally require `orgId` and only include
   workspace-less rows (agent lifecycle events) for admin-capable agents.

Proxy/temporary tokens (`credential_proxy_session_create`,
`credential_temporary_issue`) add a fourth check: redemption via
`credential_execute` requires the redeeming agent to be the same one the
token was issued to, so a leaked token string alone isn't enough to reuse
someone else's grant.

This is a place where getting it right the first time is unusually
important, so it's covered by a live end-to-end test (two full
organizations, two workspaces, cross-tenant reads via header-spoofing,
direct credential-id guessing, listing, audit querying, and agent-session
lookups) rather than by mocked unit tests alone — see the isolation
section of the test plan in the PR history for this change.

## 7. Policy engine

`src/policy/engine.ts` implements deny-overrides ABAC: policies specify
`subjects` (agent id/type/risk ceiling/owner), `actions` (the MCP tool /
REST operation), `resources` (provider/type/environment/tags/owner-scope/
sensitivity), and `conditions` (time window, network, auth strength,
approval requirement, max retrieval count, max session duration, cache/
downstream-use permission, direct-vs-brokered access mode, allowed HTTP
methods/target resources). Evaluation is fail-closed: no matching policy =
deny. Any matching `deny` policy wins regardless of priority ordering.
Among matching `allow` policies, numeric/boolean guardrails combine
conservatively (the tightest constraint from any matching policy applies),
so stacking a broader grant on top of a narrower one can never accidentally
loosen it (unit-tested in `test/policy.test.ts`).

This is layered with **RBAC capability flags on the agent record itself**
(`raw_secret_access`, `rotation_permission`, `revocation_permission`,
`auto_ingestion_permission`, `metadata_enrichment_permission`,
`metadata_admin_permission`) checked in `src/services/policyService.ts`
before the ABAC engine even runs — belt-and-suspenders: an agent that
lacks `rotation_permission` can never rotate a credential no matter what
any policy document says, and a policy can further restrict a capable agent
per-resource. `agent_to_agent_visibility`/provider allow-lists are enforced
the same way.

Seed policies (`db/migrations/0002_seed_default_policies.sql`): workspace
agents get direct access to development/staging credentials; production
credentials are always brokered and require human approval; any workspace
agent can enrich metadata on a credential another agent introduced.

## 8. Automatic credential capture (the ingestion pipeline)

`src/services/ingestionPipeline.ts` implements the required 13-step
contract:

1. **Detect** — `src/detectors/index.ts` runs provider token-prefix
   patterns (`patterns.ts`, GitHub/GitLab/OpenAI/Anthropic/Slack/AWS/npm/
   Stripe/etc.), strips Authorization-header wrappers, parses DB connection
   strings, inspects JWT structure (claims only — never signature
   verification, which stays inside the relevant adapter's `validate()`),
   and applies env-var-name heuristics — all with confidence scoring.
   Operators can register additional `TokenPattern`s for internal/custom
   credential types.
2. **Dedup** — delegated to `storeCredential`'s fingerprint lookup (§4/§5).
3. **Identify provider/type** — the detector's best-confidence match, or
   `unknown`/`text` with `status: "unresolved"` if nothing matched, so a
   credential is never silently dropped just because it wasn't recognized.
4. **Collect/infer metadata** — detector output (issuer, audience, expiry,
   scopes from JWT claims; username/host/database from connection strings;
   header name/prefix/base endpoint from the matched provider pattern).
5. **Validate** — best-effort, safe, read-only provider call via the
   resolved `ProviderAdapter.validate()` (e.g. GitHub `GET /user`, npm
   `GET /-/whoami`); failures never block storage, they just leave the
   credential enrichment `partial` instead of `complete`.
6–7. **Create-or-update, encrypt+store** — `storeCredential` (§4/§5).
8. **Assign ownership/policy** — owner scope, workspace, sharing policy set
   at creation; defaults to workspace-scoped, explicit ownership models
   (`personal | workspace | project | organization | agent |
   service_account | environment | ephemeral`) are first-class columns.
9. **Record provenance** — every metadata field's `source` +
   `introducedByAgentId` + `confidence`.
10. **Return a stable reference** — the credential UUID, stable across
    rotations (the version changes, the id doesn't).
11. **Discoverable to other agents** — a normal row in the shared
    `credentials` table, subject to policy on read.
12. **Sanitized audit event** — `secret_store` / `secret_store_detected` /
    `secret_rotate`, never containing secret material.
13. **Publish event** — `credential.detected`/`credential.created`/
    `credential.rotated` via the outbox (§3).

**Rotation detection**: if the incoming secret's fingerprint doesn't match
anything, but its `accountIdentifier`/`username` metadata matches an
existing active credential for the same provider+type+workspace, it's
treated as a rotation: a new version is appended and the prior version is
marked `superseded` (`findRotationCandidate`/`rotateInternal` in
`credentialService.ts`) instead of creating a second credential.

## 9. Provider adapters

`src/adapters/types.ts` defines the full contract called for by the spec
(provider id, credential types, token patterns, endpoints, auth scheme,
required headers, OAuth metadata, supported operations, error
sanitization). Bundled adapters: GitHub, GitLab, OpenAI-compatible,
Anthropic-compatible, npm registry, plus generic bearer / API-key-header /
OAuth2 / database fallbacks used when no dedicated adapter exists
(`adapterRegistry.resolve()`). `execute()` drives brokered
`credential_execute` calls; `validate()` drives both auto-capture
enrichment and the `credential_validate` tool; `sanitizeError()` strips
Authorization-header-shaped and `token=`/`secret=`-shaped substrings out of
provider error bodies before they're ever logged or returned. Custom
providers register via `adapterRegistry.register(new MyAdapter())` at boot.

## 10. Direct vs. brokered access

`checkPolicy()` returns an `accessMode` (`direct | brokered | temporary |
proxy | process_injection`) chosen by the matching policy's
`conditions.accessMode`. `secret_get` only succeeds for `direct`; any other
mode raises a `wrong_access_mode` error directing the caller to
`credential_execute` (brokered — the adapter performs the HTTP call, the
raw secret never crosses the tool boundary), `credential_proxy_session_create`
(a short-lived, revocable token that authorizes repeated brokered calls
without re-running the full policy check each time), or
`credential_temporary_issue` (a single/limited-use handle, for cases that
want an explicit "temporary" grant even without a true provider-side
short-lived-credential API). Proxy/temporary tokens live in
`src/services/proxySessionStore.ts`, intentionally in-memory and
per-process (§11 covers the HA implication).

## 11. What's fully implemented vs. designed as an extension point

Being explicit about this distinction is part of the job, not a hedge.

**Fully implemented and tested**: envelope encryption + local KeyProvider;
keyed-fingerprint dedup with a real unique-constraint race test path;
credential CRUD/versioning/rotation/revocation with atomic transactions;
provenance-aware metadata merge; the ABAC+RBAC policy engine; the 13-step
auto-capture pipeline with 6 real provider adapters + safe fallbacks;
Postgres-outbox event bus with LISTEN/NOTIFY fan-out and gap-free
catch-up; MCP over stdio and streamable HTTP with the full 24-tool surface;
a 1:1 REST mirror; SSE push events; Unix-socket/named-pipe listening (same
code path — Node treats a string passed to `listen()` as a socket/pipe
path on both platforms); Docker Compose self-hosting; audit trail covering
every spec'd field.

**Extension points, deliberately not bundled**:

| Area | Current state | Production seam |
|---|---|---|
| KMS/HSM | `LocalKeyProvider` (env-var-derived key) | Implement `KeyProvider` (`src/crypto/kms.ts`) against AWS KMS / GCP KMS / Vault Transit / PKCS#11 |
| mTLS, OIDC, workload identity, passkeys, hardware-backed client keys | `agents.auth_method` column + API-key auth implemented; other methods are schema-ready but not wired | Add an auth strategy per method in `src/api/auth.ts` / `src/mcp/httpServer.ts`; agent identity model already carries `public_key`, `auth_method` |
| gRPC | Not implemented | Tool handlers in `toolHandlers.ts` are already transport-agnostic; add a `.proto` + server wrapping the same functions, same pattern as the REST mirror |
| Distributed rate limiting | In-memory per-process token bucket | Swap `InMemoryRateLimiter` (`agentService.ts`) for Redis INCR/PEXPIRE or a Lua token-bucket, same interface |
| Proxy/temporary session store | In-memory per-process | Swap `ProxySessionStore` for Redis SETEX, same interface |
| Distributed locking beyond row-level `FOR UPDATE`/unique constraints | Not needed for current operations (Postgres transactions + unique constraints are sufficient for the write patterns here) | Add Postgres advisory locks or a lease table if a future operation needs cross-statement, cross-transaction mutual exclusion |
| Policy DSL | Custom ABAC engine (JSON documents in `policies` table) | Swap `evaluatePolicy()` internals for an OPA/Rego sidecar call if org standardizes on Rego |
| Backup/DR | Postgres is the single source of truth; standard `pg_dump`/WAL-archiving/replica promotion applies | Document and automate per the operator's existing Postgres HA tooling (Patroni, RDS Multi-AZ, etc.) — this is intentionally left to infra, not reinvented here |
| Leader election | Not used — no operation in this design requires a singleton leader (all writes are per-row atomic transactions) | If a future background job (e.g. expiry-sweep) needs exactly-one-runner semantics, use a Postgres advisory lock, not a new coordination system |
| Approval UI | `approval_request` tool/endpoint + `approval_requests` table | Wire a human-facing admin UI/Slack bot that calls `POST /v1/approvals` with `action:"decide"` |

None of these are silently stubbed-and-insecure — each either fails loudly
(`LocalKeyProvider` throws if `SECURESTORE_MASTER_KEY` is unset; unknown
`KMS_PROVIDER` throws at boot) or is a real, working default appropriate
for a single-deployment self-hosted setup that documents its own ceiling.

## 12. Required workflows, walked through

1. **Web AI agent stores a supplied API key, discovers endpoint/username,
   returns a stable reference.** `secret_store_detected` ->
   `ingestDetectedCredential`: detect (provider pattern match) -> resolve
   adapter -> `adapter.validate()` (safe GET, harvests username/account id/
   scopes) -> `storeCredential` -> returns `credentialId`.
2. **A second agent discovers and uses the shared credential later.**
   `secret_find`/`secret_list` (policy-gated, scoped to the shared
   workspace) -> `secret_get` if policy allows direct access.
3. **Two agents race to store the same token.** Both call
   `secret_store`/`secret_store_detected` concurrently; both compute the
   same fingerprint; the `credential_fingerprints` unique index lets exactly
   one INSERT win; the loser's transaction catches the `23505` and the
   pipeline treats it as the dedup path — one credential row results.
4. **An agent uses an unknown token in an HTTP request; it gets captured.**
   `secret_store_detected` with `sourceKind: "http_authorization_header"`
   and the raw header value — the header-prefix stripper + pattern matcher
   handle it the same as workflow 1.
5. **OAuth flow stores access+refresh tokens with full context.**
   `oauth_authorize` (`action:"complete"`) -> `exchangeAuthorizationCode`
   -> `storeOAuthTokens`, which records issuer/audience/scopes/token+refresh
   endpoints/expiry/account identifier in one credential.
6. **Rotated token updates the existing credential version.**
   `secret_rotate`, or automatically via the `accountIdentifier`-matching
   heuristic in `findRotationCandidate` when a new value arrives through
   any ingestion path — either way, `insertVersion` appends and marks the
   prior version `superseded`.
7. **Revocation propagates immediately to all connected agents.**
   `secret_revoke` -> `credentials.status = 'revoked'` +
   `credential.revoked` event published in the same transaction -> every
   replica's LISTEN connection fans it out to its local subscribers within
   one NOTIFY round-trip; reconnecting clients catch up via
   `credential_event_subscribe`/`GET /v1/events`.
8. **IDE agent stores a registry token a CLI agent later uses.** Same
   shared-workspace discovery as workflow 2 — ownership scope defaults to
   `workspace`, so any agent in that workspace with policy-granted access
   sees it via `secret_find`.
9. **Local agent creates a credential; Claude web accesses it via remote
   MCP.** stdio-connected agent calls `secret_store`; an HTTP-connected
   agent (different transport, same Postgres) calls `secret_get` — both
   paths run through the identical `toolHandlers.ts` functions.
10. **Web agent stores a credential; local CLI agent injects it into a
    child process.** `secret_get` over stdio returns the raw value to the
    local agent process, which is then free to set it as an env var for a
    spawned child — that injection step is local-agent responsibility (by
    design SecureStore hands back a value once policy has approved direct
    access; it doesn't reach into a caller's process tree).
11. **Unidentifiable credential stored pending enrichment.** Detection
    returns `matched:false`; `ingestDetectedCredential` stores it with
    `provider:"unknown"`, `status:"unresolved"`, `enrichmentStatus:"pending"`.
12. **A different agent enriches that unresolved credential.**
    `secret_claim` (flips `unresolved` -> `active`) then `secret_enrich`
    (provenance-tagged metadata fields) — gated by
    `metadata_enrichment_permission` and the `secret_enrich` policy action.

## 13. Threat model (summary)

- **DB compromise without the fingerprint pepper or master key**: attacker
  gets ciphertext and fingerprints, but neither is reversible without the
  separately-held pepper/KEK.
- **Compromised agent API key**: blast radius is bounded by that agent's
  RBAC capability flags + whatever ABAC policies match its identity/type/
  risk classification — not full store access. `secret_revoke` on affected
  credentials plus revoking the agent (`agents.revoked`) cuts it off
  immediately (sessions revoked in the same call).
- **Malicious/buggy adapter code**: adapters only ever receive the single
  secret value they're asked to operate on (`AdapterContext`), never the
  full credential store; `sanitizeError()` bounds what a misbehaving
  provider response can leak into logs.
- **Audit/event integrity**: both are written in the same transaction as
  the mutation they describe, so there's no window where a write commits
  without a corresponding audit row, or vice versa.
