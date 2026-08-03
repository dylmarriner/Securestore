# SecureStore

A self-hostable, shared credential-storage and policy platform for multi-agent
systems: one persistent store, one policy engine, reachable concurrently from
web AI agents, local CLI/IDE agents, CI/CD, and custom apps over MCP (stdio,
authenticated HTTPS, Unix sockets/named pipes) and a REST API.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design —
threat model, concurrency strategy, HA/DR posture, and a field-by-field
mapping from the platform requirements to what's implemented.

## Quick start (Docker Compose)

```bash
cp .env.example .env
# fill in three peppers/keys, e.g.:
for v in SECURESTORE_MASTER_KEY SECURESTORE_FINGERPRINT_PEPPER SECURESTORE_APIKEY_PEPPER; do
  echo "$v=$(openssl rand -base64 32)" >> .env
done

docker compose up -d postgres
docker compose run --rm migrate
docker compose --profile seed run --rm seed   # prints your first admin API key — save it
docker compose up -d app
curl http://localhost:8443/healthz
```

Scale the MCP/REST tier horizontally with `docker compose up -d --scale app=3`
behind a load balancer (see the session-affinity note in
`src/mcp/httpServer.ts`) — all state lives in Postgres, so replicas are
interchangeable except for in-flight streamable-HTTP sessions.

## Local development (no Docker)

Requires Node 20+ and a running Postgres instance.

```bash
npm install
cp .env.example .env   # fill in DATABASE_URL + the three generated keys
npm run migrate
npm run seed            # prints the admin agent's API key
npm run dev              # REST + MCP-over-HTTP on :8443
```

## Connecting a client

Every client authenticates with a **SecureStore agent API key**
(`sss_...`, minted by `agent_register` / the seed script / `POST
/v1/agents`) and, optionally, a workspace id.

### Local CLI / IDE agent (MCP over stdio)

```bash
SECURESTORE_AGENT_API_KEY=sss_... \
SECURESTORE_WORKSPACE_ID=<workspace-uuid> \
node dist/mcp/stdioMain.js
```

Point your MCP client config at that command, e.g. for a generic MCP-capable
CLI/IDE:

```json
{
  "mcpServers": {
    "securestore": {
      "command": "node",
      "args": ["/path/to/securestore/dist/mcp/stdioMain.js"],
      "env": { "SECURESTORE_AGENT_API_KEY": "sss_...", "SECURESTORE_WORKSPACE_ID": "..." }
    }
  }
}
```

### Remote / web clients (Claude web, ChatGPT connectors, browser agents)

Point the client at the streamable-HTTP MCP endpoint:

```
POST https://your-host:8443/mcp
Authorization: Bearer sss_...
X-SecureStore-Workspace-Id: <workspace-uuid>
```

The server assigns an `Mcp-Session-Id`; the client reuses it for subsequent
`GET`/`POST`/`DELETE /mcp` calls per the MCP streamable-HTTP spec. A
local-to-remote bridge (e.g. a desktop app running a stdio<->HTTP proxy) is
just another client of this same endpoint.

### CI/CD, scripts, custom apps (REST)

```bash
curl -X POST https://your-host:8443/v1/secrets/detected \
  -H "Authorization: Bearer $SECURESTORE_AGENT_API_KEY" \
  -H "X-SecureStore-Workspace-Id: $WORKSPACE_ID" \
  -H "Content-Type: application/json" \
  -d '{"rawValue":"'"$SOME_TOKEN"'","sourceKind":"cli_command"}'
```

REST endpoints are a 1:1 mirror of the MCP tool set — see
`src/api/routes.ts`. Live event push is available at `GET
/v1/events/stream` (Server-Sent Events); polling clients can instead call
`credential_event_subscribe` / `GET /v1/events?sinceEventId=...`.

### Containers / dev containers / local sockets

Set `SECURESTORE_SOCKET_PATH=/var/run/securestore.sock` (or, on Windows,
`\\.\pipe\securestore`) and mount/share that path into the client's
container — no network port required. See `src/server.ts`.

## Registering additional agents

Any agent holding `metadata_admin_permission` can mint others via
`agent_register` (MCP) or `POST /v1/agents` (REST). Set capability flags
deliberately — `raw_secret_access`, `rotation_permission`,
`revocation_permission`, `auto_ingestion_permission`,
`metadata_enrichment_permission` — plus `allowed_providers` /
`allowed_transports` / `risk_classification`, since these gate every
destructive or high-trust operation independently of the ABAC policy engine
(see `src/services/policyService.ts`).

## Policies

Seed policies (`db/migrations/0002_seed_default_policies.sql`) give a
sensible default: workspace agents share development/staging credentials
directly; production credentials are always brokered and require approval.
Add org/workspace-scoped policies by inserting into the `policies` table —
schema and evaluation semantics are documented in `src/policy/types.ts` and
`src/policy/engine.ts`.

## Provider adapters

Bundled: GitHub, GitLab, OpenAI-compatible, Anthropic-compatible, npm
registry, plus generic bearer/API-key-header/OAuth2/database fallbacks.
Add a custom provider by implementing `ProviderAdapter`
(`src/adapters/types.ts`) and calling `adapterRegistry.register(...)` at
boot — see `src/adapters/registry.ts`.

## Testing

```bash
npm test        # vitest: crypto, fingerprinting, detection, policy engine, dedup/provenance merge
npm run build    # tsc typecheck + compile
```

## Security notes

- Secrets are envelope-encrypted (AES-256-GCM, per-secret DEK wrapped by a
  KEK) and stored in a table physically separate from credential metadata.
- Deduplication uses a keyed HMAC fingerprint with a server-side pepper —
  plaintext secrets are never compared or logged.
- The bundled `LocalKeyProvider` derives its KEK from
  `SECURESTORE_MASTER_KEY`, an operator-supplied env var/mounted secret.
  For production, set `KMS_PROVIDER=aws-kms` + `AWS_KMS_KEY_ID` to use the
  bundled `AwsKmsKeyProvider` instead, or implement `KeyProvider`
  (`src/crypto/kms.ts`) against GCP Cloud KMS / HashiCorp Vault Transit /
  an HSM the same way.
- `POST /v1/bootstrap` (creates the very first admin agent) only works when
  `SECURESTORE_ADMIN_BOOTSTRAP_TOKEN` is set and supplied; unset it after
  initial setup.
- Beyond API keys, agents can authenticate via mTLS client certificate or
  an OIDC bearer token — set `SECURESTORE_TLS_CERT_PATH`/`KEY_PATH`/
  `CA_PATH` (mTLS) and/or `SECURESTORE_OIDC_ISSUER`/`JWKS_URI`/`AUDIENCE`
  (OIDC), then register the agent with `authMethod` and `authIdentifier`
  (client cert SHA-256 fingerprint, or the OIDC token's `sub` claim). See
  `src/auth/resolveAgent.ts`.
