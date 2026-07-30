-- SecureStore core schema
-- Design notes:
--  * Secret ciphertext is physically separated from credential metadata
--    (credential_secrets vs credential_versions/credentials) so the two can
--    later be split across separate database instances/trust boundaries.
--  * Every credential has a logical `credentials` row (current pointer) and
--    an immutable, append-only `credential_versions` history for rotation.
--  * Deduplication relies on a UNIQUE keyed-fingerprint index, never on
--    plaintext comparison.
--  * `events` is an outbox table: writers insert in the same transaction as
--    the mutation, a NOTIFY wakes listeners, and a polling fallback covers
--    listeners that were disconnected (at-least-once delivery).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE schema_migrations (
  version     text PRIMARY KEY,
  applied_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name        text NOT NULL,
  slug        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug)
);

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email         text NOT NULL,
  display_name  text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, email)
);

CREATE TABLE workspace_members (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role          text NOT NULL DEFAULT 'member', -- owner | admin | member | viewer
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Agent identity
-- ---------------------------------------------------------------------------

CREATE TABLE agents (
  id                              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                            text NOT NULL,
  agent_type                      text NOT NULL, -- web_ai | browser_ai | cli | ide | desktop | automation | ci_cd | service | custom
  platform                        text,          -- claude-web | chatgpt | cursor | vscode | jetbrains | github-actions | ...
  version                         text,
  owner_user_id                   uuid REFERENCES users(id),
  auth_method                     text NOT NULL DEFAULT 'api_key', -- api_key | jwt | oidc | mtls | workload_identity | passkey | client_assertion
  public_key                      text,
  allowed_transports              text[] NOT NULL DEFAULT '{}',
  allowed_tools                   text[] NOT NULL DEFAULT '{}',
  allowed_namespaces              text[] NOT NULL DEFAULT '{}',
  allowed_providers               text[] NOT NULL DEFAULT '{}',
  allowed_operations              text[] NOT NULL DEFAULT '{}',
  raw_secret_access               boolean NOT NULL DEFAULT false,
  auto_ingestion_permission       boolean NOT NULL DEFAULT true,
  metadata_enrichment_permission  boolean NOT NULL DEFAULT true,
  rotation_permission             boolean NOT NULL DEFAULT false,
  revocation_permission           boolean NOT NULL DEFAULT false,
  metadata_admin_permission       boolean NOT NULL DEFAULT false,
  risk_classification             text NOT NULL DEFAULT 'standard', -- low | standard | elevated | high
  revoked                         boolean NOT NULL DEFAULT false,
  revoked_at                      timestamptz,
  created_at                      timestamptz NOT NULL DEFAULT now(),
  last_connected_at               timestamptz
);

CREATE TABLE agent_workspace_memberships (
  agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  role          text NOT NULL DEFAULT 'member',
  PRIMARY KEY (agent_id, workspace_id)
);

-- API-key auth material (hashed, never stores the raw key)
CREATE TABLE agent_api_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  prefix      text NOT NULL,     -- first 8 chars, for fast lookup/display
  key_hash    text NOT NULL,     -- HMAC-SHA256(server pepper, key)
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);
CREATE UNIQUE INDEX agent_api_keys_hash_idx ON agent_api_keys(key_hash);

CREATE TABLE agent_sessions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  workspace_id   uuid REFERENCES workspaces(id),
  transport      text NOT NULL, -- stdio | http | sse | uds | named_pipe | grpc
  client_network text,
  started_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz,
  revoked_at     timestamptz
);
CREATE INDEX agent_sessions_agent_idx ON agent_sessions(agent_id);

-- ---------------------------------------------------------------------------
-- Credentials
-- ---------------------------------------------------------------------------

CREATE TABLE credentials (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  workspace_id           uuid REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_scope            text NOT NULL DEFAULT 'workspace', -- personal|workspace|project|organization|agent|service_account|environment|ephemeral
  owner_user_id          uuid REFERENCES users(id),
  owner_agent_id         uuid REFERENCES agents(id),
  project_id             text,
  repository             text,
  name                   text NOT NULL,
  provider               text NOT NULL,             -- github | gitlab | openai | anthropic | aws | npm | generic-bearer | ...
  service                text,
  credential_type        text NOT NULL,              -- api_key | pat | oauth_access_token | oauth_refresh_token | service_account | ssh_key | tls_cert | db_connection_string | webhook_secret | text | json
  auth_scheme            text,                       -- bearer | api_key_header | basic | query_param | mtls | ssh
  status                 text NOT NULL DEFAULT 'active', -- active|expiring|expired|revoked|deleted|archived|unresolved
  current_version_id     uuid,
  sensitivity            text NOT NULL DEFAULT 'medium', -- low|medium|high|critical
  environment            text NOT NULL DEFAULT 'development', -- development|staging|production
  sharing_policy         jsonb NOT NULL DEFAULT '{"visibility":"workspace"}',
  approval_required       boolean NOT NULL DEFAULT false,
  metadata               jsonb NOT NULL DEFAULT '{}', -- { field: {value, confidence, source, verified, updatedAt} }
  tags                   text[] NOT NULL DEFAULT '{}',
  notes                  text,
  introducing_agent_id   uuid REFERENCES agents(id),
  creation_source        text NOT NULL DEFAULT 'manual', -- auto_capture|manual|oauth_flow|rotation|import
  last_used_at           timestamptz,
  last_used_agent_id     uuid REFERENCES agents(id),
  last_validation_at     timestamptz,
  last_validation_result text,
  health                 text NOT NULL DEFAULT 'unknown', -- healthy|degraded|invalid|unknown
  enrichment_status      text NOT NULL DEFAULT 'pending', -- complete|partial|pending
  idempotency_key        text,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  deleted_at             timestamptz
);
CREATE INDEX credentials_workspace_idx ON credentials(workspace_id);
CREATE INDEX credentials_provider_idx ON credentials(provider, credential_type);
CREATE INDEX credentials_status_idx ON credentials(status);
CREATE UNIQUE INDEX credentials_idempotency_idx ON credentials(workspace_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE credential_versions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  credential_id    uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  version_number   int NOT NULL,
  status           text NOT NULL DEFAULT 'active', -- active|superseded|revoked
  rotation_of      uuid REFERENCES credential_versions(id),
  issued_at        timestamptz,
  expires_at       timestamptz,
  refresh_expires_at timestamptz,
  scopes           text[] NOT NULL DEFAULT '{}',
  validated        boolean NOT NULL DEFAULT false,
  validation_result text,
  created_by_agent_id uuid REFERENCES agents(id),
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (credential_id, version_number)
);
CREATE INDEX credential_versions_credential_idx ON credential_versions(credential_id);

ALTER TABLE credentials
  ADD CONSTRAINT credentials_current_version_fk
  FOREIGN KEY (current_version_id) REFERENCES credential_versions(id);

-- Secret values live in a physically separate table (1:1 with a version),
-- so the metadata store and secret store can be split onto separate
-- infrastructure/trust boundaries without a schema change.
CREATE TABLE credential_secrets (
  version_id    uuid PRIMARY KEY REFERENCES credential_versions(id) ON DELETE CASCADE,
  ciphertext    bytea NOT NULL,
  nonce         bytea NOT NULL,
  wrapped_dek   bytea NOT NULL,
  kek_id        text NOT NULL,
  kek_version   int NOT NULL,
  encoding      text NOT NULL DEFAULT 'utf8', -- utf8 | json | base64 | pem
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Keyed cryptographic fingerprints for deduplication. Never derived from a
-- reversible transform of the secret alone: HMAC(server pepper || provider
-- || normalized secret). Unique index is what actually prevents duplicate
-- secret rows under concurrent writers.
CREATE TABLE credential_fingerprints (
  fingerprint      text PRIMARY KEY,
  credential_id    uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  version_id       uuid NOT NULL REFERENCES credential_versions(id) ON DELETE CASCADE,
  provider         text NOT NULL,
  credential_type  text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX credential_fingerprints_credential_idx ON credential_fingerprints(credential_id);

CREATE TABLE encryption_keys (
  id          text NOT NULL,
  version     int NOT NULL,
  provider    text NOT NULL DEFAULT 'local', -- local|aws-kms|gcp-kms|vault-transit|hsm
  status      text NOT NULL DEFAULT 'active', -- active|retired
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, version)
);

-- ---------------------------------------------------------------------------
-- Policy engine
-- ---------------------------------------------------------------------------

CREATE TABLE policies (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid REFERENCES organizations(id) ON DELETE CASCADE,
  workspace_id  uuid REFERENCES workspaces(id) ON DELETE CASCADE,
  name          text NOT NULL,
  description   text,
  effect        text NOT NULL DEFAULT 'allow', -- allow|deny
  priority      int NOT NULL DEFAULT 100,       -- lower evaluates first; deny always wins on match
  subjects      jsonb NOT NULL DEFAULT '{}',    -- {agentIds, agentTypes, riskMax, ...}
  actions       text[] NOT NULL DEFAULT '{}',   -- secret_get, secret_store, credential_rotate, ...
  resources     jsonb NOT NULL DEFAULT '{}',    -- {providers, credentialTypes, environments, tags, ownerScopes}
  conditions    jsonb NOT NULL DEFAULT '{}',    -- {timeWindow, networkCidrs, minAuthStrength, requireApproval, maxRetrievalCount, maxSessionSeconds, cachePermitted, downstreamUsePermitted, accessMode}
  enabled       boolean NOT NULL DEFAULT true,
  created_by    uuid REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  version       int NOT NULL DEFAULT 1
);
CREATE INDEX policies_workspace_idx ON policies(workspace_id);

CREATE TABLE approval_requests (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  credential_id  uuid REFERENCES credentials(id) ON DELETE CASCADE,
  agent_id       uuid NOT NULL REFERENCES agents(id),
  operation      text NOT NULL,
  requested_at   timestamptz NOT NULL DEFAULT now(),
  status         text NOT NULL DEFAULT 'pending', -- pending|approved|denied|expired
  decided_by     uuid REFERENCES users(id),
  decided_at     timestamptz,
  reason         text
);

-- ---------------------------------------------------------------------------
-- Audit + events
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
  id                  bigserial PRIMARY KEY,
  occurred_at         timestamptz NOT NULL DEFAULT now(),
  user_id             uuid REFERENCES users(id),
  agent_id            uuid REFERENCES agents(id),
  client_type         text,
  session_id          uuid,
  device_id           text,
  workspace_id        uuid,
  project_id          text,
  credential_id       uuid,
  credential_version  int,
  provider            text,
  operation           text NOT NULL,
  access_mode         text, -- direct|brokered|temporary|proxy|process_injection
  creation_source     text,
  introducing_agent_id uuid,
  metadata_source      text,
  policy_decision      text, -- allow|deny|approval_required
  approval_decision    text,
  source_network       text,
  mcp_transport         text,
  result                text NOT NULL, -- success|denied|error
  details               jsonb NOT NULL DEFAULT '{}' -- sanitized only; never raw secret material
);
CREATE INDEX audit_log_occurred_idx ON audit_log(occurred_at);
CREATE INDEX audit_log_credential_idx ON audit_log(credential_id);
CREATE INDEX audit_log_agent_idx ON audit_log(agent_id);

-- Transactional outbox: mutations insert an event row in the same
-- transaction, then pg_notify wakes live listeners. Subscribers without a
-- live connection catch up by polling `id > last_seen_id`.
CREATE TABLE events (
  id            bigserial PRIMARY KEY,
  event_type    text NOT NULL,
  org_id        uuid,
  workspace_id  uuid,
  credential_id uuid,
  agent_id      uuid,
  payload       jsonb NOT NULL DEFAULT '{}', -- sanitized only; never raw secret material
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_workspace_idx ON events(workspace_id, id);
CREATE INDEX events_created_idx ON events(created_at);

CREATE OR REPLACE FUNCTION notify_credential_event() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('securestore_events', json_build_object(
    'id', NEW.id,
    'event_type', NEW.event_type,
    'workspace_id', NEW.workspace_id,
    'credential_id', NEW.credential_id
  )::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER events_notify_trigger
  AFTER INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION notify_credential_event();
