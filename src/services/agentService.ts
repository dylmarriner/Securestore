import { pool, withTransaction } from "../db/pool.js";
import { generateApiKey, hashApiKey } from "../crypto/fingerprint.js";
import { config } from "../config.js";
import { getRedisClient, isRedisConfigured } from "./redisClient.js";
import { RedisRateLimiter } from "./redisRateLimiter.js";
import type { AgentRecord } from "./types.js";

export interface RegisterAgentInput {
  orgId: string;
  name: string;
  agentType: string;
  platform?: string;
  version?: string;
  ownerUserId?: string;
  authMethod?: string;
  publicKey?: string;
  allowedTransports?: string[];
  allowedTools?: string[];
  allowedNamespaces?: string[];
  allowedProviders?: string[];
  allowedOperations?: string[];
  rawSecretAccess?: boolean;
  autoIngestionPermission?: boolean;
  metadataEnrichmentPermission?: boolean;
  rotationPermission?: boolean;
  revocationPermission?: boolean;
  riskClassification?: AgentRecord["riskClassification"];
  workspaceIds?: string[];
}

export async function registerAgent(input: RegisterAgentInput): Promise<{ agent: AgentRecord; apiKey?: string }> {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      `INSERT INTO agents (
         org_id, name, agent_type, platform, version, owner_user_id, auth_method, public_key,
         allowed_transports, allowed_tools, allowed_namespaces, allowed_providers, allowed_operations,
         raw_secret_access, auto_ingestion_permission, metadata_enrichment_permission,
         rotation_permission, revocation_permission, risk_classification
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       RETURNING *`,
      [
        input.orgId, input.name, input.agentType, input.platform ?? null, input.version ?? null,
        input.ownerUserId ?? null, input.authMethod ?? "api_key", input.publicKey ?? null,
        input.allowedTransports ?? [], input.allowedTools ?? [], input.allowedNamespaces ?? [],
        input.allowedProviders ?? [], input.allowedOperations ?? [],
        input.rawSecretAccess ?? false, input.autoIngestionPermission ?? true,
        input.metadataEnrichmentPermission ?? true, input.rotationPermission ?? false,
        input.revocationPermission ?? false, input.riskClassification ?? "standard",
      ],
    );
    const agentRow = rows[0];

    for (const wsId of input.workspaceIds ?? []) {
      // Membership can only be granted into a workspace that actually
      // belongs to the same org as the agent being created — otherwise an
      // admin in org A could hand a new agent visibility into org B's
      // workspaces just by supplying its UUID.
      const { rows: wsRows } = await client.query(`SELECT 1 FROM workspaces WHERE id = $1 AND org_id = $2`, [wsId, input.orgId]);
      if (wsRows.length === 0) {
        throw new Error(`workspace ${wsId} does not belong to org ${input.orgId}`);
      }
      await client.query(
        `INSERT INTO agent_workspace_memberships (agent_id, workspace_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [agentRow.id, wsId],
      );
    }

    let apiKey: string | undefined;
    if ((input.authMethod ?? "api_key") === "api_key") {
      const { raw, prefix } = generateApiKey();
      await client.query(
        `INSERT INTO agent_api_keys (agent_id, prefix, key_hash) VALUES ($1, $2, $3)`,
        [agentRow.id, prefix, hashApiKey(raw)],
      );
      apiKey = raw;
    }

    return { agent: rowToAgent(agentRow), apiKey };
  });
}

export async function authenticateApiKey(rawKey: string): Promise<AgentRecord | null> {
  const hash = hashApiKey(rawKey);
  const { rows } = await pool.query(
    `SELECT a.* FROM agent_api_keys k
     JOIN agents a ON a.id = k.agent_id
     WHERE k.key_hash = $1 AND k.revoked_at IS NULL
       AND (k.expires_at IS NULL OR k.expires_at > now())
       AND a.revoked = false`,
    [hash],
  );
  if (rows.length === 0) return null;
  await pool.query(`UPDATE agents SET last_connected_at = now() WHERE id = $1`, [rows[0].id]);
  return rowToAgent(rows[0]);
}

export async function getAgent(agentId: string): Promise<AgentRecord | null> {
  const { rows } = await pool.query(`SELECT * FROM agents WHERE id = $1`, [agentId]);
  return rows[0] ? rowToAgent(rows[0]) : null;
}

export async function revokeAgent(agentId: string): Promise<void> {
  await pool.query(`UPDATE agents SET revoked = true, revoked_at = now() WHERE id = $1`, [agentId]);
  await pool.query(
    `UPDATE agent_sessions SET revoked_at = now() WHERE agent_id = $1 AND revoked_at IS NULL`,
    [agentId],
  );
}

export class WorkspaceAccessError extends Error {}

/** Membership is what actually scopes workspace-visible credentials — see src/services/visibilityService.ts. */
export async function isAgentWorkspaceMember(agentId: string, workspaceId: string): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT 1 FROM agent_workspace_memberships WHERE agent_id = $1 AND workspace_id = $2`,
    [agentId, workspaceId],
  );
  return rows.length > 0;
}

export async function getAgentWorkspaceIds(agentId: string): Promise<string[]> {
  const { rows } = await pool.query(
    `SELECT workspace_id FROM agent_workspace_memberships WHERE agent_id = $1`,
    [agentId],
  );
  return rows.map((r) => r.workspace_id);
}

/**
 * Opening a session is where workspace selection is authorized: a caller
 * cannot simply supply an arbitrary X-SecureStore-Workspace-Id header and
 * get scoped into a workspace it isn't a member of. This is what makes the
 * `ctx.workspaceId` used throughout the tool handlers trustworthy.
 */
export async function openSession(
  agentId: string,
  workspaceId: string | null,
  transport: string,
  clientNetwork?: string,
): Promise<{ sessionId: string }> {
  if (workspaceId && !(await isAgentWorkspaceMember(agentId, workspaceId))) {
    throw new WorkspaceAccessError(`agent is not a member of workspace ${workspaceId}`);
  }
  const { rows } = await pool.query(
    `INSERT INTO agent_sessions (agent_id, workspace_id, transport, client_network, expires_at)
     VALUES ($1, $2, $3, $4, now() + interval '12 hours') RETURNING id`,
    [agentId, workspaceId, transport, clientNetwork ?? null],
  );
  return { sessionId: rows[0].id };
}

export async function listSessions(agentId: string) {
  const { rows } = await pool.query(
    `SELECT * FROM agent_sessions WHERE agent_id = $1 ORDER BY started_at DESC LIMIT 100`,
    [agentId],
  );
  return rows;
}

function rowToAgent(row: any): AgentRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    agentType: row.agent_type,
    platform: row.platform,
    ownerUserId: row.owner_user_id,
    authMethod: row.auth_method,
    allowedTransports: row.allowed_transports ?? [],
    allowedTools: row.allowed_tools ?? [],
    allowedNamespaces: row.allowed_namespaces ?? [],
    allowedProviders: row.allowed_providers ?? [],
    allowedOperations: row.allowed_operations ?? [],
    rawSecretAccess: row.raw_secret_access,
    autoIngestionPermission: row.auto_ingestion_permission,
    metadataEnrichmentPermission: row.metadata_enrichment_permission,
    rotationPermission: row.rotation_permission,
    revocationPermission: row.revocation_permission,
    metadataAdminPermission: row.metadata_admin_permission,
    riskClassification: row.risk_classification,
    revoked: row.revoked,
  };
}

/** Per-agent rate limiting. Async so a Redis-backed implementation is a drop-in swap — see src/services/redisRateLimiter.ts. */
export interface RateLimiter {
  tryConsume(agentId: string): Promise<boolean>;
}

/**
 * In-memory token-bucket rate limiting. Correct for a single instance, and
 * approximately correct (each replica enforces its own share of the limit)
 * under horizontal scale-out. This is the default; set REDIS_URL to switch
 * to RedisRateLimiter for an exact global limit across a replica fleet.
 */
class InMemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; lastRefill: number }>();

  constructor(private readonly perMinute: number) {}

  async tryConsume(agentId: string): Promise<boolean> {
    const now = Date.now();
    const bucket = this.buckets.get(agentId) ?? { tokens: this.perMinute, lastRefill: now };
    const elapsedMinutes = (now - bucket.lastRefill) / 60_000;
    bucket.tokens = Math.min(this.perMinute, bucket.tokens + elapsedMinutes * this.perMinute);
    bucket.lastRefill = now;
    if (bucket.tokens < 1) {
      this.buckets.set(agentId, bucket);
      return false;
    }
    bucket.tokens -= 1;
    this.buckets.set(agentId, bucket);
    return true;
  }
}

let rateLimiterInstance: RateLimiter | undefined;

export function getRateLimiter(): RateLimiter {
  if (rateLimiterInstance) return rateLimiterInstance;
  if (isRedisConfigured()) {
    rateLimiterInstance = new RedisRateLimiter(getRedisClient()!, config.rateLimit.defaultPerMinute);
  } else {
    rateLimiterInstance = new InMemoryRateLimiter(config.rateLimit.defaultPerMinute);
  }
  return rateLimiterInstance;
}
