import { EventEmitter } from "node:events";
import pg from "pg";
import { config } from "../config.js";
import { pool, type DbClient } from "../db/pool.js";

export type SecureStoreEventType =
  | "credential.detected" | "credential.created" | "credential.enriched" | "credential.validated"
  | "credential.used" | "credential.rotated" | "credential.expiring" | "credential.expired"
  | "credential.revoked" | "credential.deleted" | "credential.shared" | "credential.policy_changed"
  | "agent.connected" | "agent.revoked" | "access.denied";

export interface SecureStoreEvent {
  id: number;
  eventType: SecureStoreEventType;
  orgId: string | null;
  workspaceId: string | null;
  credentialId: string | null;
  agentId: string | null;
  payload: Record<string, unknown>;
  createdAt: string;
}

/**
 * Transactional-outbox event bus. `publish()` must be called with the same
 * DB client/transaction as the mutation it announces, so an event is never
 * observed for a write that later rolls back, and never silently dropped
 * for a write that commits. A dedicated LISTEN connection gives sub-second
 * fan-out to in-process subscribers (MCP `credential_event_subscribe`
 * streams, SSE clients); `listEventsSince` gives reconnecting clients a
 * reliable, gap-free catch-up path independent of whether they were
 * listening when the NOTIFY fired.
 *
 * Horizontal scaling: every SecureStore process runs its own LISTEN
 * connection against the same Postgres instance, so a NOTIFY fired by one
 * replica's write is fanned out to subscribers connected to every other
 * replica — this is what makes revocation/policy propagation "real-time"
 * across a horizontally scaled MCP-server fleet without a separate message
 * broker. Swap the notify transport for Redis pub/sub or NATS if outgrowing
 * Postgres LISTEN/NOTIFY's payload-size and throughput ceiling.
 */
class EventBus {
  private readonly emitter = new EventEmitter();
  private listenClient: pg.Client | undefined;

  constructor() {
    this.emitter.setMaxListeners(1000);
  }

  async start(): Promise<void> {
    this.listenClient = new pg.Client({ connectionString: config.db.connectionString });
    await this.listenClient.connect();
    await this.listenClient.query("LISTEN securestore_events");
    this.listenClient.on("notification", (msg) => {
      if (!msg.payload) return;
      try {
        const parsed = JSON.parse(msg.payload) as { id: number };
        void this.hydrateAndEmit(parsed.id);
      } catch {
        // malformed notify payload; ignore, the polling-based catch-up path remains correct
      }
    });
    this.listenClient.on("error", (err) => {
      console.error("event bus LISTEN connection error", err);
    });
  }

  async stop(): Promise<void> {
    await this.listenClient?.end();
  }

  private async hydrateAndEmit(id: number): Promise<void> {
    const { rows } = await pool.query("SELECT * FROM events WHERE id = $1", [id]);
    const row = rows[0];
    if (!row) return;
    const event = rowToEvent(row);
    this.emitter.emit("event", event);
  }

  async publish(
    client: DbClient,
    eventType: SecureStoreEventType,
    fields: {
      orgId?: string | null;
      workspaceId?: string | null;
      credentialId?: string | null;
      agentId?: string | null;
      payload?: Record<string, unknown>;
    },
  ): Promise<void> {
    await client.query(
      `INSERT INTO events (event_type, org_id, workspace_id, credential_id, agent_id, payload)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        eventType,
        fields.orgId ?? null,
        fields.workspaceId ?? null,
        fields.credentialId ?? null,
        fields.agentId ?? null,
        JSON.stringify(fields.payload ?? {}),
      ],
    );
  }

  /**
   * Live subscription for in-process consumers (MCP streams, SSE). `scope`
   * is mandatory and mirrors AuditQuery's isolation model: orgId always
   * filters, workspaceIds restricts to the caller's actual memberships
   * (plus workspaceless org-wide events when includeWorkspaceless is set).
   * There is intentionally no "no scope = everything" fallback — that was
   * the bug (an agent with no single workspace selected could see every
   * other org's events). Returns an unsubscribe function.
   */
  subscribe(
    scope: { orgId: string; workspaceIds: string[]; includeWorkspaceless?: boolean },
    filter: { eventTypes?: SecureStoreEventType[] },
    handler: (event: SecureStoreEvent) => void,
  ): () => void {
    const listener = (event: SecureStoreEvent) => {
      if (event.orgId !== scope.orgId) return;
      const workspaceMatch =
        (event.workspaceId && scope.workspaceIds.includes(event.workspaceId)) ||
        (!event.workspaceId && scope.includeWorkspaceless);
      if (!workspaceMatch) return;
      if (filter.eventTypes && !filter.eventTypes.includes(event.eventType)) return;
      handler(event);
    };
    this.emitter.on("event", listener);
    return () => this.emitter.off("event", listener);
  }

  /** Gap-free catch-up for a client that reconnects after being offline; dedupe on event id downstream. */
  async listEventsSince(
    sinceId: number,
    scope: { orgId: string; workspaceIds: string[]; includeWorkspaceless?: boolean },
    limit = 500,
  ): Promise<SecureStoreEvent[]> {
    const { rows } = await pool.query(
      `SELECT * FROM events
       WHERE id > $1 AND org_id = $2
         AND (workspace_id = ANY($3::uuid[]) OR ($4 AND workspace_id IS NULL))
       ORDER BY id ASC LIMIT $5`,
      [sinceId, scope.orgId, scope.workspaceIds, scope.includeWorkspaceless ?? false, limit],
    );
    return rows.map(rowToEvent);
  }
}

function rowToEvent(row: any): SecureStoreEvent {
  return {
    id: Number(row.id),
    eventType: row.event_type,
    orgId: row.org_id,
    workspaceId: row.workspace_id,
    credentialId: row.credential_id,
    agentId: row.agent_id,
    payload: row.payload,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

export const eventBus = new EventBus();
