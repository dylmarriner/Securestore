import type { DbClient } from "../db/pool.js";
import { pool } from "../db/pool.js";

export interface AuditEntry {
  userId?: string | null;
  agentId?: string | null;
  clientType?: string | null;
  sessionId?: string | null;
  deviceId?: string | null;
  workspaceId?: string | null;
  projectId?: string | null;
  credentialId?: string | null;
  credentialVersion?: number | null;
  provider?: string | null;
  operation: string;
  accessMode?: string | null;
  creationSource?: string | null;
  introducingAgentId?: string | null;
  metadataSource?: string | null;
  policyDecision?: string | null;
  approvalDecision?: string | null;
  sourceNetwork?: string | null;
  mcpTransport?: string | null;
  result: "success" | "denied" | "error";
  /** Sanitized-only. Never pass raw secret material here — enforced by convention, not runtime scanning. */
  details?: Record<string, unknown>;
}

/**
 * Every audit write happens inside the same transaction as the mutation it
 * describes (pass the transaction's `client`), so audit records and the
 * events they accompany can never diverge from what actually committed.
 */
export async function recordAudit(client: DbClient, entry: AuditEntry): Promise<void> {
  await client.query(
    `INSERT INTO audit_log (
       user_id, agent_id, client_type, session_id, device_id, workspace_id, project_id,
       credential_id, credential_version, provider, operation, access_mode, creation_source,
       introducing_agent_id, metadata_source, policy_decision, approval_decision,
       source_network, mcp_transport, result, details
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
    [
      entry.userId ?? null, entry.agentId ?? null, entry.clientType ?? null, entry.sessionId ?? null,
      entry.deviceId ?? null, entry.workspaceId ?? null, entry.projectId ?? null, entry.credentialId ?? null,
      entry.credentialVersion ?? null, entry.provider ?? null, entry.operation, entry.accessMode ?? null,
      entry.creationSource ?? null, entry.introducingAgentId ?? null, entry.metadataSource ?? null,
      entry.policyDecision ?? null, entry.approvalDecision ?? null, entry.sourceNetwork ?? null,
      entry.mcpTransport ?? null, entry.result, JSON.stringify(entry.details ?? {}),
    ],
  );
}

export interface AuditQuery {
  workspaceId?: string;
  credentialId?: string;
  agentId?: string;
  operation?: string;
  since?: Date;
  limit?: number;
}

export async function queryAudit(q: AuditQuery) {
  const clauses: string[] = [];
  const params: unknown[] = [];
  let i = 1;
  if (q.workspaceId) { clauses.push(`workspace_id = $${i++}`); params.push(q.workspaceId); }
  if (q.credentialId) { clauses.push(`credential_id = $${i++}`); params.push(q.credentialId); }
  if (q.agentId) { clauses.push(`agent_id = $${i++}`); params.push(q.agentId); }
  if (q.operation) { clauses.push(`operation = $${i++}`); params.push(q.operation); }
  if (q.since) { clauses.push(`occurred_at >= $${i++}`); params.push(q.since); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const limit = Math.min(q.limit ?? 100, 1000);
  params.push(limit);
  const { rows } = await pool.query(
    `SELECT * FROM audit_log ${where} ORDER BY occurred_at DESC LIMIT $${i}`,
    params,
  );
  return rows;
}
