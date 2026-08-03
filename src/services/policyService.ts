import { evaluatePolicy } from "../policy/engine.js";
import { loadApplicablePolicies } from "../policy/repository.js";
import type { PolicyAction, PolicyDecision } from "../policy/types.js";
import type { AgentRecord, CredentialRecord } from "./types.js";
import { recordAudit } from "./auditService.js";
import { pool, withTransaction } from "../db/pool.js";

export interface CheckPolicyRequest {
  action: PolicyAction;
  transport: string;
  sourceNetwork?: string;
  authStrength?: "weak" | "strong" | "mfa";
  requestedCount?: number;
}

/** RBAC capability flags that gate destructive/high-trust operations regardless of what ABAC policy allows (belt-and-suspenders). */
const CAPABILITY_GATED_ACTIONS: Partial<Record<PolicyAction, keyof AgentRecord>> = {
  secret_get: "rawSecretAccess",
  secret_rotate: "rotationPermission",
  secret_revoke: "revocationPermission",
  secret_store: "autoIngestionPermission",
  secret_store_detected: "autoIngestionPermission",
  secret_enrich: "metadataEnrichmentPermission",
};

export async function checkPolicy(
  agent: AgentRecord,
  credential: Pick<CredentialRecord, "id" | "provider" | "credentialType" | "environment" | "tags" | "ownerScope" | "sensitivity">,
  req: CheckPolicyRequest,
): Promise<PolicyDecision> {
  const capabilityField = CAPABILITY_GATED_ACTIONS[req.action];
  if (capabilityField && agent[capabilityField] === false) {
    return {
      effect: "deny",
      accessMode: "direct",
      requiresApproval: false,
      cachePermitted: false,
      downstreamUsePermitted: false,
      matchedPolicyIds: [],
      reason: `agent lacks capability flag "${capabilityField}"`,
    };
  }
  if (agent.allowedProviders.length && !agent.allowedProviders.includes(credential.provider)) {
    return {
      effect: "deny",
      accessMode: "direct",
      requiresApproval: false,
      cachePermitted: false,
      downstreamUsePermitted: false,
      matchedPolicyIds: [],
      reason: `agent is not allowed to access provider "${credential.provider}"`,
    };
  }

  const policies = await loadApplicablePolicies(agent.orgId, null);
  return evaluatePolicy(
    policies,
    req.action,
    {
      agentId: agent.id,
      agentType: agent.agentType,
      riskClassification: agent.riskClassification,
      ownerUserId: agent.ownerUserId,
    },
    {
      credentialId: credential.id,
      provider: credential.provider,
      credentialType: credential.credentialType,
      environment: credential.environment,
      tags: credential.tags,
      ownerScope: credential.ownerScope,
      sensitivity: credential.sensitivity,
    },
    {
      transport: req.transport,
      sourceNetwork: req.sourceNetwork,
      authStrength: req.authStrength,
      nowUtc: new Date(),
      requestedCount: req.requestedCount,
    },
  );
}

export async function recordAccessDenied(
  orgId: string,
  agentId: string,
  workspaceId: string | null,
  credentialId: string | null,
  operation: string,
  reason: string,
): Promise<void> {
  await withTransaction(async (client) => {
    await recordAudit(client, {
      orgId, agentId, workspaceId, credentialId, operation, policyDecision: "deny",
      result: "denied", details: { reason },
    });
    const { eventBus } = await import("./eventBus.js");
    await eventBus.publish(client, "access.denied", {
      orgId, workspaceId, credentialId, agentId, payload: { operation, reason },
    });
  });
}

export async function createApprovalRequest(credentialId: string, agentId: string, operation: string): Promise<string> {
  const { rows } = await pool.query(
    `INSERT INTO approval_requests (credential_id, agent_id, operation) VALUES ($1,$2,$3) RETURNING id`,
    [credentialId, agentId, operation],
  );
  return rows[0].id;
}

// Both queries join through `credentials` and filter on its org_id, so an
// agent in one org can't decide or inspect another org's approval request
// even if it knows/guesses the approval id.

export async function decideApproval(orgId: string, approvalId: string, decidedBy: string, approve: boolean, reason?: string) {
  const { rows } = await pool.query(
    `UPDATE approval_requests ar SET status = $1, decided_by = $2, decided_at = now(), reason = $3
     FROM credentials c
     WHERE ar.id = $4 AND ar.credential_id = c.id AND c.org_id = $5
     RETURNING ar.*`,
    [approve ? "approved" : "denied", decidedBy, reason ?? null, approvalId, orgId],
  );
  return rows[0] ?? null;
}

export async function getApprovalStatus(orgId: string, approvalId: string) {
  const { rows } = await pool.query(
    `SELECT ar.* FROM approval_requests ar
     JOIN credentials c ON c.id = ar.credential_id
     WHERE ar.id = $1 AND c.org_id = $2`,
    [approvalId, orgId],
  );
  return rows[0] ?? null;
}
