import { isAgentWorkspaceMember } from "./agentService.js";
import type { AgentRecord, CredentialRecord } from "./types.js";

export type VisibleCredential = Pick<
  CredentialRecord,
  "id" | "orgId" | "workspaceId" | "ownerScope" | "ownerUserId" | "ownerAgentId" | "sharingPolicy"
>;

/**
 * Enforces org and workspace isolation. This is the gate every credential
 * read/write path must pass through before a policy decision is even
 * considered — policy answers "is this operation allowed", this answers
 * "can this agent see this credential exists at all". A cross-org or
 * cross-workspace request fails as `not_found` rather than `denied`, so it
 * doesn't confirm a credential ID's existence to an agent that has no
 * business knowing about it.
 *
 * `credentials.sharing_policy.visibility` controls the scoping model:
 *   - "workspace" (default): visible only to agents that are members of
 *     the credential's workspace (agent_workspace_memberships).
 *   - "organization": visible to any agent in the same org, regardless of
 *     workspace membership.
 *   - "agents": visible only to the agent ids listed in
 *     sharing_policy.agentIds.
 *   - "private": visible only to the introducing/owning agent, or another
 *     agent owned by the same user.
 */
export async function assertCredentialVisible(agent: AgentRecord, credential: VisibleCredential): Promise<void> {
  if (!(await isCredentialVisible(agent, credential))) {
    throw new VisibilityError("credential not found");
  }
}

export class VisibilityError extends Error {}

export async function isCredentialVisible(agent: AgentRecord, credential: VisibleCredential): Promise<boolean> {
  if (credential.orgId !== agent.orgId) return false;

  const visibility = (credential.sharingPolicy?.["visibility"] as string | undefined) ?? "workspace";

  if (visibility === "organization") return true;

  if (visibility === "private") {
    if (credential.ownerAgentId === agent.id) return true;
    if (credential.ownerUserId && agent.ownerUserId && credential.ownerUserId === agent.ownerUserId) return true;
    return false;
  }

  if (visibility === "agents") {
    const allowed = (credential.sharingPolicy?.["agentIds"] as string[] | undefined) ?? [];
    return allowed.includes(agent.id);
  }

  // default: "workspace"
  if (!credential.workspaceId) return false;
  return isAgentWorkspaceMember(agent.id, credential.workspaceId);
}

/** SQL fragment + params for scoping a credential *listing* query to what an agent may see (used by findCredentials). */
export function visibilityWhereClause(paramIndexStart: number): { clause: string; paramCount: number } {
  // $n = orgId, $n+1 = agentId, $n+2 = memberWorkspaceIds (text[])
  const orgIdx = paramIndexStart;
  const agentIdx = paramIndexStart + 1;
  const workspacesIdx = paramIndexStart + 2;
  return {
    clause: `
      c.org_id = $${orgIdx}
      AND (
        COALESCE(c.sharing_policy ->> 'visibility', 'workspace') = 'organization'
        OR c.workspace_id = ANY($${workspacesIdx}::uuid[])
        OR c.owner_agent_id = $${agentIdx}
        OR (COALESCE(c.sharing_policy ->> 'visibility', 'workspace') = 'agents'
            AND c.sharing_policy -> 'agentIds' ? $${agentIdx}::text)
      )`,
    paramCount: 3,
  };
}
