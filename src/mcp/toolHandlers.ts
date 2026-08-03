import type { AgentContext } from "./context.js";
import { checkPolicy, recordAccessDenied, createApprovalRequest, decideApproval, getApprovalStatus } from "../services/policyService.js";
import {
  findCredentials, getCredential, revealSecret, revealSecretForBrokeredUse,
  updateMetadata, revokeCredential, deleteCredential, claimCredential, shareCredential,
  markValidation, storeCredential,
} from "../services/credentialService.js";
import { ingestDetectedCredential, type IngestInput } from "../services/ingestionPipeline.js";
import { adapterRegistry } from "../adapters/registry.js";
import { queryAudit } from "../services/auditService.js";
import { registerAgent, listSessions, getAgent, getAgentWorkspaceIds } from "../services/agentService.js";
import { assertCredentialVisible, VisibilityError } from "../services/visibilityService.js";
import { proxySessionStore } from "../services/proxySessionStore.js";
import { buildAuthorizationUrl, exchangeAuthorizationCode, refreshAccessToken, storeOAuthTokens } from "../services/oauthService.js";
import { eventBus } from "../services/eventBus.js";
import { pool, withTransaction } from "../db/pool.js";
import { recordAudit } from "../services/auditService.js";
import type { CredentialMetadata } from "../services/types.js";

export class ToolError extends Error {
  constructor(message: string, readonly code: string = "tool_error") {
    super(message);
  }
}

function reqCtxOf(ctx: AgentContext) {
  return { transport: ctx.transport, sourceNetwork: ctx.sourceNetwork };
}

/**
 * Fetches a credential and enforces org/workspace visibility before any
 * policy decision is made. Returns `not_found` for both "doesn't exist"
 * and "exists but you can't see it" so a cross-tenant probe can't
 * distinguish the two. Every tool handler that operates on a specific
 * credentialId goes through this instead of calling getCredential directly.
 */
async function loadVisibleCredential(ctx: AgentContext, credentialId: string) {
  const cred = await getCredential(credentialId);
  if (!cred) throw new ToolError("credential not found", "not_found");
  try {
    await assertCredentialVisible(ctx.agent, cred);
  } catch (err) {
    if (err instanceof VisibilityError) throw new ToolError("credential not found", "not_found");
    throw err;
  }
  return cred;
}

function summarize(cred: NonNullable<Awaited<ReturnType<typeof getCredential>>>) {
  return {
    credentialId: cred.id,
    name: cred.name,
    provider: cred.provider,
    credentialType: cred.credentialType,
    status: cred.status,
    environment: cred.environment,
    sensitivity: cred.sensitivity,
    ownerScope: cred.ownerScope,
    tags: cred.tags,
    health: cred.health,
    enrichmentStatus: cred.enrichmentStatus,
    currentVersion: cred.currentVersionNumber,
    lastUsedAt: cred.lastUsedAt,
    metadata: cred.metadata,
    createdAt: cred.createdAt,
    updatedAt: cred.updatedAt,
  };
}

async function requirePolicy(
  ctx: AgentContext,
  action: Parameters<typeof checkPolicy>[2]["action"],
  credential: Parameters<typeof checkPolicy>[1],
) {
  const decision = await checkPolicy(ctx.agent, credential, { ...reqCtxOf(ctx), action });
  if (decision.effect === "deny") {
    await recordAccessDenied(ctx.agent.orgId, ctx.agent.id, ctx.workspaceId, credential.id ?? null, action, decision.reason);
    throw new ToolError(`access denied: ${decision.reason}`, "access_denied");
  }
  return decision;
}

// ---------------------------------------------------------------------------
// secret_* tools
// ---------------------------------------------------------------------------

export async function toolSecretGet(ctx: AgentContext, args: { credentialId: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  const decision = await requirePolicy(ctx, "secret_get", cred);

  if (decision.requiresApproval) {
    const approvalId = await createApprovalRequest(cred.id, ctx.agent.id, "secret_get");
    return { status: "approval_required", approvalId, message: "Human approval required before this credential can be retrieved." };
  }
  if (decision.accessMode !== "direct") {
    throw new ToolError(
      `policy requires accessMode="${decision.accessMode}" for this credential; use credential_execute, credential_proxy_session_create, or credential_temporary_issue instead of secret_get`,
      "wrong_access_mode",
    );
  }
  const value = await revealSecret(cred.id, ctx.agent.id, { workspaceId: ctx.workspaceId, mcpTransport: ctx.transport, sourceNetwork: ctx.sourceNetwork, sessionId: ctx.sessionId });
  return {
    credentialId: cred.id,
    provider: cred.provider,
    credentialType: cred.credentialType,
    authScheme: cred.authScheme,
    value,
    metadata: cred.metadata,
    version: cred.currentVersionNumber,
  };
}

export async function toolSecretFind(ctx: AgentContext, args: {
  provider?: string; credentialType?: string; environment?: string; tags?: string[]; nameQuery?: string; limit?: number;
}) {
  await requirePolicy(ctx, "secret_find", { id: undefined as any, provider: args.provider ?? "*", credentialType: args.credentialType ?? "*", environment: args.environment ?? "development", tags: args.tags ?? [], ownerScope: "workspace", sensitivity: "medium" });
  const memberWorkspaceIds = await getAgentWorkspaceIds(ctx.agent.id);
  const results = await findCredentials({
    ...args, workspaceId: ctx.workspaceId ?? undefined,
    visibleTo: { orgId: ctx.agent.orgId, agentId: ctx.agent.id, memberWorkspaceIds },
  });
  return { credentials: results.map(summarize) };
}

export async function toolSecretList(ctx: AgentContext, args: { status?: string; limit?: number }) {
  await requirePolicy(ctx, "secret_list", { id: undefined as any, provider: "*", credentialType: "*", environment: "development", tags: [], ownerScope: "workspace", sensitivity: "medium" });
  const memberWorkspaceIds = await getAgentWorkspaceIds(ctx.agent.id);
  const results = await findCredentials({
    workspaceId: ctx.workspaceId ?? undefined, status: args.status, limit: args.limit,
    visibleTo: { orgId: ctx.agent.orgId, agentId: ctx.agent.id, memberWorkspaceIds },
  });
  return { credentials: results.map(summarize) };
}

export async function toolSecretMetadata(ctx: AgentContext, args: { credentialId: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_metadata", cred);
  return summarize(cred);
}

export async function toolSecretStore(ctx: AgentContext, args: {
  name: string; provider: string; credentialType: string; secretValue: string; authScheme?: string;
  environment?: string; sensitivity?: string; tags?: string[]; metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}) {
  await requirePolicy(ctx, "secret_store", { id: undefined as any, provider: args.provider, credentialType: args.credentialType, environment: args.environment ?? "development", tags: args.tags ?? [], ownerScope: "workspace", sensitivity: args.sensitivity ?? "medium" });
  const metadata: CredentialMetadata = {};
  const now = new Date().toISOString();
  for (const [k, v] of Object.entries(args.metadata ?? {})) {
    metadata[k] = { value: v, confidence: 0.99, source: "user_provided", verified: true, updatedAt: now };
  }
  const result = await storeCredential({
    orgId: ctx.agent.orgId, workspaceId: ctx.workspaceId, ownerScope: "workspace", name: args.name,
    provider: args.provider, credentialType: args.credentialType, authScheme: args.authScheme ?? null,
    secretValue: args.secretValue, sensitivity: args.sensitivity, environment: args.environment,
    metadata, tags: args.tags, introducingAgentId: ctx.agent.id, creationSource: "manual",
    idempotencyKey: args.idempotencyKey, sessionId: ctx.sessionId, mcpTransport: ctx.transport, sourceNetwork: ctx.sourceNetwork,
  });
  return { credentialId: result.credential.id, created: result.created, rotated: result.rotated, credential: summarize(result.credential) };
}

export async function toolSecretStoreDetected(ctx: AgentContext, args: {
  rawValue: string; sourceKind: IngestInput["sourceKind"]; headerName?: string; envVarName?: string;
  hostHint?: string; name?: string; validate?: boolean; idempotencyKey?: string;
}) {
  if (!ctx.agent.autoIngestionPermission) throw new ToolError("agent lacks auto-ingestion permission", "capability_denied");
  const result = await ingestDetectedCredential({
    ...args, orgId: ctx.agent.orgId, workspaceId: ctx.workspaceId, introducingAgentId: ctx.agent.id,
    sessionId: ctx.sessionId, mcpTransport: ctx.transport, sourceNetwork: ctx.sourceNetwork,
  });
  return {
    credentialId: result.credential.id, created: result.created, rotated: result.rotated,
    provider: result.provider, credentialType: result.credentialType, detectionMatched: result.detectionMatched,
    validationAttempted: result.validationAttempted, validationResult: result.validationResult,
    enrichmentStatus: result.credential.enrichmentStatus, status: result.credential.status,
  };
}

export async function toolSecretUpdate(ctx: AgentContext, args: { credentialId: string; name?: string; tags?: string[]; notes?: string; sensitivity?: string; environment?: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_update", cred);
  const sets: string[] = [];
  const params: unknown[] = [];
  let i = 1;
  if (args.name !== undefined) { sets.push(`name = $${i++}`); params.push(args.name); }
  if (args.tags !== undefined) { sets.push(`tags = $${i++}`); params.push(args.tags); }
  if (args.notes !== undefined) { sets.push(`notes = $${i++}`); params.push(args.notes); }
  if (args.sensitivity !== undefined) { sets.push(`sensitivity = $${i++}`); params.push(args.sensitivity); }
  if (args.environment !== undefined) { sets.push(`environment = $${i++}`); params.push(args.environment); }
  if (sets.length === 0) return summarize(cred);
  params.push(args.credentialId);
  await pool.query(`UPDATE credentials SET ${sets.join(", ")}, updated_at = now() WHERE id = $${i}`, params);
  return summarize((await getCredential(args.credentialId))!);
}

export async function toolSecretEnrich(ctx: AgentContext, args: { credentialId: string; fields: Record<string, unknown>; verified?: boolean }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  if (!ctx.agent.metadataEnrichmentPermission) throw new ToolError("agent lacks metadata-enrichment permission", "capability_denied");
  await requirePolicy(ctx, "secret_enrich", cred);
  const now = new Date().toISOString();
  const metadata: CredentialMetadata = {};
  for (const [k, v] of Object.entries(args.fields)) {
    metadata[k] = { value: v, confidence: args.verified ? 1 : 0.7, source: "agent_enrichment", verified: args.verified ?? false, updatedAt: now };
  }
  const updated = await updateMetadata(args.credentialId, ctx.agent.id, metadata, { enrichmentStatus: "complete" });
  return summarize(updated);
}

export async function toolSecretRotate(ctx: AgentContext, args: { credentialId: string; newSecretValue: string; metadata?: Record<string, unknown> }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_rotate", cred);
  const now = new Date().toISOString();
  const metadata: CredentialMetadata = {
    accountIdentifier: cred.metadata["accountIdentifier"] ?? { value: cred.id, confidence: 0.5, source: "fallback", updatedAt: now },
  };
  for (const [k, v] of Object.entries(args.metadata ?? {})) {
    metadata[k] = { value: v, confidence: 0.9, source: "agent_declared", updatedAt: now };
  }
  const result = await storeCredential({
    orgId: cred.orgId, workspaceId: cred.workspaceId, ownerScope: cred.ownerScope, name: cred.name,
    provider: cred.provider, credentialType: cred.credentialType, authScheme: cred.authScheme,
    secretValue: args.newSecretValue, sensitivity: cred.sensitivity, environment: cred.environment,
    metadata, introducingAgentId: ctx.agent.id, creationSource: "rotation",
    sessionId: ctx.sessionId, mcpTransport: ctx.transport, sourceNetwork: ctx.sourceNetwork,
  });
  return { credentialId: result.credential.id, rotated: result.rotated, version: result.credential.currentVersionNumber };
}

export async function toolSecretRevoke(ctx: AgentContext, args: { credentialId: string; reason?: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_revoke", cred);
  await revokeCredential(args.credentialId, ctx.agent.id, args.reason);
  return { credentialId: args.credentialId, status: "revoked" };
}

export async function toolSecretDelete(ctx: AgentContext, args: { credentialId: string; hard?: boolean }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_delete", cred);
  await deleteCredential(args.credentialId, ctx.agent.id, args.hard);
  return { credentialId: args.credentialId, status: args.hard ? "deleted_permanently" : "deleted" };
}

export async function toolSecretClaim(ctx: AgentContext, args: { credentialId: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_enrich", cred);
  const updated = await claimCredential(args.credentialId, ctx.agent.id);
  return summarize(updated);
}

export async function toolSecretShare(ctx: AgentContext, args: { credentialId: string; sharingPolicy: Record<string, unknown> }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "secret_share", cred);
  const updated = await shareCredential(args.credentialId, ctx.agent.id, args.sharingPolicy);
  return summarize(updated);
}

// ---------------------------------------------------------------------------
// Brokered / execution tools
// ---------------------------------------------------------------------------

export async function toolCredentialExecute(ctx: AgentContext, args: {
  credentialId?: string; proxyToken?: string; operation: string; params?: Record<string, unknown>;
}) {
  let credentialId = args.credentialId;
  let cred: NonNullable<Awaited<ReturnType<typeof getCredential>>>;
  if (args.proxyToken) {
    const session = await proxySessionStore.redeem(args.proxyToken);
    if (!session) throw new ToolError("proxy token invalid or expired", "invalid_proxy_token");
    // A proxy/temporary token is scoped to the agent it was issued to at
    // creation time (which already passed visibility + policy checks) —
    // redemption by a different agent that merely obtained the token
    // string is rejected rather than implicitly re-granting access.
    if (session.agentId !== ctx.agent.id) throw new ToolError("proxy token was not issued to this agent", "invalid_proxy_token");
    credentialId = session.credentialId;
    const found = await getCredential(credentialId);
    if (!found) throw new ToolError("credential not found", "not_found");
    cred = found;
  } else {
    if (!credentialId) throw new ToolError("credentialId or proxyToken is required", "bad_request");
    cred = await loadVisibleCredential(ctx, credentialId);
    await requirePolicy(ctx, "credential_execute", cred);
  }

  const { secretValue, authScheme, metadata } = await revealSecretForBrokeredUse(credentialId);
  const adapter = adapterRegistry.resolve(cred.provider, cred.credentialType);
  try {
    const headerName = metadata["headerName"]?.value as string | undefined;
    const headerPrefix = metadata["headerPrefix"]?.value as string | undefined;
    const baseEndpoint = (metadata["baseEndpoint"]?.value as string | undefined) ?? adapter.defaultBaseEndpoint;
    const result = await adapter.execute(
      { secretValue, authScheme: authScheme ?? undefined, headerName, headerPrefix, baseEndpoint },
      args.operation,
      args.params ?? {},
    );
    await withTransaction(async (client) => {
      await recordAudit(client, {
        orgId: cred.orgId,
        agentId: ctx.agent.id, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
        operation: "credential_execute", accessMode: "brokered", policyDecision: "allow",
        sessionId: ctx.sessionId, mcpTransport: ctx.transport, sourceNetwork: ctx.sourceNetwork,
        result: "success", details: { operation: args.operation, status: result.status },
      });
      await eventBus.publish(client, "credential.used", {
        orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId: ctx.agent.id,
        payload: { accessMode: "brokered", operation: args.operation },
      });
    });
    return { status: result.status, body: result.body };
  } catch (err) {
    throw new ToolError(adapter.sanitizeError(err), "execution_failed");
  }
}

export async function toolCredentialValidate(ctx: AgentContext, args: { credentialId: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "credential_validate", cred);
  const { secretValue, metadata } = await revealSecretForBrokeredUse(args.credentialId);
  const adapter = adapterRegistry.resolve(cred.provider, cred.credentialType);
  const outcome = await adapter.validate({
    secretValue, headerName: metadata["headerName"]?.value as string | undefined,
    headerPrefix: metadata["headerPrefix"]?.value as string | undefined,
    baseEndpoint: (metadata["baseEndpoint"]?.value as string | undefined) ?? adapter.defaultBaseEndpoint,
  });
  await markValidation(args.credentialId, ctx.agent.id, { valid: outcome.valid, result: outcome.result });
  return { valid: outcome.valid, result: outcome.result, scopes: outcome.scopes, expiresAt: outcome.expiresAt };
}

export async function toolCredentialProxySessionCreate(ctx: AgentContext, args: { credentialId: string; ttlSeconds?: number; maxUses?: number }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  const decision = await requirePolicy(ctx, "credential_proxy_session_create", cred);
  const ttl = Math.min(args.ttlSeconds ?? 300, decision.maxSessionSeconds ?? 3600);
  const session = await proxySessionStore.create({
    credentialId: cred.id, agentId: ctx.agent.id, workspaceId: ctx.workspaceId,
    usesRemaining: args.maxUses ?? decision.maxRetrievalCount ?? 10, mode: "proxy", ttlSeconds: ttl,
  });
  return { proxyToken: session.token, expiresAt: session.expiresAt, ttlSeconds: ttl };
}

export async function toolCredentialTemporaryIssue(ctx: AgentContext, args: { credentialId: string; ttlSeconds?: number; maxUses?: number }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "credential_temporary_issue", cred);
  const ttl = Math.min(args.ttlSeconds ?? 60, 900);
  const session = await proxySessionStore.create({
    credentialId: cred.id, agentId: ctx.agent.id, workspaceId: ctx.workspaceId,
    usesRemaining: args.maxUses ?? 1, mode: "temporary", ttlSeconds: ttl,
  });
  return {
    proxyToken: session.token, expiresAt: session.expiresAt, ttlSeconds: ttl,
    note: "Redeem via credential_execute with proxyToken; raw secret material is never returned for temporary issuance.",
  };
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

const pendingOAuthState = new Map<string, { codeVerifier: string; clientId: string; clientSecret?: string; redirectUri: string; provider: string; tokenEndpoint: string; refreshEndpoint?: string; authorizationEndpoint: string; revocationEndpoint?: string }>();

export async function toolOAuthAuthorize(ctx: AgentContext, args: {
  action: "start" | "complete";
  provider: string; clientId: string; clientSecret?: string; redirectUri: string; scopes?: string[];
  authorizationEndpoint?: string; tokenEndpoint?: string; refreshEndpoint?: string; revocationEndpoint?: string;
  state?: string; code?: string; name?: string;
}) {
  const adapter = adapterRegistry.get(args.provider);
  const authorizationEndpoint = args.authorizationEndpoint ?? adapter?.oauth?.authorizationEndpoint;
  const tokenEndpoint = args.tokenEndpoint ?? adapter?.oauth?.tokenEndpoint;
  if (!authorizationEndpoint || !tokenEndpoint) throw new ToolError("authorizationEndpoint/tokenEndpoint required (not known for this provider)", "bad_request");

  if (args.action === "start") {
    const result = buildAuthorizationUrl({
      authorizationEndpoint, tokenEndpoint, clientId: args.clientId, redirectUri: args.redirectUri, scopes: args.scopes ?? [],
    });
    pendingOAuthState.set(result.state, {
      codeVerifier: result.codeVerifier, clientId: args.clientId, clientSecret: args.clientSecret,
      redirectUri: args.redirectUri, provider: args.provider, tokenEndpoint,
      refreshEndpoint: args.refreshEndpoint, authorizationEndpoint, revocationEndpoint: args.revocationEndpoint,
    });
    return { status: "authorization_url_created", url: result.url, state: result.state };
  }

  if (!args.state || !args.code) throw new ToolError("state and code are required to complete the flow", "bad_request");
  const pending = pendingOAuthState.get(args.state);
  if (!pending) throw new ToolError("unknown or expired oauth state", "invalid_state");
  pendingOAuthState.delete(args.state);

  const tokens = await exchangeAuthorizationCode(pending, {
    code: args.code, clientId: pending.clientId, clientSecret: pending.clientSecret,
    redirectUri: pending.redirectUri, codeVerifier: pending.codeVerifier,
  });
  const result = await storeOAuthTokens({
    orgId: ctx.agent.orgId, workspaceId: ctx.workspaceId, provider: pending.provider,
    name: args.name ?? `${pending.provider} oauth`, tokens, endpoints: pending,
    introducingAgentId: ctx.agent.id,
  });
  return { status: "stored", credentialId: result.credential.id, created: result.created };
}

export async function toolOAuthRefresh(ctx: AgentContext, args: { credentialId: string; clientId: string; clientSecret?: string }) {
  const cred = await loadVisibleCredential(ctx, args.credentialId);
  await requirePolicy(ctx, "oauth_refresh", cred);
  const tokenEndpoint = cred.metadata["tokenEndpoint"]?.value as string | undefined;
  const refreshEndpoint = (cred.metadata["refreshEndpoint"]?.value as string | undefined) ?? tokenEndpoint;
  const authorizationEndpoint = cred.metadata["authEndpoint"]?.value as string | undefined;
  if (!tokenEndpoint || !refreshEndpoint || !authorizationEndpoint) throw new ToolError("credential is missing OAuth endpoint metadata required to refresh", "missing_metadata");

  const { secretValue } = await revealSecretForBrokeredUse(args.credentialId);
  const parsed = JSON.parse(secretValue) as { refresh_token?: string };
  if (!parsed.refresh_token) throw new ToolError("credential has no refresh_token to use", "no_refresh_token");

  const tokens = await refreshAccessToken({ authorizationEndpoint, tokenEndpoint, refreshEndpoint }, {
    refreshToken: parsed.refresh_token, clientId: args.clientId, clientSecret: args.clientSecret,
  });
  const result = await storeOAuthTokens({
    orgId: cred.orgId, workspaceId: cred.workspaceId, provider: cred.provider, name: cred.name,
    tokens: { ...tokens, refresh_token: tokens.refresh_token ?? parsed.refresh_token },
    endpoints: { authorizationEndpoint, tokenEndpoint, refreshEndpoint },
    accountIdentifier: cred.metadata["accountIdentifier"]?.value as string | undefined,
    introducingAgentId: ctx.agent.id, isRefresh: true,
  });
  return { credentialId: result.credential.id, rotated: result.rotated, version: result.credential.currentVersionNumber };
}

// ---------------------------------------------------------------------------
// Policy / approval / audit / agent tools
// ---------------------------------------------------------------------------

export async function toolPolicyCheck(ctx: AgentContext, args: {
  action: Parameters<typeof checkPolicy>[2]["action"]; provider: string; credentialType: string; environment?: string;
}) {
  const decision = await checkPolicy(ctx.agent, { id: undefined as any, provider: args.provider, credentialType: args.credentialType, environment: args.environment ?? "development", tags: [], ownerScope: "workspace", sensitivity: "medium" }, { ...reqCtxOf(ctx), action: args.action });
  return decision;
}

export async function toolApprovalRequest(ctx: AgentContext, args: {
  action: "create" | "decide" | "status"; credentialId?: string; operation?: string; approvalId?: string; approve?: boolean; reason?: string;
}) {
  if (args.action === "create") {
    if (!args.credentialId || !args.operation) throw new ToolError("credentialId and operation are required", "bad_request");
    const cred = await loadVisibleCredential(ctx, args.credentialId);
    const id = await createApprovalRequest(cred.id, ctx.agent.id, args.operation);
    return { approvalId: id, status: "pending" };
  }
  if (args.action === "decide") {
    if (!ctx.agent.metadataAdminPermission) throw new ToolError("agent lacks admin permission required to decide approvals", "capability_denied");
    if (!args.approvalId) throw new ToolError("approvalId is required", "bad_request");
    const row = await decideApproval(ctx.agent.orgId, args.approvalId, ctx.agent.id, Boolean(args.approve), args.reason);
    if (!row) throw new ToolError("approval request not found", "not_found");
    return row;
  }
  if (!args.approvalId) throw new ToolError("approvalId is required", "bad_request");
  const status = await getApprovalStatus(ctx.agent.orgId, args.approvalId);
  if (!status) throw new ToolError("approval request not found", "not_found");
  return status;
}

export async function toolAuditQuery(ctx: AgentContext, args: { credentialId?: string; agentId?: string; operation?: string; sinceIso?: string; limit?: number }) {
  await requirePolicy(ctx, "audit_query", { id: undefined as any, provider: "*", credentialType: "*", environment: "development", tags: [], ownerScope: "workspace", sensitivity: "low" });
  const memberWorkspaceIds = await getAgentWorkspaceIds(ctx.agent.id);
  // Org-wide (workspaceless) audit rows — e.g. agent lifecycle events — are
  // only surfaced to admin-capable agents; ordinary agents see only the
  // workspaces they belong to.
  const rows = await queryAudit({
    orgId: ctx.agent.orgId,
    workspaceScope: { workspaceIds: memberWorkspaceIds, includeWorkspaceless: ctx.agent.metadataAdminPermission },
    credentialId: args.credentialId, agentId: args.agentId,
    operation: args.operation, since: args.sinceIso ? new Date(args.sinceIso) : undefined, limit: args.limit,
  });
  return { entries: rows };
}

export async function toolAgentRegister(ctx: AgentContext, args: Parameters<typeof registerAgent>[0]) {
  if (!ctx.agent.metadataAdminPermission) throw new ToolError("agent lacks admin permission required to register other agents", "capability_denied");
  const result = await registerAgent({ ...args, orgId: ctx.agent.orgId });
  return { agentId: result.agent.id, apiKey: result.apiKey, note: apiKeyNote(result.apiKey) };
}

function apiKeyNote(apiKey?: string) {
  return apiKey ? "Store this API key now; it will not be shown again." : undefined;
}

export async function toolAgentSessionList(ctx: AgentContext, args: { agentId?: string }) {
  const targetId = args.agentId ?? ctx.agent.id;
  if (targetId !== ctx.agent.id && !ctx.agent.metadataAdminPermission) {
    throw new ToolError("agent lacks admin permission required to list another agent's sessions", "capability_denied");
  }
  const target = await getAgent(targetId);
  if (!target || target.orgId !== ctx.agent.orgId) throw new ToolError("agent not found", "not_found");
  const sessions = await listSessions(targetId);
  return { agentId: targetId, sessions };
}

export async function toolCredentialEventSubscribe(ctx: AgentContext, args: { sinceEventId?: number; eventTypes?: string[] }) {
  const memberWorkspaceIds = await getAgentWorkspaceIds(ctx.agent.id);
  const events = await eventBus.listEventsSince(args.sinceEventId ?? 0, {
    orgId: ctx.agent.orgId, workspaceIds: memberWorkspaceIds, includeWorkspaceless: ctx.agent.metadataAdminPermission,
  });
  const filtered = args.eventTypes?.length ? events.filter((e) => args.eventTypes!.includes(e.eventType)) : events;
  return {
    events: filtered,
    nextSinceEventId: events.length ? events[events.length - 1]!.id : args.sinceEventId ?? 0,
    note: "Poll again with nextSinceEventId for gap-free catch-up. For push delivery, use the REST/SSE endpoint GET /v1/events/stream instead.",
  };
}
