import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AgentContext } from "./context.js";
import { ToolError, toolSecretGet, toolSecretFind, toolSecretList, toolSecretMetadata, toolSecretStore,
  toolSecretStoreDetected, toolSecretUpdate, toolSecretEnrich, toolSecretRotate, toolSecretRevoke,
  toolSecretDelete, toolSecretClaim, toolSecretShare, toolSecretTransferOwnership, toolCredentialExecute, toolCredentialValidate,
  toolCredentialProxySessionCreate, toolCredentialTemporaryIssue, toolOAuthAuthorize, toolOAuthRefresh,
  toolPolicyCheck, toolApprovalRequest, toolAuditQuery, toolAgentRegister, toolAgentSessionList,
  toolCredentialEventSubscribe } from "./toolHandlers.js";

const metadataFieldSchema = z.record(z.string(), z.unknown());
const sourceKindSchema = z.enum([
  "agent_instruction", "tool_input", "mcp_tool_argument", "api_request_config", "http_authorization_header",
  "environment_variable", "interactive_input", "oauth_response", "oauth_refresh", "cli_command",
  "ide_task_config", "imported_config_file", "provider_sdk_config", "agent_memory", "tool_call_result",
  "connector_config", "package_manager_auth", "git_credential", "cloud_auth", "database_config",
  "service_account_file", "agent_generated", "rotation",
]);

function wrap<Args>(ctx: AgentContext, fn: (ctx: AgentContext, args: Args) => Promise<unknown>) {
  return async (args: Args) => {
    try {
      const result = await fn(ctx, args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof ToolError ? err.message : err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }], isError: true };
    }
  };
}

/**
 * Registers the full SecureStore tool set on an McpServer instance bound to
 * one already-authenticated agent context. One McpServer/context pair per
 * connection (stdio process, or HTTP session) — the tool handlers in
 * toolHandlers.ts are transport-agnostic and reused verbatim by the REST
 * API, so behavior is identical across every client surface.
 */
export function registerSecureStoreTools(server: McpServer, ctx: AgentContext): void {
  server.tool("secret_get", "Retrieve a stored credential's raw value when policy permits direct access.",
    { credentialId: z.string() }, wrap(ctx, toolSecretGet));

  server.tool("secret_find", "Search stored credentials by provider, type, environment, tags, or name. Never returns raw secret values.",
    { provider: z.string().optional(), credentialType: z.string().optional(), environment: z.string().optional(), tags: z.array(z.string()).optional(), nameQuery: z.string().optional(), limit: z.number().optional() },
    wrap(ctx, toolSecretFind));

  server.tool("secret_list", "List credentials visible to this agent's workspace. Never returns raw secret values.",
    { status: z.string().optional(), limit: z.number().optional() }, wrap(ctx, toolSecretList));

  server.tool("secret_metadata", "Fetch full metadata for a single credential without its secret value.",
    { credentialId: z.string() }, wrap(ctx, toolSecretMetadata));

  server.tool("secret_store", "Manually store a new credential (or update/dedupe an existing one) in the shared store.",
    {
      name: z.string(), provider: z.string(), credentialType: z.string(), secretValue: z.string(),
      authScheme: z.string().optional(), environment: z.string().optional(), sensitivity: z.string().optional(),
      tags: z.array(z.string()).optional(), metadata: metadataFieldSchema.optional(), idempotencyKey: z.string().optional(),
    }, wrap(ctx, toolSecretStore));

  server.tool("secret_store_detected", "Auto-capture a credential this agent just encountered (header, env var, tool arg, OAuth response, etc). Detects provider/type, dedupes, enriches, validates, and stores it.",
    {
      rawValue: z.string(), sourceKind: sourceKindSchema, headerName: z.string().optional(),
      envVarName: z.string().optional(), hostHint: z.string().optional(), name: z.string().optional(),
      validate: z.boolean().optional(), idempotencyKey: z.string().optional(),
    }, wrap(ctx, toolSecretStoreDetected));

  server.tool("secret_update", "Update non-secret fields (name, tags, notes, sensitivity, environment) on a credential.",
    { credentialId: z.string(), name: z.string().optional(), tags: z.array(z.string()).optional(), notes: z.string().optional(), sensitivity: z.string().optional(), environment: z.string().optional() },
    wrap(ctx, toolSecretUpdate));

  server.tool("secret_enrich", "Add or correct metadata fields on a credential (including ones another agent introduced).",
    { credentialId: z.string(), fields: metadataFieldSchema, verified: z.boolean().optional() }, wrap(ctx, toolSecretEnrich));

  server.tool("secret_rotate", "Store a replacement secret value as a new version of an existing credential.",
    { credentialId: z.string(), newSecretValue: z.string(), metadata: metadataFieldSchema.optional() }, wrap(ctx, toolSecretRotate));

  server.tool("secret_revoke", "Mark a credential revoked; connected agents lose access immediately via the event stream.",
    { credentialId: z.string(), reason: z.string().optional() }, wrap(ctx, toolSecretRevoke));

  server.tool("secret_delete", "Soft-delete (or, if hard=true, permanently delete) a credential record.",
    { credentialId: z.string(), hard: z.boolean().optional() }, wrap(ctx, toolSecretDelete));

  server.tool("secret_claim", "Take ownership/enrichment responsibility for an unresolved credential another agent introduced.",
    { credentialId: z.string() }, wrap(ctx, toolSecretClaim));

  server.tool("secret_share", "Change a credential's sharing policy (visibility scope).",
    { credentialId: z.string(), sharingPolicy: z.record(z.string(), z.unknown()) }, wrap(ctx, toolSecretShare));

  server.tool("secret_transfer_ownership", "Reassign who owns/is accountable for a credential (distinct from secret_share, which changes visibility without changing ownership). Only the current owner or an admin-capable agent may call this.",
    {
      credentialId: z.string(),
      ownerScope: z.enum(["personal", "workspace", "project", "organization", "agent", "service_account", "environment", "ephemeral"]),
      ownerUserId: z.string().optional(), ownerAgentId: z.string().optional(), workspaceId: z.string().optional(),
    }, wrap(ctx, toolSecretTransferOwnership as any));

  server.tool("credential_execute", "Perform a brokered operation with a credential without ever receiving its raw value. Accepts either credentialId (policy-checked per call) or a proxyToken from credential_proxy_session_create.",
    { credentialId: z.string().optional(), proxyToken: z.string().optional(), operation: z.string(), params: z.record(z.string(), z.unknown()).optional() },
    wrap(ctx, toolCredentialExecute));

  server.tool("credential_validate", "Run the provider's safe validation call against a credential and update its health status.",
    { credentialId: z.string() }, wrap(ctx, toolCredentialValidate));

  server.tool("credential_proxy_session_create", "Issue a short-lived, revocable proxy token that authorizes brokered credential_execute calls without repeating a full policy check each time.",
    { credentialId: z.string(), ttlSeconds: z.number().optional(), maxUses: z.number().optional() }, wrap(ctx, toolCredentialProxySessionCreate));

  server.tool("credential_temporary_issue", "Issue a short-lived, limited-use handle for a credential. Never returns raw secret material.",
    { credentialId: z.string(), ttlSeconds: z.number().optional(), maxUses: z.number().optional() }, wrap(ctx, toolCredentialTemporaryIssue));

  server.tool("oauth_authorize", "Drives OAuth 2.1 grants: authorization-code + PKCE (action=start then action=complete), device code (action=device_start then poll with action=device_poll), and client_credentials (action=client_credentials, one call). Stores the resulting tokens as a new credential.",
    {
      action: z.enum(["start", "complete", "device_start", "device_poll", "client_credentials"]),
      provider: z.string(), clientId: z.string(), clientSecret: z.string().optional(),
      redirectUri: z.string().optional(), scopes: z.array(z.string()).optional(), authorizationEndpoint: z.string().optional(),
      tokenEndpoint: z.string().optional(), refreshEndpoint: z.string().optional(), revocationEndpoint: z.string().optional(),
      deviceAuthorizationEndpoint: z.string().optional(), deviceCode: z.string().optional(),
      state: z.string().optional(), code: z.string().optional(), name: z.string().optional(),
    }, wrap(ctx, toolOAuthAuthorize));

  server.tool("oauth_refresh", "Refresh an OAuth credential's access token using its stored refresh token; stores the result as a new version.",
    { credentialId: z.string(), clientId: z.string(), clientSecret: z.string().optional() }, wrap(ctx, toolOAuthRefresh));

  server.tool("policy_check", "Dry-run the policy engine for an action/provider/type/environment combination without performing it.",
    { action: z.string(), provider: z.string(), credentialType: z.string(), environment: z.string().optional() }, wrap(ctx, toolPolicyCheck as any));

  server.tool("approval_request", "Create, decide, or check the status of a human-approval request for a gated operation.",
    { action: z.enum(["create", "decide", "status"]), credentialId: z.string().optional(), operation: z.string().optional(), approvalId: z.string().optional(), approve: z.boolean().optional(), reason: z.string().optional() },
    wrap(ctx, toolApprovalRequest));

  server.tool("audit_query", "Query the sanitized audit trail for this agent's workspace.",
    { credentialId: z.string().optional(), agentId: z.string().optional(), operation: z.string().optional(), sinceIso: z.string().optional(), limit: z.number().optional() },
    wrap(ctx, toolAuditQuery));

  server.tool("agent_register", "Register a new agent identity (requires admin capability).",
    {
      name: z.string(), agentType: z.string(), platform: z.string().optional(), version: z.string().optional(),
      authMethod: z.string().optional(), allowedTransports: z.array(z.string()).optional(), allowedTools: z.array(z.string()).optional(),
      allowedNamespaces: z.array(z.string()).optional(), allowedProviders: z.array(z.string()).optional(), allowedOperations: z.array(z.string()).optional(),
      rawSecretAccess: z.boolean().optional(), autoIngestionPermission: z.boolean().optional(), metadataEnrichmentPermission: z.boolean().optional(),
      rotationPermission: z.boolean().optional(), revocationPermission: z.boolean().optional(),
      riskClassification: z.enum(["low", "standard", "elevated", "high"]).optional(), workspaceIds: z.array(z.string()).optional(),
    }, wrap(ctx, toolAgentRegister as any));

  server.tool("agent_session_list", "List active/recent sessions for this agent, or (with admin capability) another agent.",
    { agentId: z.string().optional() }, wrap(ctx, toolAgentSessionList));

  server.tool("credential_event_subscribe", "Fetch credential/policy lifecycle events since a given event id (poll with the returned nextSinceEventId for gap-free catch-up).",
    { sinceEventId: z.number().optional(), eventTypes: z.array(z.string()).optional() }, wrap(ctx, toolCredentialEventSubscribe));
}
