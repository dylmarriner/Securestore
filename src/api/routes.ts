import type { FastifyInstance } from "fastify";
import { requireAgent } from "./auth.js";
import { ToolError, toolSecretGet, toolSecretFind, toolSecretList, toolSecretMetadata, toolSecretStore,
  toolSecretStoreDetected, toolSecretUpdate, toolSecretEnrich, toolSecretRotate, toolSecretRevoke,
  toolSecretDelete, toolSecretClaim, toolSecretShare, toolCredentialExecute, toolCredentialValidate,
  toolCredentialProxySessionCreate, toolCredentialTemporaryIssue, toolOAuthAuthorize, toolOAuthRefresh,
  toolPolicyCheck, toolApprovalRequest, toolAuditQuery, toolAgentRegister, toolAgentSessionList,
  toolCredentialEventSubscribe } from "../mcp/toolHandlers.js";
import { eventBus } from "../services/eventBus.js";
import { registerAgent } from "../services/agentService.js";

/**
 * REST mirror of the MCP tool surface, for clients that don't speak MCP
 * (CI/CD pipelines, curl/scripts, custom backend integrations). Every
 * route delegates to the same handler function the MCP tools call, so
 * policy evaluation, auditing, and event publication are identical
 * regardless of which transport a client used.
 */
export function registerRestRoutes(app: FastifyInstance): void {
  app.get("/healthz", async () => ({ status: "ok" }));

  app.addHook("preHandler", async (request, reply) => {
    if (request.url === "/healthz" || request.url.startsWith("/v1/bootstrap")) return;
    await requireAgent(request, reply);
  });

  const handle = (fn: (ctx: any, args: any) => Promise<unknown>) => async (request: any, reply: any) => {
    try {
      const args = { ...(request.params ?? {}), ...(request.query ?? {}), ...(request.body ?? {}) };
      const result = await fn(request.ssCtx, args);
      return result;
    } catch (err) {
      if (err instanceof ToolError) {
        reply.code(err.code === "access_denied" || err.code === "capability_denied" ? 403 : err.code === "not_found" ? 404 : 400);
        return { error: err.message, code: err.code };
      }
      request.log.error(err);
      reply.code(500);
      return { error: "internal error" };
    }
  };

  app.get("/v1/secrets/:credentialId", handle(toolSecretGet));
  app.get("/v1/secrets", handle(toolSecretFind));
  app.get("/v1/secrets/:credentialId/metadata", handle(toolSecretMetadata));
  app.post("/v1/secrets", handle(toolSecretStore));
  app.post("/v1/secrets/detected", handle(toolSecretStoreDetected));
  app.patch("/v1/secrets/:credentialId", handle(toolSecretUpdate));
  app.post("/v1/secrets/:credentialId/enrich", handle(toolSecretEnrich));
  app.post("/v1/secrets/:credentialId/rotate", handle(toolSecretRotate));
  app.post("/v1/secrets/:credentialId/revoke", handle(toolSecretRevoke));
  app.delete("/v1/secrets/:credentialId", handle(toolSecretDelete));
  app.post("/v1/secrets/:credentialId/claim", handle(toolSecretClaim));
  app.post("/v1/secrets/:credentialId/share", handle(toolSecretShare));

  app.post("/v1/credentials/execute", handle(toolCredentialExecute));
  app.post("/v1/credentials/:credentialId/validate", handle(toolCredentialValidate));
  app.post("/v1/credentials/:credentialId/proxy-session", handle(toolCredentialProxySessionCreate));
  app.post("/v1/credentials/:credentialId/temporary-issue", handle(toolCredentialTemporaryIssue));

  app.post("/v1/oauth/authorize", handle(toolOAuthAuthorize));
  app.post("/v1/oauth/refresh", handle(toolOAuthRefresh));

  app.post("/v1/policy/check", handle(toolPolicyCheck));
  app.post("/v1/approvals", handle(toolApprovalRequest));
  app.get("/v1/audit", handle(toolAuditQuery));
  app.post("/v1/agents", handle(toolAgentRegister));
  app.get("/v1/agents/:agentId/sessions", handle(toolAgentSessionList));
  app.get("/v1/agents/sessions", handle(toolAgentSessionList));

  app.get("/v1/events", handle(toolCredentialEventSubscribe));

  // Real-time push delivery for clients that want a live stream instead of polling /v1/events.
  app.get("/v1/events/stream", async (request, reply) => {
    await requireAgent(request, reply);
    if (reply.sent) return;
    const ctx = request.ssCtx!;

    reply.raw.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });

    const { getAgentWorkspaceIds } = await import("../services/agentService.js");
    const memberWorkspaceIds = await getAgentWorkspaceIds(ctx.agent.id);
    const unsubscribe = eventBus.subscribe(
      { orgId: ctx.agent.orgId, workspaceIds: memberWorkspaceIds, includeWorkspaceless: ctx.agent.metadataAdminPermission },
      {},
      (event) => {
        reply.raw.write(`id: ${event.id}\nevent: ${event.eventType}\ndata: ${JSON.stringify(event)}\n\n`);
      },
    );
    request.raw.on("close", unsubscribe);
  });

  // Unauthenticated bootstrap route for standing up the very first admin agent in a fresh deployment.
  app.post("/v1/bootstrap", async (request, reply) => {
    const body = request.body as { bootstrapToken?: string; orgId: string; name: string };
    const { config } = await import("../config.js");
    if (!config.auth.adminBootstrapToken || body.bootstrapToken !== config.auth.adminBootstrapToken) {
      reply.code(403);
      return { error: "invalid bootstrap token" };
    }
    const result = await registerAgent({
      orgId: body.orgId, name: body.name, agentType: "admin", rawSecretAccess: true,
      rotationPermission: true, revocationPermission: true, riskClassification: "low",
    });
    await import("../db/pool.js").then(({ pool }) =>
      pool.query(`UPDATE agents SET metadata_admin_permission = true WHERE id = $1`, [result.agent.id]),
    );
    return { agentId: result.agent.id, apiKey: result.apiKey };
  });
}
