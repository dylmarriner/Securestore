import type { FastifyReply, FastifyRequest } from "fastify";
import type { TLSSocket } from "node:tls";
import { openSession, getRateLimiter } from "../services/agentService.js";
import { resolveAgentIdentity } from "../auth/resolveAgent.js";
import type { AgentContext } from "../mcp/context.js";

declare module "fastify" {
  interface FastifyRequest {
    ssCtx?: AgentContext;
  }
}

/**
 * Authenticates every REST call the same way the MCP transports do (mTLS
 * client certificate, SecureStore API key, or OIDC bearer token — see
 * src/auth/resolveAgent.ts), so REST and MCP clients share one identity
 * model, one rate limiter, and one audit trail. A session row is opened
 * per REST connection-equivalent (first authenticated call) and reused via
 * the returned session id header for subsequent calls from the same
 * client, mirroring MCP session semantics for CI/CD scripts and custom
 * apps that don't speak MCP.
 */
export async function requireAgent(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const identity = await resolveAgentIdentity({
    socket: request.raw.socket as TLSSocket,
    authorizationHeader: request.headers.authorization,
  });
  if (!identity) {
    reply.code(401).send({ error: "no valid credential presented (mTLS client certificate, Bearer <SecureStore API key>, or Bearer <OIDC token>)" });
    return reply;
  }
  const { agent } = identity;
  if (!(await getRateLimiter().tryConsume(agent.id))) {
    reply.code(429).send({ error: "rate limit exceeded" });
    return reply;
  }

  const workspaceId = (request.headers["x-securestore-workspace-id"] as string | undefined) ?? null;
  let sessionId = request.headers["x-securestore-session-id"] as string | undefined;
  if (!sessionId) {
    try {
      const session = await openSession(agent.id, workspaceId, "http", request.ip);
      sessionId = session.sessionId;
    } catch (err) {
      reply.code(403).send({ error: err instanceof Error ? err.message : "workspace access denied" });
      return reply;
    }
    reply.header("x-securestore-session-id", sessionId);
  }

  request.ssCtx = { agent, sessionId, workspaceId, transport: "http", sourceNetwork: request.ip };
}
