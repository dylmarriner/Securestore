import type { FastifyReply, FastifyRequest } from "fastify";
import { authenticateApiKey, openSession, getRateLimiter } from "../services/agentService.js";
import type { AgentContext } from "../mcp/context.js";

declare module "fastify" {
  interface FastifyRequest {
    ssCtx?: AgentContext;
  }
}

/**
 * Authenticates every REST call the same way the MCP transports do (a
 * SecureStore agent API key), so REST and MCP clients share one identity
 * model, one rate limiter, and one audit trail. A session row is opened
 * per REST connection-equivalent (first authenticated call) and reused via
 * the returned session id header for subsequent calls from the same
 * client, mirroring MCP session semantics for CI/CD scripts and custom
 * apps that don't speak MCP.
 */
export async function requireAgent(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization;
  const apiKey = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  if (!apiKey) {
    reply.code(401).send({ error: "missing Authorization: Bearer <SecureStore agent API key>" });
    return reply;
  }
  const agent = await authenticateApiKey(apiKey);
  if (!agent) {
    reply.code(401).send({ error: "invalid or revoked SecureStore agent API key" });
    return reply;
  }
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
