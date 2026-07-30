import type { FastifyInstance } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import { authenticateApiKey, openSession } from "../services/agentService.js";
import { registerSecureStoreTools } from "./registerTools.js";
import type { AgentContext } from "./context.js";

interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
}

// Session state lives per-process. Any replica in a horizontally scaled
// deployment can serve any *new* session (auth + policy state is fully
// shared via Postgres), but an in-flight streamable-HTTP session must keep
// hitting the same replica for its lifetime — put a load balancer with
// session/cookie affinity (or Mcp-Session-Id-aware routing) in front of a
// multi-replica deployment. Session bootstrap itself (agent auth, workspace
// resolution, audit) is stateless and safe to load-balance per-request.
const sessions = new Map<string, SessionEntry>();

function extractApiKey(authHeader: string | string[] | undefined): string | undefined {
  const header = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!header?.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length);
}

/**
 * Mounts the remote/authenticated-HTTPS MCP transport used by Claude web,
 * ChatGPT connectors/actions, browser-hosted agents, and any other
 * MCP-compatible remote client. Each new session authenticates its own
 * agent identity via `Authorization: Bearer <SecureStore API key>` on the
 * MCP `initialize` call; the workspace is selected via the
 * `X-SecureStore-Workspace-Id` header. Local-to-remote bridges (e.g. a
 * stdio<->HTTP proxy run by a desktop app) are just another client of this
 * same endpoint.
 */
export function registerMcpHttpRoutes(app: FastifyInstance): void {
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => {
    try {
      done(null, body.length ? JSON.parse(body as string) : undefined);
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  app.post("/mcp", async (request, reply) => {
    const sessionIdHeader = request.headers["mcp-session-id"] as string | undefined;

    if (sessionIdHeader) {
      const existing = sessions.get(sessionIdHeader);
      if (!existing) {
        reply.code(404).send({ error: "unknown or expired mcp session" });
        return;
      }
      await existing.transport.handleRequest(request.raw, reply.raw, request.body);
      return;
    }

    const apiKey = extractApiKey(request.headers.authorization);
    if (!apiKey) {
      reply.code(401).send({ error: "missing Authorization: Bearer <SecureStore agent API key>" });
      return;
    }
    const agent = await authenticateApiKey(apiKey);
    if (!agent) {
      reply.code(401).send({ error: "invalid or revoked SecureStore agent API key" });
      return;
    }

    const workspaceId = (request.headers["x-securestore-workspace-id"] as string | undefined) ?? null;
    const sourceNetwork = request.ip;
    const { sessionId } = await openSession(agent.id, workspaceId, "http", sourceNetwork);
    const ctx: AgentContext = { agent, sessionId, workspaceId, transport: "http", sourceNetwork };

    const server = new McpServer({ name: "securestore", version: "0.1.0" });
    registerSecureStoreTools(server, ctx);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => sessionId ?? randomUUID(),
      onsessioninitialized: (sid) => {
        sessions.set(sid, { transport, server });
      },
    });
    transport.onclose = () => {
      sessions.delete(sessionId);
    };

    await server.connect(transport);
    await transport.handleRequest(request.raw, reply.raw, request.body);
  });

  app.get("/mcp", async (request, reply) => {
    const sessionIdHeader = request.headers["mcp-session-id"] as string | undefined;
    const existing = sessionIdHeader ? sessions.get(sessionIdHeader) : undefined;
    if (!existing) {
      reply.code(404).send({ error: "unknown or expired mcp session" });
      return;
    }
    await existing.transport.handleRequest(request.raw, reply.raw);
  });

  app.delete("/mcp", async (request, reply) => {
    const sessionIdHeader = request.headers["mcp-session-id"] as string | undefined;
    const existing = sessionIdHeader ? sessions.get(sessionIdHeader) : undefined;
    if (!existing) {
      reply.code(404).send({ error: "unknown or expired mcp session" });
      return;
    }
    await existing.transport.handleRequest(request.raw, reply.raw);
    sessions.delete(sessionIdHeader!);
  });
}
