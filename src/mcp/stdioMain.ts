#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { authenticateApiKey, openSession } from "../services/agentService.js";
import { registerSecureStoreTools } from "./registerTools.js";
import type { AgentContext } from "./context.js";

/**
 * Entry point for local agents (CLI tools, IDE extensions, terminal
 * assistants) that speak MCP over stdio. One process = one agent identity,
 * authenticated once at startup via SECURESTORE_AGENT_API_KEY — this is
 * the standard pattern for stdio MCP servers, since stdio has no per-request
 * auth headers. For multi-agent/remote scenarios, use the HTTP transport
 * (src/mcp/httpServer.ts) instead, which authenticates per session.
 */
async function main() {
  const apiKey = process.env.SECURESTORE_AGENT_API_KEY;
  if (!apiKey) {
    console.error("SECURESTORE_AGENT_API_KEY is required to start the stdio MCP server");
    process.exit(1);
  }
  const agent = await authenticateApiKey(apiKey);
  if (!agent) {
    console.error("invalid or revoked SecureStore agent API key");
    process.exit(1);
  }

  const workspaceId = process.env.SECURESTORE_WORKSPACE_ID ?? null;
  const { sessionId } = await openSession(agent.id, workspaceId, "stdio");

  const ctx: AgentContext = { agent, sessionId, workspaceId, transport: "stdio" };

  const server = new McpServer({ name: "securestore", version: "0.1.0" });
  registerSecureStoreTools(server, ctx);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
