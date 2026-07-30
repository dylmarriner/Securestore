import Fastify from "fastify";
import cors from "@fastify/cors";
import { config } from "./config.js";
import { eventBus } from "./services/eventBus.js";
import { registerRestRoutes } from "./api/routes.js";
import { registerMcpHttpRoutes } from "./mcp/httpServer.js";

/**
 * Builds one Fastify app exposing both the REST API and the MCP
 * streamable-HTTP transport, so every non-stdio client (Claude web,
 * ChatGPT connectors, browser agents, CI/CD, custom apps) talks to the
 * same process on the same port. Horizontal scaling = run N copies of this
 * process behind a load balancer; they share state entirely through
 * Postgres (see src/services/eventBus.ts for the cross-replica real-time
 * fan-out story and src/mcp/httpServer.ts for the session-affinity caveat).
 */
export async function buildApp() {
  const app = Fastify({ logger: true, trustProxy: true });
  await app.register(cors, { origin: true });
  registerMcpHttpRoutes(app);
  registerRestRoutes(app);
  return app;
}

async function main() {
  await eventBus.start();
  const app = await buildApp();

  await app.listen({ host: config.http.host, port: config.http.port });
  app.log.info(`SecureStore listening on http://${config.http.host}:${config.http.port}`);

  // Optional additional listener on a Unix domain socket (Linux/macOS) or
  // Windows named pipe (e.g. \\.\pipe\securestore) for local, filesystem-
  // permission-scoped clients (containers sharing a mounted socket,
  // desktop apps, dev-container sidecars) that shouldn't need a network
  // port at all. Node's http server treats a string passed to `listen()`
  // as a socket/pipe path automatically — no separate code path needed for
  // Windows vs. Unix.
  const socketPath = process.env.SECURESTORE_SOCKET_PATH;
  if (socketPath) {
    const socketApp = await buildApp();
    await socketApp.listen({ path: socketPath });
    socketApp.log.info(`SecureStore also listening on socket ${socketPath}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
