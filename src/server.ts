import Fastify from "fastify";
import cors from "@fastify/cors";
import { readFileSync } from "node:fs";
import { config } from "./config.js";
import { eventBus } from "./services/eventBus.js";
import { registerRestRoutes } from "./api/routes.js";
import { registerMcpHttpRoutes } from "./mcp/httpServer.js";
import { startScheduledJobs } from "./services/scheduledJobs.js";
import { isMtlsConfigured } from "./auth/mtls.js";

/**
 * Builds one Fastify app exposing both the REST API and the MCP
 * streamable-HTTP transport, so every non-stdio client (Claude web,
 * ChatGPT connectors, browser agents, CI/CD, custom apps) talks to the
 * same port. Horizontal scaling = run N copies of this process behind a
 * load balancer; they share state entirely through Postgres (see
 * src/services/eventBus.ts for the cross-replica real-time fan-out story
 * and src/mcp/httpServer.ts for the session-affinity caveat).
 *
 * When SECURESTORE_TLS_CERT_PATH/KEY_PATH/CA_PATH are all set, the
 * listener switches from plain HTTP to HTTPS with client-certificate
 * support (`requestCert: true`); the CA is what SecureStore trusts to
 * have actually signed a connecting client's certificate, independent of
 * whether SECURESTORE_MTLS_REQUIRE forces every connection to present
 * one. Certificate-to-agent identity resolution happens per-request in
 * src/auth/resolveAgent.ts, not here — this only sets up the transport.
 */
export async function buildApp() {
  const httpsOptions = isMtlsConfigured()
    ? {
        cert: readFileSync(config.mtls.certPath!),
        key: readFileSync(config.mtls.keyPath!),
        ca: readFileSync(config.mtls.caPath!),
        requestCert: true,
        rejectUnauthorized: config.mtls.requireClientCert,
      }
    : null;

  const app = Fastify({ logger: true, trustProxy: true, https: httpsOptions });
  await app.register(cors, { origin: true });
  registerMcpHttpRoutes(app);
  registerRestRoutes(app);
  return app;
}

async function main() {
  await eventBus.start();
  const app = await buildApp();

  // Every replica calls this; the advisory locks in scheduledJobs.ts
  // ensure only one of them actually does the work per tick. Set
  // SECURESTORE_DISABLE_SCHEDULED_JOBS=1 to opt a replica out entirely
  // (e.g. a read-heavy replica you don't want doing background writes).
  if (process.env.SECURESTORE_DISABLE_SCHEDULED_JOBS !== "1") {
    startScheduledJobs();
  }

  await app.listen({ host: config.http.host, port: config.http.port });
  const scheme = isMtlsConfigured() ? "https" : "http";
  app.log.info(`SecureStore listening on ${scheme}://${config.http.host}:${config.http.port}`);

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
