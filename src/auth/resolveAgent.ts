import type { TLSSocket } from "node:tls";
import { authenticateApiKey, authenticateByIdentifier } from "../services/agentService.js";
import { extractClientCertIdentity } from "./mtls.js";
import { verifyOidcToken, isOidcConfigured } from "./oidc.js";
import type { AgentRecord } from "../services/types.js";

export interface ResolvedIdentity {
  agent: AgentRecord;
  authMethod: "mtls" | "api_key" | "oidc";
}

/**
 * Single identity-resolution path shared by the REST middleware
 * (src/api/auth.ts) and the MCP HTTP transport (src/mcp/httpServer.ts),
 * so "how does a request prove who it is" has exactly one implementation
 * regardless of which surface a client used. Tries, in order:
 *   1. mTLS — if the connection is TLS and the client presented a
 *      certificate that passed chain validation (socket.authorized), and
 *      its fingerprint matches a registered agent. Strongest signal, so
 *      checked first; a request can't spoof this without the private key.
 *   2. API key — `Authorization: Bearer sss_...`.
 *   3. OIDC — `Authorization: Bearer <JWT>`, verified against the
 *      configured issuer's JWKS, matched by `sub` claim.
 * Returns null (never throws) when nothing matches; callers turn that
 * into a 401.
 */
export async function resolveAgentIdentity(params: {
  socket?: TLSSocket;
  authorizationHeader?: string;
}): Promise<ResolvedIdentity | null> {
  if (params.socket && "authorized" in params.socket) {
    const clientCert = extractClientCertIdentity(params.socket);
    if (clientCert) {
      const agent = await authenticateByIdentifier("mtls", clientCert.fingerprint);
      if (agent) return { agent, authMethod: "mtls" };
    }
  }

  const bearer = params.authorizationHeader?.startsWith("Bearer ") ? params.authorizationHeader.slice(7) : undefined;
  if (!bearer) return null;

  const apiKeyAgent = await authenticateApiKey(bearer);
  if (apiKeyAgent) return { agent: apiKeyAgent, authMethod: "api_key" };

  if (isOidcConfigured()) {
    try {
      const { sub } = await verifyOidcToken(bearer);
      const oidcAgent = await authenticateByIdentifier("oidc", sub);
      if (oidcAgent) return { agent: oidcAgent, authMethod: "oidc" };
    } catch {
      // Not a valid OIDC token either (or verification failed) — fall through to null.
    }
  }

  return null;
}
