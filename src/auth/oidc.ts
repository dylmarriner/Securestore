import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { config } from "../config.js";

let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

function getJwks() {
  if (!config.oidc.jwksUri) {
    throw new Error("SECURESTORE_OIDC_JWKS_URI is not configured");
  }
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(config.oidc.jwksUri));
  }
  return jwks;
}

export function isOidcConfigured(): boolean {
  return Boolean(config.oidc.issuer && config.oidc.jwksUri && config.oidc.audience);
}

/**
 * Verifies a bearer JWT against the configured OIDC issuer's JWKS
 * (signature, issuer, audience, expiry — all via `jose`'s standard
 * verification, not the structural-only inspection used by the
 * credential-detection pipeline in src/detectors/jwt.ts, which explicitly
 * never verifies a signature). Returns the token's `sub` claim, which is
 * what gets matched against `agents.auth_identifier`.
 */
export async function verifyOidcToken(token: string): Promise<{ sub: string; claims: JWTPayload }> {
  if (!isOidcConfigured()) {
    throw new Error("OIDC auth is not configured (SECURESTORE_OIDC_ISSUER/JWKS_URI/AUDIENCE)");
  }
  const { payload } = await jwtVerify(token, getJwks(), {
    issuer: config.oidc.issuer,
    audience: config.oidc.audience,
  });
  if (!payload.sub) throw new Error("OIDC token has no sub claim");
  return { sub: payload.sub, claims: payload };
}
