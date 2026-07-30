export interface JwtClaims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  exp?: number;
  iat?: number;
  scope?: string;
  scp?: string[];
  azp?: string;
  [k: string]: unknown;
}

/**
 * Structural JWT inspection ONLY — this never verifies a signature and must
 * never be treated as proof of authenticity. It exists purely to harvest
 * safe, public metadata (issuer, audience, expiry, scopes) that helps
 * enrich a credential record. Signature verification (when needed for
 * trust decisions) belongs to the relevant provider adapter's validation
 * method, which calls the provider's real verification endpoint/JWKS.
 */
export function tryParseJwt(value: string): { header: Record<string, unknown>; claims: JwtClaims } | null {
  const parts = value.split(".");
  if (parts.length !== 3) return null;
  try {
    const decode = (seg: string) =>
      JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    const header = decode(parts[0]!);
    const claims = decode(parts[1]!);
    if (typeof header !== "object" || typeof claims !== "object") return null;
    return { header, claims };
  } catch {
    return null;
  }
}
