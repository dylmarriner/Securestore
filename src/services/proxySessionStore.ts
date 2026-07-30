import { randomBytes } from "node:crypto";

interface ProxySession {
  credentialId: string;
  agentId: string;
  workspaceId: string | null;
  expiresAt: number;
  usesRemaining: number;
  mode: "proxy" | "temporary";
}

/**
 * Ephemeral brokered-access sessions/tokens. Deliberately in-memory and
 * per-process: a proxy/temporary-issue token is meant to live seconds-to-
 * minutes, so a restart invalidating it is an acceptable failure mode, and
 * it keeps `credential_execute` fast (no DB round-trip to re-check a token
 * that was already policy-checked at issuance). For a horizontally scaled
 * deployment where a token must be redeemable against *any* replica, back
 * this with Redis (SETEX + DECR for usesRemaining) instead — same
 * interface, no call-site changes.
 */
class ProxySessionStore {
  private readonly sessions = new Map<string, ProxySession>();

  create(input: Omit<ProxySession, "expiresAt"> & { ttlSeconds: number }): { token: string; expiresAt: string } {
    const token = randomBytes(24).toString("base64url");
    const expiresAt = Date.now() + input.ttlSeconds * 1000;
    this.sessions.set(token, { ...input, expiresAt });
    return { token, expiresAt: new Date(expiresAt).toISOString() };
  }

  redeem(token: string): ProxySession | null {
    const session = this.sessions.get(token);
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(token);
      return null;
    }
    session.usesRemaining -= 1;
    if (session.usesRemaining <= 0) this.sessions.delete(token);
    return session;
  }
}

export const proxySessionStore = new ProxySessionStore();
