import { randomBytes } from "node:crypto";
import { getRedisClient, isRedisConfigured } from "./redisClient.js";
import { RedisProxySessionStore } from "./redisProxySessionStore.js";

export interface ProxySession {
  credentialId: string;
  agentId: string;
  workspaceId: string | null;
  usesRemaining: number;
  mode: "proxy" | "temporary";
}

export interface ProxySessionStoreBackend {
  create(input: ProxySession & { ttlSeconds: number }): Promise<{ token: string; expiresAt: string }>;
  redeem(token: string): Promise<ProxySession | null>;
}

/**
 * In-memory backend. A proxy/temporary-issue token is meant to live
 * seconds-to-minutes, so a process restart invalidating it is an
 * acceptable failure mode for a single-instance deployment, and it keeps
 * `credential_execute` fast (no round-trip to re-check a token that was
 * already policy-checked at issuance). For a horizontally scaled
 * deployment where a token must be redeemable against *any* replica, set
 * REDIS_URL to switch to RedisProxySessionStore — same interface.
 */
class InMemoryProxySessionStore implements ProxySessionStoreBackend {
  private readonly sessions = new Map<string, ProxySession & { expiresAt: number }>();

  async create(input: ProxySession & { ttlSeconds: number }): Promise<{ token: string; expiresAt: string }> {
    const token = randomBytes(24).toString("base64url");
    const expiresAt = Date.now() + input.ttlSeconds * 1000;
    const { ttlSeconds: _ttlSeconds, ...session } = input;
    this.sessions.set(token, { ...session, expiresAt });
    return { token, expiresAt: new Date(expiresAt).toISOString() };
  }

  async redeem(token: string): Promise<ProxySession | null> {
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

let instance: ProxySessionStoreBackend | undefined;

function resolveStore(): ProxySessionStoreBackend {
  if (instance) return instance;
  instance = isRedisConfigured()
    ? new RedisProxySessionStore(getRedisClient()!)
    : new InMemoryProxySessionStore();
  return instance;
}

export const proxySessionStore: ProxySessionStoreBackend = {
  create: (input) => resolveStore().create(input),
  redeem: (token) => resolveStore().redeem(token),
};
