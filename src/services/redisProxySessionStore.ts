import type { Redis } from "ioredis";
import { randomBytes } from "node:crypto";
import type { ProxySession, ProxySessionStoreBackend } from "./proxySessionStore.js";

// Atomically decrements usesRemaining and returns the post-decrement hash;
// deletes the key once exhausted. Redis's own key TTL (set at creation)
// handles time-based expiry — a redeem against an expired/nonexistent key
// just finds EXISTS == 0 and returns nil, no separate expiresAt bookkeeping
// needed. Doing the decrement + conditional delete in one script closes
// the race a plain GET-then-DECR-then-DEL would have between two replicas
// redeeming the same last use concurrently.
const REDEEM_SCRIPT = `
local exists = redis.call('EXISTS', KEYS[1])
if exists == 0 then
  return nil
end
local uses = redis.call('HINCRBY', KEYS[1], 'usesRemaining', -1)
local data = redis.call('HGETALL', KEYS[1])
if uses <= 0 then
  redis.call('DEL', KEYS[1])
end
return data
`;

function keyFor(token: string): string {
  return `securestore:proxysession:${token}`;
}

function hgetallArrayToObject(flat: string[]): Record<string, string> {
  const obj: Record<string, string> = {};
  for (let i = 0; i < flat.length; i += 2) {
    obj[flat[i]!] = flat[i + 1]!;
  }
  return obj;
}

/**
 * Redis-backed proxy/temporary-issue session store: a token minted by one
 * replica is redeemable against any other replica, which matters once
 * `credential_proxy_session_create` and the later `credential_execute`
 * call can legitimately land on different instances behind a load
 * balancer. Activated by setting REDIS_URL — see resolveStore() in
 * proxySessionStore.ts.
 */
export class RedisProxySessionStore implements ProxySessionStoreBackend {
  constructor(private readonly redis: Redis) {}

  async create(input: ProxySession & { ttlSeconds: number }): Promise<{ token: string; expiresAt: string }> {
    const token = randomBytes(24).toString("base64url");
    const key = keyFor(token);
    const ttlMs = input.ttlSeconds * 1000;
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();

    const tx = this.redis.multi();
    tx.hset(key, {
      credentialId: input.credentialId,
      agentId: input.agentId,
      workspaceId: input.workspaceId ?? "",
      mode: input.mode,
      usesRemaining: String(input.usesRemaining),
    });
    tx.pexpire(key, ttlMs);
    await tx.exec();

    return { token, expiresAt };
  }

  async redeem(token: string): Promise<ProxySession | null> {
    const key = keyFor(token);
    const raw = (await this.redis.eval(REDEEM_SCRIPT, 1, key)) as string[] | null;
    if (!raw || raw.length === 0) return null;
    const obj = hgetallArrayToObject(raw);
    return {
      credentialId: obj.credentialId!,
      agentId: obj.agentId!,
      workspaceId: obj.workspaceId ? obj.workspaceId : null,
      mode: obj.mode as ProxySession["mode"],
      usesRemaining: Number(obj.usesRemaining),
    };
  }
}
