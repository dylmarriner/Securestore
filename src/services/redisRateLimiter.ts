import type { Redis } from "ioredis";
import type { RateLimiter } from "./agentService.js";

// Atomic fixed-window counter: INCR and the first-hit PEXPIRE happen in one
// round-trip, so concurrent requests from different replicas can't race
// each other into skipping the expiry (which would otherwise let the key
// live forever after the first caller's INCR won the race). Fixed-window
// (rather than a true rolling/token-bucket window) is a deliberate
// simplicity tradeoff — it admits a burst of up to 2x the limit at a
// window boundary, which is acceptable for the coarse per-agent quotas
// this guards.
const SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if current > tonumber(ARGV[2]) then
  return 0
else
  return 1
end
`;

/**
 * Redis-backed rate limiter: gives an exact (not per-replica-approximate)
 * global limit across a horizontally scaled deployment. Activated by
 * setting REDIS_URL — see getRateLimiter() in agentService.ts.
 */
export class RedisRateLimiter implements RateLimiter {
  constructor(
    private readonly redis: Redis,
    private readonly perMinute: number,
  ) {}

  async tryConsume(agentId: string): Promise<boolean> {
    const key = `securestore:ratelimit:${agentId}`;
    const result = await this.redis.eval(SCRIPT, 1, key, 60_000, this.perMinute);
    return result === 1;
  }
}
