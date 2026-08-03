import { Redis } from "ioredis";
import { config } from "../config.js";

let client: Redis | undefined;

/** Returns a shared ioredis client, or undefined if REDIS_URL isn't configured (in-memory fallbacks apply). */
export function getRedisClient(): Redis | undefined {
  if (!config.redis.url) return undefined;
  if (!client) {
    client = new Redis(config.redis.url, { lazyConnect: false, maxRetriesPerRequest: 3 });
    client.on("error", (err: Error) => console.error("redis connection error", err));
  }
  return client;
}

export function isRedisConfigured(): boolean {
  return Boolean(config.redis.url);
}
