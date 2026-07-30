import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "../config.js";

function pepper(name: string, b64?: string): Buffer {
  if (!b64) {
    throw new Error(
      `${name} is not set. Generate one with \`openssl rand -base64 32\` and set it in the environment.`,
    );
  }
  return Buffer.from(b64, "base64");
}

/**
 * Deterministic, keyed fingerprint used ONLY for deduplication — never for
 * decryption. HMAC-SHA256(serverPepper, provider || ":" || credentialType ||
 * ":" || normalizedSecret). Because it's keyed with a server-side secret
 * that never leaves the trusted boundary, an attacker with database access
 * alone cannot brute-force which plaintext produced a given fingerprint,
 * unlike a bare hash. The DB's UNIQUE index on this column is what actually
 * enforces "never store the same secret twice" under concurrent writers.
 */
export function fingerprintSecret(
  provider: string,
  credentialType: string,
  normalizedSecret: string,
): string {
  const key = pepper("SECURESTORE_FINGERPRINT_PEPPER", config.crypto.fingerprintPepperB64);
  return createHmac("sha256", key)
    .update(`${provider}:${credentialType}:${normalizedSecret}`)
    .digest("hex");
}

/** Strips incidental whitespace so cosmetic differences don't defeat dedup. */
export function normalizeSecretForFingerprint(raw: string): string {
  return raw.trim();
}

export function generateApiKey(): { raw: string; prefix: string } {
  const raw = "sss_" + randomBytes(24).toString("base64url");
  return { raw, prefix: raw.slice(0, 12) };
}

export function hashApiKey(raw: string): string {
  const key = pepper("SECURESTORE_APIKEY_PEPPER", config.auth.apiKeyPepperB64);
  return createHmac("sha256", key).update(raw).digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
