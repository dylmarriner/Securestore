import { describe, expect, it } from "vitest";
import { fingerprintSecret, normalizeSecretForFingerprint, generateApiKey, hashApiKey } from "../src/crypto/fingerprint.js";

describe("fingerprinting (dedup)", () => {
  it("is deterministic for the same provider/type/secret", () => {
    const a = fingerprintSecret("github", "pat", "ghp_abc123");
    const b = fingerprintSecret("github", "pat", "ghp_abc123");
    expect(a).toBe(b);
  });

  it("differs when the provider differs, even for the same secret value", () => {
    const a = fingerprintSecret("github", "pat", "shared-value");
    const b = fingerprintSecret("gitlab", "pat", "shared-value");
    expect(a).not.toBe(b);
  });

  it("differs when the secret value differs", () => {
    const a = fingerprintSecret("github", "pat", "value-one");
    const b = fingerprintSecret("github", "pat", "value-two");
    expect(a).not.toBe(b);
  });

  it("normalizes incidental whitespace before fingerprinting", () => {
    expect(normalizeSecretForFingerprint("  ghp_abc123  \n")).toBe("ghp_abc123");
  });

  it("api keys hash deterministically and are unique per generation", () => {
    const k1 = generateApiKey();
    const k2 = generateApiKey();
    expect(k1.raw).not.toBe(k2.raw);
    expect(hashApiKey(k1.raw)).toBe(hashApiKey(k1.raw));
    expect(hashApiKey(k1.raw)).not.toBe(hashApiKey(k2.raw));
  });
});
