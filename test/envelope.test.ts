import { describe, expect, it } from "vitest";
import { encryptSecret, decryptSecret } from "../src/crypto/envelope.js";

describe("envelope encryption", () => {
  it("round-trips plaintext through encrypt/decrypt", async () => {
    const plaintext = "ghp_thisIsNotARealTokenValue1234567890";
    const encrypted = await encryptSecret(plaintext);
    expect(encrypted.ciphertext.equals(Buffer.from(plaintext))).toBe(false);
    const decrypted = await decryptSecret(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it("produces different ciphertext and DEK wrap for the same plaintext each time", async () => {
    const a = await encryptSecret("same-secret-value");
    const b = await encryptSecret("same-secret-value");
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
    expect(a.nonce.equals(b.nonce)).toBe(false);
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
  });

  it("fails to decrypt if the ciphertext is tampered with", async () => {
    const encrypted = await encryptSecret("tamper-me");
    encrypted.ciphertext[0] = (encrypted.ciphertext[0] ?? 0) ^ 0xff;
    await expect(decryptSecret(encrypted)).rejects.toThrow();
  });
});
