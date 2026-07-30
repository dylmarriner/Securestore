import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { getKeyProvider } from "./kms.js";

export interface EncryptedSecret {
  ciphertext: Buffer;
  nonce: Buffer;
  wrappedDek: Buffer;
  kekId: string;
  kekVersion: number;
  encoding: "utf8" | "json" | "base64" | "pem";
}

/**
 * Envelope-encrypts a secret value:
 *   1. generate a fresh random 256-bit DEK
 *   2. AES-256-GCM-encrypt the plaintext with the DEK
 *   3. wrap the DEK with the active KEK (local key or KMS/HSM)
 *   4. discard the plaintext DEK
 * The wrapped DEK travels alongside the ciphertext; only an entity that can
 * call the KeyProvider's unwrapKey can ever recover the plaintext.
 */
export async function encryptSecret(
  plaintext: string,
  encoding: EncryptedSecret["encoding"] = "utf8",
): Promise<EncryptedSecret> {
  const provider = getKeyProvider();
  const dek = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wrappedDek = await provider.wrapKey(dek);
  dek.fill(0);
  return {
    ciphertext: Buffer.concat([ct, tag]),
    nonce,
    wrappedDek,
    kekId: provider.kekId,
    kekVersion: provider.kekVersion,
    encoding,
  };
}

export async function decryptSecret(secret: EncryptedSecret): Promise<string> {
  const provider = getKeyProvider();
  const dek = await provider.unwrapKey(secret.wrappedDek, secret.kekId, secret.kekVersion);
  try {
    const ct = secret.ciphertext.subarray(0, secret.ciphertext.length - 16);
    const tag = secret.ciphertext.subarray(secret.ciphertext.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", dek, secret.nonce);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString("utf8");
  } finally {
    dek.fill(0);
  }
}
