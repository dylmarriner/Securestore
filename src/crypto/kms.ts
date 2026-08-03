import { randomBytes } from "node:crypto";
import { config } from "../config.js";

/**
 * A KeyProvider supplies the Key-Encryption-Key (KEK) used to wrap/unwrap
 * per-secret Data-Encryption-Keys (DEKs). SecureStore never encrypts a
 * secret directly with the KEK — every secret gets a fresh random DEK
 * (envelope encryption), and only the small DEK is wrapped by the KEK.
 * This keeps the KMS/HSM call volume low (one wrap/unwrap per credential
 * version, not per read) and lets the KEK live in hardware or a remote KMS
 * without it ever touching application memory in plaintext for long.
 *
 * Implement this interface against AWS KMS, GCP Cloud KMS, HashiCorp Vault
 * Transit, or a PKCS#11 HSM to run production self-hosted deployments with
 * a hardware- or cloud-backed master key. LocalKeyProvider (derives the KEK
 * from an operator-supplied env var) is provided for local/dev use and for
 * self-hosters who accept an OS-file-backed key.
 */
export interface KeyProvider {
  readonly kekId: string;
  readonly kekVersion: number;
  wrapKey(dek: Buffer): Promise<Buffer>;
  unwrapKey(wrapped: Buffer, kekId: string, kekVersion: number): Promise<Buffer>;
}

/**
 * Derives a KEK from SECURESTORE_MASTER_KEY (base64, 32 bytes) and wraps
 * DEKs with AES-256-GCM-KW (AES-GCM used as a key-wrap primitive). Suitable
 * for self-hosted deployments that supply the master key via a mounted
 * secret/env var; swap in a KmsKeyProvider for cloud KMS-backed deployments.
 */
export class LocalKeyProvider implements KeyProvider {
  readonly kekId = "local";
  readonly kekVersion = 1;
  private readonly kek: Buffer;

  constructor(masterKeyB64?: string) {
    const b64 = masterKeyB64 ?? config.crypto.localMasterKeyB64;
    if (!b64) {
      throw new Error(
        "SECURESTORE_MASTER_KEY is not set. Generate one with " +
          "`openssl rand -base64 32` and set it in the environment before " +
          "starting SecureStore.",
      );
    }
    const key = Buffer.from(b64, "base64");
    if (key.length !== 32) {
      throw new Error("SECURESTORE_MASTER_KEY must decode to exactly 32 bytes");
    }
    this.kek = key;
  }

  async wrapKey(dek: Buffer): Promise<Buffer> {
    const { createCipheriv } = await import("node:crypto");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.kek, iv);
    const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
    const tag = cipher.getAuthTag();
    // layout: iv(12) || tag(16) || ciphertext
    return Buffer.concat([iv, tag, ct]);
  }

  async unwrapKey(wrapped: Buffer, kekId: string, kekVersion: number): Promise<Buffer> {
    if (kekId !== this.kekId || kekVersion !== this.kekVersion) {
      throw new Error(
        `LocalKeyProvider cannot unwrap key for kek=${kekId}/v${kekVersion}; ` +
          "this credential was encrypted under a different/retired key. " +
          "Register the historical key version or run key-rotation re-encryption.",
      );
    }
    const { createDecipheriv } = await import("node:crypto");
    const iv = wrapped.subarray(0, 12);
    const tag = wrapped.subarray(12, 28);
    const ct = wrapped.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", this.kek, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }
}

/**
 * Wraps/unwraps DEKs with AWS KMS's `Encrypt`/`Decrypt` operations against
 * a single customer-managed key (CMK) — not `GenerateDataKey`, since
 * SecureStore already generates the DEK locally (`src/crypto/envelope.ts`)
 * and only needs the KMS call to protect that ~32-byte value, well under
 * KMS's 4KB direct-Encrypt limit.
 *
 * `kekVersion` is fixed at 1 and not meaningful for this provider: AWS
 * KMS's automatic annual key rotation keeps the same `KeyId`/ARN and
 * transparently retains old backing key material internally, so a
 * ciphertext blob from before a rotation still decrypts correctly without
 * SecureStore needing to track a version — the opaque `CiphertextBlob`
 * itself is self-describing to KMS. A deliberate key *replacement*
 * (different KeyId/ARN, e.g. moving regions or CMKs) is a different KEK
 * identity entirely and should be modeled as a new `kekId`, not a new
 * version of this one.
 */
export class AwsKmsKeyProvider implements KeyProvider {
  readonly kekVersion = 1;
  private client: import("@aws-sdk/client-kms").KMSClient | undefined;

  constructor(readonly kekId: string) {
    if (!kekId) {
      throw new Error("AWS KMS key id/ARN is required (AWS_KMS_KEY_ID)");
    }
  }

  private async getClient() {
    if (!this.client) {
      const { KMSClient } = await import("@aws-sdk/client-kms");
      // AWS_KMS_ENDPOINT lets a self-hoster (or this project's own tests)
      // point at a KMS-compatible endpoint other than the real AWS
      // service — e.g. a local moto/LocalStack instance — without any
      // other code change. Region/credentials otherwise come from the
      // SDK's normal resolution chain (env vars, shared config, IAM role).
      this.client = new KMSClient({
        region: process.env.AWS_REGION,
        endpoint: process.env.AWS_KMS_ENDPOINT,
      });
    }
    return this.client;
  }

  async wrapKey(dek: Buffer): Promise<Buffer> {
    const { EncryptCommand } = await import("@aws-sdk/client-kms");
    const client = await this.getClient();
    const res = await client.send(new EncryptCommand({ KeyId: this.kekId, Plaintext: dek }));
    if (!res.CiphertextBlob) throw new Error("AWS KMS Encrypt returned no CiphertextBlob");
    return Buffer.from(res.CiphertextBlob);
  }

  async unwrapKey(wrapped: Buffer, kekId: string, kekVersion: number): Promise<Buffer> {
    if (kekVersion !== this.kekVersion) {
      throw new Error(`AwsKmsKeyProvider cannot unwrap kekVersion ${kekVersion} (only ${this.kekVersion} is meaningful for this provider)`);
    }
    const { DecryptCommand } = await import("@aws-sdk/client-kms");
    const client = await this.getClient();
    // KeyId is optional for Decrypt (the ciphertext blob is self-describing)
    // but pinning it is defense-in-depth against a swapped/mismatched blob.
    const res = await client.send(new DecryptCommand({ CiphertextBlob: wrapped, KeyId: kekId }));
    if (!res.Plaintext) throw new Error("AWS KMS Decrypt returned no Plaintext");
    return Buffer.from(res.Plaintext);
  }
}

let activeProvider: KeyProvider | undefined;

export function getKeyProvider(): KeyProvider {
  if (activeProvider) return activeProvider;
  switch (config.crypto.kmsProvider) {
    case "local":
      activeProvider = new LocalKeyProvider();
      return activeProvider;
    case "aws-kms": {
      const keyId = process.env.AWS_KMS_KEY_ID;
      if (!keyId) throw new Error("KMS_PROVIDER=aws-kms requires AWS_KMS_KEY_ID (a KMS key id or ARN)");
      activeProvider = new AwsKmsKeyProvider(keyId);
      return activeProvider;
    }
    // Extension points — implement the KeyProvider interface against the
    // target KMS/HSM SDK and register it here. Left unimplemented rather
    // than stubbed-and-silently-insecure, so misconfiguration fails loudly.
    case "gcp-kms":
    case "vault-transit":
      throw new Error(
        `KMS_PROVIDER=${config.crypto.kmsProvider} has no bundled implementation. ` +
          "Implement KeyProvider against the provider SDK in src/crypto/kms.ts and register it in getKeyProvider().",
      );
    default:
      throw new Error(`Unknown KMS_PROVIDER: ${config.crypto.kmsProvider}`);
  }
}
