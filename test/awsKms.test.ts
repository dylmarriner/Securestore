import { describe, expect, it, vi, beforeEach } from "vitest";

// Minimal fake of the two KMS operations AwsKmsKeyProvider actually uses.
// A real live round-trip against a mocked AWS KMS API (moto) was also run
// manually during development — this test exists so the wrap/unwrap
// plumbing and error handling stay covered in CI without an AWS/moto
// dependency.
const state = { keyStore: new Map<string, Buffer>() };

class FakeEncryptCommand {
  constructor(public input: { KeyId: string; Plaintext: Uint8Array }) {}
}
class FakeDecryptCommand {
  constructor(public input: { CiphertextBlob: Uint8Array; KeyId?: string }) {}
}
class FakeKMSClient {
  async send(command: FakeEncryptCommand | FakeDecryptCommand) {
    if (command instanceof FakeEncryptCommand) {
      const token = `ct-${state.keyStore.size}`;
      state.keyStore.set(token, Buffer.from(command.input.Plaintext));
      return { CiphertextBlob: Buffer.from(token, "utf8") };
    }
    if (command instanceof FakeDecryptCommand) {
      const token = Buffer.from(command.input.CiphertextBlob).toString("utf8");
      const plaintext = state.keyStore.get(token);
      if (!plaintext) throw new Error("InvalidCiphertextException");
      return { Plaintext: plaintext };
    }
    throw new Error("unexpected command");
  }
}

vi.mock("@aws-sdk/client-kms", () => ({
  KMSClient: FakeKMSClient,
  EncryptCommand: FakeEncryptCommand,
  DecryptCommand: FakeDecryptCommand,
}));

describe("AwsKmsKeyProvider", () => {
  beforeEach(() => {
    state.keyStore.clear();
  });

  it("round-trips a DEK through wrap/unwrap", async () => {
    const { AwsKmsKeyProvider } = await import("../src/crypto/kms.js");
    const provider = new AwsKmsKeyProvider("arn:aws:kms:us-east-1:123456789012:key/test-key");
    const dek = Buffer.from("0123456789abcdef0123456789abcdef", "utf8").subarray(0, 32);

    const wrapped = await provider.wrapKey(dek);
    expect(wrapped.equals(dek)).toBe(false);

    const unwrapped = await provider.unwrapKey(wrapped, provider.kekId, provider.kekVersion);
    expect(unwrapped.equals(dek)).toBe(true);
  });

  it("throws on an unwrap attempt for an unknown kekVersion", async () => {
    const { AwsKmsKeyProvider } = await import("../src/crypto/kms.js");
    const provider = new AwsKmsKeyProvider("arn:aws:kms:us-east-1:123456789012:key/test-key");
    const wrapped = await provider.wrapKey(Buffer.from("x".repeat(32)));
    await expect(provider.unwrapKey(wrapped, provider.kekId, 2)).rejects.toThrow(/kekVersion/);
  });

  it("throws when constructed without a key id", async () => {
    const { AwsKmsKeyProvider } = await import("../src/crypto/kms.js");
    expect(() => new AwsKmsKeyProvider("")).toThrow(/key id/i);
  });

  it("surfaces a decrypt failure for an unrecognized ciphertext blob", async () => {
    const { AwsKmsKeyProvider } = await import("../src/crypto/kms.js");
    const provider = new AwsKmsKeyProvider("arn:aws:kms:us-east-1:123456789012:key/test-key");
    await expect(provider.unwrapKey(Buffer.from("not-a-real-token"), provider.kekId, 1)).rejects.toThrow();
  });
});
