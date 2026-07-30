import { describe, expect, it } from "vitest";
import { mergeMetadata } from "../src/services/credentialService.js";
import type { CredentialMetadata } from "../src/services/types.js";

const now = new Date().toISOString();

describe("provenance-aware metadata merge", () => {
  it("adds a field that doesn't exist yet", () => {
    const existing: CredentialMetadata = {};
    const incoming: CredentialMetadata = { username: { value: "octocat", confidence: 0.6, source: "guess", updatedAt: now } };
    const merged = mergeMetadata(existing, incoming);
    expect(merged.username?.value).toBe("octocat");
  });

  it("does not overwrite a verified field with a lower-confidence unverified one", () => {
    const existing: CredentialMetadata = {
      username: { value: "verified-user", confidence: 0.95, source: "provider_validation", verified: true, updatedAt: now },
    };
    const incoming: CredentialMetadata = {
      username: { value: "guessed-user", confidence: 0.3, source: "env_var_name", updatedAt: now },
    };
    const merged = mergeMetadata(existing, incoming);
    expect(merged.username?.value).toBe("verified-user");
  });

  it("allows a higher-or-equal confidence incoming value to win", () => {
    const existing: CredentialMetadata = { region: { value: "us-east-1", confidence: 0.4, source: "guess", updatedAt: now } };
    const incoming: CredentialMetadata = { region: { value: "eu-west-1", confidence: 0.9, source: "provider_validation", updatedAt: now } };
    const merged = mergeMetadata(existing, incoming);
    expect(merged.region?.value).toBe("eu-west-1");
  });

  it("allows an explicitly verified incoming value to override even a higher-confidence-looking existing one", () => {
    const existing: CredentialMetadata = { org: { value: "old-org", confidence: 0.99, source: "stale_cache", updatedAt: now } };
    const incoming: CredentialMetadata = { org: { value: "new-org", confidence: 0.8, source: "provider_validation", verified: true, updatedAt: now } };
    const merged = mergeMetadata(existing, incoming);
    expect(merged.org?.value).toBe("new-org");
  });

  it("leaves unrelated existing fields untouched", () => {
    const existing: CredentialMetadata = { a: { value: 1, confidence: 1, source: "x", updatedAt: now } };
    const incoming: CredentialMetadata = { b: { value: 2, confidence: 1, source: "y", updatedAt: now } };
    const merged = mergeMetadata(existing, incoming);
    expect(merged.a?.value).toBe(1);
    expect(merged.b?.value).toBe(2);
  });
});
