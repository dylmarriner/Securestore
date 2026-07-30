import { describe, expect, it } from "vitest";
import { detectCredential } from "../src/detectors/index.js";
import { tryParseJwt } from "../src/detectors/jwt.js";
import { parseConnectionString } from "../src/detectors/connectionString.js";
import { hintFromEnvVarName } from "../src/detectors/envVarHints.js";

describe("credential detection", () => {
  it("recognizes a GitHub PAT by prefix", () => {
    const result = detectCredential({
      rawValue: "ghp_" + "a".repeat(36),
      sourceKind: "tool_input",
    });
    expect(result.matched).toBe(true);
    expect(result.provider).toBe("github");
    expect(result.credentialType).toBe("pat");
    expect(result.providerConfidence).toBeGreaterThan(0.9);
  });

  it("recognizes an Anthropic API key by prefix", () => {
    const result = detectCredential({ rawValue: "sk-ant-" + "b".repeat(30), sourceKind: "environment_variable" });
    expect(result.provider).toBe("anthropic");
    expect(result.credentialType).toBe("api_key");
  });

  it("strips a Bearer header prefix before matching", () => {
    const result = detectCredential({
      rawValue: "Bearer sk-ant-" + "c".repeat(30),
      sourceKind: "http_authorization_header",
    });
    expect(result.provider).toBe("anthropic");
    expect(result.secretValue.startsWith("sk-ant-")).toBe(true);
  });

  it("parses a database connection string and isolates the password as the secret", () => {
    const result = detectCredential({
      rawValue: "postgres://appuser:sup3rSecret@db.internal:5432/appdb",
      sourceKind: "database_config",
    });
    expect(result.matched).toBe(true);
    expect(result.credentialType).toBe("db_connection_string");
    expect(result.connectionStringMeta?.username).toBe("appuser");
    expect(result.connectionStringMeta?.secret).toBe("sup3rSecret");
    expect(result.connectionStringMeta?.database).toBe("appdb");
  });

  it("falls back to unmatched for values with no recognizable shape", () => {
    const result = detectCredential({ rawValue: "not a secret at all just prose", sourceKind: "agent_instruction" });
    expect(result.matched).toBe(false);
  });

  it("extracts safe JWT claims without verifying the signature", () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: "https://issuer.example", aud: "api", exp: 9999999999 })).toString("base64url");
    const jwt = `${header}.${payload}.sig`;
    const parsed = tryParseJwt(jwt);
    expect(parsed?.claims.iss).toBe("https://issuer.example");
    expect(parsed?.claims.aud).toBe("api");
  });

  it("returns null for non-JWT-shaped strings", () => {
    expect(tryParseJwt("not.a.jwt.at.all")).toBeNull();
    expect(tryParseJwt("plaintext")).toBeNull();
  });

  it("hints provider/type from well-known env var names", () => {
    expect(hintFromEnvVarName("OPENAI_API_KEY")?.provider).toBe("openai");
    expect(hintFromEnvVarName("AWS_SECRET_ACCESS_KEY")?.provider).toBe("aws");
    expect(hintFromEnvVarName("SOME_RANDOM_VAR")).toBeNull();
  });

  it("connection string parser rejects non-DB URLs", () => {
    expect(parseConnectionString("https://example.com/path")).toBeNull();
  });
});
