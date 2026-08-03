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

  it("recognizes an OpenSSH private key block", () => {
    const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----";
    const result = detectCredential({ rawValue: key, sourceKind: "imported_config_file" });
    expect(result.matched).toBe(true);
    expect(result.credentialType).toBe("ssh_key");
    expect(result.sensitivity).toBe("critical");
    expect(result.secretValue).toContain("BEGIN OPENSSH PRIVATE KEY");
  });

  it("recognizes an RSA PEM private key and reports it as critical sensitivity", () => {
    const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    const result = detectCredential({ rawValue: key, sourceKind: "service_account_file" });
    expect(result.credentialType).toBe("ssh_key");
    expect(result.sensitivity).toBe("critical");
  });

  it("recognizes a PKCS#8 signing key distinctly from an SSH key", () => {
    const key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc...\n-----END PRIVATE KEY-----";
    const result = detectCredential({ rawValue: key, sourceKind: "imported_config_file" });
    expect(result.credentialType).toBe("signing_key");
  });

  it("recognizes an X.509 certificate as tls_cert with high (not critical) sensitivity", () => {
    const cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAK...\n-----END CERTIFICATE-----";
    const result = detectCredential({ rawValue: cert, sourceKind: "imported_config_file" });
    expect(result.credentialType).toBe("tls_cert");
    expect(result.sensitivity).toBe("high");
  });

  it("does not misclassify a bare non-PEM string as a key", () => {
    const result = detectCredential({ rawValue: "just some ordinary text without any PEM markers", sourceKind: "agent_instruction" });
    expect(result.credentialType).not.toBe("ssh_key");
  });
});
