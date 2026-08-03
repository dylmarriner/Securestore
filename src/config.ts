import "dotenv/config";

function required(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v;
}

export const config = {
  env: process.env.NODE_ENV ?? "development",
  http: {
    host: process.env.HOST ?? "0.0.0.0",
    port: Number(process.env.PORT ?? 8443),
  },
  db: {
    connectionString: required(
      "DATABASE_URL",
      "postgres://securestore:securestore@localhost:5432/securestore",
    ),
  },
  // Local KEK (envelope-encryption master key), base64-encoded 32 bytes.
  // In production, set KMS_PROVIDER=aws-kms|gcp-kms|vault-transit and wire
  // the corresponding KeyProvider implementation (see src/crypto/kms.ts).
  crypto: {
    kmsProvider: process.env.KMS_PROVIDER ?? "local",
    localMasterKeyB64: process.env.SECURESTORE_MASTER_KEY,
    fingerprintPepperB64: process.env.SECURESTORE_FINGERPRINT_PEPPER,
  },
  auth: {
    apiKeyPepperB64: process.env.SECURESTORE_APIKEY_PEPPER,
    adminBootstrapToken: process.env.SECURESTORE_ADMIN_BOOTSTRAP_TOKEN,
  },
  // OIDC bearer-token auth: an agent registered with auth_method='oidc' and
  // auth_identifier=<expected `sub` claim> authenticates by presenting a
  // JWT from this issuer instead of a SecureStore API key. Optional — only
  // consulted when these are set AND a request's Authorization header
  // fails to match a known API key.
  oidc: {
    issuer: process.env.SECURESTORE_OIDC_ISSUER,
    jwksUri: process.env.SECURESTORE_OIDC_JWKS_URI,
    audience: process.env.SECURESTORE_OIDC_AUDIENCE,
  },
  // mTLS auth: an agent registered with auth_method='mtls' and
  // auth_identifier=<client certificate SHA-256 fingerprint>
  // authenticates by presenting that certificate during the TLS
  // handshake. Optional — only active when all three paths are set, which
  // also switches the HTTP listener from plain HTTP to HTTPS.
  mtls: {
    certPath: process.env.SECURESTORE_TLS_CERT_PATH,
    keyPath: process.env.SECURESTORE_TLS_KEY_PATH,
    caPath: process.env.SECURESTORE_TLS_CA_PATH,
    requireClientCert: process.env.SECURESTORE_MTLS_REQUIRE === "1",
  },
  rateLimit: {
    defaultPerMinute: Number(process.env.SECURESTORE_DEFAULT_RATE_PER_MIN ?? 120),
  },
  // Optional: when set, rate limiting and proxy/temporary-issue sessions
  // are backed by Redis instead of per-process memory, giving exact
  // (not per-replica-approximate) behavior across a horizontally scaled
  // deployment. See src/services/redisClient.ts.
  redis: {
    url: process.env.REDIS_URL,
  },
};
