import { randomBytes } from "node:crypto";

// Deterministic-enough dev keys for unit tests that exercise crypto/fingerprint
// code paths without a real deployment secret. Never used outside the test run.
process.env.SECURESTORE_MASTER_KEY ??= randomBytes(32).toString("base64");
process.env.SECURESTORE_FINGERPRINT_PEPPER ??= randomBytes(32).toString("base64");
process.env.SECURESTORE_APIKEY_PEPPER ??= randomBytes(32).toString("base64");
process.env.DATABASE_URL ??= "postgres://securestore:securestore@localhost:5432/securestore_test";
