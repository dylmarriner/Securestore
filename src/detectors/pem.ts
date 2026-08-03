export interface PemDetection {
  credentialType: "ssh_key" | "tls_cert" | "signing_key";
  label: string; // human-readable, e.g. "OpenSSH private key", "RSA private key", "PGP private key block"
  keyAlgorithm?: string;
  encrypted: boolean;
  sensitivity: "high" | "critical";
}

interface PemRule {
  header: RegExp;
  credentialType: PemDetection["credentialType"];
  label: string;
  keyAlgorithm?: string;
  sensitivity: PemDetection["sensitivity"];
}

// Order matters: more specific headers (OPENSSH, EC, DSA, RSA) must be
// checked before the generic "PRIVATE KEY" catch-all.
const PEM_RULES: PemRule[] = [
  { header: /-----BEGIN OPENSSH PRIVATE KEY-----/, credentialType: "ssh_key", label: "OpenSSH private key", sensitivity: "critical" },
  { header: /-----BEGIN RSA PRIVATE KEY-----/, credentialType: "ssh_key", label: "RSA private key (PEM)", keyAlgorithm: "RSA", sensitivity: "critical" },
  { header: /-----BEGIN EC PRIVATE KEY-----/, credentialType: "ssh_key", label: "EC private key (PEM)", keyAlgorithm: "EC", sensitivity: "critical" },
  { header: /-----BEGIN DSA PRIVATE KEY-----/, credentialType: "ssh_key", label: "DSA private key (PEM)", keyAlgorithm: "DSA", sensitivity: "critical" },
  { header: /-----BEGIN ENCRYPTED PRIVATE KEY-----/, credentialType: "signing_key", label: "Encrypted PKCS#8 private key", sensitivity: "critical" },
  { header: /-----BEGIN PRIVATE KEY-----/, credentialType: "signing_key", label: "PKCS#8 private key", sensitivity: "critical" },
  { header: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, credentialType: "signing_key", label: "PGP/GPG private key block", sensitivity: "critical" },
  { header: /-----BEGIN CERTIFICATE-----/, credentialType: "tls_cert", label: "X.509 certificate (PEM)", sensitivity: "high" },
];

/**
 * Recognizes SSH private keys, PKCS#8/PGP signing keys, and X.509
 * certificates by their PEM armor headers. Unlike the token-prefix
 * patterns in patterns.ts, these are multi-line blocks, so detection is a
 * substring/header match rather than a full-value regex — the whole PEM
 * block (armor included) is what gets fingerprinted and encrypted, since
 * that's the form the credential is actually used in.
 */
export function detectPemBlock(raw: string): PemDetection | null {
  if (!raw.includes("-----BEGIN ")) return null;
  for (const rule of PEM_RULES) {
    if (rule.header.test(raw)) {
      return {
        credentialType: rule.credentialType,
        label: rule.label,
        keyAlgorithm: rule.keyAlgorithm,
        encrypted: /ENCRYPTED/.test(raw) || /Proc-Type:.*ENCRYPTED/.test(raw),
        sensitivity: rule.sensitivity,
      };
    }
  }
  return null;
}
