import type { TLSSocket, PeerCertificate } from "node:tls";
import { config } from "../config.js";

export function isMtlsConfigured(): boolean {
  return Boolean(config.mtls.certPath && config.mtls.keyPath && config.mtls.caPath);
}

export interface ClientCertIdentity {
  fingerprint: string; // SHA-256 fingerprint, colon-hex, e.g. "AB:CD:...", as reported by Node's tls module
  subjectCN?: string;
}

/**
 * Extracts the verified client certificate's identity from a raw request
 * socket. `authorized` is Node's own TLS-handshake verification result
 * (chain built against the configured CA, not expired, etc.) — we only
 * trust a fingerprint from a socket where that already came back true;
 * this function never does its own chain validation, that's TLS's job
 * (configured in src/server.ts via the `ca`/`requestCert`/
 * `rejectUnauthorized` https options).
 */
export function extractClientCertIdentity(socket: TLSSocket): ClientCertIdentity | null {
  if (!socket.authorized) return null;
  const cert: PeerCertificate = socket.getPeerCertificate();
  if (!cert || Object.keys(cert).length === 0 || !cert.fingerprint256) return null;
  const cn = cert.subject?.CN;
  return { fingerprint: cert.fingerprint256, subjectCN: Array.isArray(cn) ? cn[0] : cn };
}
