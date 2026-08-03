import { GENERIC_SHAPE_PATTERNS, TOKEN_PATTERNS, type TokenPattern } from "./patterns.js";
import { tryParseJwt, type JwtClaims } from "./jwt.js";
import { hintFromEnvVarName } from "./envVarHints.js";
import { parseConnectionString } from "./connectionString.js";
import { detectPemBlock } from "./pem.js";

export type SourceKind =
  | "agent_instruction" | "tool_input" | "mcp_tool_argument" | "api_request_config"
  | "http_authorization_header" | "environment_variable" | "interactive_input"
  | "oauth_response" | "oauth_refresh" | "cli_command" | "ide_task_config"
  | "imported_config_file" | "provider_sdk_config" | "agent_memory" | "tool_call_result"
  | "connector_config" | "package_manager_auth" | "git_credential" | "cloud_auth"
  | "database_config" | "service_account_file" | "agent_generated" | "rotation";

export interface DetectionInput {
  rawValue: string;
  sourceKind: SourceKind;
  headerName?: string;
  envVarName?: string;
  hostHint?: string;
  /** Operator-registered patterns for internal/custom providers. */
  customPatterns?: TokenPattern[];
}

export interface DetectionResult {
  matched: boolean;
  provider: string;
  credentialType: string;
  providerConfidence: number;
  typeConfidence: number;
  authScheme?: string;
  headerName?: string;
  headerPrefix?: string;
  defaultBaseEndpoint?: string;
  secretValue: string; // normalized value that should actually be encrypted
  isJwt: boolean;
  jwtClaims?: JwtClaims;
  connectionStringMeta?: ReturnType<typeof parseConnectionString>;
  sensitivity: "low" | "medium" | "high" | "critical";
  inferredMetadata: Record<string, { value: unknown; confidence: number; source: string }>;
}

function classifySensitivity(credentialType: string, envName?: string): DetectionResult["sensitivity"] {
  if (credentialType === "ssh_key" || credentialType === "tls_cert" || credentialType === "service_account") return "critical";
  if (/PROD/i.test(envName ?? "")) return "critical";
  if (credentialType === "oauth_refresh_token" || credentialType === "db_connection_string") return "high";
  return "medium";
}

/**
 * Runs the full detection pipeline against a candidate value: strips an
 * Authorization-header wrapper, checks for a DB connection string, checks
 * JWT structure, matches provider token patterns, falls back to generic
 * shape heuristics, and folds in env-var-name hints. Returns matched=false
 * (rather than throwing) when nothing looks credential-shaped, so callers
 * can decide whether to store as an "unresolved" record or ignore.
 */
export function detectCredential(input: DetectionInput): DetectionResult {
  const inferred: DetectionResult["inferredMetadata"] = {};
  let raw = input.rawValue.trim();

  // Strip common Authorization header schemes to get at the bare token.
  const headerMatch = raw.match(/^(Bearer|Token|Basic)\s+(.+)$/i);
  if (headerMatch) {
    inferred["authScheme"] = { value: headerMatch[1]!.toLowerCase(), confidence: 0.9, source: "header_prefix" };
    raw = headerMatch[2]!.trim();
  }

  // PEM-armored blocks (SSH keys, PKCS#8/PGP signing keys, X.509 certs) are
  // multi-line and self-describing via their armor header — check before
  // the single-line token patterns, which would never match a multi-line
  // value anyway, but this keeps the branch explicit and fast.
  const pem = detectPemBlock(raw);
  if (pem) {
    return {
      matched: true,
      provider: "generic",
      credentialType: pem.credentialType,
      providerConfidence: 0.3,
      typeConfidence: 0.97,
      authScheme: pem.credentialType === "ssh_key" ? "ssh" : undefined,
      secretValue: raw,
      isJwt: false,
      sensitivity: pem.sensitivity,
      inferredMetadata: {
        renewalMethod: { value: pem.encrypted ? "manual (passphrase-protected)" : "manual", confidence: 0.9, source: "pem_header" },
        ...(pem.keyAlgorithm ? { notes: { value: `${pem.label}${pem.keyAlgorithm ? ` (${pem.keyAlgorithm})` : ""}`, confidence: 0.9, source: "pem_header" } } : {}),
      },
    };
  }

  // Connection strings carry their own username/host metadata.
  const connMeta = parseConnectionString(raw);
  if (connMeta) {
    const secret = connMeta.secret;
    return {
      matched: true,
      provider: "generic-database",
      credentialType: "db_connection_string",
      providerConfidence: 0.6,
      typeConfidence: 0.9,
      authScheme: "basic",
      secretValue: raw, // store the full DSN; secret field marks the sensitive segment
      isJwt: false,
      connectionStringMeta: connMeta,
      sensitivity: "high",
      inferredMetadata: {
        username: { value: connMeta.username, confidence: 0.95, source: "connection_string" },
        baseEndpoint: { value: `${connMeta.scheme}://${connMeta.host}:${connMeta.port ?? ""}`, confidence: 0.95, source: "connection_string" },
        service: { value: connMeta.database, confidence: 0.9, source: "connection_string" },
      },
    };
  }

  const jwt = tryParseJwt(raw);

  const allPatterns = [...(input.customPatterns ?? []), ...TOKEN_PATTERNS];
  let best: TokenPattern | undefined;
  for (const p of allPatterns) {
    if (p.regex.test(raw)) {
      if (!best || p.confidence > best.confidence) best = p;
    }
  }
  if (!best) {
    for (const p of GENERIC_SHAPE_PATTERNS) {
      if (p.regex.test(raw)) {
        best = p;
        break;
      }
    }
  }

  const envHint = input.envVarName ? hintFromEnvVarName(input.envVarName) : null;

  let provider = best?.provider ?? envHint?.provider ?? "unknown";
  let credentialType = best?.credentialType ?? envHint?.credentialType ?? (jwt ? "oauth_access_token" : "text");
  let providerConfidence = best?.confidence ?? envHint?.confidence ?? (jwt ? 0.4 : 0.1);
  let typeConfidence = best ? best.confidence : envHint ? envHint.confidence : jwt ? 0.5 : 0.1;

  if (best && envHint && best.provider === "generic" && envHint.provider !== "generic") {
    provider = envHint.provider;
    providerConfidence = Math.max(providerConfidence, envHint.confidence);
  }

  if (jwt?.claims.iss) inferred["issuer"] = { value: jwt.claims.iss, confidence: 0.85, source: "jwt_claim" };
  if (jwt?.claims.aud) inferred["audience"] = { value: jwt.claims.aud, confidence: 0.85, source: "jwt_claim" };
  if (jwt?.claims.exp) inferred["tokenExpirationTime"] = { value: new Date(jwt.claims.exp * 1000).toISOString(), confidence: 0.95, source: "jwt_claim" };
  if (jwt?.claims.sub) inferred["accountIdentifier"] = { value: jwt.claims.sub, confidence: 0.7, source: "jwt_claim" };
  const scope = jwt?.claims.scope ?? (jwt?.claims.scp ? jwt.claims.scp.join(" ") : undefined);
  if (scope) inferred["grantedScopes"] = { value: scope.split(/\s+/), confidence: 0.85, source: "jwt_claim" };

  if (best?.headerName) inferred["headerName"] = { value: best.headerName, confidence: providerConfidence, source: "provider_pattern" };
  if (best?.headerPrefix) inferred["headerPrefix"] = { value: best.headerPrefix, confidence: providerConfidence, source: "provider_pattern" };
  if (best?.defaultBaseEndpoint) inferred["baseEndpoint"] = { value: best.defaultBaseEndpoint, confidence: providerConfidence, source: "provider_pattern" };
  if (input.hostHint) inferred["baseEndpoint"] = { value: input.hostHint, confidence: 0.6, source: "target_hostname" };
  if (input.envVarName) inferred["environmentVariableName"] = { value: input.envVarName, confidence: 0.99, source: "env_var_name" };

  return {
    matched: Boolean(best || jwt || envHint),
    provider,
    credentialType,
    providerConfidence,
    typeConfidence,
    authScheme: best?.authScheme,
    headerName: best?.headerName ?? input.headerName,
    headerPrefix: best?.headerPrefix,
    defaultBaseEndpoint: best?.defaultBaseEndpoint,
    secretValue: raw,
    isJwt: Boolean(jwt),
    jwtClaims: jwt?.claims,
    sensitivity: classifySensitivity(credentialType, input.envVarName),
    inferredMetadata: inferred,
  };
}
