import { randomBytes, createHash } from "node:crypto";
import { storeCredential, type StoreResult } from "./credentialService.js";
import type { CredentialMetadata, OwnerScope } from "./types.js";

export interface OAuthEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  refreshEndpoint?: string;
  revocationEndpoint?: string;
}

export interface BuildAuthUrlInput extends OAuthEndpoints {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  audience?: string;
}

export interface AuthUrlResult {
  url: string;
  state: string;
  codeVerifier: string; // caller must hold this (server-side, per-session) until the callback
}

/** Builds an OAuth 2.1-style authorization-code + PKCE URL. */
export function buildAuthorizationUrl(input: BuildAuthUrlInput): AuthUrlResult {
  const state = randomBytes(16).toString("hex");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  const url = new URL(input.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("scope", input.scopes.join(" "));
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (input.audience) url.searchParams.set("audience", input.audience);

  return { url: url.toString(), state, codeVerifier };
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
}

export async function exchangeAuthorizationCode(
  endpoints: OAuthEndpoints,
  params: { code: string; clientId: string; clientSecret?: string; redirectUri: string; codeVerifier: string },
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier,
  });
  if (params.clientSecret) body.set("client_secret", params.clientSecret);

  const res = await fetch(endpoints.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`token exchange failed: HTTP ${res.status}`);
  return (await res.json()) as TokenResponse;
}

export async function refreshAccessToken(
  endpoints: OAuthEndpoints,
  params: { refreshToken: string; clientId: string; clientSecret?: string },
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: params.refreshToken,
    client_id: params.clientId,
  });
  if (params.clientSecret) body.set("client_secret", params.clientSecret);

  const res = await fetch(endpoints.refreshEndpoint ?? endpoints.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`token refresh failed: HTTP ${res.status}`);
  return (await res.json()) as TokenResponse;
}

export interface StoreOAuthTokensInput {
  orgId: string;
  workspaceId: string | null;
  ownerScope?: OwnerScope;
  provider: string;
  service?: string;
  name: string;
  tokens: TokenResponse;
  endpoints: OAuthEndpoints;
  issuer?: string;
  audience?: string;
  accountIdentifier?: string;
  introducingAgentId: string;
  isRefresh?: boolean;
}

/**
 * Stores both halves of an OAuth token response as one logical credential:
 * the access token drives the active `secret_get`/brokered-use path, while
 * the refresh token (when present) is captured as enrichment metadata
 * provenance for `oauth_refresh` to consume later. Endpoint/issuer/
 * audience/scope/expiry are all recorded so the credential is immediately
 * usable without another discovery round-trip.
 */
export async function storeOAuthTokens(input: StoreOAuthTokensInput): Promise<StoreResult> {
  const now = new Date().toISOString();
  const metadata: CredentialMetadata = {
    authEndpoint: { value: input.endpoints.authorizationEndpoint, confidence: 1, source: "oauth_flow", verified: true, updatedAt: now },
    tokenEndpoint: { value: input.endpoints.tokenEndpoint, confidence: 1, source: "oauth_flow", verified: true, updatedAt: now },
  };
  if (input.endpoints.refreshEndpoint) metadata["refreshEndpoint"] = { value: input.endpoints.refreshEndpoint, confidence: 1, source: "oauth_flow", updatedAt: now };
  if (input.endpoints.revocationEndpoint) metadata["revocationEndpoint"] = { value: input.endpoints.revocationEndpoint, confidence: 1, source: "oauth_flow", updatedAt: now };
  if (input.issuer) metadata["issuer"] = { value: input.issuer, confidence: 0.9, source: "oauth_flow", updatedAt: now };
  if (input.audience) metadata["audience"] = { value: input.audience, confidence: 0.9, source: "oauth_flow", updatedAt: now };
  if (input.accountIdentifier) metadata["accountIdentifier"] = { value: input.accountIdentifier, confidence: 0.9, source: "oauth_flow", updatedAt: now };
  if (input.tokens.scope) metadata["grantedScopes"] = { value: input.tokens.scope.split(/\s+/), confidence: 0.95, source: "oauth_response", verified: true, updatedAt: now };
  if (input.tokens.expires_in) {
    metadata["tokenExpirationTime"] = {
      value: new Date(Date.now() + input.tokens.expires_in * 1000).toISOString(),
      confidence: 0.95, source: "oauth_response", updatedAt: now,
    };
  }
  if (input.tokens.refresh_token) {
    metadata["renewalMethod"] = { value: "oauth_refresh", confidence: 1, source: "oauth_flow", updatedAt: now };
  }

  return storeCredential({
    orgId: input.orgId,
    workspaceId: input.workspaceId,
    ownerScope: input.ownerScope ?? "workspace",
    name: input.name,
    provider: input.provider,
    service: input.service ?? null,
    credentialType: "oauth_access_token",
    authScheme: "bearer",
    secretValue: JSON.stringify({
      access_token: input.tokens.access_token,
      refresh_token: input.tokens.refresh_token,
      token_type: input.tokens.token_type ?? "Bearer",
    }),
    secretEncoding: "json",
    metadata,
    introducingAgentId: input.introducingAgentId,
    creationSource: input.isRefresh ? "rotation" : "oauth_flow",
  });
}
