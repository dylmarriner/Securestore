export interface TokenPattern {
  provider: string;
  credentialType: string;
  /** Regex matched against the raw secret value. */
  regex: RegExp;
  confidence: number; // 0..1
  authScheme?: "bearer" | "api_key_header" | "basic" | "query_param";
  headerName?: string;
  headerPrefix?: string;
  defaultBaseEndpoint?: string;
}

/**
 * Provider-specific token-prefix / shape patterns. This list is the seed
 * set; operators can register additional patterns for custom/internal
 * providers via the same TokenPattern shape (see detectCustomTypes in
 * src/detectors/index.ts).
 */
export const TOKEN_PATTERNS: TokenPattern[] = [
  { provider: "github", credentialType: "pat", regex: /^ghp_[A-Za-z0-9]{36}$/, confidence: 0.98, authScheme: "bearer", headerName: "Authorization", headerPrefix: "token ", defaultBaseEndpoint: "https://api.github.com" },
  { provider: "github", credentialType: "oauth_access_token", regex: /^gho_[A-Za-z0-9]{36}$/, confidence: 0.98, authScheme: "bearer", headerName: "Authorization", headerPrefix: "token ", defaultBaseEndpoint: "https://api.github.com" },
  { provider: "github", credentialType: "service_account", regex: /^ghs_[A-Za-z0-9]{36}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "token ", defaultBaseEndpoint: "https://api.github.com" },
  { provider: "github", credentialType: "pat", regex: /^github_pat_[A-Za-z0-9_]{22,255}$/, confidence: 0.98, authScheme: "bearer", headerName: "Authorization", headerPrefix: "token ", defaultBaseEndpoint: "https://api.github.com" },
  { provider: "gitlab", credentialType: "pat", regex: /^glpat-[A-Za-z0-9_-]{20}$/, confidence: 0.95, authScheme: "api_key_header", headerName: "PRIVATE-TOKEN", defaultBaseEndpoint: "https://gitlab.com/api/v4" },
  { provider: "openai", credentialType: "api_key", regex: /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/, confidence: 0.9, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer ", defaultBaseEndpoint: "https://api.openai.com/v1" },
  { provider: "anthropic", credentialType: "api_key", regex: /^sk-ant-[A-Za-z0-9_-]{20,}$/, confidence: 0.95, authScheme: "api_key_header", headerName: "x-api-key", defaultBaseEndpoint: "https://api.anthropic.com/v1" },
  { provider: "slack", credentialType: "oauth_access_token", regex: /^xox[baprs]-[A-Za-z0-9-]{10,}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer ", defaultBaseEndpoint: "https://slack.com/api" },
  { provider: "aws", credentialType: "service_account", regex: /^AKIA[0-9A-Z]{16}$/, confidence: 0.95, authScheme: "basic" },
  { provider: "npm", credentialType: "pat", regex: /^npm_[A-Za-z0-9]{36}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer ", defaultBaseEndpoint: "https://registry.npmjs.org" },
  { provider: "stripe", credentialType: "api_key", regex: /^sk_(live|test)_[A-Za-z0-9]{24,}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer ", defaultBaseEndpoint: "https://api.stripe.com/v1" },
  { provider: "vercel", credentialType: "api_key", regex: /^[A-Za-z0-9]{24}$/, confidence: 0.3, authScheme: "bearer" },
  { provider: "digitalocean", credentialType: "pat", regex: /^dop_v1_[a-f0-9]{64}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer " },
  { provider: "hugging_face", credentialType: "api_key", regex: /^hf_[A-Za-z0-9]{34,}$/, confidence: 0.95, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer ", defaultBaseEndpoint: "https://huggingface.co/api" },
];

/** Loose structural checks used when no provider-specific pattern hits. */
export const GENERIC_SHAPE_PATTERNS: TokenPattern[] = [
  { provider: "generic", credentialType: "oauth_access_token", regex: /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, confidence: 0.4, authScheme: "bearer", headerName: "Authorization", headerPrefix: "Bearer " },
  { provider: "generic", credentialType: "api_key", regex: /^[A-Za-z0-9_-]{20,64}$/, confidence: 0.15, authScheme: "api_key_header" },
];
