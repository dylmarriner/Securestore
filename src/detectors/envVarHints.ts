export interface EnvVarHint {
  provider: string;
  credentialType: string;
  confidence: number;
}

const NAME_RULES: Array<{ pattern: RegExp; hint: EnvVarHint }> = [
  { pattern: /^(GH|GITHUB)_(TOKEN|PAT)$/i, hint: { provider: "github", credentialType: "pat", confidence: 0.6 } },
  { pattern: /^GITLAB_TOKEN$/i, hint: { provider: "gitlab", credentialType: "pat", confidence: 0.6 } },
  { pattern: /^OPENAI_API_KEY$/i, hint: { provider: "openai", credentialType: "api_key", confidence: 0.7 } },
  { pattern: /^ANTHROPIC_API_KEY$/i, hint: { provider: "anthropic", credentialType: "api_key", confidence: 0.7 } },
  { pattern: /^AWS_(SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)$/i, hint: { provider: "aws", credentialType: "service_account", confidence: 0.7 } },
  { pattern: /^NPM_TOKEN$/i, hint: { provider: "npm", credentialType: "pat", confidence: 0.6 } },
  { pattern: /^(DATABASE|POSTGRES|MYSQL|MONGO(DB)?)_URL$/i, hint: { provider: "generic-database", credentialType: "db_connection_string", confidence: 0.6 } },
  { pattern: /^STRIPE_(SECRET_)?KEY$/i, hint: { provider: "stripe", credentialType: "api_key", confidence: 0.6 } },
  { pattern: /_(API_KEY|APIKEY)$/i, hint: { provider: "generic", credentialType: "api_key", confidence: 0.3 } },
  { pattern: /_(TOKEN|PAT|ACCESS_TOKEN)$/i, hint: { provider: "generic", credentialType: "pat", confidence: 0.25 } },
  { pattern: /_(SECRET|CLIENT_SECRET)$/i, hint: { provider: "generic", credentialType: "text", confidence: 0.2 } },
];

/** Infers provider/type from an environment-variable name (never its value). */
export function hintFromEnvVarName(name: string): EnvVarHint | null {
  for (const rule of NAME_RULES) {
    if (rule.pattern.test(name)) return rule.hint;
  }
  return null;
}
