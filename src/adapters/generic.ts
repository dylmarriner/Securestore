import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import type { TokenPattern } from "../detectors/patterns.js";

/**
 * Fallback adapter for any bearer-token API that doesn't have a dedicated
 * adapter. `validate()` can't know a safe identity endpoint, so it only
 * confirms the value is well-formed; real validation happens the first
 * time the credential is used via `credential_execute` (a live 401 there
 * flips health to "invalid").
 */
export class GenericBearerAdapter extends BaseAdapter {
  readonly providerId = "generic-bearer";
  readonly credentialTypes = ["api_key", "oauth_access_token", "pat"];
  readonly tokenPatterns: TokenPattern[] = [];
  readonly authScheme = "bearer" as const;

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    return {
      valid: ctx.secretValue.length > 0,
      result: "no provider-specific validation endpoint; accepted on shape only",
    };
  }
}

export class GenericApiKeyHeaderAdapter extends BaseAdapter {
  readonly providerId = "generic-api-key-header";
  readonly credentialTypes = ["api_key"];
  readonly tokenPatterns: TokenPattern[] = [];
  readonly authScheme = "api_key_header" as const;

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    return {
      valid: ctx.secretValue.length > 0,
      result: "no provider-specific validation endpoint; accepted on shape only",
    };
  }
}

export class GenericOAuth2Adapter extends BaseAdapter {
  readonly providerId = "generic-oauth2";
  readonly credentialTypes = ["oauth_access_token", "oauth_refresh_token"];
  readonly tokenPatterns: TokenPattern[] = [];
  readonly authScheme = "bearer" as const;

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    return { valid: ctx.secretValue.length > 0, result: "generic OAuth2 token accepted on shape only" };
  }
}

export class GenericDatabaseAdapter extends BaseAdapter {
  readonly providerId = "generic-database";
  readonly credentialTypes = ["db_connection_string"];
  readonly tokenPatterns: TokenPattern[] = [];
  readonly authScheme = "basic" as const;

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    return { valid: ctx.secretValue.length > 0, result: "connection string stored; live connectivity not probed automatically" };
  }
}
