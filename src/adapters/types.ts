import type { TokenPattern } from "../detectors/patterns.js";

export interface ValidationOutcome {
  valid: boolean;
  result: string; // human-readable status, safe to store/log
  accountId?: string;
  username?: string;
  email?: string;
  organization?: string;
  scopes?: string[];
  expiresAt?: string;
  raw?: Record<string, unknown>; // sanitized, non-secret fields only
}

export interface AdapterContext {
  secretValue: string;
  authScheme?: string;
  headerName?: string;
  headerPrefix?: string;
  baseEndpoint?: string;
}

/**
 * Contract every provider integration implements. Adapters never receive
 * more than the single secret value they're asked to operate on, and must
 * never log or return that value — only derived, non-secret facts.
 * `credential_execute` (brokered access) is also driven through this
 * interface via `execute()`, so adding a provider automatically gets both
 * enrichment and brokered-operation support.
 */
export interface ProviderAdapter {
  readonly providerId: string;
  readonly credentialTypes: string[];
  readonly tokenPatterns: TokenPattern[];
  readonly defaultBaseEndpoint?: string;
  readonly authScheme: "bearer" | "api_key_header" | "basic" | "query_param" | "mtls" | "ssh";
  readonly requiredHeaders: Record<string, string>;
  readonly oauth?: {
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    refreshEndpoint?: string;
    revocationEndpoint?: string;
    discoveryDocumentUrl?: string;
  };
  readonly supportedOperations: string[]; // e.g. ["read_user","list_repos","create_issue"]
  readonly docsUrl?: string;

  /** Safe, read-only call to confirm the credential works and harvest identity metadata. */
  validate(ctx: AdapterContext): Promise<ValidationOutcome>;

  /** Cheaper/looser check than validate(), for periodic health polling. */
  healthCheck(ctx: AdapterContext): Promise<{ healthy: boolean; detail: string }>;

  /** Executes a brokered operation without ever returning the raw secret to the caller. */
  execute(
    ctx: AdapterContext,
    operation: string,
    params: Record<string, unknown>,
  ): Promise<{ status: number; body: unknown }>;

  /** Strips secret material / auth headers out of provider error payloads before they're logged or returned. */
  sanitizeError(err: unknown): string;
}

export abstract class BaseAdapter implements ProviderAdapter {
  abstract readonly providerId: string;
  abstract readonly credentialTypes: string[];
  abstract readonly tokenPatterns: TokenPattern[];
  abstract readonly authScheme: ProviderAdapter["authScheme"];
  readonly requiredHeaders: Record<string, string> = {};
  readonly supportedOperations: string[] = ["http_request"];
  defaultBaseEndpoint?: string;
  oauth?: ProviderAdapter["oauth"];
  docsUrl?: string;

  protected buildAuthHeaders(ctx: AdapterContext): Record<string, string> {
    const headerName = ctx.headerName ?? "Authorization";
    const prefix = ctx.headerPrefix ?? "Bearer ";
    if (ctx.authScheme === "api_key_header" || this.authScheme === "api_key_header") {
      return { [headerName]: ctx.headerPrefix ? `${prefix}${ctx.secretValue}` : ctx.secretValue };
    }
    return { [headerName]: `${prefix}${ctx.secretValue}` };
  }

  abstract validate(ctx: AdapterContext): Promise<ValidationOutcome>;

  async healthCheck(ctx: AdapterContext): Promise<{ healthy: boolean; detail: string }> {
    try {
      const outcome = await this.validate(ctx);
      return { healthy: outcome.valid, detail: outcome.result };
    } catch (err) {
      return { healthy: false, detail: this.sanitizeError(err) };
    }
  }

  async execute(
    ctx: AdapterContext,
    operation: string,
    params: Record<string, unknown>,
  ): Promise<{ status: number; body: unknown }> {
    if (operation !== "http_request") {
      throw new Error(`Adapter ${this.providerId} does not support operation "${operation}"`);
    }
    const { method = "GET", path = "/", body } = params as { method?: string; path?: string; body?: unknown };
    const base = ctx.baseEndpoint ?? this.defaultBaseEndpoint;
    if (!base) throw new Error(`No base endpoint configured for provider ${this.providerId}`);
    const res = await fetch(new URL(String(path), base), {
      method: String(method),
      headers: { ...this.requiredHeaders, ...this.buildAuthHeaders(ctx), "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const responseBody = await res.json().catch(() => undefined);
    return { status: res.status, body: responseBody };
  }

  sanitizeError(err: unknown): string {
    const msg = err instanceof Error ? err.message : String(err);
    // Strip anything that looks like it could be an Authorization header or bearer token echoed back in an error body.
    return msg
      .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [redacted]")
      .replace(/(token|key|secret)"?\s*[:=]\s*"?[A-Za-z0-9._-]{8,}/gi, "$1=[redacted]");
  }
}
