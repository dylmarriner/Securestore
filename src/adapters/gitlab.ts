import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import { TOKEN_PATTERNS } from "../detectors/patterns.js";

export class GitLabAdapter extends BaseAdapter {
  readonly providerId = "gitlab";
  readonly credentialTypes = ["pat", "oauth_access_token"];
  readonly tokenPatterns = TOKEN_PATTERNS.filter((p) => p.provider === "gitlab");
  readonly authScheme = "api_key_header" as const;
  override defaultBaseEndpoint = "https://gitlab.com/api/v4";
  override docsUrl = "https://docs.gitlab.com/ee/api/rest/";
  override readonly supportedOperations = ["read_user", "list_projects", "http_request"];

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    try {
      const res = await fetch(new URL("/user", ctx.baseEndpoint ?? this.defaultBaseEndpoint), {
        headers: { "PRIVATE-TOKEN": ctx.secretValue },
      });
      if (res.status === 401) return { valid: false, result: "gitlab rejected credential (HTTP 401)" };
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      return {
        valid: res.ok,
        result: res.ok ? "validated via GET /user" : `unexpected status ${res.status}`,
        username: typeof body["username"] === "string" ? (body["username"] as string) : undefined,
        accountId: body["id"] !== undefined ? String(body["id"]) : undefined,
        email: typeof body["email"] === "string" ? (body["email"] as string) : undefined,
      };
    } catch (err) {
      return { valid: false, result: this.sanitizeError(err) };
    }
  }
}
