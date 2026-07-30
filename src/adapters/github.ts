import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import { TOKEN_PATTERNS } from "../detectors/patterns.js";

export class GitHubAdapter extends BaseAdapter {
  readonly providerId = "github";
  readonly credentialTypes = ["pat", "oauth_access_token", "service_account"];
  readonly tokenPatterns = TOKEN_PATTERNS.filter((p) => p.provider === "github");
  readonly authScheme = "bearer" as const;
  override defaultBaseEndpoint = "https://api.github.com";
  override docsUrl = "https://docs.github.com/en/rest";
  override readonly supportedOperations = ["read_user", "list_repos", "create_issue", "http_request"];

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    try {
      const res = await fetch(new URL("/user", ctx.baseEndpoint ?? this.defaultBaseEndpoint), {
        headers: { Authorization: `token ${ctx.secretValue}`, "user-agent": "securestore" },
      });
      if (res.status === 401 || res.status === 403) {
        return { valid: false, result: `github rejected credential (HTTP ${res.status})` };
      }
      const scopes = res.headers.get("x-oauth-scopes")?.split(",").map((s) => s.trim()).filter(Boolean);
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      return {
        valid: res.ok,
        result: res.ok ? "validated via GET /user" : `unexpected status ${res.status}`,
        username: typeof body["login"] === "string" ? (body["login"] as string) : undefined,
        accountId: body["id"] !== undefined ? String(body["id"]) : undefined,
        organization: typeof body["company"] === "string" ? (body["company"] as string) : undefined,
        scopes,
        raw: { type: body["type"] },
      };
    } catch (err) {
      return { valid: false, result: this.sanitizeError(err) };
    }
  }
}
