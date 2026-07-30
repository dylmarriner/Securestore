import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import { TOKEN_PATTERNS } from "../detectors/patterns.js";

export class NpmRegistryAdapter extends BaseAdapter {
  readonly providerId = "npm";
  readonly credentialTypes = ["pat"];
  readonly tokenPatterns = TOKEN_PATTERNS.filter((p) => p.provider === "npm");
  readonly authScheme = "bearer" as const;
  override defaultBaseEndpoint = "https://registry.npmjs.org";
  override docsUrl = "https://docs.npmjs.com/about-access-tokens";
  override readonly supportedOperations = ["whoami", "http_request"];

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    try {
      const res = await fetch(new URL("/-/whoami", ctx.baseEndpoint ?? this.defaultBaseEndpoint), {
        headers: { Authorization: `Bearer ${ctx.secretValue}` },
      });
      if (res.status === 401) return { valid: false, result: "registry rejected credential (HTTP 401)" };
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      return {
        valid: res.ok,
        result: res.ok ? "validated via GET /-/whoami" : `unexpected status ${res.status}`,
        username: typeof body["username"] === "string" ? (body["username"] as string) : undefined,
      };
    } catch (err) {
      return { valid: false, result: this.sanitizeError(err) };
    }
  }
}
