import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import { TOKEN_PATTERNS } from "../detectors/patterns.js";

export class AnthropicCompatibleAdapter extends BaseAdapter {
  readonly providerId = "anthropic";
  readonly credentialTypes = ["api_key"];
  readonly tokenPatterns = TOKEN_PATTERNS.filter((p) => p.provider === "anthropic");
  readonly authScheme = "api_key_header" as const;
  override defaultBaseEndpoint = "https://api.anthropic.com/v1";
  override docsUrl = "https://docs.claude.com/en/api";
  override readonly requiredHeaders = { "anthropic-version": "2023-06-01" };
  override readonly supportedOperations = ["list_models", "http_request"];

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    try {
      const res = await fetch(new URL("/models", ctx.baseEndpoint ?? this.defaultBaseEndpoint), {
        headers: { "x-api-key": ctx.secretValue, "anthropic-version": "2023-06-01" },
      });
      if (res.status === 401) return { valid: false, result: "provider rejected credential (HTTP 401)" };
      return { valid: res.ok, result: res.ok ? "validated via GET /models" : `unexpected status ${res.status}` };
    } catch (err) {
      return { valid: false, result: this.sanitizeError(err) };
    }
  }
}
