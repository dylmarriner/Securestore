import { BaseAdapter, type AdapterContext, type ValidationOutcome } from "./types.js";
import { TOKEN_PATTERNS } from "../detectors/patterns.js";

/** Covers OpenAI and any OpenAI-compatible gateway (Azure OpenAI proxy, local vLLM, etc). */
export class OpenAICompatibleAdapter extends BaseAdapter {
  readonly providerId = "openai";
  readonly credentialTypes = ["api_key"];
  readonly tokenPatterns = TOKEN_PATTERNS.filter((p) => p.provider === "openai");
  readonly authScheme = "bearer" as const;
  override defaultBaseEndpoint = "https://api.openai.com/v1";
  override docsUrl = "https://platform.openai.com/docs/api-reference";
  override readonly supportedOperations = ["list_models", "http_request"];

  async validate(ctx: AdapterContext): Promise<ValidationOutcome> {
    try {
      const res = await fetch(new URL("/models", ctx.baseEndpoint ?? this.defaultBaseEndpoint), {
        headers: { Authorization: `Bearer ${ctx.secretValue}` },
      });
      if (res.status === 401) return { valid: false, result: "provider rejected credential (HTTP 401)" };
      return { valid: res.ok, result: res.ok ? "validated via GET /models" : `unexpected status ${res.status}` };
    } catch (err) {
      return { valid: false, result: this.sanitizeError(err) };
    }
  }
}
