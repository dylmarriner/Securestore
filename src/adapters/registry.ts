import type { ProviderAdapter } from "./types.js";
import { GitHubAdapter } from "./github.js";
import { GitLabAdapter } from "./gitlab.js";
import { OpenAICompatibleAdapter } from "./openai.js";
import { AnthropicCompatibleAdapter } from "./anthropic.js";
import { NpmRegistryAdapter } from "./npmRegistry.js";
import {
  GenericApiKeyHeaderAdapter,
  GenericBearerAdapter,
  GenericDatabaseAdapter,
  GenericOAuth2Adapter,
} from "./generic.js";

/**
 * Central adapter lookup. Self-hosters register additional/custom provider
 * adapters at boot by calling registerAdapter() before the MCP/REST servers
 * start accepting traffic — this is the "custom user-defined providers"
 * extension point called for in the provider-adapter-framework requirement.
 */
class AdapterRegistry {
  private readonly byProvider = new Map<string, ProviderAdapter>();

  register(adapter: ProviderAdapter): void {
    this.byProvider.set(adapter.providerId, adapter);
  }

  get(providerId: string): ProviderAdapter | undefined {
    return this.byProvider.get(providerId);
  }

  /** Falls back to a generic adapter matching the credential's auth scheme when no dedicated adapter exists. */
  resolve(providerId: string, credentialType: string): ProviderAdapter {
    const exact = this.byProvider.get(providerId);
    if (exact) return exact;
    if (credentialType === "db_connection_string") return this.byProvider.get("generic-database")!;
    if (credentialType === "oauth_access_token" || credentialType === "oauth_refresh_token")
      return this.byProvider.get("generic-oauth2")!;
    if (credentialType === "api_key") return this.byProvider.get("generic-api-key-header")!;
    return this.byProvider.get("generic-bearer")!;
  }

  list(): ProviderAdapter[] {
    return [...this.byProvider.values()];
  }
}

export const adapterRegistry = new AdapterRegistry();

adapterRegistry.register(new GitHubAdapter());
adapterRegistry.register(new GitLabAdapter());
adapterRegistry.register(new OpenAICompatibleAdapter());
adapterRegistry.register(new AnthropicCompatibleAdapter());
adapterRegistry.register(new NpmRegistryAdapter());
adapterRegistry.register(new GenericBearerAdapter());
adapterRegistry.register(new GenericApiKeyHeaderAdapter());
adapterRegistry.register(new GenericOAuth2Adapter());
adapterRegistry.register(new GenericDatabaseAdapter());
