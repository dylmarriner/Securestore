import { detectCredential, type DetectionInput } from "../detectors/index.js";
import { adapterRegistry } from "../adapters/registry.js";
import { storeCredential, markValidation, type StoreResult } from "./credentialService.js";
import type { CredentialMetadata, OwnerScope } from "./types.js";

export interface IngestInput extends DetectionInput {
  orgId: string;
  workspaceId: string | null;
  introducingAgentId: string;
  ownerScope?: OwnerScope;
  ownerUserId?: string | null;
  projectId?: string | null;
  repository?: string | null;
  name?: string;
  validate?: boolean; // attempt a safe provider validation call to enrich identity metadata
  extraMetadata?: CredentialMetadata;
  idempotencyKey?: string | null;
  sessionId?: string | null;
  mcpTransport?: string | null;
  sourceNetwork?: string | null;
}

export interface IngestResult extends StoreResult {
  detectionMatched: boolean;
  provider: string;
  credentialType: string;
  validationAttempted: boolean;
  validationResult?: string;
}

function toMetadataFields(
  raw: Record<string, { value: unknown; confidence: number; source: string }>,
): CredentialMetadata {
  const now = new Date().toISOString();
  const out: CredentialMetadata = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k] = { value: v.value, confidence: v.confidence, source: v.source, updatedAt: now };
  }
  return out;
}

/**
 * The full 13-step auto-capture pipeline described in the platform spec:
 * detect -> dedup (delegated to storeCredential's fingerprint check) ->
 * identify provider/type -> collect/infer metadata -> validate (safe call
 * only) -> create-or-update -> encrypt+store -> assign ownership/policy ->
 * record provenance -> return stable reference -> make discoverable ->
 * audit -> publish event. storeCredential owns steps 6-13 atomically;
 * this function owns steps 1-5 (detection, identification, enrichment,
 * validation) before handing off.
 */
export async function ingestDetectedCredential(input: IngestInput): Promise<IngestResult> {
  const detection = detectCredential(input);

  const provider = detection.matched ? detection.provider : "unknown";
  const credentialType = detection.matched ? detection.credentialType : "text";
  const isUnresolved = !detection.matched || provider === "unknown";

  let metadata: CredentialMetadata = {
    ...toMetadataFields(detection.inferredMetadata),
    ...(input.extraMetadata ?? {}),
  };

  let validationAttempted = false;
  let validationResult: string | undefined;

  if (input.validate !== false && !isUnresolved) {
    const adapter = adapterRegistry.resolve(provider, credentialType);
    try {
      validationAttempted = true;
      const outcome = await adapter.validate({
        secretValue: detection.secretValue,
        authScheme: detection.authScheme,
        headerName: detection.headerName,
        headerPrefix: detection.headerPrefix,
        baseEndpoint: detection.defaultBaseEndpoint,
      });
      validationResult = outcome.result;
      const now = new Date().toISOString();
      if (outcome.username) metadata["username"] = { value: outcome.username, confidence: 0.95, source: "provider_validation", verified: true, updatedAt: now };
      if (outcome.accountId) metadata["accountIdentifier"] = { value: outcome.accountId, confidence: 0.95, source: "provider_validation", verified: true, updatedAt: now };
      if (outcome.email) metadata["associatedEmail"] = { value: outcome.email, confidence: 0.9, source: "provider_validation", verified: true, updatedAt: now };
      if (outcome.organization) metadata["organization"] = { value: outcome.organization, confidence: 0.85, source: "provider_validation", updatedAt: now };
      if (outcome.scopes?.length) metadata["grantedScopes"] = { value: outcome.scopes, confidence: 0.95, source: "provider_validation", verified: true, updatedAt: now };
      if (outcome.expiresAt) metadata["tokenExpirationTime"] = { value: outcome.expiresAt, confidence: 0.9, source: "provider_validation", updatedAt: now };
      metadata["lastValidationResult"] = { value: outcome.result, confidence: 1, source: "provider_validation", verified: true, updatedAt: now };
    } catch {
      // Validation is best-effort enrichment, never a hard requirement to store.
      validationResult = "validation call failed; stored without live confirmation";
    }
  }

  const name = input.name ?? `${provider}${metadata["username"] ? ":" + String(metadata["username"].value) : ""}`;

  const result = await storeCredential({
    orgId: input.orgId,
    workspaceId: input.workspaceId,
    ownerScope: input.ownerScope ?? "workspace",
    ownerUserId: input.ownerUserId ?? null,
    projectId: input.projectId ?? null,
    repository: input.repository ?? null,
    name,
    provider,
    credentialType,
    authScheme: detection.authScheme ?? null,
    secretValue: detection.secretValue,
    sensitivity: detection.sensitivity,
    metadata,
    introducingAgentId: input.introducingAgentId,
    creationSource: "auto_capture",
    status: isUnresolved ? "unresolved" : "active",
    enrichmentStatus: isUnresolved ? "pending" : validationAttempted ? "complete" : "partial",
    idempotencyKey: input.idempotencyKey ?? null,
    sessionId: input.sessionId,
    mcpTransport: input.mcpTransport,
    sourceNetwork: input.sourceNetwork,
  });

  if (validationAttempted && validationResult) {
    await markValidation(result.credential.id, input.introducingAgentId, {
      valid: !validationResult.toLowerCase().includes("failed") && !validationResult.toLowerCase().includes("rejected"),
      result: validationResult,
    });
  }

  return {
    ...result,
    detectionMatched: detection.matched,
    provider,
    credentialType,
    validationAttempted,
    validationResult,
  };
}
