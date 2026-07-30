export interface MetadataField {
  value: unknown;
  confidence: number; // 0..1; 1.0 = verified/provider-confirmed
  source: string; // e.g. "jwt_claim" | "provider_pattern" | "agent_declared" | "provider_validation" | "user_provided" | "admin_override"
  verified?: boolean;
  updatedAt: string;
  introducedByAgentId?: string;
}

export type CredentialMetadata = Record<string, MetadataField>;

export type OwnerScope =
  | "personal" | "workspace" | "project" | "organization"
  | "agent" | "service_account" | "environment" | "ephemeral";

export type CredentialStatus = "active" | "expiring" | "expired" | "revoked" | "deleted" | "archived" | "unresolved";
export type CredentialHealth = "healthy" | "degraded" | "invalid" | "unknown";
export type EnrichmentStatus = "complete" | "partial" | "pending";

export interface CredentialRecord {
  id: string;
  orgId: string;
  workspaceId: string | null;
  ownerScope: OwnerScope;
  ownerUserId: string | null;
  ownerAgentId: string | null;
  projectId: string | null;
  repository: string | null;
  name: string;
  provider: string;
  service: string | null;
  credentialType: string;
  authScheme: string | null;
  status: CredentialStatus;
  currentVersionId: string | null;
  currentVersionNumber: number | null;
  sensitivity: string;
  environment: string;
  sharingPolicy: Record<string, unknown>;
  approvalRequired: boolean;
  metadata: CredentialMetadata;
  tags: string[];
  notes: string | null;
  introducingAgentId: string | null;
  creationSource: string;
  lastUsedAt: string | null;
  lastUsedAgentId: string | null;
  lastValidationAt: string | null;
  lastValidationResult: string | null;
  health: CredentialHealth;
  enrichmentStatus: EnrichmentStatus;
  createdAt: string;
  updatedAt: string;
}

export interface AgentRecord {
  id: string;
  orgId: string;
  name: string;
  agentType: string;
  platform: string | null;
  ownerUserId: string | null;
  authMethod: string;
  allowedTransports: string[];
  allowedTools: string[];
  allowedNamespaces: string[];
  allowedProviders: string[];
  allowedOperations: string[];
  rawSecretAccess: boolean;
  autoIngestionPermission: boolean;
  metadataEnrichmentPermission: boolean;
  rotationPermission: boolean;
  revocationPermission: boolean;
  metadataAdminPermission: boolean;
  riskClassification: "low" | "standard" | "elevated" | "high";
  revoked: boolean;
}
