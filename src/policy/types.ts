export type PolicyAction =
  | "secret_get" | "secret_find" | "secret_list" | "secret_metadata" | "secret_store" | "secret_store_detected"
  | "secret_update" | "secret_enrich" | "secret_rotate" | "secret_revoke" | "secret_delete"
  | "secret_claim" | "secret_share" | "credential_execute" | "credential_validate"
  | "credential_proxy_session_create" | "credential_temporary_issue" | "oauth_authorize"
  | "oauth_refresh" | "audit_query" | "agent_to_agent_visibility";

export type AccessMode = "direct" | "brokered" | "temporary" | "proxy" | "process_injection";

export interface PolicySubjectMatch {
  agentIds?: string[];
  agentTypes?: string[];
  riskMax?: "low" | "standard" | "elevated" | "high";
  ownerUserIds?: string[];
}

export interface PolicyResourceMatch {
  providers?: string[];
  credentialTypes?: string[];
  environments?: string[];
  tags?: string[];
  ownerScopes?: string[];
  sensitivities?: string[];
}

export interface PolicyConditions {
  timeWindowStartHourUtc?: number;
  timeWindowEndHourUtc?: number;
  networkCidrs?: string[];
  minAuthStrength?: "weak" | "strong" | "mfa";
  requireApproval?: boolean;
  maxRetrievalCount?: number;
  maxSessionSeconds?: number;
  cachePermitted?: boolean;
  downstreamUsePermitted?: boolean;
  accessMode?: AccessMode;
  allowedHttpMethods?: string[];
  allowedTargetResources?: string[];
}

export interface Policy {
  id: string;
  orgId: string | null;
  workspaceId: string | null;
  name: string;
  effect: "allow" | "deny";
  priority: number;
  subjects: PolicySubjectMatch;
  actions: PolicyAction[];
  resources: PolicyResourceMatch;
  conditions: PolicyConditions;
  enabled: boolean;
}

export interface PolicySubject {
  agentId: string;
  agentType: string;
  riskClassification: "low" | "standard" | "elevated" | "high";
  ownerUserId?: string | null;
}

export interface PolicyResource {
  credentialId?: string;
  provider: string;
  credentialType: string;
  environment: string;
  tags: string[];
  ownerScope: string;
  sensitivity: string;
}

export interface PolicyRequestContext {
  transport: string;
  sourceNetwork?: string;
  authStrength?: "weak" | "strong" | "mfa";
  nowUtc: Date;
  requestedCount?: number;
}

export interface PolicyDecision {
  effect: "allow" | "deny";
  accessMode: AccessMode;
  requiresApproval: boolean;
  maxRetrievalCount?: number;
  maxSessionSeconds?: number;
  cachePermitted: boolean;
  downstreamUsePermitted: boolean;
  matchedPolicyIds: string[];
  reason: string;
}
