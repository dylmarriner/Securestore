import type {
  Policy, PolicyAction, PolicyDecision, PolicyRequestContext, PolicyResource, PolicySubject,
} from "./types.js";

const RISK_RANK = { low: 0, standard: 1, elevated: 2, high: 3 } as const;
const AUTH_RANK = { weak: 0, strong: 1, mfa: 2 } as const;

function subjectMatches(policy: Policy, subject: PolicySubject): boolean {
  const s = policy.subjects;
  if (s.agentIds?.length && !s.agentIds.includes(subject.agentId)) return false;
  if (s.agentTypes?.length && !s.agentTypes.includes(subject.agentType)) return false;
  if (s.riskMax && RISK_RANK[subject.riskClassification] > RISK_RANK[s.riskMax]) return false;
  if (s.ownerUserIds?.length && (!subject.ownerUserId || !s.ownerUserIds.includes(subject.ownerUserId))) return false;
  return true;
}

function resourceMatches(policy: Policy, resource: PolicyResource): boolean {
  const r = policy.resources;
  if (r.providers?.length && !r.providers.includes(resource.provider)) return false;
  if (r.credentialTypes?.length && !r.credentialTypes.includes(resource.credentialType)) return false;
  if (r.environments?.length && !r.environments.includes(resource.environment)) return false;
  if (r.ownerScopes?.length && !r.ownerScopes.includes(resource.ownerScope)) return false;
  if (r.sensitivities?.length && !r.sensitivities.includes(resource.sensitivity)) return false;
  if (r.tags?.length && !r.tags.some((t) => resource.tags.includes(t))) return false;
  return true;
}

function conditionsSatisfied(policy: Policy, ctx: PolicyRequestContext): boolean {
  const c = policy.conditions;
  if (c.timeWindowStartHourUtc !== undefined && c.timeWindowEndHourUtc !== undefined) {
    const hour = ctx.nowUtc.getUTCHours();
    const inWindow =
      c.timeWindowStartHourUtc <= c.timeWindowEndHourUtc
        ? hour >= c.timeWindowStartHourUtc && hour < c.timeWindowEndHourUtc
        : hour >= c.timeWindowStartHourUtc || hour < c.timeWindowEndHourUtc;
    if (!inWindow) return false;
  }
  if (c.minAuthStrength) {
    const have = ctx.authStrength ? AUTH_RANK[ctx.authStrength] : -1;
    if (have < AUTH_RANK[c.minAuthStrength]) return false;
  }
  // Network CIDR matching is intentionally simple (prefix match on dotted
  // octets); swap in a proper CIDR library for production deployments that
  // need real subnet math.
  if (c.networkCidrs?.length && ctx.sourceNetwork) {
    const ok = c.networkCidrs.some((cidr) => ctx.sourceNetwork!.startsWith(cidr.split("/")[0]!.replace(/\.0+$/, "")));
    if (!ok) return false;
  }
  return true;
}

/**
 * Deny-overrides ABAC evaluator. Fail-closed: if nothing matches, the
 * decision is deny. Among matching allow policies, the accessMode/approval
 * flag comes from the highest-priority (lowest `priority` number) match;
 * numeric/boolean guardrails (maxRetrievalCount, maxSessionSeconds,
 * cachePermitted, downstreamUsePermitted) are combined conservatively
 * (most restrictive wins) across every matching allow policy so stacking
 * grants can never accidentally loosen a narrower one.
 */
export function evaluatePolicy(
  policies: Policy[],
  action: PolicyAction,
  subject: PolicySubject,
  resource: PolicyResource,
  ctx: PolicyRequestContext,
): PolicyDecision {
  const candidates = policies
    .filter((p) => p.enabled && p.actions.includes(action))
    .filter((p) => subjectMatches(p, subject))
    .filter((p) => resourceMatches(p, resource))
    .filter((p) => conditionsSatisfied(p, ctx))
    .sort((a, b) => a.priority - b.priority);

  const denies = candidates.filter((p) => p.effect === "deny");
  if (denies.length > 0) {
    return {
      effect: "deny",
      accessMode: "direct",
      requiresApproval: false,
      cachePermitted: false,
      downstreamUsePermitted: false,
      matchedPolicyIds: denies.map((p) => p.id),
      reason: `denied by policy "${denies[0]!.name}"`,
    };
  }

  const allows = candidates.filter((p) => p.effect === "allow");
  if (allows.length === 0) {
    return {
      effect: "deny",
      accessMode: "direct",
      requiresApproval: false,
      cachePermitted: false,
      downstreamUsePermitted: false,
      matchedPolicyIds: [],
      reason: "no matching allow policy (default deny)",
    };
  }

  const primary = allows[0]!;
  let maxRetrievalCount: number | undefined;
  let maxSessionSeconds: number | undefined;
  let cachePermitted = true;
  let downstreamUsePermitted = true;
  let requiresApproval = false;

  for (const p of allows) {
    const c = p.conditions;
    if (c.requireApproval) requiresApproval = true;
    if (c.maxRetrievalCount !== undefined) {
      maxRetrievalCount = maxRetrievalCount === undefined ? c.maxRetrievalCount : Math.min(maxRetrievalCount, c.maxRetrievalCount);
    }
    if (c.maxSessionSeconds !== undefined) {
      maxSessionSeconds = maxSessionSeconds === undefined ? c.maxSessionSeconds : Math.min(maxSessionSeconds, c.maxSessionSeconds);
    }
    if (c.cachePermitted === false) cachePermitted = false;
    if (c.downstreamUsePermitted === false) downstreamUsePermitted = false;
  }

  if (ctx.requestedCount !== undefined && maxRetrievalCount !== undefined && ctx.requestedCount > maxRetrievalCount) {
    return {
      effect: "deny",
      accessMode: "direct",
      requiresApproval: false,
      cachePermitted: false,
      downstreamUsePermitted: false,
      matchedPolicyIds: allows.map((p) => p.id),
      reason: `requested count ${ctx.requestedCount} exceeds policy maximum ${maxRetrievalCount}`,
    };
  }

  return {
    effect: "allow",
    accessMode: primary.conditions.accessMode ?? "direct",
    requiresApproval,
    maxRetrievalCount,
    maxSessionSeconds,
    cachePermitted,
    downstreamUsePermitted,
    matchedPolicyIds: allows.map((p) => p.id),
    reason: `allowed by policy "${primary.name}"`,
  };
}
