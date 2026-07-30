import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/policy/engine.js";
import type { Policy } from "../src/policy/types.js";

function policy(overrides: Partial<Policy>): Policy {
  return {
    id: overrides.id ?? Math.random().toString(36),
    orgId: null,
    workspaceId: null,
    name: "test-policy",
    effect: "allow",
    priority: 100,
    subjects: {},
    actions: ["secret_get"],
    resources: {},
    conditions: {},
    enabled: true,
    ...overrides,
  };
}

const subject = { agentId: "agent-1", agentType: "cli", riskClassification: "standard" as const };
const resource = { provider: "github", credentialType: "pat", environment: "development", tags: [], ownerScope: "workspace", sensitivity: "medium" };
const ctx = { transport: "http", nowUtc: new Date("2026-01-01T12:00:00Z") };

describe("policy engine", () => {
  it("fails closed with no matching policies", () => {
    const decision = evaluatePolicy([], "secret_get", subject, resource, ctx);
    expect(decision.effect).toBe("deny");
  });

  it("allows when a matching allow policy exists", () => {
    const decision = evaluatePolicy([policy({})], "secret_get", subject, resource, ctx);
    expect(decision.effect).toBe("allow");
    expect(decision.accessMode).toBe("direct");
  });

  it("deny always overrides a matching allow, regardless of priority order", () => {
    const decision = evaluatePolicy(
      [policy({ priority: 1, effect: "allow" }), policy({ priority: 999, effect: "deny" })],
      "secret_get",
      subject,
      resource,
      ctx,
    );
    expect(decision.effect).toBe("deny");
  });

  it("does not match a policy scoped to a different provider", () => {
    const decision = evaluatePolicy(
      [policy({ resources: { providers: ["gitlab"] } })],
      "secret_get",
      subject,
      resource,
      ctx,
    );
    expect(decision.effect).toBe("deny");
  });

  it("combines maxRetrievalCount conservatively (most restrictive wins) across stacked allow policies", () => {
    const decision = evaluatePolicy(
      [policy({ conditions: { maxRetrievalCount: 10 } }), policy({ conditions: { maxRetrievalCount: 3 } })],
      "secret_get",
      subject,
      resource,
      ctx,
    );
    expect(decision.maxRetrievalCount).toBe(3);
  });

  it("denies when the requested count exceeds the combined maximum", () => {
    const decision = evaluatePolicy(
      [policy({ conditions: { maxRetrievalCount: 2 } })],
      "secret_get",
      subject,
      resource,
      { ...ctx, requestedCount: 5 },
    );
    expect(decision.effect).toBe("deny");
  });

  it("flags requiresApproval when any matching allow policy requires it", () => {
    const decision = evaluatePolicy(
      [policy({}), policy({ conditions: { requireApproval: true } })],
      "secret_get",
      subject,
      resource,
      ctx,
    );
    expect(decision.requiresApproval).toBe(true);
  });

  it("respects a subject riskMax ceiling", () => {
    const highRiskSubject = { ...subject, riskClassification: "high" as const };
    const decision = evaluatePolicy(
      [policy({ subjects: { riskMax: "standard" } })],
      "secret_get",
      highRiskSubject,
      resource,
      ctx,
    );
    expect(decision.effect).toBe("deny");
  });

  it("respects minAuthStrength conditions", () => {
    const decision = evaluatePolicy(
      [policy({ conditions: { minAuthStrength: "mfa" } })],
      "secret_get",
      subject,
      resource,
      { ...ctx, authStrength: "weak" },
    );
    expect(decision.effect).toBe("deny");
  });
});
