-- Global default policies (org_id/workspace_id NULL => apply everywhere).
-- Self-hosters are expected to layer org/workspace-scoped policies on top;
-- these seeds give a safe, usable out-of-the-box posture: same-workspace
-- agents share non-production credentials directly, production credentials
-- require approval and go through brokered execution instead of raw
-- retrieval, and destructive operations are additionally gated by the
-- per-agent rotation_permission/revocation_permission flags at the service
-- layer (belt-and-suspenders: RBAC flags + ABAC policy both must allow it).

INSERT INTO policies (org_id, workspace_id, name, description, effect, priority, subjects, actions, resources, conditions, enabled)
VALUES
(
  NULL, NULL,
  'workspace-agents-default-access',
  'Registered, non-revoked agents can read, store, and use non-production credentials directly within their workspace.',
  'allow', 100,
  '{}'::jsonb,
  ARRAY['secret_get','secret_find','secret_list','secret_metadata','secret_store','secret_store_detected',
        'secret_update','secret_enrich','credential_validate','credential_execute','secret_share',
        'credential_proxy_session_create','credential_temporary_issue'],
  '{"environments":["development","staging"]}'::jsonb,
  '{"accessMode":"direct","cachePermitted":true,"downstreamUsePermitted":true}'::jsonb,
  true
),
(
  NULL, NULL,
  'production-requires-approval-and-brokering',
  'Production-scoped credentials are never returned raw; use is brokered and requires human approval.',
  'allow', 40,
  '{}'::jsonb,
  ARRAY['secret_get','credential_execute'],
  '{"environments":["production"]}'::jsonb,
  '{"accessMode":"brokered","requireApproval":true,"cachePermitted":false,"downstreamUsePermitted":false}'::jsonb,
  true
),
(
  NULL, NULL,
  'unresolved-credentials-enrichable-by-any-workspace-agent',
  'Any workspace agent with enrichment permission may complete metadata for a credential another agent introduced.',
  'allow', 100,
  '{}'::jsonb,
  ARRAY['secret_enrich'],
  '{}'::jsonb,
  '{"accessMode":"direct"}'::jsonb,
  true
),
(
  NULL, NULL,
  'audit-query-workspace-scoped',
  'Registered agents may query audit history for their own workspace.',
  'allow', 100,
  '{}'::jsonb,
  ARRAY['audit_query'],
  '{}'::jsonb,
  '{"accessMode":"direct"}'::jsonb,
  true
);

-- To restrict a specific high-risk agent to brokered-only access, insert a
-- deny policy scoped to that agent's id via subjects.agentIds, e.g.:
--   INSERT INTO policies (name, effect, priority, subjects, actions, resources, conditions)
--   VALUES ('deny-direct-get-for-agent-x', 'deny', 10,
--           '{"agentIds":["<agent-uuid>"]}', ARRAY['secret_get'], '{}', '{}');
