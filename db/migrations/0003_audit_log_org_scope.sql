-- audit_log had no org_id column, which meant an unscoped audit_query
-- could return every organization's history, not just the caller's.
-- Add it and require every future write to populate it (enforced in
-- src/services/auditService.ts, not by a DB constraint, since a handful of
-- pre-org-context bootstrap events legitimately have no org yet).

ALTER TABLE audit_log ADD COLUMN org_id uuid REFERENCES organizations(id);
CREATE INDEX audit_log_org_idx ON audit_log(org_id);

-- Backfill from the credential the entry references, where possible.
UPDATE audit_log a
SET org_id = c.org_id
FROM credentials c
WHERE a.credential_id = c.id AND a.org_id IS NULL;

-- Any remaining rows (agent lifecycle events with no credential_id) get
-- their org from the agent they reference.
UPDATE audit_log a
SET org_id = ag.org_id
FROM agents ag
WHERE a.agent_id = ag.id AND a.org_id IS NULL;
