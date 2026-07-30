import { pool } from "../db/pool.js";
import type { Policy } from "./types.js";

interface PolicyRow {
  id: string;
  org_id: string | null;
  workspace_id: string | null;
  name: string;
  effect: string;
  priority: number;
  subjects: Policy["subjects"];
  actions: string[];
  resources: Policy["resources"];
  conditions: Policy["conditions"];
  enabled: boolean;
}

function rowToPolicy(row: PolicyRow): Policy {
  return {
    id: row.id,
    orgId: row.org_id,
    workspaceId: row.workspace_id,
    name: row.name,
    effect: row.effect as "allow" | "deny",
    priority: row.priority,
    subjects: row.subjects ?? {},
    actions: (row.actions ?? []) as Policy["actions"],
    resources: row.resources ?? {},
    conditions: row.conditions ?? {},
    enabled: row.enabled,
  };
}

/** Loads every enabled policy visible to a workspace: global (org_id IS NULL), org-wide, and workspace-scoped. */
export async function loadApplicablePolicies(orgId: string, workspaceId: string | null): Promise<Policy[]> {
  const { rows } = await pool.query<PolicyRow>(
    `SELECT * FROM policies
     WHERE enabled = true
       AND (org_id IS NULL OR org_id = $1)
       AND (workspace_id IS NULL OR workspace_id = $2)`,
    [orgId, workspaceId],
  );
  return rows.map(rowToPolicy);
}
