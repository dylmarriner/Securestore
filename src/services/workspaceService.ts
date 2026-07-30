import { pool } from "../db/pool.js";

export async function createOrganization(name: string, slug: string) {
  const { rows } = await pool.query(
    `INSERT INTO organizations (name, slug) VALUES ($1,$2)
     ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING *`,
    [name, slug],
  );
  return rows[0];
}

export async function createWorkspace(orgId: string, name: string, slug: string) {
  const { rows } = await pool.query(
    `INSERT INTO workspaces (org_id, name, slug) VALUES ($1,$2,$3)
     ON CONFLICT (org_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING *`,
    [orgId, name, slug],
  );
  return rows[0];
}

export async function createUser(orgId: string, email: string, displayName?: string) {
  const { rows } = await pool.query(
    `INSERT INTO users (org_id, email, display_name) VALUES ($1,$2,$3)
     ON CONFLICT (org_id, email) DO UPDATE SET display_name = EXCLUDED.display_name RETURNING *`,
    [orgId, email, displayName ?? null],
  );
  return rows[0];
}

export async function addWorkspaceMember(workspaceId: string, userId: string, role = "owner") {
  await pool.query(
    `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
    [workspaceId, userId, role],
  );
}
