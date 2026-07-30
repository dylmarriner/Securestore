import { createOrganization, createUser, createWorkspace, addWorkspaceMember } from "../services/workspaceService.js";
import { registerAgent } from "../services/agentService.js";
import { pool } from "../db/pool.js";

/**
 * Stands up a first organization/workspace/admin-user/admin-agent for a
 * fresh self-hosted deployment. Run with `npm run seed` after `npm run
 * migrate`. Prints the admin agent's API key exactly once — store it, it
 * cannot be recovered (only rotated) afterward.
 */
async function main() {
  const orgName = process.env.SEED_ORG_NAME ?? "Default Organization";
  const orgSlug = process.env.SEED_ORG_SLUG ?? "default";
  const workspaceName = process.env.SEED_WORKSPACE_NAME ?? "Default Workspace";
  const workspaceSlug = process.env.SEED_WORKSPACE_SLUG ?? "default";
  const adminEmail = process.env.SEED_ADMIN_EMAIL ?? "admin@example.com";

  const org = await createOrganization(orgName, orgSlug);
  const workspace = await createWorkspace(org.id, workspaceName, workspaceSlug);
  const user = await createUser(org.id, adminEmail, "Administrator");
  await addWorkspaceMember(workspace.id, user.id, "owner");

  const { agent, apiKey } = await registerAgent({
    orgId: org.id,
    name: "bootstrap-admin",
    agentType: "automation",
    platform: "securestore-cli",
    ownerUserId: user.id,
    rawSecretAccess: true,
    rotationPermission: true,
    revocationPermission: true,
    riskClassification: "low",
    workspaceIds: [workspace.id],
  });
  await pool.query(`UPDATE agents SET metadata_admin_permission = true WHERE id = $1`, [agent.id]);

  console.log("Seed complete.");
  console.log(`  organizationId: ${org.id}`);
  console.log(`  workspaceId:    ${workspace.id}`);
  console.log(`  adminUserId:    ${user.id}`);
  console.log(`  adminAgentId:   ${agent.id}`);
  console.log(`  adminApiKey:    ${apiKey}   <-- store this now, it will not be shown again`);

  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
