import type { DbClient } from "../db/pool.js";
import { pool, withTransaction } from "../db/pool.js";
import { encryptSecret, decryptSecret } from "../crypto/envelope.js";
import { fingerprintSecret, normalizeSecretForFingerprint } from "../crypto/fingerprint.js";
import { eventBus } from "./eventBus.js";
import { recordAudit } from "./auditService.js";
import { visibilityWhereClause } from "./visibilityService.js";
import type { CredentialMetadata, CredentialRecord, OwnerScope } from "./types.js";

export class DuplicateCredentialError extends Error {}

export interface StoreCredentialInput {
  orgId: string;
  workspaceId: string | null;
  ownerScope: OwnerScope;
  ownerUserId?: string | null;
  ownerAgentId?: string | null;
  projectId?: string | null;
  repository?: string | null;
  name: string;
  provider: string;
  service?: string | null;
  credentialType: string;
  authScheme?: string | null;
  secretValue: string;
  secretEncoding?: "utf8" | "json" | "base64" | "pem";
  sensitivity?: string;
  environment?: string;
  metadata?: CredentialMetadata;
  tags?: string[];
  introducingAgentId: string;
  creationSource: string;
  idempotencyKey?: string | null;
  enrichmentStatus?: "complete" | "partial" | "pending";
  status?: CredentialRecord["status"];
  /** Audit/event context */
  sessionId?: string | null;
  mcpTransport?: string | null;
  sourceNetwork?: string | null;
}

export interface StoreResult {
  credential: CredentialRecord;
  created: boolean; // false => an existing (deduplicated) credential was reused/updated
  rotated: boolean;
}

/**
 * Core auto-capture entry point. Implements the 13-step ingestion contract:
 * dedup by keyed fingerprint -> reuse-or-create -> encrypt -> version ->
 * assign ownership/policy -> record provenance -> audit -> publish event.
 * Idempotent: calling twice with the same idempotencyKey (or the same
 * secret value, which produces the same fingerprint) never creates a
 * second credential row.
 */
export async function storeCredential(input: StoreCredentialInput): Promise<StoreResult> {
  const normalized = normalizeSecretForFingerprint(input.secretValue);
  const fingerprint = fingerprintSecret(input.provider, input.credentialType, normalized);

  return withTransaction(async (client) => {
    if (input.idempotencyKey) {
      const existingByIdem = await client.query(
        `SELECT id FROM credentials WHERE workspace_id = $1 AND idempotency_key = $2`,
        [input.workspaceId, input.idempotencyKey],
      );
      if (existingByIdem.rows[0]) {
        const cred = await loadCredential(client, existingByIdem.rows[0].id);
        return { credential: cred!, created: false, rotated: false };
      }
    }

    // Dedup: an exact-same secret already stored anywhere this fingerprint's
    // unique index reaches (see credential_fingerprints.fingerprint PK).
    const existingFp = await client.query(
      `SELECT credential_id FROM credential_fingerprints WHERE fingerprint = $1`,
      [fingerprint],
    );
    if (existingFp.rows[0]) {
      const credentialId = existingFp.rows[0].credential_id;
      await client.query(`SELECT id FROM credentials WHERE id = $1 FOR UPDATE`, [credentialId]);
      const merged = await mergeIncomingMetadata(client, credentialId, input);
      await touchLastUsed(client, credentialId, input.introducingAgentId);
      await recordAudit(client, {
        orgId: input.orgId,
        agentId: input.introducingAgentId,
        workspaceId: input.workspaceId,
        credentialId,
        provider: input.provider,
        operation: input.creationSource === "auto_capture" ? "secret_store_detected" : "secret_store",
        accessMode: "direct",
        creationSource: input.creationSource,
        introducingAgentId: input.introducingAgentId,
        metadataSource: "dedup_merge",
        policyDecision: "allow",
        sessionId: input.sessionId,
        mcpTransport: input.mcpTransport,
        sourceNetwork: input.sourceNetwork,
        result: "success",
        details: { deduped: true },
      });
      await eventBus.publish(client, "credential.detected", {
        orgId: input.orgId,
        workspaceId: input.workspaceId,
        credentialId,
        agentId: input.introducingAgentId,
        payload: { deduped: true, provider: input.provider },
      });
      return { credential: merged, created: false, rotated: false };
    }

    // Not a dedup — but is it a *rotation* of an existing credential (same
    // provider/account/type, different secret)? Heuristic: caller passes
    // metadata hints (accountIdentifier/username) that match an existing
    // active credential for the same provider+type+workspace.
    const rotationCandidate = await findRotationCandidate(client, input);
    if (rotationCandidate) {
      const result = await rotateInternal(client, rotationCandidate, input, fingerprint);
      return { credential: result, created: false, rotated: true };
    }

    const credential = await createCredential(client, input, fingerprint);
    return { credential, created: true, rotated: false };
  });
}

async function createCredential(
  client: DbClient,
  input: StoreCredentialInput,
  fingerprint: string,
): Promise<CredentialRecord> {
  const metadata = buildMetadata(input.metadata ?? {}, input.introducingAgentId);

  const credRes = await client.query(
    `INSERT INTO credentials (
       org_id, workspace_id, owner_scope, owner_user_id, owner_agent_id, project_id, repository,
       name, provider, service, credential_type, auth_scheme, status, sensitivity, environment,
       metadata, tags, introducing_agent_id, creation_source, enrichment_status, idempotency_key
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
     RETURNING id`,
    [
      input.orgId, input.workspaceId, input.ownerScope, input.ownerUserId ?? null, input.ownerAgentId ?? null,
      input.projectId ?? null, input.repository ?? null, input.name, input.provider, input.service ?? null,
      input.credentialType, input.authScheme ?? null, input.status ?? "active", input.sensitivity ?? "medium",
      input.environment ?? "development", JSON.stringify(metadata), input.tags ?? [],
      input.introducingAgentId, input.creationSource, input.enrichmentStatus ?? "pending",
      input.idempotencyKey ?? null,
    ],
  );
  const credentialId = credRes.rows[0].id;

  const versionId = await insertVersion(client, credentialId, 1, null, input);

  try {
    await client.query(
      `INSERT INTO credential_fingerprints (fingerprint, credential_id, version_id, provider, credential_type)
       VALUES ($1,$2,$3,$4,$5)`,
      [fingerprint, credentialId, versionId, input.provider, input.credentialType],
    );
  } catch (err: any) {
    if (err?.code === "23505") {
      // Lost a race to a concurrent writer inserting the same fingerprint
      // between our SELECT and INSERT. Roll back our row and defer to theirs.
      throw new DuplicateCredentialError("concurrent duplicate detected");
    }
    throw err;
  }

  await client.query(`UPDATE credentials SET current_version_id = $1 WHERE id = $2`, [versionId, credentialId]);

  await recordAudit(client, {
    orgId: input.orgId,
    agentId: input.introducingAgentId,
    workspaceId: input.workspaceId,
    credentialId,
    provider: input.provider,
    operation: "secret_store",
    accessMode: "direct",
    creationSource: input.creationSource,
    introducingAgentId: input.introducingAgentId,
    metadataSource: "ingestion_pipeline",
    policyDecision: "allow",
    sessionId: input.sessionId,
    mcpTransport: input.mcpTransport,
    sourceNetwork: input.sourceNetwork,
    result: "success",
    details: { credentialType: input.credentialType },
  });
  await eventBus.publish(client, "credential.created", {
    orgId: input.orgId,
    workspaceId: input.workspaceId,
    credentialId,
    agentId: input.introducingAgentId,
    payload: { provider: input.provider, credentialType: input.credentialType },
  });

  return (await loadCredential(client, credentialId))!;
}

async function insertVersion(
  client: DbClient,
  credentialId: string,
  versionNumber: number,
  rotationOf: string | null,
  input: Pick<StoreCredentialInput, "secretValue" | "secretEncoding" | "introducingAgentId" | "metadata">,
): Promise<string> {
  const encrypted = await encryptSecret(input.secretValue, input.secretEncoding ?? "utf8");
  const expiresAt = fieldValue(input.metadata, "tokenExpirationTime");
  const refreshExpiresAt = fieldValue(input.metadata, "refreshTokenExpiration");
  const scopesField = fieldValue(input.metadata, "grantedScopes");

  const versionRes = await client.query(
    `INSERT INTO credential_versions (
       credential_id, version_number, status, rotation_of, expires_at, refresh_expires_at, scopes, created_by_agent_id
     ) VALUES ($1,$2,'active',$3,$4,$5,$6,$7) RETURNING id`,
    [
      credentialId, versionNumber, rotationOf,
      expiresAt ? new Date(String(expiresAt)) : null,
      refreshExpiresAt ? new Date(String(refreshExpiresAt)) : null,
      Array.isArray(scopesField) ? scopesField : [],
      input.introducingAgentId,
    ],
  );
  const versionId = versionRes.rows[0].id;

  await client.query(
    `INSERT INTO credential_secrets (version_id, ciphertext, nonce, wrapped_dek, kek_id, kek_version, encoding)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [versionId, encrypted.ciphertext, encrypted.nonce, encrypted.wrappedDek, encrypted.kekId, encrypted.kekVersion, encrypted.encoding],
  );

  if (rotationOf) {
    await client.query(`UPDATE credential_versions SET status = 'superseded' WHERE id = $1`, [rotationOf]);
  }

  return versionId;
}

function fieldValue(metadata: CredentialMetadata | undefined, key: string): unknown {
  return metadata?.[key]?.value;
}

function buildMetadata(input: CredentialMetadata, agentId: string): CredentialMetadata {
  const now = new Date().toISOString();
  const out: CredentialMetadata = {};
  for (const [k, v] of Object.entries(input)) {
    out[k] = { ...v, updatedAt: v.updatedAt ?? now, introducedByAgentId: v.introducedByAgentId ?? agentId };
  }
  return out;
}

/**
 * Provenance-aware merge: a field already marked `verified` (or at
 * confidence >= incoming) is never silently overwritten by a lower-
 * confidence inferred value. Equal-or-higher confidence, or an explicit
 * `verified` incoming value, wins and is recorded with its own provenance.
 */
export function mergeMetadata(existing: CredentialMetadata, incoming: CredentialMetadata): CredentialMetadata {
  const merged: CredentialMetadata = { ...existing };
  for (const [key, incomingField] of Object.entries(incoming)) {
    const existingField = existing[key];
    if (!existingField) {
      merged[key] = incomingField;
      continue;
    }
    if (existingField.verified && !incomingField.verified) continue;
    if (incomingField.confidence >= existingField.confidence || incomingField.verified) {
      merged[key] = incomingField;
    }
  }
  return merged;
}

async function mergeIncomingMetadata(
  client: DbClient,
  credentialId: string,
  input: StoreCredentialInput,
): Promise<CredentialRecord> {
  const existing = (await loadCredential(client, credentialId))!;
  const incoming = buildMetadata(input.metadata ?? {}, input.introducingAgentId);
  const merged = mergeMetadata(existing.metadata, incoming);
  await client.query(`UPDATE credentials SET metadata = $1, updated_at = now() WHERE id = $2`, [
    JSON.stringify(merged),
    credentialId,
  ]);
  return (await loadCredential(client, credentialId))!;
}

async function touchLastUsed(client: DbClient, credentialId: string, agentId: string): Promise<void> {
  await client.query(
    `UPDATE credentials SET last_used_at = now(), last_used_agent_id = $1 WHERE id = $2`,
    [agentId, credentialId],
  );
}

async function findRotationCandidate(
  client: DbClient,
  input: StoreCredentialInput,
): Promise<string | null> {
  const accountId = fieldValue(input.metadata, "accountIdentifier") ?? fieldValue(input.metadata, "username");
  if (!accountId) return null;
  const { rows } = await client.query(
    `SELECT id FROM credentials
     WHERE workspace_id = $1 AND provider = $2 AND credential_type = $3 AND status = 'active'
       AND metadata -> 'accountIdentifier' ->> 'value' = $4
     LIMIT 1`,
    [input.workspaceId, input.provider, input.credentialType, String(accountId)],
  );
  return rows[0]?.id ?? null;
}

async function rotateInternal(
  client: DbClient,
  credentialId: string,
  input: Pick<StoreCredentialInput, "secretValue" | "secretEncoding" | "introducingAgentId" | "metadata" | "orgId" | "workspaceId" | "provider" | "sessionId" | "mcpTransport" | "sourceNetwork">,
  fingerprint: string,
): Promise<CredentialRecord> {
  await client.query(`SELECT id FROM credentials WHERE id = $1 FOR UPDATE`, [credentialId]);
  const current = await client.query(
    `SELECT current_version_id, (SELECT MAX(version_number) FROM credential_versions WHERE credential_id = $1) AS max_version
     FROM credentials WHERE id = $1`,
    [credentialId],
  );
  const nextVersion = Number(current.rows[0].max_version ?? 0) + 1;
  const versionId = await insertVersion(client, credentialId, nextVersion, current.rows[0].current_version_id, input);

  await client.query(
    `INSERT INTO credential_fingerprints (fingerprint, credential_id, version_id, provider, credential_type)
     VALUES ($1,$2,$3,$4, (SELECT credential_type FROM credentials WHERE id=$2))`,
    [fingerprint, credentialId, versionId, input.provider],
  );

  await client.query(
    `UPDATE credentials SET current_version_id = $1, status = 'active', updated_at = now() WHERE id = $2`,
    [versionId, credentialId],
  );
  await mergeIncomingMetadata(client, credentialId, input as StoreCredentialInput);

  await recordAudit(client, {
    orgId: input.orgId,
    agentId: input.introducingAgentId,
    workspaceId: input.workspaceId,
    credentialId,
    credentialVersion: nextVersion,
    provider: input.provider,
    operation: "secret_rotate",
    accessMode: "direct",
    creationSource: "rotation",
    introducingAgentId: input.introducingAgentId,
    metadataSource: "rotation_detected",
    policyDecision: "allow",
    sessionId: input.sessionId,
    mcpTransport: input.mcpTransport,
    sourceNetwork: input.sourceNetwork,
    result: "success",
    details: { versionNumber: nextVersion },
  });
  await eventBus.publish(client, "credential.rotated", {
    orgId: input.orgId,
    workspaceId: input.workspaceId,
    credentialId,
    agentId: input.introducingAgentId,
    payload: { versionNumber: nextVersion },
  });

  return (await loadCredential(client, credentialId))!;
}

export async function loadCredential(client: DbClient | typeof pool, credentialId: string): Promise<CredentialRecord | null> {
  const { rows } = await client.query(
    `SELECT c.*, v.version_number AS current_version_number
     FROM credentials c
     LEFT JOIN credential_versions v ON v.id = c.current_version_id
     WHERE c.id = $1`,
    [credentialId],
  );
  return rows[0] ? rowToCredential(rows[0]) : null;
}

export async function getCredential(credentialId: string): Promise<CredentialRecord | null> {
  return loadCredential(pool, credentialId);
}

export interface FindCredentialsQuery {
  /** Isolation scope — required. See src/services/visibilityService.ts. */
  visibleTo: { orgId: string; agentId: string; memberWorkspaceIds: string[] };
  workspaceId?: string;
  provider?: string;
  credentialType?: string;
  environment?: string;
  tags?: string[];
  nameQuery?: string;
  status?: string;
  limit?: number;
}

export async function findCredentials(q: FindCredentialsQuery): Promise<CredentialRecord[]> {
  const { clause: visibilityClause, paramCount } = visibilityWhereClause(1);
  const clauses: string[] = ["c.status != 'deleted'", visibilityClause];
  const params: unknown[] = [q.visibleTo.orgId, q.visibleTo.agentId, q.visibleTo.memberWorkspaceIds];
  let i = paramCount + 1;
  if (q.workspaceId) { clauses.push(`c.workspace_id = $${i++}`); params.push(q.workspaceId); }
  if (q.provider) { clauses.push(`c.provider = $${i++}`); params.push(q.provider); }
  if (q.credentialType) { clauses.push(`c.credential_type = $${i++}`); params.push(q.credentialType); }
  if (q.environment) { clauses.push(`c.environment = $${i++}`); params.push(q.environment); }
  if (q.status) { clauses.push(`c.status = $${i++}`); params.push(q.status); }
  if (q.nameQuery) { clauses.push(`c.name ILIKE $${i++}`); params.push(`%${q.nameQuery}%`); }
  if (q.tags?.length) { clauses.push(`c.tags && $${i++}`); params.push(q.tags); }
  const limit = Math.min(q.limit ?? 50, 500);
  params.push(limit);
  const { rows } = await pool.query(
    `SELECT c.*, v.version_number AS current_version_number
     FROM credentials c LEFT JOIN credential_versions v ON v.id = c.current_version_id
     WHERE ${clauses.join(" AND ")} ORDER BY c.updated_at DESC LIMIT $${i}`,
    params,
  );
  return rows.map(rowToCredential);
}

/** Decrypts and returns the raw secret. Callers MUST have already run this through the policy engine. */
export async function revealSecret(credentialId: string, agentId: string, sessionCtx: {
  workspaceId?: string | null; mcpTransport?: string | null; sourceNetwork?: string | null; sessionId?: string | null;
}): Promise<string> {
  return withTransaction(async (client) => {
    const cred = await loadCredential(client, credentialId);
    if (!cred || !cred.currentVersionId) throw new Error("credential not found or has no active version");
    const { rows } = await client.query(`SELECT * FROM credential_secrets WHERE version_id = $1`, [cred.currentVersionId]);
    const row = rows[0];
    if (!row) throw new Error("secret material missing for current version");
    const plaintext = await decryptSecret({
      ciphertext: row.ciphertext, nonce: row.nonce, wrappedDek: row.wrapped_dek,
      kekId: row.kek_id, kekVersion: row.kek_version, encoding: row.encoding,
    });
    await touchLastUsed(client, credentialId, agentId);
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "secret_get", accessMode: "direct", policyDecision: "allow",
      sessionId: sessionCtx.sessionId, mcpTransport: sessionCtx.mcpTransport, sourceNetwork: sessionCtx.sourceNetwork,
      result: "success",
    });
    await eventBus.publish(client, "credential.used", {
      orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId,
      payload: { accessMode: "direct" },
    });
    return plaintext;
  });
}

export async function revealSecretForBrokeredUse(credentialId: string): Promise<{
  secretValue: string; authScheme: string | null; metadata: CredentialMetadata; provider: string;
}> {
  const cred = await getCredential(credentialId);
  if (!cred || !cred.currentVersionId) throw new Error("credential not found or has no active version");
  const { rows } = await pool.query(`SELECT * FROM credential_secrets WHERE version_id = $1`, [cred.currentVersionId]);
  const row = rows[0];
  if (!row) throw new Error("secret material missing for current version");
  const plaintext = await decryptSecret({
    ciphertext: row.ciphertext, nonce: row.nonce, wrappedDek: row.wrapped_dek,
    kekId: row.kek_id, kekVersion: row.kek_version, encoding: row.encoding,
  });
  return { secretValue: plaintext, authScheme: cred.authScheme, metadata: cred.metadata, provider: cred.provider };
}

export async function updateMetadata(
  credentialId: string,
  agentId: string,
  fields: CredentialMetadata,
  opts: { enrichmentStatus?: "complete" | "partial" | "pending"; workspaceId?: string | null } = {},
): Promise<CredentialRecord> {
  return withTransaction(async (client) => {
    await client.query(`SELECT id FROM credentials WHERE id = $1 FOR UPDATE`, [credentialId]);
    const existing = (await loadCredential(client, credentialId))!;
    const incoming = buildMetadata(fields, agentId);
    const merged = mergeMetadata(existing.metadata, incoming);
    await client.query(
      `UPDATE credentials SET metadata = $1, updated_at = now(), enrichment_status = COALESCE($2, enrichment_status) WHERE id = $3`,
      [JSON.stringify(merged), opts.enrichmentStatus ?? null, credentialId],
    );
    await recordAudit(client, {
      orgId: existing.orgId,
      agentId, workspaceId: existing.workspaceId, credentialId, provider: existing.provider,
      operation: "secret_enrich", accessMode: "direct", policyDecision: "allow", metadataSource: "manual_enrich",
      result: "success", details: { fields: Object.keys(fields) },
    });
    await eventBus.publish(client, "credential.enriched", {
      orgId: existing.orgId, workspaceId: existing.workspaceId, credentialId, agentId,
      payload: { fields: Object.keys(fields) },
    });
    return (await loadCredential(client, credentialId))!;
  });
}

export async function markValidation(
  credentialId: string,
  agentId: string | null,
  outcome: { valid: boolean; result: string },
): Promise<void> {
  await withTransaction(async (client) => {
    const cred = await loadCredential(client, credentialId);
    if (!cred) return;
    await client.query(
      `UPDATE credentials SET last_validation_at = now(), last_validation_result = $1,
         health = $2, status = CASE WHEN $3 = false AND status = 'unresolved' THEN status ELSE status END
       WHERE id = $4`,
      [outcome.result, outcome.valid ? "healthy" : "invalid", outcome.valid, credentialId],
    );
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "credential_validate", accessMode: "direct", policyDecision: "allow",
      result: outcome.valid ? "success" : "error", details: { result: outcome.result },
    });
    await eventBus.publish(client, "credential.validated", {
      orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId,
      payload: { valid: outcome.valid },
    });
  });
}

export async function revokeCredential(credentialId: string, agentId: string, reason?: string): Promise<void> {
  await withTransaction(async (client) => {
    const cred = await loadCredential(client, credentialId);
    if (!cred) throw new Error("credential not found");
    await client.query(`UPDATE credentials SET status = 'revoked', updated_at = now() WHERE id = $1`, [credentialId]);
    await client.query(
      `UPDATE credential_versions SET status = 'revoked' WHERE credential_id = $1 AND status = 'active'`,
      [credentialId],
    );
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "secret_revoke", accessMode: "direct", policyDecision: "allow",
      result: "success", details: { reason },
    });
    // Real-time revocation propagation: every connected agent's subscription sees this within one NOTIFY round-trip.
    await eventBus.publish(client, "credential.revoked", {
      orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId,
      payload: { reason },
    });
  });
}

export async function deleteCredential(credentialId: string, agentId: string, hard = false): Promise<void> {
  await withTransaction(async (client) => {
    const cred = await loadCredential(client, credentialId);
    if (!cred) throw new Error("credential not found");
    if (hard) {
      await client.query(`DELETE FROM credentials WHERE id = $1`, [credentialId]);
    } else {
      await client.query(`UPDATE credentials SET status = 'deleted', deleted_at = now() WHERE id = $1`, [credentialId]);
    }
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "secret_delete", accessMode: "direct", policyDecision: "allow",
      result: "success", details: { hard },
    });
    await eventBus.publish(client, "credential.deleted", {
      orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId, payload: { hard },
    });
  });
}

export async function claimCredential(credentialId: string, agentId: string): Promise<CredentialRecord> {
  return withTransaction(async (client) => {
    await client.query(
      `UPDATE credentials SET status = CASE WHEN status = 'unresolved' THEN 'active' ELSE status END, updated_at = now()
       WHERE id = $1`,
      [credentialId],
    );
    const cred = (await loadCredential(client, credentialId))!;
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "secret_claim", accessMode: "direct", policyDecision: "allow", result: "success",
    });
    return cred;
  });
}

export async function shareCredential(
  credentialId: string,
  agentId: string,
  sharingPolicy: Record<string, unknown>,
): Promise<CredentialRecord> {
  return withTransaction(async (client) => {
    await client.query(`UPDATE credentials SET sharing_policy = $1, updated_at = now() WHERE id = $2`, [
      JSON.stringify(sharingPolicy),
      credentialId,
    ]);
    const cred = (await loadCredential(client, credentialId))!;
    await recordAudit(client, {
      orgId: cred.orgId,
      agentId, workspaceId: cred.workspaceId, credentialId, provider: cred.provider,
      operation: "secret_share", accessMode: "direct", policyDecision: "allow", result: "success",
      details: { sharingPolicy },
    });
    await eventBus.publish(client, "credential.shared", {
      orgId: cred.orgId, workspaceId: cred.workspaceId, credentialId, agentId, payload: { sharingPolicy },
    });
    return cred;
  });
}

function rowToCredential(row: any): CredentialRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    workspaceId: row.workspace_id,
    ownerScope: row.owner_scope,
    ownerUserId: row.owner_user_id,
    ownerAgentId: row.owner_agent_id,
    projectId: row.project_id,
    repository: row.repository,
    name: row.name,
    provider: row.provider,
    service: row.service,
    credentialType: row.credential_type,
    authScheme: row.auth_scheme,
    status: row.status,
    currentVersionId: row.current_version_id,
    currentVersionNumber: row.current_version_number ?? null,
    sensitivity: row.sensitivity,
    environment: row.environment,
    sharingPolicy: row.sharing_policy ?? {},
    approvalRequired: row.approval_required,
    metadata: row.metadata ?? {},
    tags: row.tags ?? [],
    notes: row.notes,
    introducingAgentId: row.introducing_agent_id,
    creationSource: row.creation_source,
    lastUsedAt: row.last_used_at,
    lastUsedAgentId: row.last_used_agent_id,
    lastValidationAt: row.last_validation_at,
    lastValidationResult: row.last_validation_result,
    health: row.health,
    enrichmentStatus: row.enrichment_status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
