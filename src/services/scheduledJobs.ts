import { pool, withTransaction } from "../db/pool.js";
import { eventBus } from "./eventBus.js";
import { recordAudit } from "./auditService.js";
import { revealSecretForBrokeredUse, markValidation } from "./credentialService.js";
import { adapterRegistry } from "../adapters/registry.js";

// Fixed advisory-lock keys, one per job. Postgres advisory locks are
// server-wide and session-scoped: whichever replica's connection acquires
// the lock runs that tick; every other replica's pg_try_advisory_lock call
// returns false immediately and skips it. This is the "leader election
// only where necessary" pattern from the architecture doc — no separate
// coordination system, no assumption that any one replica is special
// beyond who happens to win a given tick.
const EXPIRY_SWEEP_LOCK_KEY = 727_001;
const HEALTH_REVALIDATION_LOCK_KEY = 727_002;

async function withAdvisoryLock(key: number, fn: () => Promise<void>): Promise<void> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query<{ locked: boolean }>("SELECT pg_try_advisory_lock($1) AS locked", [key]);
    if (!rows[0]?.locked) return; // another replica is already running this tick
    try {
      await fn();
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [key]);
    }
  } finally {
    client.release();
  }
}

const EXPIRING_WARNING_WINDOW = process.env.SECURESTORE_EXPIRY_WARNING_HOURS
  ? `${Number(process.env.SECURESTORE_EXPIRY_WARNING_HOURS)} hours`
  : "72 hours";

/**
 * Flags credentials whose active version has crossed into the
 * expiring-soon window (status -> 'expiring', event credential.expiring)
 * or fully expired (status -> 'expired', event credential.expired).
 * Idempotent: re-running finds nothing new once a credential has already
 * been flagged, since the UPDATE's WHERE clause excludes rows already in
 * the target status.
 */
export async function runExpirySweep(): Promise<void> {
  await withAdvisoryLock(EXPIRY_SWEEP_LOCK_KEY, async () => {
    await withTransaction(async (client) => {
      const expiring = await client.query(
        `UPDATE credentials c
         SET status = 'expiring', updated_at = now()
         FROM credential_versions v
         WHERE c.current_version_id = v.id
           AND c.status = 'active'
           AND v.expires_at IS NOT NULL
           AND v.expires_at <= now() + interval '${EXPIRING_WARNING_WINDOW}'
           AND v.expires_at > now()
         RETURNING c.id, c.org_id, c.workspace_id, c.provider`,
      );
      for (const row of expiring.rows) {
        await recordAudit(client, {
          orgId: row.org_id, workspaceId: row.workspace_id, credentialId: row.id, provider: row.provider,
          operation: "credential_expiring", accessMode: "direct", policyDecision: "allow",
          result: "success", details: { source: "scheduled_expiry_sweep" },
        });
        await eventBus.publish(client, "credential.expiring", {
          orgId: row.org_id, workspaceId: row.workspace_id, credentialId: row.id, payload: { provider: row.provider },
        });
      }

      const expired = await client.query(
        `UPDATE credentials c
         SET status = 'expired', updated_at = now()
         FROM credential_versions v
         WHERE c.current_version_id = v.id
           AND c.status IN ('active', 'expiring')
           AND v.expires_at IS NOT NULL
           AND v.expires_at <= now()
         RETURNING c.id, c.org_id, c.workspace_id, c.provider`,
      );
      for (const row of expired.rows) {
        await recordAudit(client, {
          orgId: row.org_id, workspaceId: row.workspace_id, credentialId: row.id, provider: row.provider,
          operation: "credential_expired", accessMode: "direct", policyDecision: "allow",
          result: "success", details: { source: "scheduled_expiry_sweep" },
        });
        await eventBus.publish(client, "credential.expired", {
          orgId: row.org_id, workspaceId: row.workspace_id, credentialId: row.id, payload: { provider: row.provider },
        });
      }
    });
  });
}

const HEALTH_REVALIDATION_BATCH_SIZE = Number(process.env.SECURESTORE_HEALTH_REVALIDATION_BATCH ?? 20);
const HEALTH_REVALIDATION_STALE_AFTER = process.env.SECURESTORE_HEALTH_REVALIDATION_STALE_HOURS
  ? `${Number(process.env.SECURESTORE_HEALTH_REVALIDATION_STALE_HOURS)} hours`
  : "24 hours";

/**
 * Re-runs each provider adapter's safe validate() call against a batch of
 * active credentials whose health hasn't been checked recently, so
 * `credentials.health` reflects reality even for credentials no agent has
 * actively used lately. Best-effort and bounded: a batch limit keeps a
 * single tick from hammering every provider at once, and a failed
 * validation call is treated the same as an adapter-reported "invalid"
 * (never thrown out of the loop), so one bad credential can't stop the
 * rest of the batch from being checked.
 */
export async function runHealthRevalidation(): Promise<void> {
  await withAdvisoryLock(HEALTH_REVALIDATION_LOCK_KEY, async () => {
    const { rows } = await pool.query(
      `SELECT id, provider, credential_type
       FROM credentials
       WHERE status = 'active'
         AND (last_validation_at IS NULL OR last_validation_at <= now() - interval '${HEALTH_REVALIDATION_STALE_AFTER}')
       ORDER BY last_validation_at ASC NULLS FIRST
       LIMIT $1`,
      [HEALTH_REVALIDATION_BATCH_SIZE],
    );

    for (const row of rows) {
      try {
        const { secretValue, metadata } = await revealSecretForBrokeredUse(row.id);
        const adapter = adapterRegistry.resolve(row.provider, row.credential_type);
        const outcome = await adapter.validate({
          secretValue,
          headerName: metadata["headerName"]?.value as string | undefined,
          headerPrefix: metadata["headerPrefix"]?.value as string | undefined,
          baseEndpoint: (metadata["baseEndpoint"]?.value as string | undefined) ?? adapter.defaultBaseEndpoint,
        });
        await markValidation(row.id, null, { valid: outcome.valid, result: outcome.result });
      } catch (err) {
        await markValidation(row.id, null, {
          valid: false,
          result: `scheduled revalidation failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  });
}

export interface ScheduledJobsHandle {
  stop(): void;
}

/**
 * Starts both jobs on independent intervals. Call once per process; safe
 * to call in every horizontally-scaled replica since the advisory locks
 * ensure only one replica does the work on any given tick. Returns a
 * handle to clear the intervals (used by tests and graceful shutdown).
 */
export function startScheduledJobs(): ScheduledJobsHandle {
  const expiryIntervalMs = Number(process.env.SECURESTORE_EXPIRY_SWEEP_INTERVAL_MS ?? 5 * 60_000);
  const healthIntervalMs = Number(process.env.SECURESTORE_HEALTH_REVALIDATION_INTERVAL_MS ?? 30 * 60_000);

  const expiryTimer = setInterval(() => {
    runExpirySweep().catch((err) => console.error("expiry sweep failed", err));
  }, expiryIntervalMs);
  const healthTimer = setInterval(() => {
    runHealthRevalidation().catch((err) => console.error("health revalidation failed", err));
  }, healthIntervalMs);

  // Node keeps the process alive while these timers are pending; unref so
  // they don't prevent a clean shutdown on SIGTERM in environments that
  // rely on the event loop draining naturally.
  expiryTimer.unref?.();
  healthTimer.unref?.();

  return {
    stop() {
      clearInterval(expiryTimer);
      clearInterval(healthTimer);
    },
  };
}
