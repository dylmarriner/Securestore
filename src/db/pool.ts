import pg from "pg";
import { config } from "../config.js";

export const pool = new pg.Pool({
  connectionString: config.db.connectionString,
  max: Number(process.env.DATABASE_POOL_MAX ?? 20),
  idleTimeoutMillis: 30_000,
});

export type DbClient = pg.PoolClient;

/**
 * Runs `fn` inside a single transaction. Rolls back on any thrown error.
 * Used for every multi-statement mutation so writes are atomic.
 */
export async function withTransaction<T>(
  fn: (client: DbClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
