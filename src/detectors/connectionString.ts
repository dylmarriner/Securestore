export interface ParsedConnectionString {
  scheme: string;
  username?: string;
  secret: string; // the password portion — the sensitive part
  host?: string;
  port?: number;
  database?: string;
}

const DB_SCHEMES = new Set([
  "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv",
  "redis", "rediss", "amqp", "amqps", "mssql", "sqlserver",
]);

/**
 * Parses `scheme://user:password@host:port/db` connection strings. Only the
 * password segment is treated as the secret value for fingerprinting; the
 * rest becomes non-sensitive metadata (username, host, port, database).
 */
export function parseConnectionString(value: string): ParsedConnectionString | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "");
  if (!DB_SCHEMES.has(scheme) || !url.password) return null;
  return {
    scheme,
    username: url.username || undefined,
    secret: decodeURIComponent(url.password),
    host: url.hostname || undefined,
    port: url.port ? Number(url.port) : undefined,
    database: url.pathname && url.pathname !== "/" ? url.pathname.slice(1) : undefined,
  };
}
