import { X509Certificate } from "node:crypto";
import type { PoolConfig } from "pg";
import { noteResolvedSecret } from "./secrets";

export interface PostgresTlsConfig {
  rejectUnauthorized: true;
  ca?: string;
}

const CERTIFICATE_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const UNSAFE_SSL_MODES = new Set(["disable", "no-verify", "allow", "prefer"]);
const ACCEPTED_SSL_MODES = new Set(["require", "verify-ca", "verify-full"]);
type Environment = Readonly<Record<string, string | undefined>>;

function assertSafeTlsEnvironment(env: Environment): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("postgres_tls_unsafe_configuration");
  }

  const sslMode = env.PGSSLMODE?.trim().toLowerCase();
  if (sslMode && (!ACCEPTED_SSL_MODES.has(sslMode) || UNSAFE_SSL_MODES.has(sslMode))) {
    throw new Error("postgres_tls_unsafe_configuration");
  }
}

function validateCaCertificate(value: string): string {
  const ca = value.trim();
  if (!ca) throw new Error("database_ca_cert_invalid");

  const blocks = ca.match(CERTIFICATE_BLOCK_RE) ?? [];
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").trim();
  if (blocks.length === 0 || remainder.length > 0) {
    throw new Error("database_ca_cert_invalid");
  }

  try {
    for (const block of blocks) {
      if (!new X509Certificate(block).ca) throw new Error("not_ca");
    }
  } catch {
    throw new Error("database_ca_cert_invalid");
  }

  noteResolvedSecret("DATABASE_CA_CERT", ca);
  return ca;
}

export function postgresTlsConfig(env: Environment = process.env): PostgresTlsConfig {
  assertSafeTlsEnvironment(env);
  const caValue = env.DATABASE_CA_CERT;
  if (caValue === undefined) return { rejectUnauthorized: true };
  return { rejectUnauthorized: true, ca: validateCaCertificate(caValue) };
}

function decodeUrlPart(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error("database_url_invalid");
  }
}

export function postgresPoolConfig(
  connectionString: string,
  env: Environment = process.env
): PoolConfig {
  const url = (() => {
    try {
      return new URL(connectionString);
    } catch {
      throw new Error("database_url_invalid");
    }
  })();

  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new Error("database_url_invalid");
  }

  for (const [key, value] of url.searchParams) {
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "sslmode") {
      const mode = value.toLowerCase();
      if (UNSAFE_SSL_MODES.has(mode) || !ACCEPTED_SSL_MODES.has(mode)) {
        throw new Error("postgres_tls_unsafe_configuration");
      }
    } else if (normalizedKey.startsWith("ssl")) {
      throw new Error("postgres_tls_unsafe_configuration");
    }
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname || !url.username) throw new Error("database_url_invalid");

  return {
    host: hostname,
    port: url.port ? Number(url.port) : undefined,
    user: decodeUrlPart(url.username),
    password: decodeUrlPart(url.password),
    database: decodeUrlPart(url.pathname.replace(/^\//, "")),
    max: 3,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
    ssl: postgresTlsConfig(env)
  };
}