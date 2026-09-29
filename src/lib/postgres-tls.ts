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
type CaCertificateRepresentation = "pem" | "escaped_newlines" | "whitespace_normalized";

export type CaCertificateDiagnostic =
  | { status: "missing" }
  | { status: "valid"; representation: CaCertificateRepresentation }
  | { status: "malformed"; representation: CaCertificateRepresentation };

function assertSafeTlsEnvironment(env: Environment): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("postgres_tls_unsafe_configuration");
  }

  const sslMode = env.PGSSLMODE?.trim().toLowerCase();
  if (sslMode && (!ACCEPTED_SSL_MODES.has(sslMode) || UNSAFE_SSL_MODES.has(sslMode))) {
    throw new Error("postgres_tls_unsafe_configuration");
  }
}

function normalizeCaCertificate(value: string): {
  ca: string;
  representation: CaCertificateRepresentation;
} {
  const escapedNewlines = /(?:\\r)?\\n/.test(value);
  const ca = (escapedNewlines ? value.replace(/(?:\\r)?\\n/g, "\n") : value).trim();
  const hasWhitespaceNormalization =
    /^[ \t]/.test(value) ||
    /[ \t]$/.test(value) ||
    /\r\n/.test(value) ||
    /\n[ \t]+/.test(value);
  return {
    ca,
    representation: escapedNewlines
      ? "escaped_newlines"
      : hasWhitespaceNormalization
        ? "whitespace_normalized"
        : "pem"
  };
}

function parseCaCertificate(ca: string): boolean {
  if (!ca) return false;
  const blocks = ca.match(CERTIFICATE_BLOCK_RE) ?? [];
  const remainder = ca.replace(CERTIFICATE_BLOCK_RE, "").trim();
  if (blocks.length === 0 || remainder.length > 0) return false;

  try {
    for (const block of blocks) {
      if (!new X509Certificate(block).ca) return false;
    }
  } catch {
    return false;
  }
  return true;
}

export function diagnoseCaCertificate(value: string | undefined): CaCertificateDiagnostic {
  if (value === undefined) return { status: "missing" };
  const { ca, representation } = normalizeCaCertificate(value);
  return {
    status: parseCaCertificate(ca) ? "valid" : "malformed",
    representation
  };
}

function validateCaCertificate(value: string): string {
  const { ca } = normalizeCaCertificate(value);
  if (!parseCaCertificate(ca)) throw new Error("database_ca_cert_invalid");

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