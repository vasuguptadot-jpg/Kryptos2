import { redactSecrets } from "./secrets";

/**
 * Production database diagnostics.
 *
 * Classifies why the metadata store is unreachable WITHOUT exposing
 * connection strings, credentials, hostnames, or other secrets.
 * TLS verification is never relaxed here — this module is read-only
 * observation of existing configuration and error objects.
 */

export const DB_DIAGNOSTIC_CODES = [
  "ok",
  "not_configured",
  "memory_backend",
  "invalid_url",
  "tls_failure",
  "auth_failure",
  "timeout",
  "dns_failure",
  "connection_refused",
  "network_unreachable",
  "database_missing",
  "schema_failure",
  "unknown"
] as const;

export type DbDiagnosticCode = (typeof DB_DIAGNOSTIC_CODES)[number];

const SSL_MODES = new Set([
  "disable",
  "allow",
  "prefer",
  "require",
  "verify-ca",
  "verify-full"
]);

export interface DbConnectionFacts {
  /** True when DATABASE_URL is a non-empty string. Never the value. */
  present: boolean;
  /** True when the value parses as a postgres(ql) URL. */
  valid: boolean;
  scheme: "postgres" | "postgresql" | "other" | null;
  hasUsername: boolean;
  hasPassword: boolean;
  /** Allowlisted sslmode from the URL query string only. */
  sslMode: string | null;
}

export interface DbDiagnostic {
  code: DbDiagnosticCode;
  database: "ok" | "unavailable" | "not_configured";
  tlsVerification: "enforced" | "disabled";
  reason: string;
}

export function isDbDiagnosticCode(value: unknown): value is DbDiagnosticCode {
  return typeof value === "string" && (DB_DIAGNOSTIC_CODES as readonly string[]).includes(value);
}

/**
 * PostgreSQL TLS verification is always enforced by the pool configuration.
 */
export function tlsVerificationMode(): "enforced" | "disabled" {
  return "enforced";
}

export function isTlsVerificationEnforced(): boolean {
  return tlsVerificationMode() === "enforced";
}

export function safeReason(code: DbDiagnosticCode): string {
  switch (code) {
    case "ok":
      return "reachable";
    case "not_configured":
      return "DATABASE_URL is not set";
    case "memory_backend":
      return "memory store backend is not permitted in production";
    case "invalid_url":
      return "DATABASE_URL is present but is not a valid postgres URL";
    case "tls_failure":
      return "TLS certificate verification failed (verification remains enforced)";
    case "auth_failure":
      return "database authentication failed";
    case "timeout":
      return "database connection timed out";
    case "dns_failure":
      return "database host could not be resolved";
    case "connection_refused":
      return "database connection refused";
    case "network_unreachable":
      return "database network unreachable";
    case "database_missing":
      return "specified database does not exist";
    case "schema_failure":
      return "database schema is unavailable";
    default:
      return "database unreachable";
  }
}

/**
 * Inspect DATABASE_URL structure without retaining or returning secrets,
 * hostnames, usernames, database names, or the raw URL.
 */
export function inspectConnectionString(raw: string | undefined | null): DbConnectionFacts {
  const empty: DbConnectionFacts = {
    present: false,
    valid: false,
    scheme: null,
    hasUsername: false,
    hasPassword: false,
    sslMode: null
  };
  if (typeof raw !== "string" || raw.trim().length === 0) return empty;

  const present: DbConnectionFacts = { ...empty, present: true };
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return present;
  }

  const protocol = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (protocol !== "postgres" && protocol !== "postgresql") {
    return { ...present, scheme: "other" };
  }

  const sslRaw = parsed.searchParams.get("sslmode")?.toLowerCase() ?? null;
  const sslMode = sslRaw && SSL_MODES.has(sslRaw) ? sslRaw : null;

  return {
    present: true,
    valid: true,
    scheme: protocol,
    hasUsername: parsed.username.length > 0,
    hasPassword: parsed.password.length > 0,
    sslMode
  };
}

export function inspectDatabaseUrl(): DbConnectionFacts {
  return inspectConnectionString(process.env.DATABASE_URL);
}

const TLS_MESSAGE =
  /self[- ]signed|unable to verify|certificate|cert_untrusted|ssl|tls|unable to get local issuer|hostname\/ip does not match/i;
const AUTH_MESSAGE =
  /password authentication failed|invalid authorization|authentication failed|role .* does not exist|no pg_hba\.conf entry/i;
const TIMEOUT_MESSAGE = /timeout|timed out|etimedout/i;
const DNS_MESSAGE = /enotfound|eai_again|getaddrinfo|dns/i;
const REFUSED_MESSAGE = /econnrefused|connection refused/i;
const UNREACHABLE_MESSAGE = /enetunreach|ehostunreach|network unreachable/i;
const MISSING_DB_MESSAGE = /database .* does not exist|3d000/i;
const SCHEMA_MESSAGE = /3f000|42p01|schema .* does not exist|relation .* does not exist/i;

function errorCode(err: unknown): string {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === "string") return code;
    if (typeof code === "number") return String(code);
  }
  return "";
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return "";
}

export function classifyDbError(err: unknown): DbDiagnosticCode {
  const code = errorCode(err);
  const msg = errorMessage(err);

  // Node network / TLS codes.
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "dns_failure";
  if (code === "ECONNREFUSED") return "connection_refused";
  if (code === "ETIMEDOUT" || code === "ETIME") return "timeout";
  if (code === "ENETUNREACH" || code === "EHOSTUNREACH") return "network_unreachable";
  if (
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
  ) {
    return "tls_failure";
  }

  // PostgreSQL SQLSTATE.
  if (code === "28P01" || code === "28000") return "auth_failure";
  if (code === "3D000") return "database_missing";
  if (code === "3F000" || code === "42P01") return "schema_failure";

  if (TIMEOUT_MESSAGE.test(msg) || msg === "timeout") return "timeout";
  if (DNS_MESSAGE.test(msg)) return "dns_failure";
  if (REFUSED_MESSAGE.test(msg)) return "connection_refused";
  if (UNREACHABLE_MESSAGE.test(msg)) return "network_unreachable";
  if (MISSING_DB_MESSAGE.test(msg)) return "database_missing";
  if (SCHEMA_MESSAGE.test(msg)) return "schema_failure";
  // pg_hba "no SSL" / certificate failures before generic auth.
  if (/pg_hba/i.test(msg) && /ssl|tls|cert/i.test(msg)) return "tls_failure";
  if (AUTH_MESSAGE.test(msg)) return "auth_failure";
  if (TLS_MESSAGE.test(msg)) return "tls_failure";

  return "unknown";
}

const POSTGRES_URL_RE = /postgres(?:ql)?:\/\/\S+/gi;
const USERINFO_RE = /[A-Za-z0-9._~!$&'()*+,;=:-]+:[^@\s/]+@[^\s]+/g;

/**
 * Strip connection strings and userinfo from an error before it is logged
 * or returned. Complements redactSecrets() which covers env values.
 */
export function sanitizeDbErrorMessage(err: unknown): string {
  let out = errorMessage(err) || "unknown";
  out = out.replace(POSTGRES_URL_RE, "postgres://[REDACTED]");
  out = out.replace(USERINFO_RE, "[REDACTED]");
  return redactSecrets(out);
}

export function diagnosticFromCaught(err: unknown): DbDiagnostic {
  let code: DbDiagnosticCode = "unknown";
  if (err && typeof err === "object" && "diagnosticCode" in err) {
    const tagged = (err as { diagnosticCode: unknown }).diagnosticCode;
    if (isDbDiagnosticCode(tagged)) code = tagged;
  }
  if (code === "unknown") {
    const facts = inspectDatabaseUrl();
    if (!facts.present) code = "not_configured";
    else if (!facts.valid) code = "invalid_url";
    else code = classifyDbError(err);
  }

  const database: DbDiagnostic["database"] =
    code === "ok" ? "ok" : code === "not_configured" ? "not_configured" : "unavailable";

  return {
    code,
    database,
    tlsVerification: tlsVerificationMode(),
    reason: safeReason(code)
  };
}

export function okDiagnostic(code: DbDiagnosticCode = "ok"): DbDiagnostic {
  return {
    code,
    database: "ok",
    tlsVerification: tlsVerificationMode(),
    reason: code === "ok" ? safeReason("ok") : safeReason(code)
  };
}
