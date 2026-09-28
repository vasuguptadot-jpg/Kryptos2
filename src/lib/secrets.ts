import { createHash } from "node:crypto";

/**
 * Secret handling primitives. There is intentionally NO hard-coded list of
 * provider secrets: any env var may be registered through the secret
 * registry (admin), and values are resolved server-side only.
 *
 * This module contains:
 *  - redaction of any plausible secret value from logs/errors
 *  - env presence checks and fingerprints (#) safe for the admin dashboard
 */

/** Infrastructure secrets that always exist outside the registry. */
const INFRA_SECRET_NAMES: readonly string[] = [
  "DATABASE_URL",
  "DATABASE_CA_CERT",
  "ADMIN_PASSWORD",
  "ADMIN_SESSION_SECRET",
  "CREDENTIAL_PEPPER",
  "SUPABASE_SERVICE_ROLE_KEY",
  "VAPID_PRIVATE_KEY"
];

/** Names that look like credentials — used for dynamic redaction scanning. */
const SECRET_NAME_PATTERN = /(_KEY|_SECRET|PASSWORD|_TOKEN|PRIVATE_KEY|_CREDENTIALS?)$/;

/** Values resolved by the server runtime so far (never shared with clients). */
const resolvedSecretCache = new Set<string>();
const resolvedNameCache = new Set<string>();

/** Called by the server-side resolver whenever a secret value is loaded. */
export function noteResolvedSecret(name: string, value: string): void {
  resolvedNameCache.add(name);
  if (value && value.length >= 8) resolvedSecretCache.add(value);
}

export function registeredRedactionNames(): string[] {
  return [...new Set([...INFRA_SECRET_NAMES, ...resolvedNameCache])];
}

/** Environment variable name format the registry accepts. */
export const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{1,63}$/;

/** Presence check — value itself is never copied here. */
export function isSecretConfigured(secretName: string): boolean {
  const v = process.env[secretName];
  return typeof v === "string" && v.length > 0;
}

/** Non-reversible fingerprint for "is it configured?" admin metadata. */
export function secretFingerprint(secretName: string): string | null {
  const value = process.env[secretName];
  if (!value) return null;
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

/**
 * Every currently-known secret value, for redaction purposes:
 *  - values the resolver has actually loaded (covers arbitrary registry names)
 *  - process.env values whose NAMES match the credential pattern
 *  - named infrastructure secrets
 * This dynamic scan is what lets redaction protect MY_WEATHER_API_KEY or any
 * future secret without source-code changes.
 */
export function activeSecretValues(): string[] {
  const values: string[] = [...resolvedSecretCache];
  for (const [name, value] of Object.entries(process.env)) {
    if (!value || value.length < 8) continue;
    if (SECRET_NAME_PATTERN.test(name) || INFRA_SECRET_NAMES.includes(name)) {
      values.push(value);
    }
  }
  return values;
}

/**
 * Redact any known secret value (or env var assignment) from a string before
 * it is logged or embedded in an error message.
 */
export function redactSecrets(input: string): string {
  let out = input;
  for (const secret of activeSecretValues()) {
    if (secret && out.includes(secret)) out = out.split(secret).join("[REDACTED]");
  }
  for (const name of registeredRedactionNames()) {
    const assignment = new RegExp(`${name}=\\S+`, "g");
    out = out.replace(assignment, `${name}=[REDACTED]`);
  }
  return out;
}
