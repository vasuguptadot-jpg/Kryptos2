import { isSecretConfigured, noteResolvedSecret } from "./secrets";
import type { CapabilityRecord, Store } from "./types";

export type Resolution =
  | { ok: true; secret: string }
  | { ok: false; status: 403 | 503; code: string };

/**
 * SERVER-ONLY secret resolver. There is intentionally no client-callable
 * endpoint for this — it is invoked exclusively from the trusted request
 * pipeline AFTER authentication and authorization have succeeded.
 *
 *   capability → secret registry metadata → env var VALUE (never returned)
 *
 * The value is handed only to the provider adapter. It is never placed in
 * responses, logs, or the database.
 */
export async function resolveSecretForCapability(
  store: Store,
  cap: CapabilityRecord
): Promise<Resolution> {
  let record;
  try {
    record = await store.getSecretByName(cap.secretName);
  } catch {
    // Fail closed: a store error must never coerce into "no secret needed".
    return { ok: false, status: 503, code: "configuration_unavailable" };
  }
  if (!record || record.providerId !== cap.providerId) {
    return { ok: false, status: 503, code: "capability_misconfigured" };
  }
  if (!record.enabled) {
    return { ok: false, status: 403, code: "secret_disabled" };
  }
  if (!isSecretConfigured(cap.secretName)) {
    return { ok: false, status: 503, code: "provider_not_configured" };
  }
  const value = process.env[cap.secretName]!;
  noteResolvedSecret(cap.secretName, value);
  return { ok: true, secret: value };
}
