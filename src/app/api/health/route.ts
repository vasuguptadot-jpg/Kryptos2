import {
  diagnosticFromCaught,
  okDiagnostic,
  safeReason,
  tlsVerificationMode,
  type DbDiagnostic
} from "@/lib/db-diagnostics";
import { json } from "@/lib/http";
import { isSecretConfigured } from "@/lib/secrets";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Public health endpoint. Safe metadata only: service status, DB state and
 * per-provider "configured/not_configured" derived from the server-side
 * capability registry. Never credentials, never env names, never values.
 *
 * databaseDiagnostic is a coarse, secret-free classification of why the
 * metadata store is unreachable. It never includes DATABASE_URL, hosts,
 * usernames, or passwords. TLS verification is reported, never relaxed.
 */
export async function GET(): Promise<Response> {
  let db: "ok" | "unavailable" | "not_configured" = "not_configured";
  let databaseDiagnostic: DbDiagnostic = {
    code: "not_configured",
    database: "not_configured",
    tlsVerification: tlsVerificationMode(),
    reason: safeReason("not_configured")
  };
  const providers: Record<string, string> = {};
  let capabilityCount = 0;

  try {
    const store = getStore();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        store.ping(),
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error("timeout")), 3000);
        })
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
    db = "ok";
    databaseDiagnostic = okDiagnostic();
    const capabilities = await store.listCapabilities();
    capabilityCount = capabilities.length;
    for (const cap of capabilities) {
      if (!cap.enabled) continue;
      // A provider is "configured" if at least one enabled capability's
      // secret is present in the deployment environment.
      const status = isSecretConfigured(cap.secretName) ? "configured" : providers[cap.providerId] ?? "not_configured";
      if (status === "configured" || !(cap.providerId in providers)) providers[cap.providerId] = status;
    }
  } catch (err) {
    databaseDiagnostic = diagnosticFromCaught(err);
    db = databaseDiagnostic.database;
  }

  return json({
    status: "ok",
    service: "kryptos",
    version: process.env.APP_VERSION ?? "1.0.0",
    time: new Date().toISOString(),
    database: db,
    databaseDiagnostic: {
      code: databaseDiagnostic.code,
      tlsVerification: databaseDiagnostic.tlsVerification,
      reason: safeReason(databaseDiagnostic.code)
    },
    providers,
    capabilities: capabilityCount
  });
}
