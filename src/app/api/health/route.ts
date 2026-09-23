import { json } from "@/lib/http";
import { isSecretConfigured } from "@/lib/secrets";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Public health endpoint. Safe metadata only: service status, DB state and
 * per-provider "configured/not_configured" derived from the server-side
 * capability registry. Never credentials, never env names, never values.
 */
export async function GET(): Promise<Response> {
  let db: "ok" | "unavailable" | "not_configured" = "not_configured";
  const providers: Record<string, string> = {};
  let capabilityCount = 0;

  try {
    const store = getStore();
    await Promise.race([
      store.ping(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 3000))
    ]);
    db = "ok";
    const capabilities = await store.listCapabilities();
    capabilityCount = capabilities.length;
    for (const cap of capabilities) {
      if (!cap.enabled) continue;
      // A provider is "configured" if at least one enabled capability's
      // secret is present in the deployment environment.
      const status = isSecretConfigured(cap.secretName) ? "configured" : providers[cap.providerId] ?? "not_configured";
      if (status === "configured" || !(cap.providerId in providers)) providers[cap.providerId] = status;
    }
  } catch {
    db = process.env.DATABASE_URL || process.env.STORE_BACKEND === "memory" ? "unavailable" : "not_configured";
  }

  return json({
    status: "ok",
    service: "kryptos",
    version: process.env.APP_VERSION ?? "1.0.0",
    time: new Date().toISOString(),
    database: db,
    providers,
    capabilities: capabilityCount
  });
}
