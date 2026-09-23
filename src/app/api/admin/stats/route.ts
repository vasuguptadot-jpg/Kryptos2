import { requireAdmin } from "@/lib/admin-guard";
import { json, jsonError } from "@/lib/http";
import { isSecretConfigured, secretFingerprint } from "@/lib/secrets";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Safe operational overview for the dashboard: provider/capability status
 * (configured / fingerprint only — never values), usage statistics and
 * rate-limit pressure.
 */
export async function GET(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  try {
    const store = getStore();
    const [stats, apps, capabilities, secrets] = await Promise.all([
      store.stats(),
      store.listApplications(),
      store.listCapabilities(),
      store.listSecrets()
    ]);
    const secretByName = new Map(secrets.map((s) => [s.secretName, s]));
    const providerMap = new Map<string, { status: string; capabilities: string[]; keyFingerprint: string | null }>();
    for (const cap of capabilities) {
      const cur = providerMap.get(cap.providerId) ?? {
        status: "not_configured",
        capabilities: [],
        keyFingerprint: null
      };
      cur.capabilities.push(cap.capability);
      const rec = secretByName.get(cap.secretName);
      if (rec?.enabled && isSecretConfigured(cap.secretName)) {
        cur.status = "configured";
        cur.keyFingerprint = cur.keyFingerprint ?? secretFingerprint(cap.secretName);
      }
      providerMap.set(cap.providerId, cur);
    }
    return json({
      version: process.env.APP_VERSION ?? "1.0.0",
      providers: Object.fromEntries(providerMap),
      totals: {
        applications: apps.length,
        activeApplications: apps.filter((a) => a.status === "active").length,
        capabilities: capabilities.length,
        secrets: secrets.length,
        events: stats.totalEvents,
        failures: stats.totalFailures,
        rateLimited: stats.totalRateLimited
      },
      perProvider: stats.perProvider,
      perApplication: stats.perApplication
    });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
