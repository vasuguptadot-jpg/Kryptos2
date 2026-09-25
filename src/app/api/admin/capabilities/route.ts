import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { CAPABILITY_NAME_RE, getAdapter, listAdapters } from "@/lib/adapters/registry";
import { json, jsonError } from "@/lib/http";
import { isSecretConfigured } from "@/lib/secrets";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  try {
    const store = getStore();
    const [capabilities, secrets] = await Promise.all([store.listCapabilities(), store.listSecrets()]);
    const secretByName = new Map(secrets.map((s) => [s.secretName, s.enabled]));
    return json({
      adapters: listAdapters(),
      capabilityNameFormat: "name.scope — e.g. ai.generate, weather.current",
      capabilities: capabilities.map((c) => ({
        capability: c.capability,
        providerId: c.providerId,
        operation: c.operation,
        // Secret reference is safe ADMIN metadata (it is an env var NAME,
        // not a value). It never reaches non-admin clients.
        secretName: c.secretName,
        secretConfigured: isSecretConfigured(c.secretName) ? "CONFIGURED" : "NOT CONFIGURED",
        secretEnabled: secretByName.get(c.secretName) ?? false,
        config: c.config,
        enabled: c.enabled,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt
      }))
    });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

/**
 * Create or replace a capability mapping (upsert).
 * The capability determines provider, adapter operation and secret reference.
 * Configuration is validated by the adapter itself (e.g. http-generic
 * requires an approved https destination and rejects private hosts).
 */
export async function POST(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError(400, "invalid_json", "Request body must be valid JSON");
  }
  const b = (body ?? {}) as Record<string, unknown>;
  for (const key of Object.keys(b)) {
    if (!["capability", "providerId", "secretName", "operation", "config", "enabled"].includes(key)) {
      return jsonError(400, "invalid_request", `unsupported field: ${key}`);
    }
  }
  const capability = typeof b.capability === "string" ? b.capability.trim().toLowerCase() : "";
  const providerId = typeof b.providerId === "string" ? b.providerId.trim() : "";
  const secretName = typeof b.secretName === "string" ? b.secretName.trim().toUpperCase() : "";
  const operation = typeof b.operation === "string" ? b.operation.trim() : "";
  const enabled = b.enabled === undefined ? true : b.enabled === true;

  if (!CAPABILITY_NAME_RE.test(capability)) {
    return jsonError(400, "invalid_request", "capability must look like ai.generate / weather.current");
  }
  const adapter = getAdapter(providerId);
  if (!adapter) {
    return jsonError(400, "invalid_request", `unknown providerId: ${providerId || "(empty)"}`);
  }
  if (!adapter.supportedOperations.includes(operation)) {
    return jsonError(400, "invalid_request", `operation must be one of: ${adapter.supportedOperations.join(", ")}`);
  }
  if (!secretName) return jsonError(400, "invalid_request", "secretName is required");
  const validation = adapter.validateConfig(b.config ?? {});
  if (!validation.ok) {
    return jsonError(400, "invalid_config", validation.error, undefined);
  }

  try {
    const store = getStore();
    const secret = await store.getSecretByName(secretName);
    if (!secret) {
      return jsonError(400, "secret_not_registered", `Register ${secretName} in the secret registry first`);
    }
    if (secret.providerId !== providerId) {
      return jsonError(400, "provider_mismatch", `${secretName} is registered for provider "${secret.providerId}", not "${providerId}"`);
    }
    const rec = await store.upsertCapability({
      capability,
      providerId,
      secretName,
      operation,
      config: validation.config,
      enabled
    });
    await auditAdmin(req, "capability.upsert", "success", 200);
    return json({ capability: rec }, 200);
  } catch {
    await auditAdmin(req, "capability.upsert", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
