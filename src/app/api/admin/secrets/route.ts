import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { getAdapter } from "@/lib/adapters/registry";
import { json, jsonError } from "@/lib/http";
import { isSecretConfigured, secretFingerprint, SECRET_NAME_RE } from "@/lib/secrets";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Secret registry — METADATA ONLY. This endpoint never touches, displays or
 * stores raw secret values; it only records which env var name belongs to
 * which provider, plus presence status and a non-reversible fingerprint.
 */
export async function GET(req: Request): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  try {
    const store = getStore();
    const [secrets, capabilities] = await Promise.all([
      store.listSecrets(),
      store.listCapabilities()
    ]);
    return json({
      secrets: secrets.map((s) => {
        const usedBy = capabilities.filter((c) => c.secretName === s.secretName).map((c) => c.capability);
        return {
          id: s.id,
          secretName: s.secretName,
          providerId: s.providerId,
          notes: s.notes,
          enabled: s.enabled,
          createdAt: s.createdAt,
          updatedAt: s.updatedAt,
          status: isSecretConfigured(s.secretName) ? "CONFIGURED" : "NOT CONFIGURED",
          fingerprint: secretFingerprint(s.secretName),
          usedBy
        };
      })
    });
  } catch {
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}

/**
 * Register secret metadata. Body: {secretName, providerId, notes?}
 * The VALUE must already exist in the deployment environment — this route
 * never accepts one.
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
  // Envelope keys only — never accept anything resembling a value.
  for (const key of Object.keys(b)) {
    if (key !== "secretName" && key !== "providerId" && key !== "notes") {
      return jsonError(400, "invalid_request", `unsupported field: ${key}. Secret VALUES are never accepted here.`);
    }
  }
  const secretName = typeof b.secretName === "string" ? b.secretName.trim().toUpperCase() : "";
  const providerId = typeof b.providerId === "string" ? b.providerId.trim() : "";
  const notes = typeof b.notes === "string" ? b.notes.slice(0, 300) : "";
  if (!SECRET_NAME_RE.test(secretName)) {
    return jsonError(400, "invalid_request", "secretName must look like AN_ENV_VAR (A-Z, 0-9, _, 2-64 chars)");
  }
  if (!getAdapter(providerId)) {
    return jsonError(400, "invalid_request", `unknown providerId: ${providerId || "(empty)"}`);
  }
  try {
    const rec = await getStore().createSecret({ secretName, providerId, notes });
    await auditAdmin(req, "secret.register", "success", 201);
    return json(
      {
        secret: {
          id: rec.id,
          secretName: rec.secretName,
          providerId: rec.providerId,
          enabled: rec.enabled,
          status: isSecretConfigured(rec.secretName) ? "CONFIGURED" : "NOT CONFIGURED"
        }
      },
      201
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    if (message === "secret_exists") {
      return jsonError(409, "secret_exists", "This secret name is already registered");
    }
    await auditAdmin(req, "secret.register", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
