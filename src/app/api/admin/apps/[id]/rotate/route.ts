import { auditAdmin, requireAdmin } from "@/lib/admin-guard";
import { generateCredential } from "@/lib/credentials";
import { json, jsonError } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Rotate an application's credential: issue a fresh one, then revoke the old.
 * The new credential is returned exactly once. Other apps are unaffected.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<Response> {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const { id } = await params;
  try {
    const store = getStore();
    const apps = await store.listApplications();
    const app = apps.find((a) => a.id === id);
    if (!app) return jsonError(404, "app_not_found", "Application not found");
    if (app.status === "revoked") {
      return jsonError(400, "app_revoked", "A revoked application cannot be rotated");
    }
    // Revoke existing credentials FIRST, then issue the replacement —
    // revokeCredentials() marks all of the app's credentials revoked.
    await store.revokeCredentials(app.id);
    const cred = generateCredential();
    await store.createCredential(app.id, cred.keyHash, cred.keyPrefix);
    await auditAdmin(req, "app.rotate", "success", 200);
    return json({
      ok: true,
      appId: app.appId,
      credential: cred.rawKey,
      credentialPrefix: cred.keyPrefix,
      instructions: "Distribute this credential securely. It cannot be retrieved again."
    });
  } catch {
    await auditAdmin(req, "app.rotate", "failure", 503, "store_unavailable");
    return jsonError(503, "store_unavailable", "Metadata store unavailable");
  }
}
